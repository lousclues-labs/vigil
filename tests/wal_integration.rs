use std::sync::atomic::Ordering;
use std::sync::Arc;

use vigil::metrics::Metrics;
use vigil::types::{Change, Severity};
use vigil::wal::{DetectionRecord, DetectionSource, DetectionWal};

/// Verifies that panic-sourced detection records roundtrip through the WAL
/// with the correct field values (Critical severity, empty changes, Panic source).
/// The actual panic handler in worker::process_safe creates exactly this shape.
#[test]
fn panic_produces_detection_record() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("detections.wal");
    let wal = DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap();

    // Create a panic record exactly as process_safe does
    let panic_record = DetectionRecord {
        timestamp: chrono::Utc::now().timestamp(),
        path: "/usr/bin/test-panic-path".to_string(),
        changes: vec![],
        severity: Severity::Critical,
        monitored_group: "unknown".into(),
        process: None,
        package: None,
        package_update: false,
        maintenance_window: false,
        source: DetectionSource::Panic,
        disambiguation: None,
    };

    let seq = wal.append(&panic_record).unwrap();

    let entries = wal.iter_unconsumed().unwrap();
    let entry = entries.iter().find(|e| e.sequence == seq).unwrap();

    assert_eq!(entry.record.source, DetectionSource::Panic);
    assert_eq!(entry.record.severity, Severity::Critical);
    assert!(entry.record.changes.is_empty());
    assert_eq!(entry.record.path, "/usr/bin/test-panic-path");
    assert_eq!(entry.record.monitored_group, "unknown");
}

/// Verifies that when detection_wal is disabled in config, the WAL file is not
/// created and the alert dispatcher operates without WAL (wal_active=false).
#[test]
fn wal_disabled_uses_current_path() {
    let dir = tempfile::tempdir().unwrap();
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let mut cfg = vigil::config::default_config();
    cfg.daemon.detection_wal = false;
    cfg.daemon.runtime_dir = runtime_dir.clone();
    cfg.daemon.db_path = dir.path().join("baseline.db");

    // With detection_wal=false, no WAL file should be created at the expected path
    let wal_path = runtime_dir.join("detections.wal");
    assert!(
        !wal_path.exists(),
        "WAL file should not exist when detection_wal=false"
    );

    // Verify AlertDispatcher can be created with wal_active=false
    let audit_path = dir.path().join("audit.db");
    cfg.alerts.syslog = false;
    cfg.alerts.desktop_notifications = false;
    cfg.alerts.log_file = std::path::PathBuf::new();
    cfg.hooks.signal_socket.clear();
    cfg.alerts.remote_syslog.enabled = false;

    let metrics = Arc::new(Metrics::new());
    let dispatcher = vigil::alert::AlertDispatcher::new(
        &cfg,
        &audit_path,
        metrics.clone(),
        None,
        false, // wal_active = false
        "test".to_string(),
    )
    .unwrap();

    // Send a detection through the alert channel (non-WAL path)
    let (tx, rx) = crossbeam_channel::bounded(4);
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let handle = std::thread::spawn(move || {
        dispatcher.run(rx, shutdown_clone);
    });

    let change = vigil::types::ChangeResult {
        path: Arc::new(std::path::PathBuf::from("/tmp/wal-disabled-test")),
        changes: vec![Change::Created],
        severity: Severity::High,
        monitored_group: "test".into(),
        process: None,
        package: None,
        package_update: false,
        disambiguation: None,
    };

    tx.send(vigil::alert::AlertPayload {
        change,
        maintenance_window: false,
    })
    .unwrap();

    // Give the dispatcher time to process
    std::thread::sleep(std::time::Duration::from_millis(100));
    shutdown.store(true, Ordering::Release);
    drop(tx);
    handle.join().unwrap();

    // Verify that the detection was processed (audit entry written since wal_active=false)
    let conn = rusqlite::Connection::open(&audit_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 1,
        "detection should go through alert channel to audit DB"
    );

    // Verify no WAL file was created
    assert!(
        !wal_path.exists(),
        "WAL file should not be created when detection_wal=false"
    );
}

/// An authentic WAL entry whose payload this build cannot decode must be
/// retained, not erased.
///
/// The entry has already passed CRC and HMAC: it is undamaged and genuine,
/// and only its schema is unreadable -- exactly what a `DetectionRecord`
/// change across an upgrade looks like. The scanner previously skipped it
/// with a bare `continue`, and because `truncate_consumed` rebuilds the WAL
/// from whatever the scanner returns, the record was then deleted from disk
/// within the minute. A real detection would disappear from the audit log and
/// every alert sink with nothing logged and no counter moved.
///
/// The CRC must be recomputed after corrupting the payload. Without that the
/// entry fails the CRC check first and takes the gap-recovery path, which is
/// a different branch that was already announced -- a test that skips this
/// step passes against the broken code and proves nothing.
#[test]
fn an_undecodable_entry_is_retained_not_erased() {
    use std::io::{Read, Seek, SeekFrom, Write};

    const WAL_HEADER_SIZE: usize = 64;

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("detections.wal");

    let record = |seq: u64| vigil::wal::DetectionRecord {
        timestamp: 1_700_000_000 + seq as i64,
        path: format!("/etc/target{seq}"),
        changes: vec![vigil::types::Change::ContentModified {
            old_hash: "old".into(),
            new_hash: "new".into(),
        }],
        severity: vigil::types::Severity::Critical,
        monitored_group: "system".to_string(),
        process: None,
        package: None,
        package_update: false,
        maintenance_window: false,
        source: vigil::wal::DetectionSource::ScheduledScan,
        disambiguation: None,
    };

    {
        let wal = vigil::wal::DetectionWal::open(&wal_path, None, 1024 * 1024).unwrap();
        for seq in 0..3 {
            wal.append(&record(seq)).unwrap();
        }
    }

    // Corrupt the middle entry's payload and repair its CRC, so it reaches the
    // decode path rather than the gap-recovery path.
    let mut buf = Vec::new();
    std::fs::File::open(&wal_path)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();

    let marker = b"/etc/target1";
    let marker_pos = buf
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("payload marker present");

    // Walk the entry framing to find the entry containing that offset.
    let mut entry_start = WAL_HEADER_SIZE;
    let (victim_start, victim_size) = loop {
        let size =
            u32::from_le_bytes(buf[entry_start..entry_start + 4].try_into().unwrap()) as usize;
        assert!(
            size > 0 && entry_start + size <= buf.len(),
            "walked off the WAL"
        );
        if marker_pos < entry_start + size {
            break (entry_start, size);
        }
        entry_start += size;
    };

    // 0xC1 is the MessagePack "never used" byte: valid framing, invalid payload.
    buf[marker_pos] = 0xC1;
    let recomputed = crc32fast::hash(&buf[victim_start..victim_start + victim_size - 4]);
    buf[victim_start + victim_size - 4..victim_start + victim_size]
        .copy_from_slice(&recomputed.to_le_bytes());

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&buf).unwrap();
        f.sync_all().unwrap();
    }

    let before = std::fs::metadata(&wal_path).unwrap().len();

    // Compaction, which the audit writer runs every 60 seconds.
    {
        let wal = vigil::wal::DetectionWal::open(&wal_path, None, 1024 * 1024).unwrap();
        wal.truncate_consumed().unwrap();
    }

    let after = std::fs::metadata(&wal_path).unwrap().len();
    assert_eq!(
        after, before,
        "compaction must carry every unconsumed entry forward, including one this          build cannot decode. {before} -> {after} bytes means a genuine,          integrity-verified detection was erased from disk."
    );
}
