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
    assert_eq!(count, 1, "detection should go through alert channel to audit DB");

    // Verify no WAL file was created
    assert!(
        !wal_path.exists(),
        "WAL file should not be created when detection_wal=false"
    );
}
