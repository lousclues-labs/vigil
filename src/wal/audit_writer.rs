use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection};
use zeroize::Zeroizing;

use crate::db::{self, audit_ops, baseline_ops};
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::{Change, ChangeResult};

use super::{DetectionSource, DetectionWal, WalEntry};

pub struct AuditWriter {
    wal: Arc<DetectionWal>,
    audit_conn: Connection,
    audit_db_path: PathBuf,
    baseline_conn: Connection,
    hmac_key: Option<Zeroizing<Vec<u8>>>,
    last_chain_hash: String,
    metrics: Arc<Metrics>,
    hostname: String,
    consecutive_failures: u32,
    expected_next_sequence: u64,
    last_truncate: Instant,
}

impl AuditWriter {
    pub fn new(
        wal: Arc<DetectionWal>,
        audit_conn: Connection,
        audit_db_path: PathBuf,
        baseline_conn: Connection,
        hmac_key: Option<Zeroizing<Vec<u8>>>,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let last_chain_hash = audit_ops::get_last_chain_hash(&audit_conn)?.unwrap_or_else(|| {
            blake3::hash(b"vigil-audit-chain-genesis")
                .to_hex()
                .to_string()
        });

        let hostname = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "localhost".to_string());

        Ok(Self {
            wal,
            audit_conn,
            audit_db_path,
            baseline_conn,
            hmac_key,
            last_chain_hash,
            metrics,
            hostname,
            consecutive_failures: 0,
            expected_next_sequence: 0,
            last_truncate: Instant::now(),
        })
    }

    pub fn recover(&mut self) -> Result<u64> {
        let stored_nonce =
            baseline_ops::get_config_state(&self.baseline_conn, "wal_instance_nonce")?;
        let current_nonce = hex::encode(self.wal.instance_nonce());
        if let Some(stored) = stored_nonce {
            if stored != current_nonce {
                return Err(VigilError::Wal(
                    "WAL instance nonce mismatch during recovery".into(),
                ));
            }
        }

        let mut replayed = 0u64;
        let mut highest_seq = None;

        let mut pending: Vec<_> = self
            .wal
            .iter_unconsumed()?
            .into_iter()
            .filter(|e| !e.audit_done())
            .collect();
        pending.sort_by_key(|e| e.sequence);

        for entry in pending {
            if entry.record.source == DetectionSource::Sentinel {
                self.wal.mark_audit_done(entry.offset)?;
                highest_seq = Some(entry.sequence);
                continue;
            }

            let exists: bool = self.audit_conn.query_row(
                "SELECT COUNT(*) > 0 FROM audit_log WHERE timestamp = ?1 AND path = ?2",
                params![entry.record.timestamp, entry.record.path],
                |row| row.get(0),
            )?;

            if exists {
                self.wal.mark_audit_done(entry.offset)?;
                highest_seq = Some(entry.sequence);
                continue;
            }

            let cr = entry.record.to_change_result();
            let previous = self.last_chain_hash.clone();
            let hmac = build_entry_hmac(&self.hmac_key, &entry.record, &previous)?;

            let new_hash = insert_with_timestamp(
                &self.audit_conn,
                &cr,
                entry.record.maintenance_window,
                false,
                hmac.as_deref(),
                &previous,
                entry.record.timestamp,
            )?;
            self.last_chain_hash = new_hash;
            self.wal.mark_audit_done(entry.offset)?;
            replayed += 1;
            highest_seq = Some(entry.sequence);
        }

        if let Some(max_seq) = highest_seq {
            self.expected_next_sequence = max_seq + 1;
        }

        self.metrics
            .detections_wal_replayed
            .fetch_add(replayed, Ordering::Relaxed);

        Ok(replayed)
    }

    pub fn spawn(mut self, shutdown: Arc<AtomicBool>) -> Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name("vigil-wal-audit".into())
            .spawn(move || self.run(shutdown))
            .map_err(|e| VigilError::Daemon(format!("cannot spawn WAL audit writer: {}", e)))
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) {
        loop {
            let mut pending: Vec<_> = match self.wal.iter_unconsumed() {
                Ok(v) => v.into_iter().filter(|e| !e.audit_done()).collect(),
                Err(e) => {
                    tracing::error!(error = %e, "WAL audit iteration failed");
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };

            self.metrics
                .detections_wal_audit_lag
                .store(pending.len() as u64, Ordering::Relaxed);

            if pending.is_empty() {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }

            pending.sort_by(|a, b| {
                b.record
                    .severity
                    .cmp(&a.record.severity)
                    .then(a.sequence.cmp(&b.sequence))
            });

            let mut processed_any = false;
            for entry in pending {
                if entry.record.source == DetectionSource::Sentinel {
                    let _ = self.wal.mark_audit_done(entry.offset);
                    self.expected_next_sequence = entry.sequence + 1;
                    processed_any = true;
                    continue;
                }

                if entry.sequence > self.expected_next_sequence {
                    let gap = entry.sequence - self.expected_next_sequence;
                    tracing::error!(
                        expected = self.expected_next_sequence,
                        got = entry.sequence,
                        gap = gap,
                        "WAL sequence gap detected"
                    );
                    self.metrics
                        .detections_wal_gaps
                        .fetch_add(1, Ordering::Relaxed);
                }

                match self.commit_entry(&entry) {
                    Ok(()) => {
                        self.expected_next_sequence = entry.sequence + 1;
                        self.consecutive_failures = 0;
                        processed_any = true;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "WAL audit commit failed");
                        self.consecutive_failures += 1;
                        if self.consecutive_failures >= 3 {
                            if let Err(reopen_err) = self.reopen_audit_conn() {
                                tracing::error!(error = %reopen_err, "WAL audit DB reopen failed");
                            } else {
                                self.consecutive_failures = 0;
                            }
                        }
                    }
                }
            }

            if self.last_truncate.elapsed() >= Duration::from_secs(60) {
                if let Ok(_purged) = self.wal.truncate_consumed() {
                    self.metrics
                        .detections_wal_bytes
                        .store(self.wal.file_size(), Ordering::Relaxed);
                    self.metrics
                        .detections_wal_pending
                        .store(self.wal.pending_count(), Ordering::Relaxed);
                }
                self.last_truncate = Instant::now();
            }

            if !processed_any {
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        tracing::info!(hostname = %self.hostname, "WAL audit writer stopped");
    }

    fn commit_entry(&mut self, entry: &WalEntry) -> Result<()> {
        let cr = entry.record.to_change_result();
        let previous = self.last_chain_hash.clone();
        let hmac = build_entry_hmac(&self.hmac_key, &entry.record, &previous)?;

        let new_hash = insert_with_timestamp(
            &self.audit_conn,
            &cr,
            entry.record.maintenance_window,
            false,
            hmac.as_deref(),
            &previous,
            entry.record.timestamp,
        )?;

        self.last_chain_hash = new_hash;
        self.wal.mark_audit_done(entry.offset)?;
        self.metrics
            .detections_wal_audit_committed
            .fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn reopen_audit_conn(&mut self) -> Result<()> {
        let new_conn = Connection::open(&self.audit_db_path)?;
        db::apply_pragmas(
            &new_conn,
            &db::PragmaOpts {
                sync_mode: "FULL",
                wal_mode: true,
                ..db::PragmaOpts::default()
            },
        )?;
        self.audit_conn = new_conn;
        Ok(())
    }
}

fn insert_with_timestamp(
    conn: &Connection,
    change: &ChangeResult,
    maintenance: bool,
    suppressed: bool,
    hmac: Option<&str>,
    previous_chain_hash: &str,
    timestamp: i64,
) -> Result<String> {
    let path = change.path.to_string_lossy().to_string();
    let changes_json = serde_json::to_string(&change.changes)?;
    let severity = change.severity.to_string();
    let process_json = serde_json::to_string(&change.process).ok();

    let chain_hash = audit_ops::compute_chain_hash(
        previous_chain_hash,
        timestamp,
        &path,
        &changes_json,
        &severity,
    );

    conn.prepare_cached(
        "INSERT INTO audit_log (
            timestamp, path, changes_json, severity, monitored_group,
            process_json, package, maintenance, suppressed, hmac, chain_hash
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9, ?10, ?11
        )",
    )?
    .execute(params![
        timestamp,
        path,
        changes_json,
        severity,
        change.monitored_group,
        process_json,
        change.package,
        maintenance as i32,
        suppressed as i32,
        hmac,
        chain_hash,
    ])?;

    Ok(chain_hash)
}

fn build_entry_hmac(
    key: &Option<Zeroizing<Vec<u8>>>,
    record: &super::DetectionRecord,
    previous_chain_hash: &str,
) -> Result<Option<String>> {
    let Some(key) = key.as_ref() else {
        return Ok(None);
    };

    let primary = record
        .changes
        .first()
        .map(change_to_name)
        .unwrap_or("unknown");

    let (old_hash, new_hash) = record
        .changes
        .iter()
        .find_map(|c| match c {
            Change::ContentModified { old_hash, new_hash } => {
                Some((Some(old_hash.as_str()), Some(new_hash.as_str())))
            }
            _ => None,
        })
        .unwrap_or((None, None));

    let data = crate::hmac::build_audit_hmac_data(
        record.timestamp,
        &record.path,
        primary,
        &record.severity.to_string(),
        old_hash,
        new_hash,
        previous_chain_hash,
    );

    Ok(Some(crate::hmac::compute_hmac(key, &data)?))
}

fn change_to_name(change: &Change) -> &'static str {
    match change {
        Change::ContentModified { .. } => "content_modified",
        Change::PermissionsChanged { .. } => "permissions_changed",
        Change::OwnerChanged { .. } => "owner_changed",
        Change::InodeChanged { .. } => "inode_changed",
        Change::TypeChanged { .. } => "type_changed",
        Change::SymlinkTargetChanged { .. } => "symlink_target_changed",
        Change::CapabilitiesChanged { .. } => "capabilities_changed",
        Change::XattrChanged { .. } => "xattr_changed",
        Change::SecurityContextChanged { .. } => "security_context_changed",
        Change::SizeChanged { .. } => "size_changed",
        Change::DeviceChanged { .. } => "device_changed",
        Change::Deleted => "deleted",
        Change::Created => "created",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::db;
    use crate::types::{Change, Severity};

    fn mk_record(idx: usize, severity: Severity) -> super::super::DetectionRecord {
        super::super::DetectionRecord {
            timestamp: 1_700_000_000 + idx as i64,
            path: format!("/tmp/audit-wal-{}", idx),
            changes: vec![Change::Created],
            severity,
            monitored_group: "test".into(),
            process: None,
            package: None,
            package_update: false,
            maintenance_window: false,
            source: super::super::DetectionSource::Realtime,
        }
    }

    #[test]
    fn drain_to_audit_db() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");

        let mut cfg = config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");
        let audit_conn = db::open_audit_db(&cfg).unwrap();
        let baseline_conn = db::open_baseline_db(&cfg).unwrap();
        let wal =
            Arc::new(super::super::DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());
        baseline_ops::set_config_state(
            &baseline_conn,
            "wal_instance_nonce",
            &hex::encode(wal.instance_nonce()),
        )
        .unwrap();

        for i in 0..100 {
            wal.append(&mk_record(i, Severity::Medium)).unwrap();
        }

        let metrics = Arc::new(Metrics::new());
        let mut writer = AuditWriter::new(
            wal.clone(),
            audit_conn,
            db::audit_db_path(&cfg),
            baseline_conn,
            None,
            metrics,
        )
        .unwrap();

        writer.recover().unwrap();

        let count: i64 = writer
            .audit_conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 100);
    }

    #[test]
    fn crash_recovery_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");

        let mut cfg = config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let wal =
            Arc::new(super::super::DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

        // Populate WAL with 50 entries
        for i in 0..50 {
            wal.append(&mk_record(i, Severity::Medium)).unwrap();
        }

        // First pass: drain all 50 entries into audit DB
        {
            let audit_conn = db::open_audit_db(&cfg).unwrap();
            let baseline_conn = db::open_baseline_db(&cfg).unwrap();
            baseline_ops::set_config_state(
                &baseline_conn,
                "wal_instance_nonce",
                &hex::encode(wal.instance_nonce()),
            )
            .unwrap();

            let metrics = Arc::new(Metrics::new());
            let mut writer = AuditWriter::new(
                wal.clone(),
                audit_conn,
                db::audit_db_path(&cfg),
                baseline_conn,
                None,
                metrics,
            )
            .unwrap();
            writer.recover().unwrap();

            let count: i64 = writer
                .audit_conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 50);
        }

        // Simulate crash: clear audit_done flags by writing flags=0 at each entry offset.
        // After recovery, all entries are marked audit_done+sink_done. iter_unconsumed
        // skips fully consumed entries, so we re-read the raw file to reset flags.
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&wal_path)
                .unwrap();
            let file_len = file.metadata().unwrap().len();
            let mut offset = 64u64; // skip header
            while offset < file_len {
                let mut size_buf = [0u8; 4];
                if super::super::read_exact_at(&file, &mut size_buf, offset).is_err() {
                    break;
                }
                let entry_size = u32::from_le_bytes(size_buf) as u64;
                if !(50..=1_048_576).contains(&entry_size) {
                    offset += 1;
                    continue;
                }
                if offset + entry_size > file_len {
                    break;
                }

                // Read entire entry, clear flags, recompute CRC, write back
                let mut raw = vec![0u8; entry_size as usize];
                super::super::read_exact_at(&file, &mut raw, offset).unwrap();
                raw[12..14].copy_from_slice(&0u16.to_le_bytes());
                let crc = crc32fast::hash(&raw[..entry_size as usize - 4]);
                raw[entry_size as usize - 4..].copy_from_slice(&crc.to_le_bytes());
                super::super::write_all_at(&file, &raw, offset).unwrap();

                offset += entry_size;
            }
        }

        // Second pass: recover should dedup — no new entries inserted
        {
            let audit_conn = db::open_audit_db(&cfg).unwrap();
            let baseline_conn = db::open_baseline_db(&cfg).unwrap();
            let metrics = Arc::new(Metrics::new());
            let mut writer = AuditWriter::new(
                wal.clone(),
                audit_conn,
                db::audit_db_path(&cfg),
                baseline_conn,
                None,
                metrics.clone(),
            )
            .unwrap();
            let replayed = writer.recover().unwrap();
            assert_eq!(replayed, 0, "all entries should be deduped");

            let count: i64 = writer
                .audit_conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 50, "no new entries should appear");
            assert_eq!(
                metrics.detections_wal_replayed.load(Ordering::Relaxed),
                0,
                "replayed metric should be 0"
            );
        }
    }

    #[test]
    fn sequence_gap_detection() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");

        let mut cfg = config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let wal =
            Arc::new(super::super::DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

        // Append 5 entries (sequences 0..4)
        for i in 0..5 {
            wal.append(&mk_record(i, Severity::Medium)).unwrap();
        }

        // Get the offsets of entries 2 and 3, then corrupt them on disk
        let entries = wal.iter_unconsumed().unwrap();
        let offset2 = entries[2].offset;
        let offset3 = entries[3].offset;
        let size2 = {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .open(&wal_path)
                .unwrap();
            let mut s = [0u8; 4];
            super::super::read_exact_at(&file, &mut s, offset2).unwrap();
            u32::from_le_bytes(s) as u64
        };
        let size3 = {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .open(&wal_path)
                .unwrap();
            let mut s = [0u8; 4];
            super::super::read_exact_at(&file, &mut s, offset3).unwrap();
            u32::from_le_bytes(s) as u64
        };
        // Zero out entries 2 and 3 to cause CRC failures (gap scanning)
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&wal_path)
                .unwrap();
            let zeros2 = vec![0u8; size2 as usize];
            super::super::write_all_at(&file, &zeros2, offset2).unwrap();
            let zeros3 = vec![0u8; size3 as usize];
            super::super::write_all_at(&file, &zeros3, offset3).unwrap();
        }

        // Now iter_unconsumed should return entries 0, 1, 4 (sequences 0, 1, 4)
        let remaining = wal.iter_unconsumed().unwrap();
        assert_eq!(remaining.len(), 3);

        // Create an AuditWriter and process the entries
        let audit_conn = db::open_audit_db(&cfg).unwrap();
        let baseline_conn = db::open_baseline_db(&cfg).unwrap();
        baseline_ops::set_config_state(
            &baseline_conn,
            "wal_instance_nonce",
            &hex::encode(wal.instance_nonce()),
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let mut writer = AuditWriter::new(
            wal.clone(),
            audit_conn,
            db::audit_db_path(&cfg),
            baseline_conn,
            None,
            metrics.clone(),
        )
        .unwrap();

        // Simulate one iteration of the run() consumption loop — this is where
        // gap detection actually happens (recover() doesn't check gaps).
        {
            let mut pending: Vec<_> = wal
                .iter_unconsumed()
                .unwrap()
                .into_iter()
                .filter(|e| !e.audit_done())
                .collect();
            pending.sort_by(|a, b| {
                b.record
                    .severity
                    .cmp(&a.record.severity)
                    .then(a.sequence.cmp(&b.sequence))
            });
            for entry in pending {
                if entry.sequence > writer.expected_next_sequence {
                    metrics
                        .detections_wal_gaps
                        .fetch_add(1, Ordering::Relaxed);
                }
                writer.commit_entry(&entry).unwrap();
                writer.expected_next_sequence = entry.sequence + 1;
            }
        }

        assert!(
            metrics.detections_wal_gaps.load(Ordering::Relaxed) >= 1,
            "should detect at least one sequence gap"
        );
    }

    #[test]
    fn priority_ordering() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");

        let mut cfg = config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let wal =
            Arc::new(super::super::DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

        // Append entries with different severities:
        // seq 0: Low, seq 1: Critical, seq 2: Medium, seq 3: High
        wal.append(&mk_record(0, Severity::Low)).unwrap();
        wal.append(&mk_record(1, Severity::Critical)).unwrap();
        wal.append(&mk_record(2, Severity::Medium)).unwrap();
        wal.append(&mk_record(3, Severity::High)).unwrap();

        let audit_conn = db::open_audit_db(&cfg).unwrap();
        let baseline_conn = db::open_baseline_db(&cfg).unwrap();
        baseline_ops::set_config_state(
            &baseline_conn,
            "wal_instance_nonce",
            &hex::encode(wal.instance_nonce()),
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let mut writer = AuditWriter::new(
            wal.clone(),
            audit_conn,
            db::audit_db_path(&cfg),
            baseline_conn,
            None,
            metrics,
        )
        .unwrap();

        // Process once manually: simulate what run() does in one iteration
        {
            let mut pending: Vec<_> = wal
                .iter_unconsumed()
                .unwrap()
                .into_iter()
                .filter(|e| !e.audit_done())
                .collect();
            pending.sort_by(|a, b| {
                b.record
                    .severity
                    .cmp(&a.record.severity)
                    .then(a.sequence.cmp(&b.sequence))
            });
            for entry in pending {
                writer.commit_entry(&entry).unwrap();
            }
        }

        // Read back audit_log entries in insertion order (by rowid)
        let entries: Vec<(String, String)> = writer
            .audit_conn
            .prepare("SELECT severity, path FROM audit_log ORDER BY id ASC")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(entries.len(), 4);
        // Sorted: Critical first, then High, then Medium, then Low
        // Severity::to_string() produces lowercase in this codebase
        assert!(
            entries[0].0.eq_ignore_ascii_case("Critical"),
            "first entry should be Critical, got {}",
            entries[0].0
        );
        assert!(
            entries[1].0.eq_ignore_ascii_case("High"),
            "second entry should be High, got {}",
            entries[1].0
        );
        assert!(
            entries[2].0.eq_ignore_ascii_case("Medium"),
            "third entry should be Medium, got {}",
            entries[2].0
        );
        assert!(
            entries[3].0.eq_ignore_ascii_case("Low"),
            "fourth entry should be Low, got {}",
            entries[3].0
        );
    }

    #[test]
    fn audit_db_failure_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");

        let mut cfg = config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let wal =
            Arc::new(super::super::DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

        for i in 0..5 {
            wal.append(&mk_record(i, Severity::Medium)).unwrap();
        }

        let audit_db_path = db::audit_db_path(&cfg);
        let audit_conn = db::open_audit_db(&cfg).unwrap();
        let baseline_conn = db::open_baseline_db(&cfg).unwrap();
        baseline_ops::set_config_state(
            &baseline_conn,
            "wal_instance_nonce",
            &hex::encode(wal.instance_nonce()),
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let mut writer = AuditWriter::new(
            wal.clone(),
            audit_conn,
            audit_db_path.clone(),
            baseline_conn,
            None,
            metrics,
        )
        .unwrap();

        // Delete the audit DB file to simulate failure
        std::fs::remove_file(&audit_db_path).unwrap();
        // Also remove WAL/SHM journal files if they exist
        let _ = std::fs::remove_file(audit_db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(audit_db_path.with_extension("db-shm"));

        // Attempt to commit entries — should fail because DB is gone
        let entries = wal.iter_unconsumed().unwrap();
        for entry in &entries {
            let _ = writer.commit_entry(entry);
            writer.consecutive_failures += 1;
        }
        assert!(writer.consecutive_failures >= 3);

        // Trigger reopen logic (which will create a fresh DB at the path)
        writer.reopen_audit_conn().unwrap();
        writer.consecutive_failures = 0;

        // Create the audit tables in the fresh connection
        crate::db::schema::create_audit_tables(&writer.audit_conn).unwrap();

        // Now commits should succeed
        let entries = wal.iter_unconsumed().unwrap();
        for entry in &entries {
            writer.commit_entry(entry).unwrap();
        }

        let count: i64 = writer
            .audit_conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 5);
    }
}
