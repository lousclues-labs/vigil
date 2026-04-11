// tests/chaos/chaos_common.rs — Shared types, helpers, and test record factories.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use vigil::metrics::Metrics;
use vigil::types::Severity;
use vigil::wal::{DetectionRecord, DetectionSource, DetectionWal};

/// WAL header size constant (must match src/wal/mod.rs).
pub const WAL_HEADER_SIZE: u64 = 64;

/// Permission mode expected on WAL files.
pub const WAL_EXPECTED_MODE: u32 = 0o600;

/// Create a DetectionRecord suitable for chaos tests.
pub fn make_record(path: &str, severity: Severity, source: DetectionSource) -> DetectionRecord {
    DetectionRecord {
        timestamp: chrono::Utc::now().timestamp(),
        path: path.to_string(),
        changes: vec![vigil::types::Change::Created],
        severity,
        monitored_group: "chaos-test".into(),
        process: None,
        package: None,
        package_update: false,
        maintenance_window: false,
        source,
    }
}

/// Create a DetectionRecord with explicit timestamp.
pub fn make_record_at(
    path: &str,
    severity: Severity,
    source: DetectionSource,
    timestamp: i64,
) -> DetectionRecord {
    let mut r = make_record(path, severity, source);
    r.timestamp = timestamp;
    r
}

/// Create a sentinel record.
pub fn make_sentinel() -> DetectionRecord {
    DetectionRecord {
        timestamp: chrono::Utc::now().timestamp(),
        path: String::new(),
        changes: vec![],
        severity: Severity::Low,
        monitored_group: String::new(),
        process: None,
        package: None,
        package_update: false,
        maintenance_window: false,
        source: DetectionSource::Sentinel,
    }
}

/// Create a panic detection record (matches worker::process_safe output).
pub fn make_panic_record(path: &str) -> DetectionRecord {
    DetectionRecord {
        timestamp: chrono::Utc::now().timestamp(),
        path: path.to_string(),
        changes: vec![],
        severity: Severity::Critical,
        monitored_group: "unknown".into(),
        process: None,
        package: None,
        package_update: false,
        maintenance_window: false,
        source: DetectionSource::Panic,
    }
}

/// Open a DetectionWal in a temp directory with default settings.
pub fn open_wal(dir: &Path) -> DetectionWal {
    let p = dir.join("detections.wal");
    DetectionWal::open(&p, None, 64 * 1024 * 1024).unwrap()
}

/// Open a DetectionWal with a specified max size.
pub fn open_wal_sized(dir: &Path, max_bytes: u64) -> DetectionWal {
    let p = dir.join("detections.wal");
    DetectionWal::open(&p, None, max_bytes).unwrap()
}

/// Open a DetectionWal with HMAC key.
pub fn open_wal_hmac(dir: &Path, key: &[u8]) -> DetectionWal {
    let p = dir.join("detections.wal");
    let k = zeroize::Zeroizing::new(key.to_vec());
    DetectionWal::open(&p, Some(&k), 64 * 1024 * 1024).unwrap()
}

/// Create fresh Metrics instance.
pub fn fresh_metrics() -> Arc<Metrics> {
    Arc::new(Metrics::new())
}

/// Create a minimal Config for chaos tests.
pub fn chaos_config(dir: &Path) -> vigil::config::Config {
    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = dir.join("baseline.db");
    cfg.daemon.runtime_dir = dir.join("run");
    cfg.daemon.detection_wal = true;
    cfg.daemon.detection_wal_max_bytes = 64 * 1024 * 1024;
    cfg.alerts.syslog = false;
    cfg.alerts.desktop_notifications = false;
    cfg.alerts.log_file = PathBuf::new();
    cfg.hooks.signal_socket.clear();
    cfg.alerts.remote_syslog.enabled = false;
    // Clear system exclusions so tempdir paths aren't excluded
    cfg.exclusions.system_exclusions.clear();
    cfg.exclusions.patterns.clear();
    std::fs::create_dir_all(&cfg.daemon.runtime_dir).ok();
    cfg
}

/// Open an audit DB with schema initialized.
pub fn open_audit_db(dir: &Path) -> rusqlite::Connection {
    let p = dir.join("audit.db");
    let conn = vigil::db::open_db_at(&p, false).unwrap();
    vigil::db::schema::create_audit_tables(&conn).unwrap();
    conn
}

/// Open a baseline DB with schema initialized.
pub fn open_baseline_db(dir: &Path) -> rusqlite::Connection {
    let p = dir.join("baseline.db");
    let conn = vigil::db::open_db_at(&p, false).unwrap();
    vigil::db::schema::create_baseline_tables(&conn).unwrap();
    conn
}

/// Count audit entries in a DB connection.
pub fn audit_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
        .unwrap_or(0)
}

/// Get WAL file permissions (mode bits).
pub fn wal_file_mode(dir: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("detections.wal");
    std::fs::metadata(&p)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0)
}
