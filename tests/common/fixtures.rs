// Shared test fixtures and builders for Vigil tests.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use vigil::config::*;
use vigil::db;
use vigil::types::*;

// ── Temp directory helper ──────────────────────────────────

/// A temporary directory that cleans up after itself.
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("vigil-test-{}-{}", prefix, std::process::id()));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    /// Create a file inside this temp dir with the given content.
    pub fn create_file(&self, name: &str, content: &[u8]) -> PathBuf {
        let file_path = self.path.join(name);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&file_path, content).expect("write test file");
        file_path
    }

    /// Create a file with specific permissions.
    pub fn create_file_with_perms(&self, name: &str, content: &[u8], mode: u32) -> PathBuf {
        let file_path = self.create_file(name, content);
        fs::set_permissions(&file_path, fs::Permissions::from_mode(mode)).expect("set permissions");
        file_path
    }

    /// Create a subdirectory.
    #[allow(dead_code)]
    pub fn create_dir(&self, name: &str) -> PathBuf {
        let dir_path = self.path.join(name);
        fs::create_dir_all(&dir_path).expect("create subdir");
        dir_path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ── Config builders ────────────────────────────────────────

/// Build a minimal test config pointing at a temp directory.
pub fn test_config(tmp: &TempDir) -> Config {
    let db_path = tmp.path.join("test-baseline.db");
    let log_file = tmp.path.join("test-alerts.json");

    let mut watch = HashMap::new();
    watch.insert(
        "test_group".into(),
        WatchGroup {
            severity: Severity::High,
            paths: vec![tmp.path.to_string_lossy().into_owned() + "/"],
        },
    );

    // Use the default exclusion patterns (matching what serde would produce)
    // Note: /tmp/* is NOT in system_exclusions for test configs because
    // test temp dirs live under /tmp/
    let exclusions = ExclusionsConfig {
        patterns: vec![
            "*.swp".into(),
            "*.swx".into(),
            "*~".into(),
            "*.tmp".into(),
            "*.log".into(),
            "*.cache".into(),
            ".git/*".into(),
            "__pycache__/*".into(),
        ],
        system_exclusions: vec![
            "/proc/*".into(),
            "/sys/*".into(),
            "/dev/*".into(),
            "/run/*".into(),
        ],
    };

    Config {
        daemon: DaemonConfig {
            pid_file: tmp.path.join("test.pid"),
            db_path,
            log_level: "debug".into(),
            monitor_backend: MonitorBackend::Inotify,
            worker_threads: 2,
        },
        scanner: ScannerConfig::default(),
        alerts: AlertsConfig {
            desktop_notifications: false,
            syslog: false,
            log_file,
            webhook_url: String::new(),
            rate_limit: 100,
            cooldown_seconds: 0,
            severity_filter: SeverityFilterConfig::default(),
            notification_rate_limit: 5,
            notification_rate_window_secs: 10,
        },
        exclusions,
        package_manager: PackageManagerConfig::default(),
        hooks: HooksConfig::default(),
        security: SecurityConfig::default(),
        database: DatabaseConfig::default(),
        watch,
    }
}

/// Build a config with custom watch paths.
#[allow(dead_code)]
pub fn test_config_with_paths(tmp: &TempDir, paths: Vec<String>, severity: Severity) -> Config {
    let mut cfg = test_config(tmp);
    cfg.watch.clear();
    cfg.watch
        .insert("custom".into(), WatchGroup { severity, paths });
    cfg
}

// ── Database helpers ───────────────────────────────────────

/// Open an in-memory SQLite database with Vigil's schema.
pub fn test_db() -> Connection {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "synchronous", "NORMAL").ok();
    conn.pragma_update(None, "foreign_keys", "ON").ok();
    vigil::db::schema::create_tables(&conn).expect("create tables");
    conn
}

/// Open a file-backed test database in the given temp dir.
#[allow(dead_code)]
pub fn test_db_at(tmp: &TempDir) -> Connection {
    let cfg = test_config(tmp);
    db::open_db(&cfg).expect("open test db")
}

// ── Baseline entry builders ────────────────────────────────

/// Build a baseline entry for a real file on disk.
pub fn baseline_entry_for(path: &Path) -> BaselineEntry {
    use std::os::unix::fs::MetadataExt;

    let file = fs::File::open(path).expect("open file for baseline");
    let meta = file.metadata().expect("stat file");
    let hash = vigil::baseline::hash::blake3_hash_file(&file).expect("hash file");

    BaselineEntry {
        id: None,
        path: path.to_path_buf(),
        hash,
        size: meta.len(),
        permissions: meta.mode(),
        owner_uid: meta.uid(),
        owner_gid: meta.gid(),
        mtime: meta.mtime(),
        inode: meta.ino(),
        device: meta.dev(),
        xattrs: "{}".into(),
        security_context: String::new(),
        package: None,
        source: BaselineSource::AutoScan,
        added_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    }
}

/// Build a synthetic baseline entry (not tied to a real file).
pub fn synthetic_baseline(path: &str, hash: &str) -> BaselineEntry {
    BaselineEntry {
        id: None,
        path: PathBuf::from(path),
        hash: hash.into(),
        size: 100,
        permissions: 0o100644,
        owner_uid: 1000,
        owner_gid: 1000,
        mtime: 1700000000,
        inode: 12345,
        device: 1,
        xattrs: "{}".into(),
        security_context: String::new(),
        package: None,
        source: BaselineSource::AutoScan,
        added_at: 1700000000,
        updated_at: 1700000000,
    }
}
