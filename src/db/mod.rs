//! SQLite database layer -- split baseline and audit stores.
//!
//! Baseline DB holds the known-good filesystem state. Audit DB holds the
//! HMAC-chained detection log. Connections are opened per-thread (never
//! shared via Arc). WAL mode + FULL sync for crash safety.

pub mod access;
pub mod audit_ack;
pub mod audit_ops;
pub mod audit_path;
pub mod audit_retention;
pub mod baseline_ops;
pub mod migrate;
pub mod schema;

use crate::config::Config;
use crate::error::{Result, VigilError};
use rusqlite::Connection;
use std::path::Path;

/// Identity (inode + device) of a database file, used for TOCTOU detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbFileIdentity {
    pub inode: u64,
    pub device: u64,
}

impl DbFileIdentity {
    /// Stat the given path and return its inode + device.
    pub fn from_path(path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            inode: meta.ino(),
            device: meta.dev(),
        })
    }

    /// Compare against the current stat of the path. Returns `true` if the file
    /// has been replaced (different inode or device).
    pub fn is_replaced(&self, path: &Path) -> Result<bool> {
        let current = Self::from_path(path)?;
        Ok(current != *self)
    }
}

/// Common SQLite pragma configuration.
pub struct PragmaOpts<'a> {
    pub sync_mode: &'a str,
    pub busy_timeout_ms: u32,
    pub wal_mode: bool,
    pub cache_size: &'a str,
    pub mmap_size: &'a str,
}

impl<'a> Default for PragmaOpts<'a> {
    fn default() -> Self {
        Self {
            sync_mode: "NORMAL",
            busy_timeout_ms: 5000,
            wal_mode: true,
            cache_size: "-16000",
            mmap_size: "536870912",
        }
    }
}

/// Apply all standard pragmas to a SQLite connection in one place.
pub fn apply_pragmas(conn: &Connection, opts: &PragmaOpts) -> Result<()> {
    if opts.wal_mode {
        conn.pragma_update(None, "journal_mode", "WAL")?;
    }
    conn.pragma_update(None, "synchronous", opts.sync_mode)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", opts.busy_timeout_ms.to_string())?;
    conn.pragma_update(None, "cache_size", opts.cache_size)?;
    conn.pragma_update(None, "mmap_size", opts.mmap_size)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(())
}

/// Open (or create) the baseline SQLite database.
/// Uses synchronous = NORMAL for performance on the hot path.
pub fn open_baseline_db(config: &Config) -> Result<Connection> {
    let db_path = &config.daemon.db_path;
    open_db_internal(
        db_path,
        "NORMAL",
        config.database.wal_mode,
        config.database.busy_timeout_ms,
        true,
    )
}

/// Open baseline DB read-only (for worker threads).
/// Open a writable baseline DB at the given path (for baseline writer thread).
pub fn open_baseline_db_at_path(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn, &PragmaOpts::default())?;
    Ok(conn)
}

/// Open baseline DB read-only (for worker threads).
pub fn open_baseline_db_readonly(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    apply_pragmas(
        &conn,
        &PragmaOpts {
            sync_mode: "NORMAL",
            wal_mode: false,
            ..PragmaOpts::default()
        },
    )?;
    Ok(conn)
}

/// Open (or create) the audit SQLite database.
/// Uses synchronous = FULL for tamper-evident audit trail.
pub fn open_audit_db(config: &Config) -> Result<Connection> {
    let audit_path = audit_db_path(config);
    open_db_internal(
        &audit_path,
        "FULL",
        config.database.wal_mode,
        config.database.busy_timeout_ms,
        false,
    )
}

/// Derive the audit.db path from config (sibling of baseline.db).
pub fn audit_db_path(config: &Config) -> std::path::PathBuf {
    let baseline = &config.daemon.db_path;
    baseline
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/vigil"))
        .join("audit.db")
}

fn open_db_internal(
    db_path: &Path,
    sync_mode: &str,
    wal_mode: bool,
    busy_timeout_ms: u32,
    is_baseline: bool,
) -> Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
        // Only enforce directory ownership checks in production builds.
        // Tests run as unprivileged users in temp directories.
        #[cfg(not(any(test, debug_assertions)))]
        verify_directory_safety(parent)?;
    }

    let conn = Connection::open(db_path)?;

    // Restrict database file permissions to owner-only (0600)
    if db_path.exists() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
    }

    apply_pragmas(
        &conn,
        &PragmaOpts {
            sync_mode,
            busy_timeout_ms,
            wal_mode,
            ..PragmaOpts::default()
        },
    )?;

    // Restrict WAL/SHM sidecar file permissions to owner-only (0600)
    restrict_sidecar_permissions(db_path);

    if is_baseline {
        // Run v1→v2 migration if the old JSON blob schema is present
        migrate::migrate_v1_to_v2(&conn)?;
        schema::create_baseline_tables(&conn)?;
    } else {
        schema::create_audit_tables(&conn)?;
    }

    Ok(conn)
}

/// Open the database using the legacy single-DB approach (for CLI commands).
pub fn open_db(config: &Config) -> Result<Connection> {
    let db_path = &config.daemon.db_path;
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_path)?;
    if db_path.exists() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
    }
    configure_connection(&conn, config)?;
    schema::create_tables(&conn)?;
    Ok(conn)
}

/// Open the database at an explicit path (used by CLI commands).
pub fn open_db_at(path: &Path, wal_mode: bool) -> Result<Connection> {
    open_db_at_with_options(path, wal_mode, None, None)
}

pub fn open_db_at_with_options(
    path: &Path,
    wal_mode: bool,
    sync_mode: Option<&str>,
    busy_timeout_ms: Option<u32>,
) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    apply_pragmas(
        &conn,
        &PragmaOpts {
            sync_mode: sync_mode.unwrap_or("NORMAL"),
            busy_timeout_ms: busy_timeout_ms.unwrap_or(5000),
            wal_mode,
            ..PragmaOpts::default()
        },
    )?;
    schema::create_tables(&conn)?;
    Ok(conn)
}

fn configure_connection(conn: &Connection, config: &Config) -> Result<()> {
    apply_pragmas(
        conn,
        &PragmaOpts {
            sync_mode: config.database.sync_mode.as_pragma(),
            busy_timeout_ms: config.database.busy_timeout_ms,
            wal_mode: config.database.wal_mode,
            ..PragmaOpts::default()
        },
    )
}

/// Run SQLite integrity check. Returns Ok(()) if database is healthy.
pub fn integrity_check(conn: &Connection) -> Result<()> {
    let result: String = conn.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    if result != "ok" {
        return Err(VigilError::Config(format!(
            "database integrity check failed: {}",
            result
        )));
    }
    Ok(())
}

/// Checkpoint WAL and truncate.
pub fn wal_checkpoint(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")?;
    Ok(())
}

/// Restrict permissions on WAL and SHM sidecar files to 0600 if they exist.
fn restrict_sidecar_permissions(db_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for suffix in &["-wal", "-shm"] {
        let mut sidecar = db_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar_path = std::path::Path::new(&sidecar);
        if sidecar_path.exists() {
            if let Err(e) =
                std::fs::set_permissions(sidecar_path, std::fs::Permissions::from_mode(0o600))
            {
                tracing::warn!(
                    path = %sidecar_path.display(),
                    error = %e,
                    "failed to restrict sidecar file permissions"
                );
            }
        }
    }
}

/// Verify that the database directory is owned by root (uid 0) and has
/// permissions no wider than 0750. Returns an error if unsafe.
#[cfg(not(any(test, debug_assertions)))]
fn verify_directory_safety(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(dir)?;
    if meta.uid() != 0 {
        return Err(VigilError::Config(format!(
            "database directory has unsafe ownership: {} is owned by uid {} (expected root/0)",
            dir.display(),
            meta.uid()
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o027 != 0 {
        return Err(VigilError::Config(format!(
            "database directory has unsafe permissions: {} has mode {:04o} (expected 0700 or 0750)",
            dir.display(),
            mode
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_pragmas_sets_values() {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas(&conn, &PragmaOpts::default()).unwrap();

        let cache_size: i64 = conn
            .pragma_query_value(None, "cache_size", |row| row.get(0))
            .unwrap();
        assert_eq!(cache_size, -16000);

        let foreign_keys: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);

        let busy_timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5000);
    }
}
