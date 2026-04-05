pub mod audit_ops;
pub mod baseline_ops;
pub mod migrate;
pub mod schema;

use crate::config::Config;
use crate::error::{Result, VigilError};
use rusqlite::Connection;
use std::path::Path;

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
pub fn open_baseline_db_readonly(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.pragma_update(None, "busy_timeout", "5000")?;
    conn.pragma_update(None, "cache_size", "-8000")?;
    conn.pragma_update(None, "mmap_size", "268435456")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
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
    }

    let conn = Connection::open(db_path)?;

    // Restrict database file permissions to owner-only (0600)
    if db_path.exists() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
    }

    if wal_mode {
        conn.pragma_update(None, "journal_mode", "WAL")?;
    }
    conn.pragma_update(None, "synchronous", sync_mode)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", busy_timeout_ms.to_string())?;
    conn.pragma_update(None, "cache_size", "-8000")?;
    conn.pragma_update(None, "mmap_size", "268435456")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;

    if is_baseline {
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
    if wal_mode {
        conn.pragma_update(None, "journal_mode", "WAL")?;
    }
    conn.pragma_update(
        None,
        "synchronous",
        sync_mode.unwrap_or("NORMAL").to_string(),
    )?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(
        None,
        "busy_timeout",
        busy_timeout_ms.unwrap_or(5000).to_string(),
    )?;
    conn.pragma_update(None, "cache_size", "-8000")?;
    conn.pragma_update(None, "mmap_size", "268435456")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    schema::create_tables(&conn)?;
    Ok(conn)
}

fn configure_connection(conn: &Connection, config: &Config) -> Result<()> {
    if config.database.wal_mode {
        conn.pragma_update(None, "journal_mode", "WAL")?;
    }
    conn.pragma_update(None, "synchronous", &config.database.sync_mode)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(
        None,
        "busy_timeout",
        config.database.busy_timeout_ms.to_string(),
    )?;
    conn.pragma_update(None, "cache_size", "-8000")?;
    conn.pragma_update(None, "mmap_size", "268435456")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(())
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
