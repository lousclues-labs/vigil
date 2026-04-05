pub mod ops;
pub mod schema;

use crate::config::Config;
use crate::error::{Result, VigilError};
use rusqlite::Connection;
use std::path::Path;

/// Open (or create) the Vigil SQLite database with proper settings.
pub fn open_db(config: &Config) -> Result<Connection> {
    let db_path = &config.daemon.db_path;

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(db_path)?;

    // Restrict database file permissions to owner-only (0600)
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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)?;

    if wal_mode {
        conn.pragma_update(None, "journal_mode", "WAL")?;
    }
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    // Performance pragmas
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
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    // Performance pragmas
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
