use crate::error::Result;
use rusqlite::Connection;

/// Create baseline tables (baseline.db).
pub fn create_baseline_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS baseline (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            path            TEXT NOT NULL UNIQUE,
            identity_json   TEXT NOT NULL,
            content_json    TEXT NOT NULL,
            perms_json      TEXT NOT NULL,
            security_json   TEXT NOT NULL,
            mtime           INTEGER NOT NULL,
            package         TEXT,
            source          TEXT NOT NULL DEFAULT 'auto_scan',
            added_at        INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL,
            CHECK(source IN ('package_manager', 'manual', 'auto_scan'))
        );

        CREATE INDEX IF NOT EXISTS idx_baseline_path ON baseline(path);

        CREATE TABLE IF NOT EXISTS config_state (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,
            updated_at  INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

/// Create audit tables (audit.db).
pub fn create_audit_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       INTEGER NOT NULL,
            path            TEXT NOT NULL,
            changes_json    TEXT NOT NULL,
            severity        TEXT NOT NULL,
            monitored_group TEXT,
            process_json    TEXT,
            package         TEXT,
            maintenance     INTEGER NOT NULL DEFAULT 0,
            suppressed      INTEGER NOT NULL DEFAULT 0,
            hmac            TEXT,
            chain_hash      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_path ON audit_log(path);
        CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);
        ",
    )?;
    Ok(())
}

/// Legacy: create all tables in a single database (backward compat for CLI).
pub fn create_tables(conn: &Connection) -> Result<()> {
    create_baseline_tables(conn)?;
    // Also create audit tables in the same DB for backward compat
    create_audit_tables(conn)?;
    Ok(())
}
