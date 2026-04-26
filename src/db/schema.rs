//! Database schema definitions and table creation.
//!
//! Baseline (v2 flattened) and audit tables are created here.
//! Called from `migrate::ensure_schema` on first open.

use crate::error::Result;
use rusqlite::Connection;

/// Create baseline tables (baseline.db), v2 flattened schema.
pub fn create_baseline_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS baseline (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            path            TEXT NOT NULL UNIQUE,
            -- identity (was identity_json)
            inode           INTEGER NOT NULL,
            device          INTEGER NOT NULL,
            file_type       TEXT NOT NULL DEFAULT 'regular',
            symlink_target  TEXT,
            -- content (was content_json)
            hash            TEXT NOT NULL,
            size            INTEGER NOT NULL,
            -- permissions (was perms_json)
            mode            INTEGER NOT NULL,
            owner_uid       INTEGER NOT NULL,
            owner_gid       INTEGER NOT NULL,
            capabilities    TEXT,
            -- security (was security_json)
            xattrs_json     TEXT NOT NULL DEFAULT '{}',
            security_context TEXT NOT NULL DEFAULT '',
            -- metadata
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

/// Create baseline tables with the old v1 JSON blob schema (for migration).
pub fn create_baseline_v1_tables(conn: &Connection) -> Result<()> {
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
            chain_hash      TEXT NOT NULL,
            encoding_version INTEGER NOT NULL DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_path ON audit_log(path);
        CREATE INDEX IF NOT EXISTS idx_audit_path_id ON audit_log(path, id);
        CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);
        CREATE INDEX IF NOT EXISTS idx_audit_group ON audit_log(monitored_group);

        CREATE TABLE IF NOT EXISTS audit_segments (
            id                INTEGER PRIMARY KEY,
            first_sequence    INTEGER NOT NULL,
            last_sequence     INTEGER NOT NULL,
            first_timestamp   INTEGER NOT NULL,
            last_timestamp    INTEGER NOT NULL,
            first_chain_hash  TEXT NOT NULL,
            sealed_chain_hash TEXT NOT NULL,
            seal_hmac         TEXT NOT NULL,
            sealed_at         INTEGER NOT NULL,
            archive_path      TEXT
        );
        ",
    )?;
    // v1.3.0: add checkpoint columns for bounded audit retention.
    migrate_audit_checkpoint_columns(conn)?;
    // VIGIL-VULN-076: add encoding_version for CBOR HMAC (v2).
    migrate_audit_encoding_version(conn)?;
    Ok(())
}

/// Add checkpoint-related columns to audit_log if missing.
/// Uses ALTER TABLE ADD COLUMN which is safe on existing rows (defaults to NULL).
fn migrate_audit_checkpoint_columns(conn: &Connection) -> Result<()> {
    let has_record_type: bool = conn
        .prepare("SELECT record_type FROM audit_log LIMIT 0")
        .is_ok();
    if has_record_type {
        return Ok(());
    }
    conn.execute_batch(
        "
        ALTER TABLE audit_log ADD COLUMN record_type TEXT NOT NULL DEFAULT 'detection';
        ALTER TABLE audit_log ADD COLUMN first_sequence INTEGER;
        ALTER TABLE audit_log ADD COLUMN last_sequence INTEGER;
        ALTER TABLE audit_log ADD COLUMN first_timestamp INTEGER;
        ALTER TABLE audit_log ADD COLUMN last_timestamp INTEGER;
        ALTER TABLE audit_log ADD COLUMN entry_count INTEGER;
        ALTER TABLE audit_log ADD COLUMN pruned_range_hmac TEXT;
        ",
    )?;
    Ok(())
}

/// VIGIL-VULN-076: Add encoding_version column for CBOR HMAC (v2).
/// Existing rows default to 1 (legacy pipe-delimited format).
fn migrate_audit_encoding_version(conn: &Connection) -> Result<()> {
    let has_col: bool = conn
        .prepare("SELECT encoding_version FROM audit_log LIMIT 0")
        .is_ok();
    if has_col {
        return Ok(());
    }
    conn.execute_batch(
        "ALTER TABLE audit_log ADD COLUMN encoding_version INTEGER NOT NULL DEFAULT 1;",
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
