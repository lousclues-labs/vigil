use crate::error::Result;
use rusqlite::Connection;

/// Create all required tables if they don't already exist.
pub fn create_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS baseline (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            path            TEXT NOT NULL,
            hash            TEXT NOT NULL,
            size            INTEGER NOT NULL,
            permissions     INTEGER NOT NULL,
            owner_uid       INTEGER NOT NULL,
            owner_gid       INTEGER NOT NULL,
            mtime           INTEGER NOT NULL,
            inode           INTEGER NOT NULL,
            device          INTEGER NOT NULL,
            xattrs          TEXT NOT NULL DEFAULT '{}',
            security_context TEXT NOT NULL DEFAULT '',
            package         TEXT,
            source          TEXT NOT NULL DEFAULT 'auto_scan',
            added_at        INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL,

            UNIQUE(path, device, inode),
            CHECK(source IN ('package_manager', 'manual', 'auto_scan'))
        );

        CREATE INDEX IF NOT EXISTS idx_baseline_path ON baseline(path);
        CREATE INDEX IF NOT EXISTS idx_baseline_hash ON baseline(hash);
        CREATE INDEX IF NOT EXISTS idx_baseline_package ON baseline(package);
        CREATE INDEX IF NOT EXISTS idx_baseline_inode ON baseline(device, inode);

        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       INTEGER NOT NULL,
            event_type      TEXT NOT NULL,
            path            TEXT NOT NULL,
            change_type     TEXT NOT NULL,
            severity        TEXT NOT NULL,
            old_hash        TEXT,
            new_hash        TEXT,
            old_permissions INTEGER,
            new_permissions INTEGER,
            old_owner_uid   INTEGER,
            new_owner_uid   INTEGER,
            old_owner_gid   INTEGER,
            new_owner_gid   INTEGER,
            old_inode       INTEGER,
            new_inode       INTEGER,
            package         TEXT,
            package_update  INTEGER NOT NULL DEFAULT 0,
            maintenance_window INTEGER NOT NULL DEFAULT 0,
            suppressed      INTEGER NOT NULL DEFAULT 0,
            monitored_group TEXT,
            hmac            TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_path ON audit_log(path);
        CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);
        CREATE INDEX IF NOT EXISTS idx_audit_change_type ON audit_log(change_type);

        CREATE TABLE IF NOT EXISTS config_state (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,
            updated_at  INTEGER NOT NULL
        );
        ",
    )?;

    Ok(())
}
