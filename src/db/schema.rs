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
            file_type       TEXT NOT NULL DEFAULT 'file',
            symlink_target  TEXT,
            capabilities    TEXT,

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
            hmac            TEXT,
            chain_hash      TEXT,
            responsible_pid INTEGER,
            responsible_exe TEXT
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

    migrate_tables(conn)?;

    Ok(())
}

/// Migrate existing tables by adding new columns if they don't exist.
/// Each ALTER TABLE is guarded so that it's safe to run on both new and
/// existing databases.
pub fn migrate_tables(conn: &Connection) -> Result<()> {
    // Check which columns exist in baseline
    let baseline_cols = get_table_columns(conn, "baseline")?;

    if !baseline_cols.contains(&"file_type".to_string()) {
        conn.execute_batch(
            "ALTER TABLE baseline ADD COLUMN file_type TEXT NOT NULL DEFAULT 'file'",
        )?;
    }
    if !baseline_cols.contains(&"symlink_target".to_string()) {
        conn.execute_batch("ALTER TABLE baseline ADD COLUMN symlink_target TEXT")?;
    }
    if !baseline_cols.contains(&"capabilities".to_string()) {
        conn.execute_batch("ALTER TABLE baseline ADD COLUMN capabilities TEXT")?;
    }

    // Check which columns exist in audit_log
    let audit_cols = get_table_columns(conn, "audit_log")?;

    if !audit_cols.contains(&"chain_hash".to_string()) {
        conn.execute_batch("ALTER TABLE audit_log ADD COLUMN chain_hash TEXT")?;
    }
    if !audit_cols.contains(&"responsible_pid".to_string()) {
        conn.execute_batch("ALTER TABLE audit_log ADD COLUMN responsible_pid INTEGER")?;
    }
    if !audit_cols.contains(&"responsible_exe".to_string()) {
        conn.execute_batch("ALTER TABLE audit_log ADD COLUMN responsible_exe TEXT")?;
    }

    Ok(())
}

/// Get column names for a table.
fn get_table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut cols = Vec::new();
    let sql = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in rows {
        cols.push(col?);
    }
    Ok(cols)
}
