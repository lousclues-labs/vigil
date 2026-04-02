use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::types::{BaselineEntry, BaselineSource, ChangeResult, ChangeType};

// ── Baseline operations ────────────────────────────────────

/// Insert a new baseline entry. Returns the row id.
pub fn insert_baseline(conn: &Connection, entry: &BaselineEntry) -> Result<i64> {
    conn.execute(
        "INSERT INTO baseline (
            path, hash, size, permissions, owner_uid, owner_gid,
            mtime, inode, device, xattrs, security_context,
            package, source, added_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            entry.path.to_string_lossy().as_ref(),
            entry.hash,
            entry.size as i64,
            entry.permissions as i64,
            entry.owner_uid as i64,
            entry.owner_gid as i64,
            entry.mtime,
            entry.inode as i64,
            entry.device as i64,
            entry.xattrs,
            entry.security_context,
            entry.package,
            entry.source.to_string(),
            entry.added_at,
            entry.updated_at,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Update an existing baseline entry identified by path.
pub fn update_baseline(conn: &Connection, entry: &BaselineEntry) -> Result<usize> {
    let rows = conn.execute(
        "UPDATE baseline SET
            hash = ?1, size = ?2, permissions = ?3, owner_uid = ?4, owner_gid = ?5,
            mtime = ?6, inode = ?7, device = ?8, xattrs = ?9, security_context = ?10,
            package = ?11, source = ?12, updated_at = ?13
        WHERE path = ?14",
        params![
            entry.hash,
            entry.size as i64,
            entry.permissions as i64,
            entry.owner_uid as i64,
            entry.owner_gid as i64,
            entry.mtime,
            entry.inode as i64,
            entry.device as i64,
            entry.xattrs,
            entry.security_context,
            entry.package,
            entry.source.to_string(),
            entry.updated_at,
            entry.path.to_string_lossy().as_ref(),
        ],
    )?;
    Ok(rows)
}

/// Upsert: insert or update if path already exists.
pub fn upsert_baseline(conn: &Connection, entry: &BaselineEntry) -> Result<()> {
    conn.execute(
        "INSERT INTO baseline (
            path, hash, size, permissions, owner_uid, owner_gid,
            mtime, inode, device, xattrs, security_context,
            package, source, added_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        ON CONFLICT(path, device, inode) DO UPDATE SET
            hash = excluded.hash,
            size = excluded.size,
            permissions = excluded.permissions,
            owner_uid = excluded.owner_uid,
            owner_gid = excluded.owner_gid,
            mtime = excluded.mtime,
            xattrs = excluded.xattrs,
            security_context = excluded.security_context,
            package = excluded.package,
            source = excluded.source,
            updated_at = excluded.updated_at",
        params![
            entry.path.to_string_lossy().as_ref(),
            entry.hash,
            entry.size as i64,
            entry.permissions as i64,
            entry.owner_uid as i64,
            entry.owner_gid as i64,
            entry.mtime,
            entry.inode as i64,
            entry.device as i64,
            entry.xattrs,
            entry.security_context,
            entry.package,
            entry.source.to_string(),
            entry.added_at,
            entry.updated_at,
        ],
    )?;
    Ok(())
}

/// Look up a baseline entry by absolute path.
pub fn get_baseline_by_path(conn: &Connection, path: &str) -> Result<Option<BaselineEntry>> {
    let entry = conn
        .query_row(
            "SELECT id, path, hash, size, permissions, owner_uid, owner_gid,
                    mtime, inode, device, xattrs, security_context,
                    package, source, added_at, updated_at
             FROM baseline WHERE path = ?1",
            params![path],
            |row| {
                Ok(BaselineEntry {
                    id: Some(row.get::<_, i64>(0)?),
                    path: std::path::PathBuf::from(row.get::<_, String>(1)?),
                    hash: row.get(2)?,
                    size: row.get::<_, i64>(3)? as u64,
                    permissions: row.get::<_, i64>(4)? as u32,
                    owner_uid: row.get::<_, i64>(5)? as u32,
                    owner_gid: row.get::<_, i64>(6)? as u32,
                    mtime: row.get(7)?,
                    inode: row.get::<_, i64>(8)? as u64,
                    device: row.get::<_, i64>(9)? as u64,
                    xattrs: row.get(10)?,
                    security_context: row.get(11)?,
                    package: row.get(12)?,
                    source: row
                        .get::<_, String>(13)?
                        .parse::<BaselineSource>()
                        .unwrap_or(BaselineSource::AutoScan),
                    added_at: row.get(14)?,
                    updated_at: row.get(15)?,
                })
            },
        )
        .optional()?;

    Ok(entry)
}

/// Get all baseline entries.
pub fn get_all_baselines(conn: &Connection) -> Result<Vec<BaselineEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, path, hash, size, permissions, owner_uid, owner_gid,
                mtime, inode, device, xattrs, security_context,
                package, source, added_at, updated_at
         FROM baseline ORDER BY path",
    )?;

    let entries = stmt
        .query_map([], |row| {
            Ok(BaselineEntry {
                id: Some(row.get::<_, i64>(0)?),
                path: std::path::PathBuf::from(row.get::<_, String>(1)?),
                hash: row.get(2)?,
                size: row.get::<_, i64>(3)? as u64,
                permissions: row.get::<_, i64>(4)? as u32,
                owner_uid: row.get::<_, i64>(5)? as u32,
                owner_gid: row.get::<_, i64>(6)? as u32,
                mtime: row.get(7)?,
                inode: row.get::<_, i64>(8)? as u64,
                device: row.get::<_, i64>(9)? as u64,
                xattrs: row.get(10)?,
                security_context: row.get(11)?,
                package: row.get(12)?,
                source: row
                    .get::<_, String>(13)?
                    .parse::<BaselineSource>()
                    .unwrap_or(BaselineSource::AutoScan),
                added_at: row.get(14)?,
                updated_at: row.get(15)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(entries)
}

/// Remove a baseline entry by path.
pub fn remove_baseline(conn: &Connection, path: &str) -> Result<usize> {
    let rows = conn.execute("DELETE FROM baseline WHERE path = ?1", params![path])?;
    Ok(rows)
}

/// Count total baseline entries.
pub fn baseline_count(conn: &Connection) -> Result<i64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM baseline", [], |row| row.get(0))?;
    Ok(count)
}

// ── Audit log operations ───────────────────────────────────

/// Write an audit log entry. Always succeeds (audit trail is never suppressed).
pub fn insert_audit_entry(
    conn: &Connection,
    change: &ChangeResult,
    primary_change: ChangeType,
    maintenance_window: bool,
    suppressed: bool,
    hmac: Option<&str>,
) -> Result<i64> {
    let now = Utc::now().timestamp();

    conn.execute(
        "INSERT INTO audit_log (
            timestamp, event_type, path, change_type, severity,
            old_hash, new_hash, old_permissions, new_permissions,
            old_owner_uid, new_owner_uid, old_owner_gid, new_owner_gid,
            old_inode, new_inode, package, package_update,
            maintenance_window, suppressed, monitored_group, hmac
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
        )",
        params![
            now,
            "change",
            change.path.to_string_lossy().as_ref(),
            primary_change.to_string(),
            change.severity.to_string(),
            change.old_hash,
            change.new_hash,
            change.old_permissions.map(|v| v as i64),
            change.new_permissions.map(|v| v as i64),
            change.old_owner_uid.map(|v| v as i64),
            change.new_owner_uid.map(|v| v as i64),
            change.old_owner_gid.map(|v| v as i64),
            change.new_owner_gid.map(|v| v as i64),
            change.old_inode.map(|v| v as i64),
            change.new_inode.map(|v| v as i64),
            change.package,
            change.package_update as i32,
            maintenance_window as i32,
            suppressed as i32,
            change.monitored_group,
            hmac,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Get recent audit entries, ordered newest first.
pub fn get_recent_audit(conn: &Connection, limit: u32) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, event_type, path, change_type, severity,
                old_hash, new_hash, package, package_update,
                maintenance_window, suppressed, monitored_group
         FROM audit_log ORDER BY timestamp DESC LIMIT ?1",
    )?;

    let entries = stmt
        .query_map(params![limit], |row| {
            Ok(AuditEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event_type: row.get(2)?,
                path: row.get(3)?,
                change_type: row.get(4)?,
                severity: row.get(5)?,
                old_hash: row.get(6)?,
                new_hash: row.get(7)?,
                package: row.get(8)?,
                package_update: row.get::<_, i32>(9)? != 0,
                maintenance_window: row.get::<_, i32>(10)? != 0,
                suppressed: row.get::<_, i32>(11)? != 0,
                monitored_group: row.get(12)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(entries)
}

/// A read-friendly representation of an audit log row.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: i64,
    pub event_type: String,
    pub path: String,
    pub change_type: String,
    pub severity: String,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub package: Option<String>,
    pub package_update: bool,
    pub maintenance_window: bool,
    pub suppressed: bool,
    pub monitored_group: Option<String>,
}

// ── Config state operations ────────────────────────────────

/// Set a key-value pair in config_state.
pub fn set_config_state(conn: &Connection, key: &str, value: &str) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO config_state (key, value, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value, now],
    )?;
    Ok(())
}

/// Get a value from config_state.
pub fn get_config_state(conn: &Connection, key: &str) -> Result<Option<String>> {
    let value = conn
        .query_row(
            "SELECT value FROM config_state WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value)
}
