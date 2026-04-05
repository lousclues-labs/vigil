use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::types::{BaselineEntry, BaselineSource, ChangeResult, ChangeType};

// ── Baseline operations ────────────────────────────────────

/// Insert a new baseline entry. Returns the row id.
pub fn insert_baseline(conn: &Connection, entry: &BaselineEntry) -> Result<i64> {
    conn.prepare_cached(
        "INSERT INTO baseline (
            path, hash, size, permissions, owner_uid, owner_gid,
            mtime, inode, device, xattrs, security_context,
            package, source, added_at, updated_at,
            file_type, symlink_target, capabilities
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
    )?
    .execute(params![
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
        entry.file_type,
        entry.symlink_target,
        entry.capabilities,
    ])?;
    Ok(conn.last_insert_rowid())
}

/// Update an existing baseline entry identified by path.
pub fn update_baseline(conn: &Connection, entry: &BaselineEntry) -> Result<usize> {
    let rows = conn
        .prepare_cached(
            "UPDATE baseline SET
            hash = ?1, size = ?2, permissions = ?3, owner_uid = ?4, owner_gid = ?5,
            mtime = ?6, inode = ?7, device = ?8, xattrs = ?9, security_context = ?10,
            package = ?11, source = ?12, updated_at = ?13,
            file_type = ?14, symlink_target = ?15, capabilities = ?16
        WHERE path = ?17",
        )?
        .execute(params![
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
            entry.file_type,
            entry.symlink_target,
            entry.capabilities,
            entry.path.to_string_lossy().as_ref(),
        ])?;
    Ok(rows)
}

/// Upsert: insert or update if path already exists.
pub fn upsert_baseline(conn: &Connection, entry: &BaselineEntry) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO baseline (
            path, hash, size, permissions, owner_uid, owner_gid,
            mtime, inode, device, xattrs, security_context,
            package, source, added_at, updated_at,
            file_type, symlink_target, capabilities
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
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
            updated_at = excluded.updated_at,
            file_type = excluded.file_type,
            symlink_target = excluded.symlink_target,
            capabilities = excluded.capabilities",
    )?
    .execute(params![
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
        entry.file_type,
        entry.symlink_target,
        entry.capabilities,
    ])?;
    Ok(())
}

/// Batch upsert multiple baseline entries within a single transaction.
/// Returns the number of entries written.
pub fn batch_upsert_baseline(conn: &Connection, entries: &[BaselineEntry]) -> Result<u64> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let mut count = 0u64;
    for entry in entries {
        if let Err(e) = upsert_baseline(conn, entry) {
            conn.execute_batch("ROLLBACK")?;
            return Err(e);
        }
        count += 1;
    }
    conn.execute_batch("COMMIT")?;
    Ok(count)
}

/// Look up a baseline entry by absolute path.
pub fn get_baseline_by_path(conn: &Connection, path: &str) -> Result<Option<BaselineEntry>> {
    let entry = conn
        .prepare_cached(
            "SELECT id, path, hash, size, permissions, owner_uid, owner_gid,
                    mtime, inode, device, xattrs, security_context,
                    package, source, added_at, updated_at,
                    file_type, symlink_target, capabilities
             FROM baseline WHERE path = ?1",
        )?
        .query_row(params![path], |row| {
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
                file_type: row.get::<_, String>(16).unwrap_or_else(|_| "file".into()),
                symlink_target: row.get(17).ok().flatten(),
                capabilities: row.get(18).ok().flatten(),
            })
        })
        .optional()?;

    Ok(entry)
}

/// Get all baseline entries.
pub fn get_all_baselines(conn: &Connection) -> Result<Vec<BaselineEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, path, hash, size, permissions, owner_uid, owner_gid,
                mtime, inode, device, xattrs, security_context,
                package, source, added_at, updated_at,
                file_type, symlink_target, capabilities
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
                file_type: row.get::<_, String>(16).unwrap_or_else(|_| "file".into()),
                symlink_target: row.get(17).ok().flatten(),
                capabilities: row.get(18).ok().flatten(),
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
/// Computes chain_hash for tamper-evident audit chain (Item 16).
pub fn insert_audit_entry(
    conn: &Connection,
    change: &ChangeResult,
    primary_change: ChangeType,
    maintenance_window: bool,
    suppressed: bool,
    hmac: Option<&str>,
) -> Result<i64> {
    let now = Utc::now().timestamp();

    // Compute chain hash: BLAKE3(prev_chain_hash || timestamp || path || change_type || severity || old_hash || new_hash)
    let prev_chain_hash: String = conn
        .query_row(
            "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap_or(None)
        .unwrap_or_else(|| crate::baseline::hash::blake3_hash_bytes(b"vigil-audit-chain-genesis"));

    let chain_data = format!(
        "{}{}{}{}{}{}{}",
        prev_chain_hash,
        now,
        change.path.to_string_lossy(),
        primary_change,
        change.severity,
        change.old_hash.as_deref().unwrap_or(""),
        change.new_hash.as_deref().unwrap_or(""),
    );
    let chain_hash = crate::baseline::hash::blake3_hash_bytes(chain_data.as_bytes());

    conn.prepare_cached(
        "INSERT INTO audit_log (
            timestamp, event_type, path, change_type, severity,
            old_hash, new_hash, old_permissions, new_permissions,
            old_owner_uid, new_owner_uid, old_owner_gid, new_owner_gid,
            old_inode, new_inode, package, package_update,
            maintenance_window, suppressed, monitored_group, hmac,
            chain_hash, responsible_pid, responsible_exe
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
        )",
    )?
    .execute(params![
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
        chain_hash,
        change.responsible_pid.map(|v| v as i64),
        change.responsible_exe,
    ])?;

    Ok(conn.last_insert_rowid())
}

/// Get recent audit entries, ordered newest first.
pub fn get_recent_audit(conn: &Connection, limit: u32) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, event_type, path, change_type, severity,
                old_hash, new_hash, package, package_update,
                maintenance_window, suppressed, monitored_group,
                chain_hash, responsible_pid, responsible_exe
         FROM audit_log ORDER BY timestamp DESC LIMIT ?1",
    )?;

    let entries = stmt
        .query_map(params![limit], read_audit_row)?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(entries)
}

/// Search audit entries with optional filters for path and severity.
/// Uses pre-defined cached queries to avoid dynamic SQL (Item 20).
pub fn search_audit(
    conn: &Connection,
    path_filter: Option<&str>,
    severity_filter: Option<&str>,
    limit: u32,
) -> Result<Vec<AuditEntry>> {
    let entries = match (path_filter, severity_filter) {
        (None, None) => {
            let mut stmt = conn.prepare_cached(
                "SELECT id, timestamp, event_type, path, change_type, severity,
                        old_hash, new_hash, package, package_update,
                        maintenance_window, suppressed, monitored_group,
                        chain_hash, responsible_pid, responsible_exe
                 FROM audit_log ORDER BY timestamp DESC LIMIT ?1",
            )?;
            let result = stmt
                .query_map(params![limit], read_audit_row)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        }
        (Some(path), None) => {
            let mut stmt = conn.prepare_cached(
                "SELECT id, timestamp, event_type, path, change_type, severity,
                        old_hash, new_hash, package, package_update,
                        maintenance_window, suppressed, monitored_group,
                        chain_hash, responsible_pid, responsible_exe
                 FROM audit_log WHERE path LIKE ?1 ORDER BY timestamp DESC LIMIT ?2",
            )?;
            let result = stmt
                .query_map(params![format!("%{}%", path), limit], read_audit_row)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        }
        (None, Some(sev)) => {
            let mut stmt = conn.prepare_cached(
                "SELECT id, timestamp, event_type, path, change_type, severity,
                        old_hash, new_hash, package, package_update,
                        maintenance_window, suppressed, monitored_group,
                        chain_hash, responsible_pid, responsible_exe
                 FROM audit_log WHERE severity = ?1 ORDER BY timestamp DESC LIMIT ?2",
            )?;
            let result = stmt
                .query_map(params![sev, limit], read_audit_row)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        }
        (Some(path), Some(sev)) => {
            let mut stmt = conn.prepare_cached(
                "SELECT id, timestamp, event_type, path, change_type, severity,
                        old_hash, new_hash, package, package_update,
                        maintenance_window, suppressed, monitored_group,
                        chain_hash, responsible_pid, responsible_exe
                 FROM audit_log WHERE path LIKE ?1 AND severity = ?2 ORDER BY timestamp DESC LIMIT ?3",
            )?;
            let result = stmt
                .query_map(params![format!("%{}%", path), sev, limit], read_audit_row)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        }
    };

    Ok(entries)
}

fn read_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
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
        chain_hash: row.get(13).ok().flatten(),
        responsible_pid: row.get(14).ok().flatten(),
        responsible_exe: row.get(15).ok().flatten(),
    })
}

/// Verify the audit chain integrity (Item 16).
/// Returns (total, valid, broken_ids, missing_chain).
pub fn verify_audit_chain(conn: &Connection) -> Result<AuditChainVerifyResult> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, path, change_type, severity, old_hash, new_hash, chain_hash
         FROM audit_log ORDER BY id ASC",
    )?;

    let rows: Vec<AuditChainRow> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut total = 0u64;
    let mut valid = 0u64;
    let mut broken = Vec::new();
    let mut missing = 0u64;

    let genesis = crate::baseline::hash::blake3_hash_bytes(b"vigil-audit-chain-genesis");
    let mut prev_chain_hash = genesis;

    for (id, ts, path, change_type, severity, old_hash, new_hash, stored_chain) in &rows {
        total += 1;

        let Some(stored) = stored_chain else {
            missing += 1;
            continue;
        };

        let chain_data = format!(
            "{}{}{}{}{}{}{}",
            prev_chain_hash,
            ts,
            path,
            change_type,
            severity,
            old_hash.as_deref().unwrap_or(""),
            new_hash.as_deref().unwrap_or(""),
        );
        let expected = crate::baseline::hash::blake3_hash_bytes(chain_data.as_bytes());

        if *stored == expected {
            valid += 1;
        } else {
            broken.push((*id, *ts));
        }

        prev_chain_hash = stored.clone();
    }

    Ok((total, valid, broken, missing))
}

/// Compute HMAC over the entire baseline for at-rest protection (Item 17).
pub fn compute_baseline_hmac(conn: &Connection, key: &[u8]) -> Result<String> {
    let mut stmt = conn.prepare_cached(
        "SELECT path, hash, permissions, owner_uid, owner_gid FROM baseline ORDER BY path",
    )?;

    let mut canonical = String::new();
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;

    for r in rows {
        let (path, hash, perms, uid, gid) = r?;
        canonical.push_str(&format!("{}|{}|{}|{}|{}\n", path, hash, perms, uid, gid));
    }

    Ok(crate::hmac::compute_hmac(key, canonical.as_bytes()))
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
    pub chain_hash: Option<String>,
    pub responsible_pid: Option<i64>,
    pub responsible_exe: Option<String>,
}

pub type AuditChainBreak = (i64, i64);
pub type AuditChainVerifyResult = (u64, u64, Vec<AuditChainBreak>, u64);
type AuditChainRow = (
    i64,
    i64,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

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

// ── Audit log rotation ────────────────────────────────────

/// Rotate the audit log by deleting entries older than `retention_days`.
/// Returns the number of rows deleted.
pub fn rotate_audit_log(conn: &Connection, retention_days: u32) -> Result<usize> {
    let cutoff = Utc::now().timestamp() - (retention_days as i64 * 86400);
    let deleted = conn
        .prepare_cached("DELETE FROM audit_log WHERE timestamp < ?1")?
        .execute(params![cutoff])?;
    Ok(deleted)
}

/// Get all baseline paths (without loading full entries).
/// Used for efficient new-file detection during diff.
pub fn get_all_baseline_paths(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare_cached("SELECT path FROM baseline")?;
    let paths = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(paths)
}

/// Get the HMAC value for a specific audit entry by id.
pub fn get_audit_hmac(conn: &Connection, id: i64) -> Result<Option<String>> {
    let hmac = conn
        .query_row(
            "SELECT hmac FROM audit_log WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(hmac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema;
    use crate::types::{BaselineSource, Severity};
    use std::path::PathBuf;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::create_tables(&conn).unwrap();
        conn
    }

    fn sample_entry(path: &str) -> BaselineEntry {
        BaselineEntry {
            id: None,
            path: PathBuf::from(path),
            hash: "abc123def456".into(),
            size: 1024,
            permissions: 0o100644,
            owner_uid: 1000,
            owner_gid: 1000,
            mtime: 1700000000,
            inode: 99999,
            device: 1,
            xattrs: "{}".into(),
            security_context: String::new(),
            package: None,
            source: BaselineSource::AutoScan,
            added_at: 1700000000,
            updated_at: 1700000000,
            file_type: "file".into(),
            symlink_target: None,
            capabilities: None,
        }
    }

    #[test]
    fn insert_and_retrieve_baseline() {
        let conn = test_conn();
        let entry = sample_entry("/etc/passwd");

        let id = insert_baseline(&conn, &entry).unwrap();
        assert!(id > 0);

        let retrieved = get_baseline_by_path(&conn, "/etc/passwd").unwrap();
        assert!(retrieved.is_some());

        let r = retrieved.unwrap();
        assert_eq!(r.hash, "abc123def456");
        assert_eq!(r.size, 1024);
        assert_eq!(r.permissions, 0o100644);
        assert_eq!(r.owner_uid, 1000);
    }

    #[test]
    fn get_nonexistent_baseline_returns_none() {
        let conn = test_conn();
        let result = get_baseline_by_path(&conn, "/nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn upsert_updates_existing() {
        let conn = test_conn();
        let mut entry = sample_entry("/etc/passwd");

        upsert_baseline(&conn, &entry).unwrap();
        assert_eq!(baseline_count(&conn).unwrap(), 1);

        entry.hash = "new_hash_value".into();
        entry.size = 2048;
        upsert_baseline(&conn, &entry).unwrap();
        assert_eq!(baseline_count(&conn).unwrap(), 1);

        let r = get_baseline_by_path(&conn, "/etc/passwd").unwrap().unwrap();
        assert_eq!(r.hash, "new_hash_value");
        assert_eq!(r.size, 2048);
    }

    #[test]
    fn batch_upsert_baseline_writes_multiple_entries() {
        let conn = test_conn();
        let entries = vec![sample_entry("/etc/a"), sample_entry("/etc/b")];

        let written = batch_upsert_baseline(&conn, &entries).unwrap();
        assert_eq!(written, 2);
        assert_eq!(baseline_count(&conn).unwrap(), 2);

        let mut updated = entries.clone();
        updated[0].hash = "changed_hash".to_string();
        let written2 = batch_upsert_baseline(&conn, &updated).unwrap();
        assert_eq!(written2, 2);
        assert_eq!(baseline_count(&conn).unwrap(), 2);

        let a = get_baseline_by_path(&conn, "/etc/a").unwrap().unwrap();
        assert_eq!(a.hash, "changed_hash");
    }

    #[test]
    fn remove_baseline_by_path() {
        let conn = test_conn();
        insert_baseline(&conn, &sample_entry("/etc/hosts")).unwrap();
        assert_eq!(baseline_count(&conn).unwrap(), 1);

        let removed = remove_baseline(&conn, "/etc/hosts").unwrap();
        assert_eq!(removed, 1);
        assert_eq!(baseline_count(&conn).unwrap(), 0);
    }

    #[test]
    fn remove_nonexistent_returns_zero() {
        let conn = test_conn();
        let removed = remove_baseline(&conn, "/nonexistent").unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn get_all_baselines_ordered() {
        let conn = test_conn();
        insert_baseline(&conn, &sample_entry("/etc/shadow")).unwrap();
        insert_baseline(&conn, &sample_entry("/etc/passwd")).unwrap();
        insert_baseline(&conn, &sample_entry("/etc/hosts")).unwrap();

        let all = get_all_baselines(&conn).unwrap();
        assert_eq!(all.len(), 3);
        // Should be ordered by path
        assert_eq!(all[0].path, PathBuf::from("/etc/hosts"));
        assert_eq!(all[1].path, PathBuf::from("/etc/passwd"));
        assert_eq!(all[2].path, PathBuf::from("/etc/shadow"));
    }

    #[test]
    fn baseline_count_accurate() {
        let conn = test_conn();
        assert_eq!(baseline_count(&conn).unwrap(), 0);

        insert_baseline(&conn, &sample_entry("/a")).unwrap();
        assert_eq!(baseline_count(&conn).unwrap(), 1);

        insert_baseline(&conn, &sample_entry("/b")).unwrap();
        assert_eq!(baseline_count(&conn).unwrap(), 2);
    }

    #[test]
    fn audit_entry_always_written() {
        let conn = test_conn();

        let change = ChangeResult {
            path: PathBuf::from("/etc/passwd"),
            change_types: vec![ChangeType::Modified],
            severity: Severity::Critical,
            old_hash: Some("old".into()),
            new_hash: Some("new".into()),
            old_permissions: Some(0o644),
            new_permissions: Some(0o644),
            old_owner_uid: Some(0),
            new_owner_uid: Some(0),
            old_owner_gid: Some(0),
            new_owner_gid: Some(0),
            old_inode: Some(100),
            new_inode: Some(100),
            old_mtime: None,
            new_mtime: None,
            package: None,
            package_update: false,
            monitored_group: "system_critical".into(),
            responsible_pid: None,
            responsible_exe: None,
        };

        // Write audit entry (suppressed)
        insert_audit_entry(&conn, &change, ChangeType::Modified, false, true, None).unwrap();

        let entries = get_recent_audit(&conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].suppressed);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[0].path, "/etc/passwd");
    }

    #[test]
    fn audit_entry_records_maintenance_window() {
        let conn = test_conn();

        let change = ChangeResult {
            path: PathBuf::from("/usr/bin/sudo"),
            change_types: vec![ChangeType::Modified],
            severity: Severity::Critical,
            old_hash: Some("old".into()),
            new_hash: Some("new".into()),
            old_permissions: None,
            new_permissions: None,
            old_owner_uid: None,
            new_owner_uid: None,
            old_owner_gid: None,
            new_owner_gid: None,
            old_inode: None,
            new_inode: None,
            old_mtime: None,
            new_mtime: None,
            package: Some("sudo".into()),
            package_update: true,
            monitored_group: "system_critical".into(),
            responsible_pid: None,
            responsible_exe: None,
        };

        insert_audit_entry(&conn, &change, ChangeType::Modified, true, true, None).unwrap();

        let entries = get_recent_audit(&conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].maintenance_window);
        assert!(entries[0].package_update);
    }

    #[test]
    fn config_state_set_and_get() {
        let conn = test_conn();

        set_config_state(&conn, "test_key", "test_value").unwrap();
        let val = get_config_state(&conn, "test_key").unwrap();
        assert_eq!(val, Some("test_value".into()));
    }

    #[test]
    fn config_state_upsert() {
        let conn = test_conn();

        set_config_state(&conn, "key", "value1").unwrap();
        set_config_state(&conn, "key", "value2").unwrap();

        let val = get_config_state(&conn, "key").unwrap();
        assert_eq!(val, Some("value2".into()));
    }

    #[test]
    fn config_state_missing_key() {
        let conn = test_conn();
        let val = get_config_state(&conn, "nonexistent").unwrap();
        assert!(val.is_none());
    }

    #[test]
    fn audit_log_rotation_deletes_old_entries() {
        let conn = test_conn();

        // Insert an audit entry with an old timestamp (100 days ago)
        let old_ts = Utc::now().timestamp() - (100 * 86400);
        conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, path, change_type, severity, monitored_group)
             VALUES (?1, 'change', '/etc/test', 'modified', 'medium', 'test')",
            params![old_ts],
        )
        .unwrap();

        // Rotating with 90 day retention should delete the 100-day-old entry
        let deleted = rotate_audit_log(&conn, 90).unwrap();
        assert_eq!(deleted, 1);

        // Verify it's gone
        let entries = get_recent_audit(&conn, 10).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn audit_log_rotation_preserves_recent_entries() {
        let conn = test_conn();

        let change = ChangeResult {
            path: PathBuf::from("/etc/test"),
            change_types: vec![ChangeType::Modified],
            severity: Severity::Medium,
            old_hash: None,
            new_hash: None,
            old_permissions: None,
            new_permissions: None,
            old_owner_uid: None,
            new_owner_uid: None,
            old_owner_gid: None,
            new_owner_gid: None,
            old_inode: None,
            new_inode: None,
            old_mtime: None,
            new_mtime: None,
            package: None,
            package_update: false,
            monitored_group: "test".into(),
            responsible_pid: None,
            responsible_exe: None,
        };

        insert_audit_entry(&conn, &change, ChangeType::Modified, false, false, None).unwrap();

        // Rotating with 90 days retention should preserve the entry
        let deleted = rotate_audit_log(&conn, 90).unwrap();
        assert_eq!(deleted, 0);

        let entries = get_recent_audit(&conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
    }

    fn insert_test_audit(conn: &Connection, path: &str, severity: &str) {
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, path, change_type, severity, monitored_group)
             VALUES (?1, 'change', ?2, 'modified', ?3, 'test')",
            params![now, path, severity],
        )
        .unwrap();
    }

    #[test]
    fn search_audit_by_path() {
        let conn = test_conn();
        insert_test_audit(&conn, "/etc/passwd", "critical");
        insert_test_audit(&conn, "/etc/shadow", "critical");
        insert_test_audit(&conn, "/usr/bin/test", "medium");

        let results = search_audit(&conn, Some("passwd"), None, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "/etc/passwd");
    }

    #[test]
    fn search_audit_by_severity() {
        let conn = test_conn();
        insert_test_audit(&conn, "/etc/passwd", "critical");
        insert_test_audit(&conn, "/etc/shadow", "medium");
        insert_test_audit(&conn, "/usr/bin/test", "medium");

        let results = search_audit(&conn, None, Some("medium"), 100).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_audit_both_filters() {
        let conn = test_conn();
        insert_test_audit(&conn, "/etc/passwd", "critical");
        insert_test_audit(&conn, "/etc/shadow", "critical");
        insert_test_audit(&conn, "/usr/bin/test", "medium");

        let results = search_audit(&conn, Some("/etc"), Some("critical"), 100).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_audit_no_results() {
        let conn = test_conn();
        insert_test_audit(&conn, "/etc/passwd", "critical");

        let results = search_audit(&conn, Some("nonexistent"), None, 100).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn get_all_baseline_paths_returns_all_paths() {
        let conn = test_conn();
        insert_baseline(&conn, &sample_entry("/etc/passwd")).unwrap();
        insert_baseline(&conn, &sample_entry("/etc/shadow")).unwrap();
        insert_baseline(&conn, &sample_entry("/usr/bin/ls")).unwrap();

        let paths = get_all_baseline_paths(&conn).unwrap();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains("/etc/passwd"));
        assert!(paths.contains("/etc/shadow"));
        assert!(paths.contains("/usr/bin/ls"));
    }

    #[test]
    fn get_all_baseline_paths_empty_db() {
        let conn = test_conn();
        let paths = get_all_baseline_paths(&conn).unwrap();
        assert!(paths.is_empty());
    }
}
