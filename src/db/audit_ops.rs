use chrono::Utc;
use rusqlite::{params, Connection};

use crate::error::Result;
use crate::types::ChangeResult;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: i64,
    pub path: String,
    pub changes_json: String,
    pub severity: String,
    pub monitored_group: Option<String>,
    pub process_json: Option<String>,
    pub package: Option<String>,
    pub maintenance: bool,
    pub suppressed: bool,
    pub hmac: Option<String>,
    pub chain_hash: String,
}

pub type AuditChainBreak = (i64, i64);
pub type AuditChainVerifyResult = (u64, u64, Vec<AuditChainBreak>, u64);

pub fn get_last_chain_hash(conn: &Connection) -> Result<Option<String>> {
    let last = conn
        .query_row(
            "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();
    Ok(last)
}

pub fn compute_chain_hash(
    previous_chain_hash: &str,
    timestamp: i64,
    path: &str,
    changes_json: &str,
    severity: &str,
) -> String {
    let input = format!(
        "{}|{}|{}|{}|{}",
        previous_chain_hash, timestamp, path, changes_json, severity
    );
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Insert an audit entry and return the new chain hash.
pub fn insert_audit_entry(
    conn: &Connection,
    change: &ChangeResult,
    maintenance: bool,
    suppressed: bool,
    hmac: Option<&str>,
    previous_chain_hash: &str,
) -> Result<String> {
    let timestamp = Utc::now().timestamp();
    let path = change.path.to_string_lossy().to_string();
    let changes_json = serde_json::to_string(&change.changes)?;
    let severity = change.severity.to_string();
    let process_json = serde_json::to_string(&change.process).ok();

    let chain_hash = compute_chain_hash(
        previous_chain_hash,
        timestamp,
        &path,
        &changes_json,
        &severity,
    );

    conn.prepare_cached(
        "INSERT INTO audit_log (
            timestamp, path, changes_json, severity, monitored_group,
            process_json, package, maintenance, suppressed, hmac, chain_hash
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9, ?10, ?11
        )",
    )?
    .execute(params![
        timestamp,
        path,
        changes_json,
        severity,
        change.monitored_group,
        process_json,
        change.package,
        maintenance as i32,
        suppressed as i32,
        hmac,
        chain_hash,
    ])?;

    Ok(chain_hash)
}

pub fn get_recent(conn: &Connection, limit: u32) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, path, changes_json, severity,
                monitored_group, process_json, package,
                maintenance, suppressed, hmac, chain_hash
         FROM audit_log ORDER BY timestamp DESC LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit], |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            path: row.get(2)?,
            changes_json: row.get(3)?,
            severity: row.get(4)?,
            monitored_group: row.get(5)?,
            process_json: row.get(6)?,
            package: row.get(7)?,
            maintenance: row.get::<_, i32>(8)? != 0,
            suppressed: row.get::<_, i32>(9)? != 0,
            hmac: row.get(10)?,
            chain_hash: row.get(11)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn search(
    conn: &Connection,
    path_filter: Option<&str>,
    severity_filter: Option<&str>,
    limit: u32,
) -> Result<Vec<AuditEntry>> {
    match (path_filter, severity_filter) {
        (None, None) => get_recent(conn, limit),
        (Some(path), None) => {
            let mut stmt = conn.prepare_cached(
                "SELECT id, timestamp, path, changes_json, severity,
                        monitored_group, process_json, package,
                        maintenance, suppressed, hmac, chain_hash
                 FROM audit_log WHERE path LIKE ?1 ORDER BY timestamp DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![format!("%{}%", path), limit], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    path: row.get(2)?,
                    changes_json: row.get(3)?,
                    severity: row.get(4)?,
                    monitored_group: row.get(5)?,
                    process_json: row.get(6)?,
                    package: row.get(7)?,
                    maintenance: row.get::<_, i32>(8)? != 0,
                    suppressed: row.get::<_, i32>(9)? != 0,
                    hmac: row.get(10)?,
                    chain_hash: row.get(11)?,
                })
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        }
        (None, Some(sev)) => {
            let mut stmt = conn.prepare_cached(
                "SELECT id, timestamp, path, changes_json, severity,
                        monitored_group, process_json, package,
                        maintenance, suppressed, hmac, chain_hash
                 FROM audit_log WHERE severity = ?1 ORDER BY timestamp DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![sev, limit], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    path: row.get(2)?,
                    changes_json: row.get(3)?,
                    severity: row.get(4)?,
                    monitored_group: row.get(5)?,
                    process_json: row.get(6)?,
                    package: row.get(7)?,
                    maintenance: row.get::<_, i32>(8)? != 0,
                    suppressed: row.get::<_, i32>(9)? != 0,
                    hmac: row.get(10)?,
                    chain_hash: row.get(11)?,
                })
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        }
        (Some(path), Some(sev)) => {
            let mut stmt = conn.prepare_cached(
                "SELECT id, timestamp, path, changes_json, severity,
                        monitored_group, process_json, package,
                        maintenance, suppressed, hmac, chain_hash
                 FROM audit_log
                 WHERE path LIKE ?1 AND severity = ?2
                 ORDER BY timestamp DESC LIMIT ?3",
            )?;
            let rows = stmt.query_map(params![format!("%{}%", path), sev, limit], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    path: row.get(2)?,
                    changes_json: row.get(3)?,
                    severity: row.get(4)?,
                    monitored_group: row.get(5)?,
                    process_json: row.get(6)?,
                    package: row.get(7)?,
                    maintenance: row.get::<_, i32>(8)? != 0,
                    suppressed: row.get::<_, i32>(9)? != 0,
                    hmac: row.get(10)?,
                    chain_hash: row.get(11)?,
                })
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        }
    }
}

pub fn rotate_audit_log(conn: &Connection, retention_days: u32) -> Result<usize> {
    let cutoff = Utc::now().timestamp() - (retention_days as i64 * 86400);
    let deleted = conn
        .prepare_cached("DELETE FROM audit_log WHERE timestamp < ?1")?
        .execute(params![cutoff])?;
    Ok(deleted)
}

pub fn verify_chain(conn: &Connection) -> Result<AuditChainVerifyResult> {
    verify_chain_with_hmac(conn, None)
}

/// Verify the audit chain, optionally also verifying HMACs when a key is provided.
pub fn verify_chain_with_hmac(
    conn: &Connection,
    hmac_key: Option<&[u8]>,
) -> Result<AuditChainVerifyResult> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, path, changes_json, severity, chain_hash, hmac
         FROM audit_log ORDER BY id ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
        ))
    })?;

    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();
    let mut prev = genesis;

    let mut total = 0u64;
    let mut valid = 0u64;
    let mut breaks = Vec::new();
    let mut missing = 0u64;

    for row in rows {
        let (id, ts, path, changes_json, severity, chain_hash, entry_hmac) = row?;
        total += 1;

        if chain_hash.is_empty() {
            missing += 1;
            prev = chain_hash;
            continue;
        }

        let expected = compute_chain_hash(&prev, ts, &path, &changes_json, &severity);
        if expected == chain_hash {
            // Also verify HMAC if key is provided and entry has one
            if let (Some(key), Some(ref stored_hmac)) = (hmac_key, &entry_hmac) {
                // We need the primary change type and content hashes to rebuild HMAC data.
                // Parse changes_json to extract these.
                let primary = changes_json_to_primary_type(&changes_json);
                let (old_hash, new_hash) = changes_json_extract_hashes(&changes_json);
                let data = crate::hmac::build_audit_hmac_data(
                    ts,
                    &path,
                    &primary,
                    &severity,
                    old_hash.as_deref(),
                    new_hash.as_deref(),
                    &prev,
                );
                if crate::hmac::verify_hmac(key, &data, stored_hmac) {
                    valid += 1;
                } else {
                    breaks.push((id, ts));
                }
            } else {
                valid += 1;
            }
        } else {
            breaks.push((id, ts));
        }
        prev = chain_hash;
    }

    Ok((total, valid, breaks, missing))
}

/// Extract the primary change type from changes_json.
fn changes_json_to_primary_type(json: &str) -> String {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json) {
        if let Some(first) = arr.first() {
            if first.is_string() {
                return first.as_str().unwrap_or("unknown").to_string();
            }
            // Handle tagged enum format: {"ContentModified": {...}}
            if let Some(obj) = first.as_object() {
                if let Some(key) = obj.keys().next() {
                    return match key.as_str() {
                        "ContentModified" => "content_modified",
                        "PermissionsChanged" => "permissions_changed",
                        "OwnerChanged" => "owner_changed",
                        "InodeChanged" => "inode_changed",
                        "TypeChanged" => "type_changed",
                        "SymlinkTargetChanged" => "symlink_target_changed",
                        "CapabilitiesChanged" => "capabilities_changed",
                        "XattrChanged" => "xattr_changed",
                        "SecurityContextChanged" => "security_context_changed",
                        "SizeChanged" => "size_changed",
                        "DeviceChanged" => "device_changed",
                        "Deleted" => "deleted",
                        "Created" => "created",
                        _ => "unknown",
                    }
                    .to_string();
                }
            }
        }
    }
    "unknown".to_string()
}

/// Extract old_hash and new_hash from changes_json if a ContentModified change exists.
fn changes_json_extract_hashes(json: &str) -> (Option<String>, Option<String>) {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json) {
        for item in &arr {
            if let Some(obj) = item.as_object() {
                if let Some(cm) = obj.get("ContentModified") {
                    let old = cm
                        .get("old_hash")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let new = cm
                        .get("new_hash")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    return (old, new);
                }
            }
        }
    }
    (None, None)
}

#[derive(Debug, Clone)]
pub struct AuditQuery {
    pub path: Option<String>,
    pub severity: Option<String>,
    pub group: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub maintenance_only: bool,
    pub suppressed_only: bool,
    pub limit: u32,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            path: None,
            severity: None,
            group: None,
            since: None,
            until: None,
            maintenance_only: false,
            suppressed_only: false,
            limit: 50,
        }
    }
}

pub fn query(conn: &Connection, q: &AuditQuery) -> Result<Vec<AuditEntry>> {
    let mut conditions = Vec::new();
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref path) = q.path {
        conditions.push("path LIKE ?");
        let pattern = path.replace('*', "%");
        param_values.push(Box::new(if pattern.contains('%') {
            pattern
        } else {
            format!("%{}%", path)
        }));
    }
    if let Some(ref severity) = q.severity {
        conditions.push("severity = ?");
        param_values.push(Box::new(severity.to_lowercase()));
    }
    if let Some(ref group) = q.group {
        conditions.push("monitored_group = ?");
        param_values.push(Box::new(group.clone()));
    }
    if let Some(since) = q.since {
        conditions.push("timestamp >= ?");
        param_values.push(Box::new(since));
    }
    if let Some(until) = q.until {
        conditions.push("timestamp <= ?");
        param_values.push(Box::new(until));
    }
    if q.maintenance_only {
        conditions.push("maintenance = 1");
    }
    if q.suppressed_only {
        conditions.push("suppressed = 1");
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT id, timestamp, path, changes_json, severity,
                monitored_group, process_json, package,
                maintenance, suppressed, hmac, chain_hash
         FROM audit_log {} ORDER BY timestamp DESC LIMIT ?",
        where_clause
    );

    let mut stmt = conn.prepare(&sql)?;

    let mut params_ref: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();
    let limit_val = q.limit as i64;
    params_ref.push(&limit_val);

    let rows = stmt.query_map(rusqlite::params_from_iter(params_ref), |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            path: row.get(2)?,
            changes_json: row.get(3)?,
            severity: row.get(4)?,
            monitored_group: row.get(5)?,
            process_json: row.get(6)?,
            package: row.get(7)?,
            maintenance: row.get::<_, i32>(8)? != 0,
            suppressed: row.get::<_, i32>(9)? != 0,
            hmac: row.get(10)?,
            chain_hash: row.get(11)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditPathWindowState {
    pub latest_any: Option<i64>,
    pub latest_in_window: Option<i64>,
}

/// Return the latest timestamp for `path` overall and within the provided window.
pub fn get_path_window_state(
    conn: &Connection,
    path: &str,
    since: i64,
    until: i64,
) -> Result<AuditPathWindowState> {
    let state = conn.query_row(
        "SELECT
            MAX(timestamp) AS latest_any,
            MAX(CASE WHEN timestamp >= ?2 AND timestamp <= ?3 THEN timestamp END) AS latest_in_window
         FROM audit_log
         WHERE path = ?1",
        params![path, since, until],
        |row| {
            Ok(AuditPathWindowState {
                latest_any: row.get(0)?,
                latest_in_window: row.get(1)?,
            })
        },
    )?;

    Ok(state)
}

/// Fetch most recent audit entries for a single exact path.
pub fn get_recent_for_path(conn: &Connection, path: &str, limit: u32) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, path, changes_json, severity,
                monitored_group, process_json, package,
                maintenance, suppressed, hmac, chain_hash
         FROM audit_log
         WHERE path = ?1
         ORDER BY timestamp DESC
         LIMIT ?2",
    )?;

    let rows = stmt.query_map(params![path, limit], |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            path: row.get(2)?,
            changes_json: row.get(3)?,
            severity: row.get(4)?,
            monitored_group: row.get(5)?,
            process_json: row.get(6)?,
            package: row.get(7)?,
            maintenance: row.get::<_, i32>(8)? != 0,
            suppressed: row.get::<_, i32>(9)? != 0,
            hmac: row.get(10)?,
            chain_hash: row.get(11)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn count(conn: &Connection) -> Result<u64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
    Ok(count.max(0) as u64)
}

pub fn count_since(conn: &Connection, since_timestamp: i64) -> Result<u64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1",
        params![since_timestamp],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as u64)
}

pub fn get_severity_counts(
    conn: &Connection,
    since_timestamp: Option<i64>,
) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    match since_timestamp {
        Some(ts) => {
            let mut stmt = conn.prepare_cached(
                "SELECT severity, COUNT(*) FROM audit_log WHERE timestamp >= ?1 GROUP BY severity ORDER BY COUNT(*) DESC",
            )?;
            let rows = stmt.query_map(params![ts], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
        None => {
            let mut stmt = conn.prepare_cached(
                "SELECT severity, COUNT(*) FROM audit_log GROUP BY severity ORDER BY COUNT(*) DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
    }
    Ok(out)
}

pub fn get_top_paths(
    conn: &Connection,
    since_timestamp: Option<i64>,
    limit: u32,
) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    match since_timestamp {
        Some(ts) => {
            let mut stmt = conn.prepare_cached(
                "SELECT path, COUNT(*) as cnt FROM audit_log WHERE timestamp >= ?1 GROUP BY path ORDER BY cnt DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![ts, limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
        None => {
            let mut stmt = conn.prepare_cached(
                "SELECT path, COUNT(*) as cnt FROM audit_log GROUP BY path ORDER BY cnt DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
    }
    Ok(out)
}

pub fn get_group_counts(
    conn: &Connection,
    since_timestamp: Option<i64>,
) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    match since_timestamp {
        Some(ts) => {
            let mut stmt = conn.prepare_cached(
                "SELECT COALESCE(monitored_group, 'unknown'), COUNT(*) FROM audit_log WHERE timestamp >= ?1 GROUP BY monitored_group ORDER BY COUNT(*) DESC",
            )?;
            let rows = stmt.query_map(params![ts], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
        None => {
            let mut stmt = conn.prepare_cached(
                "SELECT COALESCE(monitored_group, 'unknown'), COUNT(*) FROM audit_log GROUP BY monitored_group ORDER BY COUNT(*) DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema;
    use crate::types::{Change, ChangeResult, ProcessAttribution, Severity};
    use std::path::PathBuf;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::create_audit_tables(&conn).unwrap();
        conn
    }

    fn sample_change(path: &str) -> ChangeResult {
        ChangeResult {
            path: std::sync::Arc::new(PathBuf::from(path)),
            changes: vec![Change::Created],
            severity: Severity::High,
            monitored_group: "test".into(),
            process: Some(ProcessAttribution {
                pid: 42,
                exe: Some("/usr/bin/test".into()),
            }),
            package: None,
            package_update: false,
        }
    }

    #[test]
    fn insert_and_retrieve_audit() {
        let conn = test_conn();
        let change = sample_change("/etc/passwd");
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();

        let _hash = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();
        let entries = get_recent(&conn, 10).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/etc/passwd");
        assert_eq!(entries[0].severity, "high");
    }

    #[test]
    fn chain_verification_detects_break() {
        let conn = test_conn();
        let change = sample_change("/etc/passwd");
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();

        let h1 = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();
        let _h2 = insert_audit_entry(&conn, &change, false, false, None, &h1).unwrap();

        conn.execute(
            "UPDATE audit_log SET chain_hash = 'corrupt' WHERE id = 2",
            [],
        )
        .unwrap();

        let (total, valid, breaks, _missing) = verify_chain(&conn).unwrap();
        assert_eq!(total, 2);
        assert_eq!(valid, 1);
        assert_eq!(breaks.len(), 1);
    }

    #[test]
    fn count_returns_total() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let change = sample_change("/etc/passwd");
        let h = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();
        let _ = insert_audit_entry(&conn, &change, false, false, None, &h).unwrap();
        assert_eq!(count(&conn).unwrap(), 2);
    }

    #[test]
    fn query_filters_by_severity() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let change = sample_change("/etc/passwd");
        let _ = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();

        let results = query(
            &conn,
            &AuditQuery {
                severity: Some("high".to_string()),
                ..AuditQuery::default()
            },
        )
        .unwrap();
        assert_eq!(results.len(), 1);

        let results = query(
            &conn,
            &AuditQuery {
                severity: Some("low".to_string()),
                ..AuditQuery::default()
            },
        )
        .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn query_filters_by_path() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let change = sample_change("/etc/passwd");
        let h = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();
        let change2 = sample_change("/usr/bin/test");
        let _ = insert_audit_entry(&conn, &change2, false, false, None, &h).unwrap();

        let results = query(
            &conn,
            &AuditQuery {
                path: Some("/etc/*".to_string()),
                ..AuditQuery::default()
            },
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "/etc/passwd");
    }

    #[test]
    fn query_filters_by_group() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let change = sample_change("/etc/passwd");
        let _ = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();

        let results = query(
            &conn,
            &AuditQuery {
                group: Some("test".to_string()),
                ..AuditQuery::default()
            },
        )
        .unwrap();
        assert_eq!(results.len(), 1);

        let results = query(
            &conn,
            &AuditQuery {
                group: Some("nonexistent".to_string()),
                ..AuditQuery::default()
            },
        )
        .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn get_severity_counts_works() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let change = sample_change("/etc/passwd");
        let h = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();
        let _ = insert_audit_entry(&conn, &change, false, false, None, &h).unwrap();

        let counts = get_severity_counts(&conn, None).unwrap();
        assert_eq!(counts.len(), 1);
        assert_eq!(counts[0].0, "high");
        assert_eq!(counts[0].1, 2);
    }

    #[test]
    fn get_top_paths_works() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let change = sample_change("/etc/passwd");
        let h = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();
        let change2 = sample_change("/usr/bin/test");
        let _ = insert_audit_entry(&conn, &change2, false, false, None, &h).unwrap();

        let paths = get_top_paths(&conn, None, 10).unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn get_group_counts_works() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let change = sample_change("/etc/passwd");
        let _ = insert_audit_entry(&conn, &change, false, false, None, &genesis).unwrap();

        let groups = get_group_counts(&conn, None).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "test");
        assert_eq!(groups[0].1, 1);
    }

    #[test]
    fn get_recent_for_path_is_exact_match() {
        let conn = test_conn();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();

        let c1 = sample_change("/etc/passwd");
        let h1 = insert_audit_entry(&conn, &c1, false, false, None, &genesis).unwrap();

        let c2 = sample_change("/etc/passwd.bak");
        let _ = insert_audit_entry(&conn, &c2, false, false, None, &h1).unwrap();

        let entries = get_recent_for_path(&conn, "/etc/passwd", 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/etc/passwd");
    }

    #[test]
    fn get_path_window_state_reports_latest_and_window() {
        let conn = test_conn();
        conn.execute(
            "INSERT INTO audit_log (timestamp, path, changes_json, severity, chain_hash)
             VALUES (?1, ?2, '[]', 'high', 'h1')",
            params![100_i64, "/etc/passwd"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_log (timestamp, path, changes_json, severity, chain_hash)
             VALUES (?1, ?2, '[]', 'high', 'h2')",
            params![300_i64, "/etc/passwd"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_log (timestamp, path, changes_json, severity, chain_hash)
             VALUES (?1, ?2, '[]', 'high', 'h3')",
            params![500_i64, "/etc/passwd"],
        )
        .unwrap();

        let state = get_path_window_state(&conn, "/etc/passwd", 200, 400).unwrap();
        assert_eq!(state.latest_any, Some(500));
        assert_eq!(state.latest_in_window, Some(300));
    }
}
