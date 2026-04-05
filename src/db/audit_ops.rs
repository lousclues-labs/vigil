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
    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, path, changes_json, severity, chain_hash
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
        let (id, ts, path, changes_json, severity, chain_hash) = row?;
        total += 1;

        if chain_hash.is_empty() {
            missing += 1;
            continue;
        }

        let expected = compute_chain_hash(&prev, ts, &path, &changes_json, &severity);
        if expected == chain_hash {
            valid += 1;
        } else {
            breaks.push((id, ts));
        }
        prev = chain_hash;
    }

    Ok((total, valid, breaks, missing))
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
            path: PathBuf::from(path),
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
}
