//! Audit log database operations.
//!
//! Inserts detections into the HMAC-chained audit log, computes chain
//! hashes, verifies chain integrity, and provides query/stats helpers
//! for `vigil audit show` and `vigil audit verify`.
//!
//! Checkpoints: bounded retention replaces pruned entry ranges with
//! `AuditCheckpoint` records. The chain extends across checkpoints
//! without break.

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

/// Result of chain verification with checkpoint awareness.
pub struct AuditChainVerifyDetail {
    pub total: u64,
    pub valid: u64,
    pub breaks: Vec<AuditChainBreak>,
    pub missing: u64,
    pub checkpoint_count: u64,
    pub checkpoint_covered_entries: u64,
    pub oldest_checkpoint_timestamp: Option<i64>,
}

/// Verify the audit chain, optionally also verifying HMACs when a key is provided.
pub fn verify_chain_with_hmac(
    conn: &Connection,
    hmac_key: Option<&[u8]>,
) -> Result<AuditChainVerifyResult> {
    let detail = verify_chain_detail(conn, hmac_key)?;
    Ok((detail.total, detail.valid, detail.breaks, detail.missing))
}

/// Verify the audit chain with full detail including checkpoint information.
pub fn verify_chain_detail(
    conn: &Connection,
    hmac_key: Option<&[u8]>,
) -> Result<AuditChainVerifyDetail> {
    let has_record_type = conn
        .prepare("SELECT record_type FROM audit_log LIMIT 0")
        .is_ok();

    let mut stmt = if has_record_type {
        conn.prepare_cached(
            "SELECT id, timestamp, path, changes_json, severity, chain_hash, hmac,
                    record_type, first_sequence, last_sequence, entry_count, pruned_range_hmac
             FROM audit_log ORDER BY id ASC",
        )?
    } else {
        conn.prepare_cached(
            "SELECT id, timestamp, path, changes_json, severity, chain_hash, hmac,
                    NULL, NULL, NULL, NULL, NULL
             FROM audit_log ORDER BY id ASC",
        )?
    };

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<i64>>(9)?,
            row.get::<_, Option<i64>>(10)?,
            row.get::<_, Option<String>>(11)?,
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
    let mut checkpoint_count = 0u64;
    let mut checkpoint_covered = 0u64;

    for row in rows {
        let (
            id,
            ts,
            _path,
            changes_json,
            severity,
            chain_hash,
            entry_hmac,
            record_type,
            first_seq,
            last_seq,
            entry_count,
            pruned_range_hmac,
        ) = row?;
        total += 1;

        if chain_hash.is_empty() {
            missing += 1;
            prev = chain_hash;
            continue;
        }

        let is_checkpoint = record_type.as_deref() == Some("checkpoint");

        if is_checkpoint {
            checkpoint_count += 1;
            if let Some(ec) = entry_count {
                checkpoint_covered += ec as u64;
            }

            // Checkpoint chain_hash is a bridge value (= last pruned entry's hash).
            // Verify checkpoint integrity via its hmac field, not chain_hash recomputation.
            // Extract previous_chain_hash from the checkpoint's changes_json metadata.
            let ckpt_prev =
                extract_checkpoint_previous_chain_hash(&changes_json).unwrap_or_default();

            if let (Some(key), Some(ref stored_hmac)) = (hmac_key, &entry_hmac) {
                let first_s = first_seq.unwrap_or(0);
                let last_s = last_seq.unwrap_or(0);
                let ec = entry_count.unwrap_or(0);
                let prh = pruned_range_hmac.as_deref().unwrap_or("");

                let data = build_checkpoint_hmac_data(ts, first_s, last_s, ec, prh, &ckpt_prev);
                if crate::hmac::verify_hmac(key, &data, stored_hmac) {
                    valid += 1;
                } else {
                    breaks.push((id, ts));
                }
            } else {
                // Without HMAC key, accept checkpoint on faith (chain_hash is bridge)
                valid += 1;
            }
        } else {
            // Standard detection entry -- recompute chain_hash from prev
            let expected = compute_chain_hash(&prev, ts, &_path, &changes_json, &severity);
            if expected == chain_hash {
                if let (Some(key), Some(ref stored_hmac)) = (hmac_key, &entry_hmac) {
                    let primary = changes_json_to_primary_type(&changes_json);
                    let (old_hash, new_hash) = changes_json_extract_hashes(&changes_json);
                    let data = crate::hmac::build_audit_hmac_data(
                        ts,
                        &_path,
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
        }
        prev = chain_hash;
    }

    // Get oldest checkpoint timestamp from DB
    let oldest_ckpt_ts = if checkpoint_count > 0 {
        oldest_checkpoint_timestamp(conn)?
    } else {
        None
    };

    Ok(AuditChainVerifyDetail {
        total,
        valid,
        breaks,
        missing,
        checkpoint_count,
        checkpoint_covered_entries: checkpoint_covered,
        oldest_checkpoint_timestamp: oldest_ckpt_ts,
    })
}

/// Extract previous_chain_hash from a checkpoint's changes_json metadata.
fn extract_checkpoint_previous_chain_hash(changes_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(changes_json)
        .ok()
        .and_then(|v| v.get("previous_chain_hash")?.as_str().map(String::from))
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

/// Insert a check_completed receipt into the audit chain.
pub fn insert_receipt_entry(
    conn: &Connection,
    _receipt: &crate::receipt::CheckReceipt,
    payload_json: &str,
    previous_chain_hash: &str,
    hmac_key: Option<&[u8]>,
) -> Result<String> {
    let timestamp = Utc::now().timestamp();
    let path = "vigil:check_completed";
    let severity = "info";

    let chain_hash =
        compute_chain_hash(previous_chain_hash, timestamp, path, payload_json, severity);

    let hmac = hmac_key.map(|key| {
        let data = crate::hmac::build_audit_hmac_data(
            timestamp,
            path,
            "check_completed",
            severity,
            None,
            None,
            previous_chain_hash,
        );
        crate::hmac::compute_hmac(key, &data).unwrap_or_default()
    });

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
        payload_json,
        severity,
        Option::<String>::None,
        Option::<String>::None,
        Option::<String>::None,
        0,
        0,
        hmac,
        chain_hash,
    ])?;

    Ok(chain_hash)
}

/// Insert a self_check entry into the audit chain.
pub fn insert_self_check_entry(
    conn: &Connection,
    payload_json: &str,
    overall_status: &str,
    previous_chain_hash: &str,
    hmac_key: Option<&[u8]>,
) -> Result<String> {
    let timestamp = Utc::now().timestamp();
    let path = "vigil:self_check";
    let severity = match overall_status {
        "Fail" => "critical",
        "Warn" => "warning",
        _ => "info",
    };

    let chain_hash =
        compute_chain_hash(previous_chain_hash, timestamp, path, payload_json, severity);

    let hmac = hmac_key.map(|key| {
        let data = crate::hmac::build_audit_hmac_data(
            timestamp,
            path,
            "self_check",
            severity,
            None,
            None,
            previous_chain_hash,
        );
        crate::hmac::compute_hmac(key, &data).unwrap_or_default()
    });

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
        payload_json,
        severity,
        Option::<String>::None,
        Option::<String>::None,
        Option::<String>::None,
        0,
        0,
        hmac,
        chain_hash,
    ])?;

    Ok(chain_hash)
}

/// Insert a test_alert entry into the audit chain.
pub fn insert_test_alert_entry(
    conn: &Connection,
    payload_json: &str,
    severity: &str,
    previous_chain_hash: &str,
    hmac_key: Option<&[u8]>,
) -> Result<String> {
    let timestamp = Utc::now().timestamp();
    let path = "vigil:test_alert";

    let chain_hash =
        compute_chain_hash(previous_chain_hash, timestamp, path, payload_json, severity);

    let hmac = hmac_key.map(|key| {
        let data = crate::hmac::build_audit_hmac_data(
            timestamp,
            path,
            "test_alert",
            severity,
            None,
            None,
            previous_chain_hash,
        );
        crate::hmac::compute_hmac(key, &data).unwrap_or_default()
    });

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
        payload_json,
        severity,
        Option::<String>::None,
        Option::<String>::None,
        Option::<String>::None,
        0,
        0,
        hmac,
        chain_hash,
    ])?;

    Ok(chain_hash)
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

// ── Audit Segment Operations ──────────────────────────────────

/// An audit segment row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditSegment {
    pub id: i64,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub first_timestamp: i64,
    pub last_timestamp: i64,
    pub first_chain_hash: String,
    pub sealed_chain_hash: String,
    pub sealed_at: i64,
    pub archive_path: Option<String>,
}

/// List all audit segments.
pub fn list_segments(conn: &Connection) -> Result<Vec<AuditSegment>> {
    // The table might not exist in older databases.
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_segments'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);

    if !exists {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare_cached(
        "SELECT id, first_sequence, last_sequence, first_timestamp,
                last_timestamp, first_chain_hash, sealed_chain_hash,
                sealed_at, archive_path
         FROM audit_segments ORDER BY id ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(AuditSegment {
            id: row.get(0)?,
            first_sequence: row.get(1)?,
            last_sequence: row.get(2)?,
            first_timestamp: row.get(3)?,
            last_timestamp: row.get(4)?,
            first_chain_hash: row.get(5)?,
            sealed_chain_hash: row.get(6)?,
            sealed_at: row.get(7)?,
            archive_path: row.get(8)?,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Count entries in the live audit log.
pub fn count_entries(conn: &Connection) -> Result<u64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
    Ok(count.max(0) as u64)
}

/// A checkpoint record that replaces a pruned range of audit entries.
/// Sits in the same `audit_log` table with `record_type = 'checkpoint'`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditCheckpoint {
    pub id: i64,
    pub sequence: i64,
    pub timestamp: i64,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub first_timestamp: i64,
    pub last_timestamp: i64,
    pub entry_count: i64,
    pub pruned_range_hmac: String,
    pub previous_chain_hash: String,
    pub chain_hash: String,
    pub hmac: Option<String>,
}

/// Canonical chain-hash input for a checkpoint record. Must match
/// `compute_chain_hash` for detection entries in that the result is a
/// blake3 hash of a pipe-delimited string.
pub fn compute_checkpoint_chain_hash(
    previous_chain_hash: &str,
    timestamp: i64,
    first_sequence: i64,
    last_sequence: i64,
    entry_count: i64,
    pruned_range_hmac: &str,
) -> String {
    let input = format!(
        "{}|{}|checkpoint|{}-{}|{}|{}",
        previous_chain_hash,
        timestamp,
        first_sequence,
        last_sequence,
        entry_count,
        pruned_range_hmac
    );
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Build the HMAC input bytes for a checkpoint record.
/// Parallels `build_audit_hmac_data` for detection entries.
pub fn build_checkpoint_hmac_data(
    timestamp: i64,
    first_sequence: i64,
    last_sequence: i64,
    entry_count: i64,
    pruned_range_hmac: &str,
    previous_chain_hash: &str,
) -> Vec<u8> {
    format!(
        "{}|checkpoint|{}-{}|{}|{}|{}",
        timestamp,
        first_sequence,
        last_sequence,
        entry_count,
        pruned_range_hmac,
        previous_chain_hash
    )
    .into_bytes()
}

/// Insert a checkpoint record into the audit log chain.
///
/// The checkpoint is inserted at `replace_id` (typically the last pruned entry's
/// id) so it occupies the correct position in the id-ordered chain. Its stored
/// `chain_hash` is set to `bridge_chain_hash` -- the last pruned entry's original
/// chain_hash -- so the surviving entries' chain links remain valid.
///
/// The checkpoint's own integrity is proven by its `hmac` field (computed over
/// its metadata + `previous_chain_hash`), NOT by its chain_hash.
///
/// Returns the checkpoint's stored chain_hash (= bridge_chain_hash).
#[allow(clippy::too_many_arguments)]
pub fn insert_checkpoint(
    conn: &Connection,
    replace_id: i64,
    timestamp: i64,
    first_sequence: i64,
    last_sequence: i64,
    first_timestamp: i64,
    last_timestamp: i64,
    entry_count: i64,
    pruned_range_hmac: &str,
    previous_chain_hash: &str,
    bridge_chain_hash: &str,
    hmac_key: Option<&[u8]>,
) -> Result<String> {
    let hmac = hmac_key.map(|key| {
        let data = build_checkpoint_hmac_data(
            timestamp,
            first_sequence,
            last_sequence,
            entry_count,
            pruned_range_hmac,
            previous_chain_hash,
        );
        crate::hmac::compute_hmac(key, &data).unwrap_or_default()
    });

    conn.execute(
        "INSERT INTO audit_log (
            id, timestamp, path, changes_json, severity, monitored_group,
            process_json, package, maintenance, suppressed, hmac, chain_hash,
            record_type, first_sequence, last_sequence, first_timestamp,
            last_timestamp, entry_count, pruned_range_hmac
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, NULL,
            NULL, NULL, 0, 0, ?6, ?7,
            'checkpoint', ?8, ?9, ?10,
            ?11, ?12, ?13
        )",
        params![
            replace_id,
            timestamp,
            format!("vigil:checkpoint:{}-{}", first_sequence, last_sequence),
            format!("{{\"previous_chain_hash\":\"{}\"}}", previous_chain_hash),
            "info",
            hmac,
            bridge_chain_hash,
            first_sequence,
            last_sequence,
            first_timestamp,
            last_timestamp,
            entry_count,
            pruned_range_hmac,
        ],
    )?;

    Ok(bridge_chain_hash.to_string())
}

/// Delete audit_log entries in the ID range [first_id, last_id] that are
/// detection records (not checkpoints). Returns the count deleted.
pub fn delete_detection_range(conn: &Connection, first_id: i64, last_id: i64) -> Result<usize> {
    let deleted = conn
        .prepare_cached(
            "DELETE FROM audit_log WHERE id >= ?1 AND id <= ?2 AND record_type = 'detection'",
        )?
        .execute(params![first_id, last_id])?;
    Ok(deleted)
}

/// List all checkpoint records, ordered by ID ascending.
pub fn list_checkpoints(conn: &Connection) -> Result<Vec<AuditCheckpoint>> {
    let has_record_type = conn
        .prepare("SELECT record_type FROM audit_log LIMIT 0")
        .is_ok();
    if !has_record_type {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, chain_hash, hmac,
                first_sequence, last_sequence, first_timestamp, last_timestamp,
                entry_count, pruned_range_hmac
         FROM audit_log
         WHERE record_type = 'checkpoint'
         ORDER BY id ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(AuditCheckpoint {
            id: row.get(0)?,
            sequence: row.get(0)?, // id == sequence in our model
            timestamp: row.get(1)?,
            chain_hash: row.get(2)?,
            hmac: row.get(3)?,
            first_sequence: row.get(4)?,
            last_sequence: row.get(5)?,
            first_timestamp: row.get(6)?,
            last_timestamp: row.get(7)?,
            entry_count: row.get(8)?,
            pruned_range_hmac: row.get(9)?,
            previous_chain_hash: String::new(), // not stored; reconstructed during verification
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Count only detection (non-checkpoint) entries.
pub fn count_detection_entries(conn: &Connection) -> Result<u64> {
    let has_record_type = conn
        .prepare("SELECT record_type FROM audit_log LIMIT 0")
        .is_ok();
    if !has_record_type {
        return count_entries(conn);
    }
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE record_type = 'detection'",
        [],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as u64)
}

/// Total entry count covered by checkpoints.
pub fn checkpoint_covered_entries(conn: &Connection) -> Result<u64> {
    let has_record_type = conn
        .prepare("SELECT record_type FROM audit_log LIMIT 0")
        .is_ok();
    if !has_record_type {
        return Ok(0);
    }
    let sum: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(entry_count), 0) FROM audit_log WHERE record_type = 'checkpoint'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(sum.max(0) as u64)
}

/// Get the oldest timestamp from checkpoint records (the earliest `first_timestamp`).
pub fn oldest_checkpoint_timestamp(conn: &Connection) -> Result<Option<i64>> {
    let has_record_type = conn
        .prepare("SELECT record_type FROM audit_log LIMIT 0")
        .is_ok();
    if !has_record_type {
        return Ok(None);
    }
    let ts = conn
        .query_row(
            "SELECT MIN(first_timestamp) FROM audit_log WHERE record_type = 'checkpoint'",
            [],
            |row| row.get(0),
        )
        .ok();
    Ok(ts)
}

/// Get the oldest detection entry timestamp.
pub fn oldest_detection_timestamp(conn: &Connection) -> Result<Option<i64>> {
    let ts = conn
        .query_row(
            "SELECT MIN(timestamp) FROM audit_log WHERE record_type = 'detection' OR record_type IS NULL",
            [],
            |row| row.get(0),
        )
        .ok();
    Ok(ts)
}

/// Identify the prune range for the retention sweep.
/// Returns (first_id, last_id, entry_count) of detection entries older than
/// `cutoff_timestamp`, or None if nothing to prune.
pub fn identify_prune_range(
    conn: &Connection,
    cutoff_timestamp: i64,
    min_entries_to_keep: u32,
) -> Result<Option<(i64, i64, i64)>> {
    let has_record_type = conn
        .prepare("SELECT record_type FROM audit_log LIMIT 0")
        .is_ok();

    let total_detection: i64 = if has_record_type {
        conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE record_type = 'detection'",
            [],
            |row| row.get(0),
        )?
    } else {
        conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?
    };

    // Count old detection entries
    let where_clause = if has_record_type {
        "WHERE timestamp < ?1 AND record_type = 'detection'"
    } else {
        "WHERE timestamp < ?1"
    };
    let old_count: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM audit_log {}", where_clause),
        params![cutoff_timestamp],
        |row| row.get(0),
    )?;

    if old_count == 0 {
        return Ok(None);
    }

    // Refuse to prune if it would leave fewer than min_entries_to_keep
    let would_remain = total_detection - old_count;
    if would_remain < min_entries_to_keep as i64 {
        return Ok(None);
    }

    // Get ID range of old detection entries
    let (first_id, last_id): (i64, i64) = conn.query_row(
        &format!("SELECT MIN(id), MAX(id) FROM audit_log {}", where_clause),
        params![cutoff_timestamp],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    Ok(Some((first_id, last_id, old_count)))
}

/// Read detection entries in the given ID range, ordered by ID ascending.
/// Used by the retention sweep to compute the pruned-range HMAC.
pub fn read_detection_range(
    conn: &Connection,
    first_id: i64,
    last_id: i64,
) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, timestamp, path, changes_json, severity,
                monitored_group, process_json, package,
                maintenance, suppressed, hmac, chain_hash
         FROM audit_log
         WHERE id >= ?1 AND id <= ?2 AND (record_type = 'detection' OR record_type IS NULL)
         ORDER BY id ASC",
    )?;

    let rows = stmt.query_map(params![first_id, last_id], |row| {
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

/// Get the chain_hash of the entry immediately before `first_id`.
/// Returns the genesis hash if there is no preceding entry.
pub fn get_previous_chain_hash(conn: &Connection, first_id: i64) -> Result<String> {
    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();
    let prev = conn
        .query_row(
            "SELECT chain_hash FROM audit_log WHERE id < ?1 ORDER BY id DESC LIMIT 1",
            params![first_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or(genesis);
    Ok(prev)
}

/// Get the audit DB file size in bytes.
pub fn db_file_size(conn: &Connection) -> Result<u64> {
    let page_count: u64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let page_size: u64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    Ok(page_count * page_size)
}
