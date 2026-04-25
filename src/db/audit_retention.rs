//! Audit retention, checkpoint, and specialized entry operations.
//!
//! Segments, checkpoints, pruning, and insert helpers for acknowledgment,
//! doctor event, and hooks operation records.

use chrono::Utc;
use rusqlite::{params, Connection};

use super::audit_ops::{compute_chain_hash, AuditEntry};
use crate::db::audit_path::AuditEventPath;
use crate::error::Result;

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
            AuditEventPath::checkpoint_path(first_sequence, last_sequence),
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

/// Insert an operator acknowledgment record into the audit chain.
///
/// Returns `(new_chain_hash, new_sequence)`.
pub fn insert_acknowledgment_entry(
    conn: &Connection,
    payload_json: &str,
    previous_chain_hash: &str,
    hmac_key: Option<&[u8]>,
) -> Result<(String, i64)> {
    let timestamp = Utc::now().timestamp();
    let path = AuditEventPath::OperatorAcknowledgment.as_str();
    let severity = "info";

    let chain_hash =
        compute_chain_hash(previous_chain_hash, timestamp, path, payload_json, severity);

    let hmac = hmac_key.map(|key| {
        let data = crate::hmac::build_audit_hmac_data(
            timestamp,
            path,
            "operator_acknowledgment",
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

    let seq = conn.last_insert_rowid();
    Ok((chain_hash, seq))
}

/// Insert a doctor event record into the audit chain.
///
/// Used to record historical events (hook failures, chain breaks, etc.)
/// so they can be referenced by acknowledgments.
/// Returns `(new_chain_hash, new_sequence)`.
pub fn insert_doctor_event_entry(
    conn: &Connection,
    event_path: &str,
    payload_json: &str,
    previous_chain_hash: &str,
    hmac_key: Option<&[u8]>,
) -> Result<(String, i64)> {
    let timestamp = Utc::now().timestamp();
    let severity = "warning";

    let chain_hash = compute_chain_hash(
        previous_chain_hash,
        timestamp,
        event_path,
        payload_json,
        severity,
    );

    let hmac = hmac_key.map(|key| {
        let data = crate::hmac::build_audit_hmac_data(
            timestamp,
            event_path,
            "doctor_event",
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
        event_path,
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

    let seq = conn.last_insert_rowid();
    Ok((chain_hash, seq))
}

/// Insert a hooks-disable/enable operational record into the audit chain.
pub fn insert_hooks_operation_entry(
    conn: &Connection,
    operation: &str,
    payload_json: &str,
    previous_chain_hash: &str,
    hmac_key: Option<&[u8]>,
) -> Result<(String, i64)> {
    let timestamp = Utc::now().timestamp();
    let event_path = match operation {
        "disable" => AuditEventPath::HooksDisable,
        "enable" => AuditEventPath::HooksEnable,
        _ => AuditEventPath::HooksEnable, // fallback for unknown operations
    };
    let path = event_path.as_str();
    let severity = "info";

    let chain_hash =
        compute_chain_hash(previous_chain_hash, timestamp, path, payload_json, severity);

    let hmac = hmac_key.map(|key| {
        let data = crate::hmac::build_audit_hmac_data(
            timestamp,
            path,
            &format!("hooks_{}", operation),
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

    let seq = conn.last_insert_rowid();
    Ok((chain_hash, seq))
}
