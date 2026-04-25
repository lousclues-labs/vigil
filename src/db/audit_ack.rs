//! Audit-log queries for the acknowledgment system.
//!
//! SQL operations that populate and query the acknowledgment cache.
//! Domain types live in `doctor::acknowledgment::types`.

use crate::db::audit_path::AuditEventPath;
use crate::doctor::acknowledgment::types::{
    AcknowledgmentCache, AcknowledgmentKind, AcknowledgmentPayload, AcknowledgmentState,
    DoctorEventKind, EventReference,
};

/// Populate an AcknowledgmentCache from audit log entries.
///
/// Scans the audit log for all `vigil:operator_acknowledgment` records
/// and builds the cache. If the scan fails, returns an empty cache
/// (fail-open per Principle X).
pub fn build_cache_from_audit_log(conn: &rusqlite::Connection) -> AcknowledgmentCache {
    let mut cache = AcknowledgmentCache::new();

    let result = conn.prepare(
        "SELECT id, timestamp, changes_json FROM audit_log \
         WHERE path = ?1 \
         ORDER BY id ASC",
    );

    let mut stmt = match result {
        Ok(s) => s,
        Err(_) => return cache, // fail-open
    };

    let rows = match stmt.query_map(
        rusqlite::params![AuditEventPath::OperatorAcknowledgment.as_str()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    ) {
        Ok(r) => r,
        Err(_) => return cache, // fail-open
    };

    for row in rows {
        let (seq, ts, json) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };

        let payload: AcknowledgmentPayload = match serde_json::from_str(&json) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let event_ref = EventReference {
            event_kind: payload.event_kind,
            event_sequence: payload.event_sequence,
        };

        match payload.acknowledgment_kind {
            AcknowledgmentKind::Acknowledge => {
                cache.insert(
                    event_ref,
                    AcknowledgmentState {
                        ack_sequence: seq,
                        ack_timestamp: ts,
                        operator_uid: payload.operator_uid,
                        note: payload.note,
                    },
                );
            }
            AcknowledgmentKind::Revoke => {
                cache.remove(&event_ref);
            }
        }
    }

    cache
}

/// Find unacknowledged events of a given kind in the audit log.
pub fn find_unacknowledged_events(
    conn: &rusqlite::Connection,
    kind: DoctorEventKind,
    cache: &AcknowledgmentCache,
) -> Vec<(i64, i64, String)> {
    let path_prefix = match kind {
        DoctorEventKind::HookInvocationFailure => AuditEventPath::HookFailure.as_str(),
        DoctorEventKind::BaselineRefreshFailure => AuditEventPath::BaselineRefreshFailure.as_str(),
        DoctorEventKind::AuditChainBreak => AuditEventPath::AuditChainBreak.as_str(),
        DoctorEventKind::RetentionSweepFailure => AuditEventPath::RetentionSweepFailure.as_str(),
        DoctorEventKind::DaemonDegraded => AuditEventPath::DaemonDegraded.as_str(),
    };

    let result = conn.prepare(
        "SELECT id, timestamp, changes_json FROM audit_log \
         WHERE path = ?1 \
         ORDER BY id DESC LIMIT 50",
    );

    let mut stmt = match result {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map(rusqlite::params![path_prefix], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut unacked = Vec::new();
    for row in rows {
        let (seq, ts, json) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };

        let event_ref = EventReference {
            event_kind: kind,
            event_sequence: seq,
        };

        if cache.get(&event_ref).is_none() {
            let desc = serde_json::from_str::<serde_json::Value>(&json)
                .ok()
                .and_then(|v| {
                    v.get("description")
                        .and_then(|d| d.as_str().map(String::from))
                })
                .unwrap_or_else(|| kind.description().to_string());
            unacked.push((seq, ts, desc));
        }
    }

    unacked
}

/// Find the most recent unacknowledged event of a given kind.
pub fn find_most_recent_unacknowledged(
    conn: &rusqlite::Connection,
    kind: DoctorEventKind,
    cache: &AcknowledgmentCache,
) -> Option<(i64, i64, String)> {
    find_unacknowledged_events(conn, kind, cache)
        .into_iter()
        .next()
}

/// List recent acknowledgment records.
pub fn list_recent_acknowledgments(
    conn: &rusqlite::Connection,
    limit: u32,
) -> Vec<(i64, i64, AcknowledgmentPayload)> {
    let result = conn.prepare(
        "SELECT id, timestamp, changes_json FROM audit_log \
         WHERE path = ?2 \
         ORDER BY id DESC LIMIT ?1",
    );

    let mut stmt = match result {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map(
        rusqlite::params![limit, AuditEventPath::OperatorAcknowledgment.as_str()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for row in rows {
        let (seq, ts, json) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Ok(payload) = serde_json::from_str::<AcknowledgmentPayload>(&json) {
            out.push((seq, ts, payload));
        }
    }
    out
}
