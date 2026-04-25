//! Acknowledgment model for doctor historical events.
//!
//! Operators acknowledge specific events to add context (who saw it,
//! when, optional note). Acknowledgments are first-class audit records;
//! they never hide events from doctor. See Principles V.b and V.c.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Categories of historical events surfaced by doctor.
///
/// Each variant maps to a doctor row that reports "last X happened at T."
/// Extending this enum automatically requires the new row to support
/// acknowledgment (Principle V.b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorEventKind {
    /// A hook invocation that exited with failure status.
    HookInvocationFailure,
    /// A baseline-refresh failure.
    BaselineRefreshFailure,
    /// An audit chain integrity check that failed.
    AuditChainBreak,
    /// A retention sweep that failed.
    RetentionSweepFailure,
    /// A daemon transition into a degraded state.
    DaemonDegraded,
}

impl DoctorEventKind {
    /// CLI-facing name for this event kind.
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::HookInvocationFailure => "hooks",
            Self::BaselineRefreshFailure => "baseline-refresh",
            Self::AuditChainBreak => "chain-break",
            Self::RetentionSweepFailure => "retention",
            Self::DaemonDegraded => "degraded",
        }
    }

    /// Parse a CLI-facing kind string into a DoctorEventKind.
    pub fn from_cli_name(name: &str) -> Option<Self> {
        match name {
            "hooks" => Some(Self::HookInvocationFailure),
            "baseline-refresh" => Some(Self::BaselineRefreshFailure),
            "chain-break" => Some(Self::AuditChainBreak),
            "retention" => Some(Self::RetentionSweepFailure),
            "degraded" => Some(Self::DaemonDegraded),
            _ => None,
        }
    }

    /// All known event kinds, for enumeration in help text.
    pub fn all() -> &'static [Self] {
        &[
            Self::HookInvocationFailure,
            Self::BaselineRefreshFailure,
            Self::AuditChainBreak,
            Self::RetentionSweepFailure,
            Self::DaemonDegraded,
        ]
    }

    /// Human-readable description of this event kind.
    pub fn description(self) -> &'static str {
        match self {
            Self::HookInvocationFailure => "hook invocation failure",
            Self::BaselineRefreshFailure => "baseline refresh failure",
            Self::AuditChainBreak => "audit chain break",
            Self::RetentionSweepFailure => "retention sweep failure",
            Self::DaemonDegraded => "daemon degraded transition",
        }
    }

    /// Whether acknowledgment fully de-escalates the marker from ⚠ to ○.
    ///
    /// Most events de-escalate. Chain breaks are the exception: they
    /// represent ongoing data integrity concerns, so acknowledgment adds
    /// context but the marker remains ⚠.
    pub fn ack_deescalates(self) -> bool {
        !matches!(self, Self::AuditChainBreak)
    }

    /// The disable path for this event kind, if one exists.
    ///
    /// Returns `Some("vigil <command>")` for event kinds that the operator
    /// can meaningfully disable at the integration layer. Returns `None`
    /// for core operations that cannot be disabled.
    pub fn disable_path(self) -> Option<&'static str> {
        match self {
            Self::HookInvocationFailure => Some("vigil hooks disable"),
            Self::BaselineRefreshFailure => None, // baseline refresh is core
            Self::AuditChainBreak => None,        // audit chain is core
            Self::RetentionSweepFailure => None, // configurable via retention_check_interval = "never" but not a command
            Self::DaemonDegraded => None,         // degradation is recovered, not disabled
        }
    }
}

impl fmt::Display for DoctorEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// Whether an acknowledgment is an ack or a revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgmentKind {
    Acknowledge,
    Revoke,
}

/// A reference to a specific event in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventReference {
    pub event_kind: DoctorEventKind,
    pub event_sequence: i64,
}

/// Full acknowledgment record payload, stored in the audit log's
/// `changes_json` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgmentPayload {
    pub event_kind: DoctorEventKind,
    pub event_sequence: i64,
    pub acknowledgment_kind: AcknowledgmentKind,
    pub note: Option<String>,
    pub operator_uid: u32,
    pub operator_pid: u32,
    pub operator_exe: String,
}

/// The computed state of an acknowledgment for a specific event.
#[derive(Debug, Clone)]
pub struct AcknowledgmentState {
    /// Sequence number of the ack record in the audit log.
    pub ack_sequence: i64,
    /// Timestamp of the acknowledgment.
    pub ack_timestamp: i64,
    /// UID of the operator who acknowledged.
    pub operator_uid: u32,
    /// Optional note attached to the acknowledgment.
    pub note: Option<String>,
}

/// In-memory cache of acknowledgment state, indexed by event reference.
///
/// Populated from a single audit-log scan. Rebuildable from the log if
/// the cache diverges. When unreadable, doctor falls back to treating
/// all events as unacknowledged (fail-open per Principle X).
#[derive(Debug, Default)]
pub struct AcknowledgmentCache {
    /// Maps (event_kind, event_sequence) → current ack state (if any).
    /// An entry is present only if the most recent ack/revoke for this
    /// event is an `Acknowledge`. Revocations remove the entry.
    states: HashMap<EventReference, AcknowledgmentState>,
}

impl AcknowledgmentCache {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Record an acknowledgment. Overwrites any prior state for this event.
    pub fn insert(&mut self, event_ref: EventReference, state: AcknowledgmentState) {
        self.states.insert(event_ref, state);
    }

    /// Remove an acknowledgment (revocation).
    pub fn remove(&mut self, event_ref: &EventReference) {
        self.states.remove(event_ref);
    }

    /// Look up the acknowledgment state for a specific event.
    pub fn get(&self, event_ref: &EventReference) -> Option<&AcknowledgmentState> {
        self.states.get(event_ref)
    }

    /// Check whether the most recent event of a given kind is acknowledged.
    ///
    /// `event_sequence` is the sequence number of the event to check.
    /// Returns the ack state if a matching acknowledgment exists.
    pub fn is_event_acknowledged(
        &self,
        kind: DoctorEventKind,
        event_sequence: i64,
    ) -> Option<&AcknowledgmentState> {
        let event_ref = EventReference {
            event_kind: kind,
            event_sequence,
        };
        self.get(&event_ref)
    }

    /// Number of cached acknowledgment states.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

/// Aging state for a historical event relative to the current time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgingState {
    /// Event is recent (< warn_window). Renders at natural severity.
    Fresh,
    /// Event is aging (>= warn_window, < hide_window). Renders as informational (○).
    Aging,
    /// Event is historical (>= hide_window). Hidden from doctor.
    Historical,
}

/// Compute aging state for an event.
///
/// `event_ts` is the Unix timestamp of the event.
/// `now` is the current Unix timestamp.
/// `warn_window_secs` and `hide_window_secs` are the aging thresholds.
pub fn compute_aging_state(
    event_ts: i64,
    now: i64,
    warn_window_secs: i64,
    hide_window_secs: i64,
) -> AgingState {
    let age = now.saturating_sub(event_ts);
    if age >= hide_window_secs {
        AgingState::Historical
    } else if age >= warn_window_secs {
        AgingState::Aging
    } else {
        AgingState::Fresh
    }
}

/// Build acknowledgment payload for the current operator.
pub fn build_operator_payload(
    kind: DoctorEventKind,
    event_sequence: i64,
    ack_kind: AcknowledgmentKind,
    note: Option<String>,
) -> AcknowledgmentPayload {
    let uid = effective_uid();
    let pid = std::process::id();
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    AcknowledgmentPayload {
        event_kind: kind,
        event_sequence,
        acknowledgment_kind: ack_kind,
        note,
        operator_uid: uid,
        operator_pid: pid,
        operator_exe: exe,
    }
}

fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Populate an AcknowledgmentCache from audit log entries.
///
/// Scans the audit log for all `vigil:operator_acknowledgment` records
/// and builds the cache. If the scan fails, returns an empty cache
/// (fail-open per Principle X).
pub fn build_cache_from_audit_log(
    conn: &rusqlite::Connection,
) -> AcknowledgmentCache {
    let mut cache = AcknowledgmentCache::new();

    let result = conn.prepare(
        "SELECT id, timestamp, changes_json FROM audit_log \
         WHERE path = 'vigil:operator_acknowledgment' \
         ORDER BY id ASC",
    );

    let mut stmt = match result {
        Ok(s) => s,
        Err(_) => return cache, // fail-open
    };

    let rows = match stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    }) {
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
///
/// Returns a list of (sequence, timestamp, description) for events
/// that have no corresponding Acknowledge record (or whose ack was revoked).
pub fn find_unacknowledged_events(
    conn: &rusqlite::Connection,
    kind: DoctorEventKind,
    cache: &AcknowledgmentCache,
) -> Vec<(i64, i64, String)> {
    let path_prefix = match kind {
        DoctorEventKind::HookInvocationFailure => "vigil:hook_failure",
        DoctorEventKind::BaselineRefreshFailure => "vigil:baseline_refresh_failure",
        DoctorEventKind::AuditChainBreak => "vigil:audit_chain_break",
        DoctorEventKind::RetentionSweepFailure => "vigil:retention_sweep_failure",
        DoctorEventKind::DaemonDegraded => "vigil:daemon_degraded",
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
            // Extract a human-readable description from the payload
            let desc = serde_json::from_str::<serde_json::Value>(&json)
                .ok()
                .and_then(|v| v.get("description").and_then(|d| d.as_str().map(String::from)))
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
    find_unacknowledged_events(conn, kind, cache).into_iter().next()
}

/// List recent acknowledgment records.
pub fn list_recent_acknowledgments(
    conn: &rusqlite::Connection,
    limit: u32,
) -> Vec<(i64, i64, AcknowledgmentPayload)> {
    let result = conn.prepare(
        "SELECT id, timestamp, changes_json FROM audit_log \
         WHERE path = 'vigil:operator_acknowledgment' \
         ORDER BY id DESC LIMIT ?1",
    );

    let mut stmt = match result {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map(rusqlite::params![limit], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    }) {
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
