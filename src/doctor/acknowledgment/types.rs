//! Acknowledgment domain types: event kinds, cache, aging, operator payload.
//!
//! These types are how doctor reads and renders acknowledgment state.
//! SQL queries that populate them live in `db::audit_ack`.

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
    pub fn ack_deescalates(self) -> bool {
        !matches!(self, Self::AuditChainBreak)
    }

    /// The disable path for this event kind, if one exists.
    pub fn disable_path(self) -> Option<&'static str> {
        match self {
            Self::HookInvocationFailure => Some("vigil hooks disable"),
            Self::BaselineRefreshFailure => None,
            Self::AuditChainBreak => None,
            Self::RetentionSweepFailure => None,
            Self::DaemonDegraded => None,
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
    pub ack_sequence: i64,
    pub ack_timestamp: i64,
    pub operator_uid: u32,
    pub note: Option<String>,
}

/// In-memory cache of acknowledgment state, indexed by event reference.
#[derive(Debug, Default)]
pub struct AcknowledgmentCache {
    states: HashMap<EventReference, AcknowledgmentState>,
}

impl AcknowledgmentCache {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    pub fn insert(&mut self, event_ref: EventReference, state: AcknowledgmentState) {
        self.states.insert(event_ref, state);
    }

    pub fn remove(&mut self, event_ref: &EventReference) {
        self.states.remove(event_ref);
    }

    pub fn get(&self, event_ref: &EventReference) -> Option<&AcknowledgmentState> {
        self.states.get(event_ref)
    }

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

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

/// Aging state for a historical event relative to the current time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgingState {
    Fresh,
    Aging,
    Historical,
}

/// Compute aging state for an event.
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

pub fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}
