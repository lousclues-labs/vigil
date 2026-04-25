//! Acknowledgment model for doctor historical events.
//!
//! This module is a backward-compatibility shim. The canonical locations are:
//! - Types: `crate::doctor::acknowledgment::types`
//! - SQL queries: `crate::db::audit_ack`
//!
//! New code should import from the canonical locations directly.

// Re-export domain types from their canonical home.
pub use crate::doctor::acknowledgment::types::{
    build_operator_payload, compute_aging_state, effective_uid, AcknowledgmentCache,
    AcknowledgmentKind, AcknowledgmentPayload, AcknowledgmentState, AgingState, DoctorEventKind,
    EventReference,
};

// Re-export SQL queries from their canonical home.
pub use crate::db::audit_ack::{
    build_cache_from_audit_log, find_most_recent_unacknowledged, find_unacknowledged_events,
    list_recent_acknowledgments,
};
