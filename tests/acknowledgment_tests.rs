//! Integration tests for doctor acknowledgment primitives and invariants.

use clap::Parser;
use rusqlite::Connection;
use vigil::ack::{
    self, AcknowledgmentKind, AcknowledgmentPayload, AcknowledgmentState, AgingState,
    DoctorEventKind, EventReference,
};
use vigil::cli::Cli;

fn test_audit_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    vigil::db::schema::create_audit_tables(&conn).unwrap();
    conn
}

fn genesis_hash() -> String {
    blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string()
}

#[test]
fn ack_writes_audit_record_with_invocation_context() {
    let conn = test_audit_conn();
    let payload = ack::build_operator_payload(
        DoctorEventKind::HookInvocationFailure,
        42,
        AcknowledgmentKind::Acknowledge,
        Some("manual test".to_string()),
    );
    let payload_json = serde_json::to_string(&payload).unwrap();

    let (_hash, seq) = vigil::db::audit_ops::insert_acknowledgment_entry(
        &conn,
        &payload_json,
        &genesis_hash(),
        None,
    )
    .unwrap();

    let (path, json) = conn
        .query_row(
            "SELECT path, changes_json FROM audit_log WHERE id = ?1",
            rusqlite::params![seq],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();

    assert_eq!(path, "vigil:operator_acknowledgment");

    let parsed: AcknowledgmentPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed.event_kind,
        DoctorEventKind::HookInvocationFailure,
        "event kind should round-trip"
    );
    assert_eq!(parsed.event_sequence, 42);
    assert_eq!(parsed.acknowledgment_kind, AcknowledgmentKind::Acknowledge);
    assert_eq!(parsed.note.as_deref(), Some("manual test"));
    assert!(parsed.operator_pid > 0);
    assert!(!parsed.operator_exe.is_empty());
}

#[test]
fn ack_records_appear_in_chain_with_correct_previous_hash() {
    let conn = test_audit_conn();

    let payload = ack::build_operator_payload(
        DoctorEventKind::HookInvocationFailure,
        100,
        AcknowledgmentKind::Acknowledge,
        None,
    );
    let payload_json = serde_json::to_string(&payload).unwrap();
    let prev = genesis_hash();

    let (chain_hash, seq) =
        vigil::db::audit_ops::insert_acknowledgment_entry(&conn, &payload_json, &prev, None)
            .unwrap();

    let ts = conn
        .query_row(
            "SELECT timestamp FROM audit_log WHERE id = ?1",
            rusqlite::params![seq],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();

    let expected = vigil::db::audit_ops::compute_chain_hash(
        &prev,
        ts,
        "vigil:operator_acknowledgment",
        &payload_json,
        "info",
    );

    assert_eq!(chain_hash, expected);
}

#[test]
fn ack_kind_acknowledge_distinct_from_revoke() {
    assert_ne!(AcknowledgmentKind::Acknowledge, AcknowledgmentKind::Revoke);

    let ack_json = serde_json::to_string(&AcknowledgmentKind::Acknowledge).unwrap();
    let revoke_json = serde_json::to_string(&AcknowledgmentKind::Revoke).unwrap();
    assert_ne!(ack_json, revoke_json);
}

#[test]
fn event_recurrence_after_ack_warns_afresh() {
    let mut cache = ack::AcknowledgmentCache::new();
    cache.insert(
        EventReference {
            event_kind: DoctorEventKind::HookInvocationFailure,
            event_sequence: 10,
        },
        AcknowledgmentState {
            ack_sequence: 11,
            ack_timestamp: 1000,
            operator_uid: 1000,
            note: Some("seen".to_string()),
        },
    );

    assert!(
        cache
            .is_event_acknowledged(DoctorEventKind::HookInvocationFailure, 10)
            .is_some(),
        "event T1 should be acknowledged"
    );
    assert!(
        cache
            .is_event_acknowledged(DoctorEventKind::HookInvocationFailure, 12)
            .is_none(),
        "event T3 should not be acknowledged by T1 ack"
    );
}

#[test]
fn ack_does_not_silence_future_events_of_same_kind() {
    let mut cache = ack::AcknowledgmentCache::new();
    cache.insert(
        EventReference {
            event_kind: DoctorEventKind::RetentionSweepFailure,
            event_sequence: 50,
        },
        AcknowledgmentState {
            ack_sequence: 60,
            ack_timestamp: 1000,
            operator_uid: 0,
            note: None,
        },
    );

    assert!(cache
        .is_event_acknowledged(DoctorEventKind::RetentionSweepFailure, 51)
        .is_none());
}

#[test]
fn event_at_t1_acked_event_at_t0_does_not_silence_t1() {
    let mut cache = ack::AcknowledgmentCache::new();
    cache.insert(
        EventReference {
            event_kind: DoctorEventKind::DaemonDegraded,
            event_sequence: 200,
        },
        AcknowledgmentState {
            ack_sequence: 300,
            ack_timestamp: 2000,
            operator_uid: 1000,
            note: None,
        },
    );

    assert!(cache
        .is_event_acknowledged(DoctorEventKind::DaemonDegraded, 201)
        .is_none());
}

#[test]
fn event_within_warn_window_renders_at_natural_severity() {
    let state = ack::compute_aging_state(1000, 1100, 7 * 86400, 90 * 86400);
    assert_eq!(state, AgingState::Fresh);
}

#[test]
fn event_within_inform_window_renders_as_informational() {
    let now = 100 * 86400;
    let event_ts = now - (10 * 86400);
    let state = ack::compute_aging_state(event_ts, now, 7 * 86400, 90 * 86400);
    assert_eq!(state, AgingState::Aging);
}

#[test]
fn event_beyond_hide_window_omitted_from_doctor() {
    let now = 200 * 86400;
    let event_ts = now - (120 * 86400);
    let state = ack::compute_aging_state(event_ts, now, 7 * 86400, 90 * 86400);
    assert_eq!(state, AgingState::Historical);
}

#[test]
fn no_cli_flag_exists_to_blanket_suppress_a_category() {
    let bad = ["--suppress", "--silent", "--ignore", "--blanket"];
    for flag in bad {
        let parse = Cli::try_parse_from(["vigil", "ack", "hooks", flag]);
        assert!(parse.is_err(), "forbidden flag was accepted: {}", flag);
    }
}

#[test]
fn corrupted_acknowledgment_cache_falls_back_to_empty() {
    // No schema at all simulates unreadable/unexpected storage shape.
    let conn = Connection::open_in_memory().unwrap();
    let cache = ack::build_cache_from_audit_log(&conn);
    assert!(cache.is_empty(), "cache should fail-open to empty");
}

#[test]
fn acknowledgment_records_indexed_for_fast_lookup() {
    let conn = test_audit_conn();
    let idx_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_audit_path_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(idx_exists, 1, "expected idx_audit_path_id index to exist");
}
