//! Unit tests for `ControlHandler::handle_recover` and the
//! `"recover"` control socket method (1.11.4 fix).
//!
//! Extracted from `src/control.rs` to keep that file under the
//! 1500-line architectural invariant. Mounted from `control.rs` via
//! `#[path = "control_recover_tests.rs"]`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use super::{ControlHandler, ScanRequest};
use crate::metrics::Metrics;
use crate::types::{DaemonState, DegradedReason};

fn make_handler_with_state(state: Arc<RwLock<DaemonState>>) -> ControlHandler {
    let (scan_tx, _scan_rx) = crossbeam_channel::bounded::<ScanRequest>(1);
    ControlHandler {
        metrics: Arc::new(Metrics::new()),
        state,
        reload_flag: Arc::new(AtomicBool::new(false)),
        scan_trigger_tx: scan_tx,
        baseline_db_path: PathBuf::from("/dev/null"),
        baseline_conn: Arc::new(Mutex::new({
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            crate::db::schema::create_baseline_tables(&conn).unwrap();
            conn
        })),
        config: Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::config::default_config(),
        )),
        hmac_key: None,
        auth_enabled: false,
        maintenance_active: Arc::new(AtomicBool::new(false)),
        maintenance_entered_at: Arc::new(AtomicI64::new(0)),
        control_unauthenticated_connections: Arc::new(AtomicU64::new(0)),
        wal: None,
        shared_baseline_identity: None,
        baseline_generation: Arc::new(AtomicU64::new(0)),
        expectation_registry: None,
    }
}

#[test]
fn recover_clears_matching_degraded_state() {
    let state = Arc::new(RwLock::new(DaemonState::Degraded {
        reason: DegradedReason::ClockSkewDetected { skew_secs: 121 },
        since: chrono::Utc::now(),
    }));
    let handler = make_handler_with_state(state.clone());

    let resp = handler.dispatch(
        "recover",
        &serde_json::json!({"method": "recover", "reason": "clock_skew_detected"}),
    );
    assert_eq!(resp["ok"], true, "response: {}", resp);
    assert_eq!(resp["state"], "healthy");
    assert!(matches!(*state.read(), DaemonState::Healthy));
}

#[test]
fn recover_refuses_mismatched_reason() {
    let state = Arc::new(RwLock::new(DaemonState::Degraded {
        reason: DegradedReason::ClockSkewDetected { skew_secs: 121 },
        since: chrono::Utc::now(),
    }));
    let handler = make_handler_with_state(state.clone());

    let resp = handler.dispatch(
        "recover",
        &serde_json::json!({"method": "recover", "reason": "baseline_db_replaced"}),
    );
    assert_eq!(resp["ok"], false);
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("clock_skew_detected"));
    assert!(matches!(*state.read(), DaemonState::Degraded { .. }));
}

#[test]
fn recover_when_healthy_is_idempotent() {
    let state = Arc::new(RwLock::new(DaemonState::Healthy));
    let handler = make_handler_with_state(state);

    let resp = handler.dispatch(
        "recover",
        &serde_json::json!({"method": "recover", "reason": "clock_skew_detected"}),
    );
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["state"], "healthy");
}

#[test]
fn recover_rejects_unknown_reason() {
    let handler = make_handler_with_state(Arc::new(RwLock::new(DaemonState::Healthy)));
    let resp = handler.dispatch(
        "recover",
        &serde_json::json!({"method": "recover", "reason": "not_a_real_reason"}),
    );
    assert_eq!(resp["ok"], false);
    assert!(resp["error"].as_str().unwrap().contains("unknown"));
}

#[test]
fn recover_requires_reason_parameter() {
    let handler = make_handler_with_state(Arc::new(RwLock::new(DaemonState::Healthy)));
    let resp = handler.dispatch("recover", &serde_json::json!({"method": "recover"}));
    assert_eq!(resp["ok"], false);
    assert!(resp["error"].as_str().unwrap().contains("reason"));
}
