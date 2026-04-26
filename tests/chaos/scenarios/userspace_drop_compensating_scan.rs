// tests/chaos/scenarios/userspace_drop_compensating_scan.rs
// Scenario: VIGIL-VULN-075 -- User-space event drops trigger compensating scan.
//
// The original failure mode: when the user-space event channel saturated due
// to a wedged worker pool, events were dropped and logged but no compensating
// full scan was triggered, unlike the FAN_Q_OVERFLOW kernel-overflow path.
// This created a silent blind spot exactly when the daemon was most degraded.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use vigil::coordinator::{self, CoordinatorConfig};
use vigil::db::{self, DbFileIdentity};
use vigil::metrics::Metrics;
use vigil::types::{DaemonState, DegradedReason};
use vigil::watch_index::WatchGroupIndex;

use crate::chaos_common::*;

/// When user-space drops exceed the sliding-window threshold, the coordinator
/// must enter Degraded { UserspaceEventDrops } and trigger a compensating
/// full scan via the scan_trigger channel.
#[test]
fn worker_wedged_triggers_compensating_scan() {
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");

    let baseline_conn = db::open_db_at(&baseline_path, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn).unwrap();
    baseline_conn
        .execute(
            "INSERT OR REPLACE INTO config_state (key, value, updated_at) \
             VALUES ('baseline_initialized', '1', 0)",
            [],
        )
        .unwrap();
    let audit_conn = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&audit_conn).unwrap();

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o600));

    let mut cfg = chaos_config(dir.path());
    cfg.daemon.db_path = baseline_path.clone();
    // Set per-tick threshold high so VIGIL-VULN-072 (EventLossDetected)
    // doesn't fire before the VIGIL-VULN-075 sliding window catches it.
    cfg.monitor.event_loss_alert_threshold = Some(1000);
    // Low sliding-window threshold so we can trigger quickly in test
    cfg.monitor.userspace_drop_threshold = 10;
    cfg.monitor.userspace_drop_window_secs = 60;

    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let metrics = Arc::new(Metrics::new());
    let state: Arc<RwLock<DaemonState>> = Arc::new(RwLock::new(DaemonState::Healthy));
    let watch_index = Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
        &config.load(),
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    let backpressure = Arc::new(AtomicBool::new(false));

    // Create scan trigger channel to catch the compensating scan request
    let (scan_tx, scan_rx) = crossbeam_channel::bounded::<vigil::control::ScanRequest>(4);

    let coord_cfg = CoordinatorConfig {
        config: config.clone(),
        metrics: metrics.clone(),
        state: state.clone(),
        watch_index,
        shutdown: shutdown.clone(),
        reload_flag: reload,
        backpressure,
        baseline_db_identity: DbFileIdentity::from_path(&baseline_path).ok(),
        audit_db_identity: DbFileIdentity::from_path(&audit_path).ok(),
        startup_hmac_key: None,
        startup_baseline_conn: baseline_conn,
        startup_audit_conn: audit_conn,
        reconfigure_tx: None,
        mount_mark_tx: None,
        wal_identity: None,
        wal_path: None,
        maintenance_active: Arc::new(AtomicBool::new(false)),
        maintenance_entered_at: Arc::new(AtomicI64::new(0)),
        shared_baseline_identity: None,
        scan_trigger: Some(scan_tx),
    };

    let handle = coordinator::spawn(coord_cfg).unwrap();

    // Simulate user-space drops by bumping the events_dropped metric
    // above the threshold. The coordinator's maintenance tick runs on
    // a 60-second cadence, but the first tick fires immediately.
    metrics.events_dropped.fetch_add(20, Ordering::Relaxed);

    // Wait for the first maintenance tick to fire (it triggers immediately
    // because last_tick is initialized to now - 60s).
    std::thread::sleep(Duration::from_millis(3000));

    // (a) Verify daemon entered Degraded { UserspaceEventDrops }
    {
        let current = state.read();
        match &*current {
            DaemonState::Degraded { reason, .. } => {
                assert!(
                    matches!(reason, DegradedReason::UserspaceEventDrops { .. }),
                    "expected UserspaceEventDrops, got {:?}",
                    reason,
                );
            }
            DaemonState::Healthy => {
                panic!("daemon should be Degraded after user-space drops exceed threshold");
            }
        }
    }

    // (b) Verify a Full scan was triggered
    let scan_req = scan_rx.try_recv();
    assert!(
        scan_req.is_ok(),
        "expected compensating scan request on the scan_trigger channel"
    );
    assert_eq!(
        format!("{:?}", scan_req.unwrap().mode),
        "Full",
        "compensating scan should be Full mode"
    );

    // (c) Verify metric incremented
    assert_eq!(
        metrics
            .userspace_drop_scans_triggered
            .load(Ordering::Relaxed),
        1,
        "userspace_drop_scans_triggered should be exactly 1"
    );

    shutdown.store(true, Ordering::Release);
    let _ = handle.join();
}

/// After the wedged condition resolves (no further drops), the daemon
/// state transitions back to Healthy via the coordinator's recovery path.
/// This test verifies the state model: DaemonStateHandle can recover from
/// UserspaceEventDrops when no further drops occur.
#[test]
fn userspace_drops_recover_to_healthy() {
    use vigil::types::DaemonStateHandle;

    let handle = DaemonStateHandle::new();

    // Enter degraded state
    let degraded = handle.degrade_if_healthy(DegradedReason::UserspaceEventDrops {
        dropped: 100,
        window_secs: 60,
    });
    assert!(degraded, "should transition to Degraded");

    // Verify state is degraded
    {
        let s = handle.read();
        assert!(
            matches!(&*s, DaemonState::Degraded { reason, .. }
                if matches!(reason, DegradedReason::UserspaceEventDrops { .. })
            ),
            "expected UserspaceEventDrops degraded state"
        );
    }

    // Recovery via recover_if_degraded_for
    let recovered =
        handle.recover_if_degraded_for(|r| matches!(r, DegradedReason::UserspaceEventDrops { .. }));
    assert!(recovered, "should recover to Healthy");

    // Verify state is healthy
    {
        let s = handle.read();
        assert!(
            matches!(*s, DaemonState::Healthy),
            "daemon should be Healthy after recovery"
        );
    }

    // Recovery should not fire for wrong reason
    let degraded = handle.degrade_if_healthy(DegradedReason::UserspaceEventDrops {
        dropped: 50,
        window_secs: 30,
    });
    assert!(degraded);

    let not_recovered =
        handle.recover_if_degraded_for(|r| matches!(r, DegradedReason::EventLossDetected { .. }));
    assert!(!not_recovered, "should not recover for wrong reason");
}
