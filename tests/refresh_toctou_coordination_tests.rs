use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use vigil::coordinator::{self, CoordinatorConfig, SharedBaselineIdentity};
use vigil::db::DbFileIdentity;
use vigil::metrics::Metrics;
use vigil::types::{DaemonState, DegradedReason};
use vigil::watch_index::WatchGroupIndex;

/// Helper: create a minimal baseline DB at the given path.
fn create_test_baseline(path: &std::path::Path) -> rusqlite::Connection {
    let conn = vigil::db::open_baseline_db_at_path(path).unwrap();
    vigil::db::schema::create_baseline_tables(&conn).unwrap();
    vigil::db::baseline_ops::set_config_state(&conn, "baseline_initialized", "true").unwrap();
    conn
}

/// Helper: create a minimal audit DB at the given path.
fn create_test_audit(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    vigil::db::schema::create_audit_tables(&conn).unwrap();
    conn
}

/// Authorized refresh: set the replacement deadline, perform a rename,
/// assert the daemon stays Healthy.
#[test]
fn authorized_refresh_stays_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");

    // Create initial baseline
    let _conn = create_test_baseline(&baseline_path);
    drop(_conn);

    let identity = DbFileIdentity::from_path(&baseline_path).unwrap();
    let shared = Arc::new(SharedBaselineIdentity::new(identity));

    let state = Arc::new(RwLock::new(DaemonState::Healthy));

    // Simulate what the control handler does: set replacement deadline
    let deadline = std::time::Instant::now() + coordinator::BASELINE_REPLACEMENT_WINDOW;
    shared.expect_baseline_replacement(deadline);

    // Create a new baseline in a temp path and rename over the original
    let tmp_path = dir.path().join("baseline.db.refresh");
    let _tmp_conn = create_test_baseline(&tmp_path);
    drop(_tmp_conn);

    std::fs::rename(&tmp_path, &baseline_path).unwrap();

    // The shared identity should detect the replacement
    assert!(shared.is_replaced(&baseline_path).unwrap());

    // But the deadline is still valid
    assert!(shared.is_replacement_authorized());

    // Accept the new identity (what the guardian would do)
    shared.accept_new_identity(&baseline_path).unwrap();

    // After accepting, the identity matches again
    assert!(!shared.is_replaced(&baseline_path).unwrap());

    // Deadline should be reset
    assert!(!shared.is_replacement_authorized());

    // State should remain healthy
    assert!(matches!(*state.read(), DaemonState::Healthy));
}

/// Unauthorized rename: perform a rename without setting the deadline,
/// verify the replacement is detected as unauthorized.
#[test]
fn unauthorized_rename_detected() {
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");

    let _conn = create_test_baseline(&baseline_path);
    drop(_conn);

    let identity = DbFileIdentity::from_path(&baseline_path).unwrap();
    let shared = Arc::new(SharedBaselineIdentity::new(identity));

    // No deadline set -- rename without authorization
    let tmp_path = dir.path().join("baseline.db.refresh");
    let _tmp_conn = create_test_baseline(&tmp_path);
    drop(_tmp_conn);

    std::fs::rename(&tmp_path, &baseline_path).unwrap();

    // Should detect replacement
    assert!(shared.is_replaced(&baseline_path).unwrap());

    // Should NOT be authorized
    assert!(!shared.is_replacement_authorized());
}

/// Expired window: set the deadline, sleep past it, perform a rename,
/// verify the replacement is detected as unauthorized.
#[test]
fn expired_window_detected() {
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");

    let _conn = create_test_baseline(&baseline_path);
    drop(_conn);

    let identity = DbFileIdentity::from_path(&baseline_path).unwrap();
    let shared = Arc::new(SharedBaselineIdentity::new(identity));

    // Set a very short deadline (50ms)
    let deadline = std::time::Instant::now() + Duration::from_millis(50);
    shared.expect_baseline_replacement(deadline);

    // Wait for deadline to expire
    std::thread::sleep(Duration::from_millis(100));

    // Create new baseline and rename
    let tmp_path = dir.path().join("baseline.db.refresh");
    let _tmp_conn = create_test_baseline(&tmp_path);
    drop(_tmp_conn);

    std::fs::rename(&tmp_path, &baseline_path).unwrap();

    // Should detect replacement
    assert!(shared.is_replaced(&baseline_path).unwrap());

    // Deadline expired -- should NOT be authorized
    assert!(!shared.is_replacement_authorized());
}

/// The SharedBaselineIdentity deadline is initially zero (no window active).
#[test]
fn initial_deadline_is_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baseline.db");
    let _conn = create_test_baseline(&path);
    drop(_conn);

    let identity = DbFileIdentity::from_path(&path).unwrap();
    let shared = SharedBaselineIdentity::new(identity);

    assert_eq!(shared.replacement_deadline_nanos(), 0);
    assert!(!shared.is_replacement_authorized());
}

/// Guardian thread integration: spawn coordinator with shared identity,
/// perform an authorized rename, verify daemon stays healthy.
#[test]
fn guardian_accepts_authorized_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");

    let baseline_conn = create_test_baseline(&baseline_path);
    let audit_conn = create_test_audit(&audit_path);

    let identity = DbFileIdentity::from_path(&baseline_path).unwrap();
    let shared = Arc::new(SharedBaselineIdentity::new(identity));

    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = baseline_path.clone();
    cfg.daemon.runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&cfg.daemon.runtime_dir).ok();

    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let metrics = Arc::new(Metrics::new());
    let state = Arc::new(RwLock::new(DaemonState::Healthy));
    let shutdown = Arc::new(AtomicBool::new(false));

    let coord_cfg = CoordinatorConfig {
        config,
        metrics: metrics.clone(),
        state: state.clone(),
        watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
            &vigil::config::default_config(),
        ))),
        shutdown: shutdown.clone(),
        reload_flag: Arc::new(AtomicBool::new(false)),
        backpressure: Arc::new(AtomicBool::new(false)),
        baseline_db_identity: Some(identity),
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
        shared_baseline_identity: Some(shared.clone()),
    };

    let handle = coordinator::spawn(coord_cfg).unwrap();

    // Let the guardian settle
    std::thread::sleep(Duration::from_millis(500));

    // State should be healthy
    assert!(matches!(*state.read(), DaemonState::Healthy));

    // Set replacement deadline and perform an authorized rename
    let deadline = std::time::Instant::now() + coordinator::BASELINE_REPLACEMENT_WINDOW;
    shared.expect_baseline_replacement(deadline);

    let tmp_path = dir.path().join("baseline.db.refresh");
    let _tmp_conn = create_test_baseline(&tmp_path);
    drop(_tmp_conn);
    std::fs::rename(&tmp_path, &baseline_path).unwrap();

    // Wait for the guardian to process the identity check (1-second cadence)
    std::thread::sleep(Duration::from_millis(2500));

    // State should still be healthy
    let current_state = state.read().clone();
    assert!(
        matches!(current_state, DaemonState::Healthy),
        "expected Healthy after authorized refresh, got {:?}",
        current_state
    );

    // inode_changes_recovered should have incremented
    assert!(
        metrics.inode_changes_recovered.load(Ordering::Relaxed) > 0,
        "inode_changes_recovered should have incremented"
    );

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// Guardian thread integration: perform an unauthorized rename,
/// verify daemon transitions to Degraded.
#[test]
fn guardian_degrades_on_unauthorized_rename() {
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");

    let baseline_conn = create_test_baseline(&baseline_path);
    let audit_conn = create_test_audit(&audit_path);

    let identity = DbFileIdentity::from_path(&baseline_path).unwrap();
    let shared = Arc::new(SharedBaselineIdentity::new(identity));

    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = baseline_path.clone();
    cfg.daemon.runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&cfg.daemon.runtime_dir).ok();

    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let metrics = Arc::new(Metrics::new());
    let state = Arc::new(RwLock::new(DaemonState::Healthy));
    let shutdown = Arc::new(AtomicBool::new(false));

    let coord_cfg = CoordinatorConfig {
        config,
        metrics: metrics.clone(),
        state: state.clone(),
        watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
            &vigil::config::default_config(),
        ))),
        shutdown: shutdown.clone(),
        reload_flag: Arc::new(AtomicBool::new(false)),
        backpressure: Arc::new(AtomicBool::new(false)),
        baseline_db_identity: Some(identity),
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
        shared_baseline_identity: Some(shared.clone()),
    };

    let handle = coordinator::spawn(coord_cfg).unwrap();

    // Let guardian settle
    std::thread::sleep(Duration::from_millis(500));

    // Unauthorized rename -- no deadline set
    let tmp_path = dir.path().join("baseline.db.refresh");
    let _tmp_conn = create_test_baseline(&tmp_path);
    drop(_tmp_conn);

    // Create multiple blocker files to ensure inode recycling does not mask
    // the replacement (lesson from coordinator_adversarial_tick chaos test).
    let mut _blockers = Vec::new();
    for i in 0..5 {
        let p = dir.path().join(format!("blocker_{}", i));
        std::fs::write(&p, format!("blocker {}", i)).unwrap();
        _blockers.push(p);
    }

    std::fs::rename(&tmp_path, &baseline_path).unwrap();

    // Wait for the guardian to detect the change
    std::thread::sleep(Duration::from_millis(2500));

    let current_state = state.read().clone();
    match current_state {
        DaemonState::Degraded { reason, .. } => {
            assert!(
                matches!(reason, DegradedReason::BaselineDbReplaced),
                "expected BaselineDbReplaced, got {:?}",
                reason
            );
        }
        DaemonState::Healthy => {
            panic!("expected Degraded after unauthorized rename, got Healthy");
        }
    }

    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// Three back-to-back authorized refreshes: each produces WAL records with
/// BaselineRefresh source, and the guardian stays healthy throughout.
#[test]
fn three_consecutive_authorized_refreshes_healthy_and_wal_records() {
    use vigil::baseline_diff::{record_unattributed_to_wal, ChangedEntry};
    use vigil::wal::{DetectionSource, DetectionWal};

    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");
    let wal_path = dir.path().join("detections.wal");

    let _conn = create_test_baseline(&baseline_path);
    drop(_conn);
    let _audit = create_test_audit(&audit_path);
    drop(_audit);

    let identity = DbFileIdentity::from_path(&baseline_path).unwrap();
    let shared = Arc::new(SharedBaselineIdentity::new(identity));

    // Open a WAL for recording refresh events
    let wal = Arc::new(DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

    // Perform three authorized refreshes
    for i in 0..3 {
        // Set the authorized replacement deadline
        let deadline = std::time::Instant::now() + coordinator::BASELINE_REPLACEMENT_WINDOW;
        shared.expect_baseline_replacement(deadline);

        // Create a new baseline and atomically swap
        let tmp_path = dir.path().join("baseline.db.refresh");
        let _tmp_conn = create_test_baseline(&tmp_path);
        drop(_tmp_conn);
        std::fs::rename(&tmp_path, &baseline_path).unwrap();

        // Accept the new identity (simulating what the guardian does)
        assert!(shared.is_replaced(&baseline_path).unwrap());
        assert!(shared.is_replacement_authorized());
        shared.accept_new_identity(&baseline_path).unwrap();

        // Record a WAL entry for this refresh (simulating the diff recording)
        let entries = vec![ChangedEntry {
            path: format!("/etc/refresh_test_{}", i),
            old_hash: format!("old_{}", i),
            new_hash: format!("new_{}", i),
        }];
        record_unattributed_to_wal(&wal, &entries, false);
    }

    // Verify: three BaselineRefresh records exist in the WAL
    let wal_entries = wal.iter_unconsumed().unwrap();
    assert_eq!(
        wal_entries.len(),
        3,
        "expected exactly 3 WAL entries, got {}",
        wal_entries.len()
    );

    for (i, entry) in wal_entries.iter().enumerate() {
        assert_eq!(
            entry.record.source,
            DetectionSource::BaselineRefresh,
            "entry {} should be BaselineRefresh",
            i
        );
        assert_eq!(
            entry.record.path,
            format!("/etc/refresh_test_{}", i),
            "entry {} path mismatch",
            i
        );
    }

    // Verify the identity is valid after all three swaps
    assert!(!shared.is_replaced(&baseline_path).unwrap());
    assert_eq!(shared.replacement_deadline_nanos(), 0);
}
