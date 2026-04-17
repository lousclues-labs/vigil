// tests/chaos/scenarios/coordinator_adversarial_tick.rs
// Scenario 3: Coordinator Adversarial Tick
//
// Goal: Validate coordinator detection and liveness under environmental tampering.
// Strategy: Test DbFileIdentity mechanism directly and coordinator integration.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use vigil::coordinator::{self, CoordinatorConfig};
use vigil::db::{self, DbFileIdentity};
use vigil::metrics::Metrics;
use vigil::types::DaemonState;
use vigil::watch_index::WatchGroupIndex;

use crate::chaos_common::*;
use crate::harness::*;

#[test]
fn coordinator_adversarial_tick() {
    for seed in seed_list() {
        run_coordinator_adversarial(seed);
    }
}

fn run_coordinator_adversarial(seed: u64) {
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "coordinator_adversarial_tick");

    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");
    let wal_path = dir.path().join("detections.wal");
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    // --- Part 1: DbFileIdentity inode-swap detection (unit-level) ---
    engine.set_step(1);
    artifacts.record(1, "Testing DbFileIdentity inode replacement detection");

    // Create and track baseline DB identity.
    {
        let conn = db::open_db_at(&baseline_path, false).unwrap();
        db::schema::create_baseline_tables(&conn).unwrap();
        drop(conn);
    }
    let baseline_identity = DbFileIdentity::from_path(&baseline_path).unwrap();

    // Verify not replaced initially.
    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        !baseline_identity.is_replaced(&baseline_path).unwrap(),
        "Baseline DB falsely detected as replaced before swap",
    );

    // Swap inode: write to a temp path, delete original, create blocker to occupy
    // the freed inode slot, then rename temp over original. This guarantees a
    // different inode even on filesystems that aggressively reuse inode numbers.
    {
        let backup = dir.path().join("baseline_backup.db");
        let blocker = dir.path().join("baseline_blocker");
        std::fs::copy(&baseline_path, &backup).unwrap();
        std::fs::remove_file(&baseline_path).unwrap();
        std::fs::write(&blocker, b"blocker").unwrap(); // occupy freed inode
        std::fs::copy(&backup, &baseline_path).unwrap();
        std::fs::remove_file(&backup).unwrap();
        std::fs::remove_file(&blocker).unwrap();
    }

    // I12: Inode replacement detected.
    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        baseline_identity.is_replaced(&baseline_path).unwrap(),
        "Baseline DB inode swap was not detected by DbFileIdentity",
    );

    // Same test for audit DB.
    engine.set_step(2);
    artifacts.record(2, "Testing audit DB inode replacement detection");
    {
        let conn = db::open_db_at(&audit_path, false).unwrap();
        db::schema::create_audit_tables(&conn).unwrap();
        drop(conn);
    }
    let audit_identity = DbFileIdentity::from_path(&audit_path).unwrap();

    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        !audit_identity.is_replaced(&audit_path).unwrap(),
        "Audit DB falsely detected as replaced",
    );

    {
        let backup = dir.path().join("audit_backup.db");
        let blocker = dir.path().join("audit_blocker");
        std::fs::copy(&audit_path, &backup).unwrap();
        std::fs::remove_file(&audit_path).unwrap();
        std::fs::write(&blocker, b"blocker").unwrap();
        std::fs::copy(&backup, &audit_path).unwrap();
        std::fs::remove_file(&backup).unwrap();
        std::fs::remove_file(&blocker).unwrap();
    }

    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        audit_identity.is_replaced(&audit_path).unwrap(),
        "Audit DB inode swap was not detected by DbFileIdentity",
    );

    // Same test for WAL file.
    engine.set_step(3);
    artifacts.record(3, "Testing WAL inode replacement detection");
    std::fs::write(&wal_path, vec![0u8; 64]).unwrap();
    let wal_identity = DbFileIdentity::from_path(&wal_path).unwrap();

    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        !wal_identity.is_replaced(&wal_path).unwrap(),
        "WAL falsely detected as replaced",
    );

    {
        let backup = dir.path().join("wal_backup.wal");
        let blocker = dir.path().join("wal_blocker");
        std::fs::copy(&wal_path, &backup).unwrap();
        std::fs::remove_file(&wal_path).unwrap();
        std::fs::write(&blocker, b"blocker").unwrap();
        std::fs::copy(&backup, &wal_path).unwrap();
        std::fs::remove_file(&backup).unwrap();
        std::fs::remove_file(&blocker).unwrap();
    }

    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        wal_identity.is_replaced(&wal_path).unwrap(),
        "WAL inode swap was not detected by DbFileIdentity",
    );

    // --- Part 2: Coordinator with pre-swapped inode triggers Degraded ---
    engine.set_step(4);
    artifacts.record(
        4,
        "Testing coordinator Degraded transition on pre-swapped baseline",
    );

    // Re-create fresh DBs for coordinator.
    let baseline_path2 = dir.path().join("baseline2.db");
    let audit_path2 = dir.path().join("audit2.db");
    let wal_path2 = dir.path().join("detections2.wal");

    let baseline_conn = db::open_db_at(&baseline_path2, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn).unwrap();
    let audit_conn = db::open_db_at(&audit_path2, false).unwrap();
    db::schema::create_audit_tables(&audit_conn).unwrap();
    std::fs::write(&wal_path2, vec![0u8; 64]).unwrap();

    // Record identity BEFORE swap.
    let pre_swap_identity = DbFileIdentity::from_path(&baseline_path2).unwrap();

    // Swap the baseline inode BEFORE coordinator starts — the first tick should detect it.
    {
        let backup = dir.path().join("baseline2_backup.db");
        let blocker = dir.path().join("baseline2_blocker");
        std::fs::copy(&baseline_path2, &backup).unwrap();
        std::fs::remove_file(&baseline_path2).unwrap();
        std::fs::write(&blocker, b"blocker").unwrap();
        std::fs::copy(&backup, &baseline_path2).unwrap();
        std::fs::remove_file(&backup).unwrap();
        std::fs::remove_file(&blocker).unwrap();
    }

    let mut cfg = chaos_config(dir.path());
    cfg.daemon.db_path = baseline_path2.clone();
    cfg.daemon.runtime_dir = runtime_dir.clone();

    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let metrics = Arc::new(Metrics::new());
    let state = Arc::new(RwLock::new(DaemonState::Healthy));
    let watch_index = Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
        &config.load(),
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload_flag = Arc::new(AtomicBool::new(false));
    let backpressure = Arc::new(AtomicBool::new(false));

    let coord_cfg = CoordinatorConfig {
        config: config.clone(),
        metrics: metrics.clone(),
        state: state.clone(),
        watch_index: watch_index.clone(),
        shutdown: shutdown.clone(),
        reload_flag: reload_flag.clone(),
        backpressure: backpressure.clone(),
        baseline_db_identity: Some(pre_swap_identity),
        audit_db_identity: DbFileIdentity::from_path(&audit_path2).ok(),
        startup_hmac_key: None,
        startup_baseline_conn: baseline_conn,
        startup_audit_conn: audit_conn,
        reconfigure_tx: None,
        mount_mark_tx: None,
        wal_identity: DbFileIdentity::from_path(&wal_path2).ok(),
        wal_path: Some(wal_path2.clone()),
        maintenance_active: Arc::new(AtomicBool::new(false)),
        maintenance_entered_at: Arc::new(std::sync::atomic::AtomicI64::new(0)),
    };

    // Coordinator's first tick runs immediately (last_tick initialized to now - 60s).
    let handle = coordinator::spawn(coord_cfg).unwrap();

    // Wait for the first tick to complete.
    std::thread::sleep(Duration::from_millis(2000));

    {
        let current_state = state.read();
        let is_degraded = matches!(&*current_state, DaemonState::Degraded { .. });
        engine.check(
            InvariantId::I12CoordinatorDegradedOnInodeChange,
            is_degraded,
            "Coordinator did not transition to Degraded after baseline inode swap",
        );
    }

    // Coordinator should not have panicked.
    shutdown.store(true, Ordering::Release);
    let join_result = handle.join();
    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        join_result.is_ok(),
        "Coordinator panicked during adversarial testing",
    );

    // --- Part 3: Verify coordinator does not panic under rapid state transitions ---
    engine.set_step(5);
    artifacts.record(5, "Verifying coordinator survives rapid state changes");

    let baseline_path3 = dir.path().join("baseline3.db");
    let audit_path3 = dir.path().join("audit3.db");
    let baseline_conn3 = db::open_db_at(&baseline_path3, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn3).unwrap();
    let audit_conn3 = db::open_db_at(&audit_path3, false).unwrap();
    db::schema::create_audit_tables(&audit_conn3).unwrap();

    let mut cfg3 = chaos_config(dir.path());
    cfg3.daemon.db_path = baseline_path3.clone();
    cfg3.daemon.runtime_dir = runtime_dir.clone();

    let config3 = Arc::new(ArcSwap::from_pointee(cfg3));
    let state3 = Arc::new(RwLock::new(DaemonState::Healthy));
    let shutdown3 = Arc::new(AtomicBool::new(false));
    let reload3 = Arc::new(AtomicBool::new(false));
    let bp3 = Arc::new(AtomicBool::new(false));

    let coord_cfg3 = CoordinatorConfig {
        config: config3,
        metrics: Arc::new(Metrics::new()),
        state: state3.clone(),
        watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
            &vigil::config::default_config(),
        ))),
        shutdown: shutdown3.clone(),
        reload_flag: reload3.clone(),
        backpressure: bp3,
        baseline_db_identity: DbFileIdentity::from_path(&baseline_path3).ok(),
        audit_db_identity: DbFileIdentity::from_path(&audit_path3).ok(),
        startup_hmac_key: None,
        startup_baseline_conn: baseline_conn3,
        startup_audit_conn: audit_conn3,
        reconfigure_tx: None,
        mount_mark_tx: None,
        wal_identity: None,
        wal_path: None,
        maintenance_active: Arc::new(AtomicBool::new(false)),
        maintenance_entered_at: Arc::new(std::sync::atomic::AtomicI64::new(0)),
    };

    let handle3 = coordinator::spawn(coord_cfg3).unwrap();

    // Rapidly toggle state and trigger reloads.
    for _ in 0..20 {
        *state3.write() = DaemonState::Degraded {
            reason: "chaos-test".to_string(),
            since: chrono::Utc::now(),
        };
        reload3.store(true, Ordering::Release);
        std::thread::sleep(Duration::from_millis(5));
        *state3.write() = DaemonState::Healthy;
    }

    shutdown3.store(true, Ordering::Release);
    let join3 = handle3.join();
    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        join3.is_ok(),
        "Coordinator panicked during rapid state transitions",
    );

    artifacts.write_on_failure(dir.path(), &engine);
    engine.assert_ok();
}
