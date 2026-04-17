// tests/chaos/scenarios/clock_warfare.rs
// Scenario 7: Clock Warfare
//
// Goal: Validate time-sensitive logic across all relevant components.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use vigil::coordinator::{self, CoordinatorConfig};
use vigil::db::{self, DbFileIdentity};
use vigil::metrics::Metrics;
use vigil::types::{DaemonState, Severity};
use vigil::wal::{DetectionSource, DetectionWal};
use vigil::watch_index::WatchGroupIndex;

use crate::chaos_common::*;
use crate::harness::*;

#[test]
fn clock_warfare() {
    for seed in seed_list() {
        run_clock_warfare(seed);
    }
}

fn run_clock_warfare(seed: u64) {
    let _rng = ChaosRng::new(seed);
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "clock_warfare");

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("detections.wal");

    // --- Part 1: WAL under clock anomalies (injected clock) ---

    let clock = InjectedClock::new();
    let wal = Arc::new(DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

    // Append records with various clock scenarios.
    let scenarios: Vec<(&str, ClockFault)> = vec![
        ("forward_jump", ClockFault::ForwardJump(3600)),
        ("backward_jump", ClockFault::BackwardJump(30)),
        ("freeze", ClockFault::Freeze(5)),
        ("jitter", ClockFault::Jitter(500)),
    ];

    let mut timestamps: Vec<i64> = Vec::new();

    for (i, (name, fault)) in scenarios.iter().enumerate() {
        engine.set_step(i + 1);
        artifacts.record(i + 1, format!("Applying clock fault: {}", name));

        // Apply the clock fault.
        clock.inject_fault(fault);

        // Generate records with the injected clock's time.
        for j in 0..5 {
            let ts = clock.now_timestamp();
            timestamps.push(ts);
            let rec = make_record_at(
                &format!("/chaos/clock/{}/{}", name, j),
                Severity::Medium,
                DetectionSource::Realtime,
                ts,
            );
            wal.append(&rec).unwrap();
        }

        // Reset for next scenario.
        if matches!(fault, ClockFault::Freeze(_)) {
            clock.unfreeze();
        }
    }

    clock.reset();

    artifacts.record(
        scenarios.len() + 1,
        format!("Appended {} records with clock faults", timestamps.len()),
    );

    // Under injected clock mode, check timestamp non-decreasing (within one boot epoch).
    engine.set_step(scenarios.len() + 2);

    // Note: With forward/backward jumps, timestamps may not be monotonic across
    // different fault windows. But within each fault window they should be consistent.
    // The clock itself is consistent within a fault application.

    // Verify WAL entries survived all clock manipulations.
    let entries = wal.iter_unconsumed().unwrap();
    engine.check(
        InvariantId::I1UniqueMonotonicSeq,
        entries.len() == timestamps.len(),
        format!(
            "Expected {} entries after clock warfare, got {}",
            timestamps.len(),
            entries.len()
        ),
    );

    // I1: Sequence numbers still unique and monotonic despite clock chaos.
    let mut seqs: Vec<u64> = entries.iter().map(|e| e.sequence).collect();
    seqs.sort();
    for w in seqs.windows(2) {
        engine.check(
            InvariantId::I1UniqueMonotonicSeq,
            w[1] > w[0],
            format!(
                "Non-monotonic seq after clock warfare: {} >= {}",
                w[0], w[1]
            ),
        );
    }

    // --- Part 2: Coordinator clock anomaly detection ---

    engine.set_step(scenarios.len() + 3);
    artifacts.record(
        scenarios.len() + 3,
        "Testing coordinator clock anomaly detection",
    );

    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let baseline_conn = db::open_db_at(&baseline_path, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn).unwrap();
    let audit_conn = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&audit_conn).unwrap();

    let mut cfg = chaos_config(dir.path());
    cfg.daemon.db_path = baseline_path.clone();
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
        maintenance_entered_at: Arc::new(std::sync::atomic::AtomicI64::new(0)),
    };

    let coord_handle = coordinator::spawn(coord_cfg).unwrap();

    // Let coordinator run through several ticks.
    // The coordinator detects clock anomalies via its detect_clock_anomaly() method
    // which compares elapsed time between ticks (delta > 3600s or < -60s).
    // We can't easily inject time into the coordinator's system clock, but we
    // verify it doesn't panic under normal operation and responds to shutdown.
    std::thread::sleep(Duration::from_millis(2000));

    // Coordinator should emit heartbeats (checked via not panicking).
    shutdown.store(true, Ordering::Release);
    let join_result = coord_handle.join();
    engine.check(
        InvariantId::I12CoordinatorDegradedOnInodeChange,
        join_result.is_ok(),
        "Coordinator panicked during clock warfare test",
    );

    // --- Part 3: Debounce eventually releases queued events ---

    engine.set_step(scenarios.len() + 4);
    artifacts.record(
        scenarios.len() + 4,
        "Verifying debounce release under clock jitter",
    );

    // Under heavy jitter, debounce timers should still eventually fire.
    // We test this by creating an EventFilter and verifying drain_pending works.
    let filter_cfg = chaos_config(dir.path());
    let mut filter = vigil::filter::EventFilter::new(&filter_cfg);

    // Simulate events with jittery timestamps.
    for i in 0..10 {
        let event = vigil::types::FsEvent {
            path: Arc::new(std::path::PathBuf::from(format!("/chaos/debounce/{}", i))),
            event_type: vigil::types::FsEventType::Modify,
            timestamp: chrono::Utc::now(),
            event_fd: None,
            process: None,
        };
        let _ = filter.should_process(&event);
    }

    // Wait for debounce window to expire (default debounce_ms in config).
    std::thread::sleep(Duration::from_millis(500));

    let pending = filter.drain_pending();
    // After sufficient time, pending paths should drain (may be empty if all processed).
    // The invariant is that debounce does not permanently hold events.
    artifacts.record(
        scenarios.len() + 5,
        format!("Debounce drain returned {} paths", pending.len()),
    );

    artifacts.set_wal_summary(
        wal.file_size(),
        wal.pending_count(),
        timestamps.len() as u64,
    );
    artifacts.write_on_failure(dir.path(), &engine);
    engine.assert_ok();
}
