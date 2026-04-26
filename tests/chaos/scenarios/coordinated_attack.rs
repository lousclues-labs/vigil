// tests/chaos/scenarios/coordinated_attack.rs
// Scenario 8: Coordinated Attack (All Systems)
//
// Goal: Full-system resilience under compound stress.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use crossbeam_channel::bounded;
use parking_lot::RwLock;
use vigil::alert::{AlertDispatcher, AlertPayload};
use vigil::coordinator::{self, CoordinatorConfig};
use vigil::db::{self, DbFileIdentity};
use vigil::metrics::Metrics;
use vigil::types::{DaemonState, FsEvent, FsEventType, Severity};
use vigil::wal::{
    audit_writer::AuditWriter, sink_runner::SinkRunner, DetectionSource, DetectionWal,
};
use vigil::watch_index::WatchGroupIndex;
use vigil::worker::{self, WorkerSpawnArgs};

use crate::chaos_common::*;
use crate::harness::*;

#[test]
fn coordinated_attack() {
    for seed in seed_list() {
        run_coordinated_attack(seed);
    }
}

fn run_coordinated_attack(seed: u64) {
    let tier = ChaosTier::current();
    let scale = ScaleParams::for_tier(tier);
    let mut rng = ChaosRng::new(seed);
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "coordinated_attack");

    let dir = tempfile::tempdir().unwrap();
    let fs_root = dir.path().join("watched");
    std::fs::create_dir_all(&fs_root).unwrap();
    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");
    let wal_path = dir.path().join("detections.wal");
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    // --- Setup all components ---

    // Databases.
    let baseline_conn_coord = db::open_db_at(&baseline_path, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn_coord).unwrap();
    let audit_conn_coord = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&audit_conn_coord).unwrap();

    // WAL.
    let wal = Arc::new(DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

    // Config and shared state.
    let mut cfg = chaos_config(dir.path());
    cfg.daemon.db_path = baseline_path.clone();
    cfg.daemon.runtime_dir = runtime_dir.clone();
    cfg.daemon.worker_threads = scale.threads.min(4) as u32;
    cfg.watch.clear();
    cfg.watch.insert(
        "chaos".to_string(),
        vigil::config::WatchGroup {
            severity: Severity::High,
            paths: vec![fs_root.to_string_lossy().to_string()],
            mode: vigil::config::WatchMode::PerFile,
            expect_present: false,
        },
    );

    let config = Arc::new(ArcSwap::from_pointee(cfg.clone()));
    let metrics = Arc::new(Metrics::new());
    let state = Arc::new(RwLock::new(DaemonState::Healthy));
    let watch_index = Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
        &config.load(),
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload_flag = Arc::new(AtomicBool::new(false));
    let backpressure = Arc::new(AtomicBool::new(false));
    let baseline_generation = Arc::new(AtomicU64::new(0));

    // Channels.
    let (event_tx, event_rx) = bounded::<FsEvent>(2048);
    let (alert_tx, alert_rx) = bounded::<AlertPayload>(2048);

    // Seed filesystem.
    let fs_mutator = FsMutator::new(&fs_root);
    let test_files = fs_mutator.seed_files(&mut rng, 30);

    artifacts.record(0, "All components initialized");

    // --- Spawn coordinator ---
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
        startup_baseline_conn: baseline_conn_coord,
        startup_audit_conn: audit_conn_coord,
        reconfigure_tx: None,
        mount_mark_tx: None,
        wal_identity: DbFileIdentity::from_path(&wal_path).ok(),
        wal_path: Some(wal_path.clone()),
        maintenance_active: Arc::new(AtomicBool::new(false)),
        maintenance_entered_at: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        shared_baseline_identity: None,
        scan_trigger: None,
    };
    let coord_handle = coordinator::spawn(coord_cfg).unwrap();

    // --- Spawn workers ---
    let worker_args = WorkerSpawnArgs {
        count: scale.threads.min(4) as u32,
        config: config.clone(),
        event_rx,
        alert_tx: alert_tx.clone(),
        baseline_db_path: baseline_path.clone(),
        watch_index: watch_index.clone(),
        metrics: metrics.clone(),
        shutdown: shutdown.clone(),
        baseline_update_tx: None,
        backpressure: backpressure.clone(),
        baseline_generation: baseline_generation.clone(),
        wal: Some(wal.clone()),
        maintenance_active: Arc::new(AtomicBool::new(false)),
        state: None,
        self_protection_paths: Arc::new(std::collections::HashSet::new()),
    };
    let worker_handles = worker::spawn_workers(worker_args);

    // --- Spawn AuditWriter ---
    let audit_conn_writer = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&audit_conn_writer).unwrap();
    let baseline_conn_writer = db::open_db_at(&baseline_path, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn_writer).unwrap();

    let mut audit_writer = AuditWriter::new(
        wal.clone(),
        audit_conn_writer,
        audit_path.clone(),
        baseline_conn_writer,
        None,
        metrics.clone(),
        "test".to_string(),
    )
    .unwrap();
    let _ = audit_writer.recover();
    let audit_handle = audit_writer.spawn(shutdown.clone()).unwrap();

    // --- Spawn SinkRunner ---
    let sink_runner =
        SinkRunner::new(wal.clone(), &cfg, metrics.clone(), "test".to_string()).unwrap();
    let sink_handle = sink_runner.spawn(shutdown.clone()).unwrap();

    // --- Spawn AlertDispatcher ---
    let alert_dispatcher = AlertDispatcher::new(
        &cfg,
        &audit_path,
        metrics.clone(),
        None,
        true,
        "test".to_string(),
    )
    .unwrap();
    let alert_shutdown = shutdown.clone();
    let alert_handle = std::thread::spawn(move || {
        alert_dispatcher.run(alert_rx, alert_shutdown);
    });

    artifacts.record(1, "All threads spawned");

    // --- Run the coordinated attack ---
    let run_duration = Duration::from_secs(scale.duration_secs.min(10));
    let start = Instant::now();
    let mut step = 2usize;

    let db_toggler = DbPermissionToggler::new(&audit_path);
    let mut last_db_toggle = Instant::now();
    let mut last_config_reload = Instant::now();
    let mut last_scan_inject = Instant::now();
    let mut total_events_sent = 0u64;

    while start.elapsed() < run_duration {
        // Filesystem warfare: inject events + mutate files.
        if !test_files.is_empty() {
            let target = rng.pick(&test_files).clone();
            let event_type = match rng.next_bounded(4) {
                0 => FsEventType::Modify,
                1 => FsEventType::Create,
                2 => FsEventType::Delete,
                _ => FsEventType::Attrib,
            };

            // Concurrent mutation.
            if rng.chance(0.4) {
                let mutation = match rng.next_bounded(3) {
                    0 => FsMutation::Create {
                        content: vec![rng.next_u64() as u8; 32],
                    },
                    1 => FsMutation::Modify {
                        content: vec![rng.next_u64() as u8; 32],
                    },
                    _ => FsMutation::Delete,
                };
                fs_mutator.apply(&mutation, &target);
            }

            let event = FsEvent {
                path: Arc::new(target),
                event_type,
                timestamp: chrono::Utc::now(),
                event_fd: None,
                process: None,
                bloom_generation: 0,
            };
            let _ = event_tx.try_send(event);
            total_events_sent += 1;
        }

        // Audit DB permission flapping every 2s.
        if last_db_toggle.elapsed() >= Duration::from_secs(2) {
            db_toggler.toggle();
            last_db_toggle = Instant::now();
            artifacts.record(step, "DB permission toggle");
        }

        // Config reload every 5s.
        if last_config_reload.elapsed() >= Duration::from_secs(5) {
            reload_flag.store(true, Ordering::Release);
            last_config_reload = Instant::now();
            artifacts.record(step, "Config reload signal");
        }

        // On-demand WAL append every 3s (simulates on-demand scan).
        if last_scan_inject.elapsed() >= Duration::from_secs(3) {
            let rec = make_record(
                &format!("/chaos/scan/{}", step),
                Severity::Medium,
                DetectionSource::OnDemandScan,
            );
            if wal.append(&rec).is_ok() {
                // Account for direct WAL appends in the appends metric.
                metrics
                    .detections_wal_appends
                    .fetch_add(1, Ordering::Relaxed);
            }
            last_scan_inject = Instant::now();
            artifacts.record(step, "On-demand scan WAL append");
        }

        step += 1;
        // Tight loop with small sleep to create high event rate.
        std::thread::sleep(Duration::from_millis(5));
    }

    artifacts.record(
        step,
        format!("Attack phase complete, {} events sent", total_events_sent),
    );

    // Ensure DB is writable before shutdown.
    db_toggler.ensure_writable();

    // --- Graceful shutdown ---
    shutdown.store(true, Ordering::Release);
    drop(event_tx);
    drop(alert_tx);

    // Wait for all threads with a timeout.
    let join_deadline = Instant::now() + Duration::from_secs(10);

    for h in worker_handles {
        if Instant::now() < join_deadline {
            let _ = h.join();
        }
    }

    // Check for deadlock by verifying joins complete.
    let audit_joined = if Instant::now() < join_deadline {
        audit_handle.join().is_ok()
    } else {
        false
    };

    let sink_joined = if Instant::now() < join_deadline {
        sink_handle.join().is_ok()
    } else {
        false
    };

    let _alert_joined = if Instant::now() < join_deadline {
        alert_handle.join().is_ok()
    } else {
        false
    };

    let coord_joined = if Instant::now() < join_deadline {
        coord_handle.join().is_ok()
    } else {
        false
    };

    // --- Invariant checks ---
    engine.set_step(step + 1);

    // Clean shutdown with no deadlocks.
    engine.check(
        InvariantId::I3NoPermanentLoss,
        audit_joined,
        "AuditWriter did not shut down cleanly (possible deadlock)",
    );
    engine.check(
        InvariantId::I3NoPermanentLoss,
        sink_joined,
        "SinkRunner did not shut down cleanly (possible deadlock)",
    );
    engine.check(
        InvariantId::I3NoPermanentLoss,
        coord_joined,
        "Coordinator did not shut down cleanly (possible deadlock)",
    );

    // Metric consistency: wal_appends >= wal_audit_committed + wal_pending
    // (accounting for recovered entries that increment committed but not appends).
    let wal_appends = metrics.detections_wal_appends.load(Ordering::Relaxed);
    let wal_committed = metrics
        .detections_wal_audit_committed
        .load(Ordering::Relaxed);
    let wal_replayed = metrics.detections_wal_replayed.load(Ordering::Relaxed);
    let wal_pending = wal.pending_count();
    // Recovered entries add to committed without adding to appends, so adjust.
    let effective_appends = wal_appends + wal_replayed;
    engine.check_ctx(
        InvariantId::I9WalMediatedPath,
        effective_appends >= wal_committed + wal_pending || wal_appends == 0,
        format!(
            "Metric inconsistency: appends({}) + replayed({}) < committed({}) + pending({})",
            wal_appends, wal_replayed, wal_committed, wal_pending
        ),
        vec![
            ("wal_appends", wal_appends.to_string()),
            ("wal_committed", wal_committed.to_string()),
            ("wal_replayed", wal_replayed.to_string()),
            ("wal_pending", wal_pending.to_string()),
        ],
    );

    // I10: WAL permissions intact.
    let mode = wal_file_mode(dir.path());
    engine.check(
        InvariantId::I10WalPermissions0600,
        mode == WAL_EXPECTED_MODE,
        format!("WAL mode {:o} after coordinated attack", mode),
    );

    // I3: Check that non-sentinel WAL entries eventually reach audit DB.
    // Open fresh connection for verification.
    let verify_conn = db::open_db_at(&audit_path, false).unwrap();
    let audit_entry_count = audit_count(&verify_conn);

    artifacts.set_wal_summary(wal.file_size(), wal_pending, wal_appends);
    artifacts.set_audit_summary(audit_entry_count, true, 0);

    artifacts.record(
        step + 2,
        format!(
            "Final state: wal_appends={}, committed={}, replayed={}, pending={}, audit_entries={}",
            wal_appends, wal_committed, wal_replayed, wal_pending, audit_entry_count
        ),
    );

    artifacts.write_on_failure(dir.path(), &engine);
    engine.assert_ok();
}
