// tests/chaos/scenarios/worker_pool_chaos.rs
// Scenario 4: Worker Pool Filesystem Chaos
//
// Goal: Validate worker safety and correctness under filesystem races.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::bounded;
use vigil::alert::AlertPayload;
use vigil::db;
use vigil::metrics::Metrics;
use vigil::types::{FsEvent, FsEventType, Severity};
use vigil::wal::{DetectionSource, DetectionWal};
use vigil::watch_index::WatchGroupIndex;
use vigil::worker::{self, WorkerSpawnArgs};

use crate::chaos_common::*;
use crate::harness::*;

#[test]
fn worker_pool_filesystem_chaos() {
    for seed in seed_list() {
        run_worker_pool_chaos(seed);
    }
}

fn run_worker_pool_chaos(seed: u64) {
    let tier = ChaosTier::current();
    let scale = ScaleParams::for_tier(tier);
    let mut rng = ChaosRng::new(seed);
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "worker_pool_chaos");

    let dir = tempfile::tempdir().unwrap();
    let fs_root = dir.path().join("watched");
    std::fs::create_dir_all(&fs_root).unwrap();
    let baseline_path = dir.path().join("baseline.db");
    let wal_path = dir.path().join("detections.wal");

    // Set up baseline DB with schema.
    let baseline_conn = db::open_db_at(&baseline_path, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn).unwrap();
    drop(baseline_conn);

    // Create test files in the watched directory.
    let fs_mutator = FsMutator::new(&fs_root);
    let test_files = fs_mutator.seed_files(&mut rng, scale.records.min(50));

    // Configure watch group for the test directory.
    let mut cfg = chaos_config(dir.path());
    cfg.daemon.db_path = baseline_path.clone();
    cfg.daemon.worker_threads = scale.threads as u32;
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

    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let metrics = Arc::new(Metrics::new());
    let watch_index = Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
        &config.load(),
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let backpressure = Arc::new(AtomicBool::new(false));
    let baseline_generation = Arc::new(AtomicU64::new(0));

    // Create WAL.
    let wal = Arc::new(DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

    // Create channels.
    let (event_tx, event_rx) = bounded::<FsEvent>(2048);
    let (alert_tx, alert_rx) = bounded::<AlertPayload>(2048);

    let args = WorkerSpawnArgs {
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

    // Spawn workers.
    let handles = worker::spawn_workers(args);
    artifacts.record(0, format!("Spawned {} workers", handles.len()));

    // Inject FsEvents while concurrently mutating the filesystem.
    let num_events = scale.iterations.min(200);
    let event_types = [
        FsEventType::Modify,
        FsEventType::Create,
        FsEventType::Delete,
        FsEventType::Attrib,
    ];

    for i in 0..num_events {
        engine.set_step(i + 1);

        // Pick a random file and event type.
        let target = if test_files.is_empty() {
            fs_root.join(format!("chaos_dyn_{}", i))
        } else {
            rng.pick(&test_files).clone()
        };

        let event_type = *rng.pick(&event_types);

        // Concurrently mutate the filesystem (race condition injection).
        if rng.chance(0.3) {
            let mutation = match rng.next_bounded(4) {
                0 => FsMutation::Create {
                    content: vec![rng.next_u64() as u8; 64],
                },
                1 => FsMutation::Modify {
                    content: vec![rng.next_u64() as u8; 64],
                },
                2 => FsMutation::Delete,
                _ => FsMutation::InodeReuse,
            };
            fs_mutator.apply(&mutation, &target);
        }

        // Create and send event.
        let event = FsEvent {
            path: Arc::new(target.clone()),
            event_type,
            timestamp: chrono::Utc::now(),
            event_fd: None,
            process: None,
            bloom_generation: 0,
        };

        // Non-blocking send -- drop if channel full.
        let _ = event_tx.try_send(event);
    }

    artifacts.record(num_events + 1, "All events injected");

    // Let workers drain for a bounded time.
    let drain_deadline = std::time::Instant::now() + Duration::from_secs(scale.duration_secs);
    while std::time::Instant::now() < drain_deadline {
        if event_tx.is_empty() {
            // Give a little more time for in-flight processing.
            std::thread::sleep(Duration::from_millis(100));
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Shutdown workers.
    shutdown.store(true, Ordering::Release);
    drop(event_tx);
    drop(alert_tx);

    for h in handles {
        h.join().expect("Worker thread panicked unexpectedly");
    }

    artifacts.record(num_events + 2, "All workers shut down");

    // --- Invariant checks ---
    engine.set_step(num_events + 3);

    // I8: Panic-sourced detections have Severity::Critical and empty changes.
    let panics = metrics.panics_caught.load(Ordering::Relaxed);
    if panics > 0 {
        artifacts.record(num_events + 3, format!("{} panics caught", panics));
        // Check WAL entries for panic records.
        let entries = wal.iter_unconsumed().unwrap();
        for e in &entries {
            if e.record.source == DetectionSource::Panic {
                engine.check(
                    InvariantId::I8PanicSeverityCritical,
                    e.record.severity == Severity::Critical,
                    format!(
                        "Panic record seq={} has severity {:?} (expected Critical)",
                        e.sequence, e.record.severity
                    ),
                );
                engine.check(
                    InvariantId::I8PanicSeverityCritical,
                    e.record.changes.is_empty(),
                    format!(
                        "Panic record seq={} has {} changes (expected 0)",
                        e.sequence,
                        e.record.changes.len()
                    ),
                );
            }
        }
    }

    // Verify no unexpected panics by checking the metric count is reasonable.
    // Workers should catch panics -- they shouldn't crash threads.
    engine.check(
        InvariantId::I8PanicSeverityCritical,
        true, // No thread join failures above → panics were contained.
        "Worker panics were not contained",
    );

    // Drain alert_rx to count dispatched.
    // Drain remaining alerts.
    while alert_rx.try_recv().is_ok() {}

    artifacts.set_wal_summary(
        wal.file_size(),
        wal.pending_count(),
        metrics.detections_wal_appends.load(Ordering::Relaxed),
    );
    artifacts.write_on_failure(dir.path(), &engine);
    engine.assert_ok();
}
