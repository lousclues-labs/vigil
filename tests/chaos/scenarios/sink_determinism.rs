// tests/chaos/scenarios/sink_determinism.rs
// Scenario 6: Sink Suppression Determinism
//
// Goal: Prove suppression decisions are deterministic for identical inputs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vigil::metrics::Metrics;
use vigil::types::Severity;
use vigil::wal::{sink_runner::SinkRunner, DetectionRecord, DetectionSource};

use crate::chaos_common::*;
use crate::harness::*;

#[test]
fn sink_suppression_determinism() {
    for seed in seed_list() {
        run_sink_determinism(seed);
    }
}

fn run_sink_determinism(seed: u64) {
    let mut rng = ChaosRng::new(seed);
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "sink_determinism");

    // Create two identical WAL instances with identical records.
    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();

    let wal1 = Arc::new(open_wal(dir1.path()));
    let wal2 = Arc::new(open_wal(dir2.path()));

    // Generate a stream of detection records with the same seed.
    let num_records = 30;
    let mut records: Vec<DetectionRecord> = Vec::new();
    for i in 0..num_records {
        let severity = match rng.next_bounded(4) {
            0 => Severity::Low,
            1 => Severity::Medium,
            2 => Severity::High,
            _ => Severity::Critical,
        };
        let source = if rng.chance(0.1) {
            DetectionSource::Sentinel
        } else {
            DetectionSource::Realtime
        };
        let path = format!("/chaos/sink/{}", i);
        records.push(make_record_at(&path, severity, source, 1000000 + i as i64));
    }

    // Append identical records to both WALs.
    for rec in &records {
        wal1.append(rec).unwrap();
        wal2.append(rec).unwrap();
    }

    artifacts.record(
        0,
        format!("Appended {} identical records to both WALs", num_records),
    );

    // Create identical configs.
    let cfg1 = chaos_config(dir1.path());
    let cfg2 = chaos_config(dir2.path());

    // Run both SinkRunners and collect their dispatch/suppress decisions.
    let metrics1 = Arc::new(Metrics::new());
    let metrics2 = Arc::new(Metrics::new());

    let runner1 = SinkRunner::new(Arc::clone(&wal1), &cfg1, metrics1.clone()).unwrap();
    let runner2 = SinkRunner::new(Arc::clone(&wal2), &cfg2, metrics2.clone()).unwrap();

    // Run each SinkRunner briefly.
    let shutdown1 = Arc::new(AtomicBool::new(false));
    let shutdown2 = Arc::new(AtomicBool::new(false));

    let sc1 = shutdown1.clone();
    let sc2 = shutdown2.clone();

    let h1 = runner1.spawn(sc1).unwrap();
    let h2 = runner2.spawn(sc2).unwrap();

    // Wait for both to process.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let p1 = wal1.pending_count();
        let p2 = wal2.pending_count();
        if p1 == 0 && p2 == 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    shutdown1.store(true, Ordering::Release);
    shutdown2.store(true, Ordering::Release);
    h1.join().expect("SinkRunner 1 panicked");
    h2.join().expect("SinkRunner 2 panicked");

    // --- Invariant checks ---
    engine.set_step(1);

    // Compare dispatch/suppress decisions via metrics.
    let dispatched1 = metrics1.alerts_dispatched.load(Ordering::Relaxed);
    let dispatched2 = metrics2.alerts_dispatched.load(Ordering::Relaxed);
    let suppressed1 = metrics1.alerts_suppressed.load(Ordering::Relaxed);
    let suppressed2 = metrics2.alerts_suppressed.load(Ordering::Relaxed);
    let sink_dispatched1 = metrics1
        .detections_wal_sink_dispatched
        .load(Ordering::Relaxed);
    let sink_dispatched2 = metrics2
        .detections_wal_sink_dispatched
        .load(Ordering::Relaxed);

    engine.check_ctx(
        InvariantId::I6SentinelExcludedFromDurability,
        dispatched1 == dispatched2,
        format!("Dispatch counts differ: {} vs {}", dispatched1, dispatched2),
        vec![
            ("dispatched1", dispatched1.to_string()),
            ("dispatched2", dispatched2.to_string()),
        ],
    );

    engine.check_ctx(
        InvariantId::I6SentinelExcludedFromDurability,
        suppressed1 == suppressed2,
        format!("Suppress counts differ: {} vs {}", suppressed1, suppressed2),
        vec![
            ("suppressed1", suppressed1.to_string()),
            ("suppressed2", suppressed2.to_string()),
        ],
    );

    engine.check(
        InvariantId::I6SentinelExcludedFromDurability,
        sink_dispatched1 == sink_dispatched2,
        format!(
            "WAL sink dispatch counts differ: {} vs {}",
            sink_dispatched1, sink_dispatched2
        ),
    );

    // Verify both WALs have identical sink_done status.
    let entries1 = wal1.iter_unconsumed().unwrap_or_default();
    let entries2 = wal2.iter_unconsumed().unwrap_or_default();

    engine.check(
        InvariantId::I5MarkIdempotent,
        entries1.len() == entries2.len(),
        format!(
            "Unconsumed entry counts differ: {} vs {}",
            entries1.len(),
            entries2.len()
        ),
    );

    artifacts.set_wal_summary(wal1.file_size(), wal1.pending_count(), num_records as u64);
    artifacts.write_on_failure(dir1.path(), &engine);
    engine.assert_ok();
}
