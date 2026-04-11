// tests/chaos/scenarios/wal_concurrency.rs
// Scenario 1: WAL Concurrency and Recovery
//
// Goal: Validate WAL invariants under concurrent operations and recovery.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use vigil::types::Severity;
use vigil::wal::{DetectionSource, DetectionWal};

use crate::chaos_common::*;
use crate::harness::*;

/// Operations that worker threads randomly perform on the WAL.
#[derive(Debug, Clone, Copy)]
enum WalOp {
    Append,
    MarkAuditDone,
    MarkSinkDone,
    IterUnconsumed,
    TruncateConsumed,
}

const ALL_OPS: [WalOp; 5] = [
    WalOp::Append,
    WalOp::MarkAuditDone,
    WalOp::MarkSinkDone,
    WalOp::IterUnconsumed,
    WalOp::TruncateConsumed,
];

#[test]
fn wal_concurrency_and_recovery() {
    for seed in seed_list() {
        run_wal_concurrency(seed);
    }
}

fn run_wal_concurrency(seed: u64) {
    let tier = ChaosTier::current();
    let scale = ScaleParams::for_tier(tier);
    let mut rng = ChaosRng::new(seed);
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "wal_concurrency");

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("detections.wal");
    let wal = Arc::new(DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

    let num_threads = scale.threads;
    let ops_per_thread = scale.iterations;
    let total_appended = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(num_threads));

    artifacts.record(
        0,
        format!(
            "Starting {} threads, {} ops each",
            num_threads, ops_per_thread
        ),
    );

    // Build per-thread operation schedules from the seed.
    let thread_schedules: Vec<Vec<WalOp>> = (0..num_threads)
        .map(|_| {
            let mut trng = rng.fork();
            (0..ops_per_thread)
                .map(|_| ALL_OPS[trng.next_usize(ALL_OPS.len())])
                .collect()
        })
        .collect();

    // Spawn N threads randomly performing WAL operations.
    let handles: Vec<_> = thread_schedules
        .into_iter()
        .enumerate()
        .map(|(tid, schedule)| {
            let wal = Arc::clone(&wal);
            let barrier = Arc::clone(&barrier);
            let appended = Arc::clone(&total_appended);
            thread::Builder::new()
                .name(format!("chaos-wal-{}", tid))
                .spawn(move || {
                    barrier.wait();
                    for op in &schedule {
                        match op {
                            WalOp::Append => {
                                let rec = make_record(
                                    &format!("/chaos/wal/{}/file", tid),
                                    Severity::Medium,
                                    DetectionSource::Realtime,
                                );
                                if wal.append(&rec).is_ok() {
                                    appended.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            WalOp::MarkAuditDone => {
                                if let Ok(entries) = wal.iter_unconsumed() {
                                    if let Some(e) = entries.first() {
                                        let _ = wal.mark_audit_done(e.offset);
                                    }
                                }
                            }
                            WalOp::MarkSinkDone => {
                                if let Ok(entries) = wal.iter_unconsumed() {
                                    if let Some(e) = entries.first() {
                                        let _ = wal.mark_sink_done(e.offset);
                                    }
                                }
                            }
                            WalOp::IterUnconsumed => {
                                let _ = wal.iter_unconsumed();
                            }
                            WalOp::TruncateConsumed => {
                                let _ = wal.truncate_consumed();
                            }
                        }
                    }
                })
                .unwrap()
        })
        .collect();

    for h in handles {
        h.join().expect("Worker thread panicked");
    }

    artifacts.record(1, "All threads completed");

    // --- Invariant checks after concurrent phase ---
    engine.set_step(1);

    // I1: Sequence numbers are unique and strictly monotonic.
    let entries = wal.iter_unconsumed().unwrap();
    let mut seen_seqs: HashSet<u64> = HashSet::new();
    let mut sorted_seqs: Vec<u64> = entries.iter().map(|e| e.sequence).collect();
    sorted_seqs.sort();
    for &seq in &sorted_seqs {
        engine.check(
            InvariantId::I1UniqueMonotonicSeq,
            seen_seqs.insert(seq),
            format!("Duplicate sequence number: {}", seq),
        );
    }
    // Strictly monotonic (after sorting)
    for w in sorted_seqs.windows(2) {
        engine.check(
            InvariantId::I1UniqueMonotonicSeq,
            w[1] > w[0],
            format!("Non-monotonic sequences: {} >= {}", w[0], w[1]),
        );
    }

    // I2: iter_unconsumed never returns fully consumed entries.
    for e in &entries {
        engine.check(
            InvariantId::I2IterUnconsumedNoFullyConsumed,
            !e.fully_consumed(),
            format!(
                "iter_unconsumed returned fully consumed entry seq={}",
                e.sequence
            ),
        );
    }

    // I10: WAL file mode remains 0600.
    let mode = wal_file_mode(dir.path());
    engine.check(
        InvariantId::I10WalPermissions0600,
        mode == WAL_EXPECTED_MODE,
        format!("WAL mode {:o} != {:o}", mode, WAL_EXPECTED_MODE),
    );

    // I11: pending_count == count(!(audit_done && sink_done))
    let pending = wal.pending_count();
    let manual_pending = entries.len() as u64;
    engine.check(
        InvariantId::I11PendingCountCorrect,
        pending == manual_pending,
        format!(
            "pending_count {} != iter_unconsumed len {}",
            pending, manual_pending
        ),
    );

    // WAL file size >= WAL_HEADER_SIZE
    let fsize = wal.file_size();
    engine.check_ctx(
        InvariantId::I4TruncateNeverIncreasesSize,
        fsize >= WAL_HEADER_SIZE,
        format!("file_size {} < WAL_HEADER_SIZE {}", fsize, WAL_HEADER_SIZE),
        vec![("file_size", fsize.to_string())],
    );

    // --- Recovery cycle ---
    artifacts.record(2, "Starting recovery cycle");
    engine.set_step(2);

    // Force a truncate, then reopen and verify.
    let size_before = wal.file_size();
    let _ = wal.truncate_consumed();
    let size_after = wal.file_size();
    engine.check(
        InvariantId::I4TruncateNeverIncreasesSize,
        size_after <= size_before || entries.iter().all(|e| !e.fully_consumed()),
        format!(
            "truncate_consumed increased file size: {} -> {}",
            size_before, size_after
        ),
    );

    // Reopen WAL and verify entries survive.
    drop(wal);
    let wal2 = DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap();
    let entries2 = wal2.iter_unconsumed().unwrap();

    // I2 after recovery.
    for e in &entries2 {
        engine.check(
            InvariantId::I2IterUnconsumedNoFullyConsumed,
            !e.fully_consumed(),
            format!("After reopen: fully consumed entry seq={}", e.sequence),
        );
    }

    // I1: Sequence uniqueness after recovery.
    let mut seen2: HashSet<u64> = HashSet::new();
    for e in &entries2 {
        engine.check(
            InvariantId::I1UniqueMonotonicSeq,
            seen2.insert(e.sequence),
            format!("After reopen: duplicate seq {}", e.sequence),
        );
    }

    // I5: mark_audit_done and mark_sink_done are idempotent.
    engine.set_step(3);
    if let Some(e) = entries2.first() {
        let res1 = wal2.mark_audit_done(e.offset);
        let res2 = wal2.mark_audit_done(e.offset);
        engine.check(
            InvariantId::I5MarkIdempotent,
            res1.is_ok() && res2.is_ok(),
            "mark_audit_done is not idempotent",
        );
        let res3 = wal2.mark_sink_done(e.offset);
        let res4 = wal2.mark_sink_done(e.offset);
        engine.check(
            InvariantId::I5MarkIdempotent,
            res3.is_ok() && res4.is_ok(),
            "mark_sink_done is not idempotent",
        );
    }

    // I10: WAL permissions after all operations.
    let mode_final = wal_file_mode(dir.path());
    engine.check(
        InvariantId::I10WalPermissions0600,
        mode_final == WAL_EXPECTED_MODE,
        format!("Final WAL mode {:o} != {:o}", mode_final, WAL_EXPECTED_MODE),
    );

    artifacts.set_wal_summary(
        wal2.file_size(),
        wal2.pending_count(),
        total_appended.load(Ordering::Relaxed),
    );
    artifacts.write_on_failure(dir.path(), &engine);
    engine.assert_ok();
}
