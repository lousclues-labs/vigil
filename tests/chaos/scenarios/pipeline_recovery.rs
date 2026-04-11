// tests/chaos/scenarios/pipeline_recovery.rs
// Scenario 2: Detection Pipeline Crash Recovery
//
// Goal: Prove end-to-end durability through repeated AuditWriter crashes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vigil::db;
use vigil::db::audit_ops;
use vigil::metrics::Metrics;
use vigil::types::Severity;
use vigil::wal::{audit_writer::AuditWriter, DetectionSource, DetectionWal};

use crate::chaos_common::*;
use crate::harness::*;

#[test]
fn pipeline_crash_recovery() {
    for seed in seed_list() {
        run_pipeline_recovery(seed);
    }
}

fn run_pipeline_recovery(seed: u64) {
    let tier = ChaosTier::current();
    let scale = ScaleParams::for_tier(tier);
    let mut rng = ChaosRng::new(seed);
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "pipeline_recovery");

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("detections.wal");
    let audit_path = dir.path().join("audit.db");
    let baseline_path = dir.path().join("baseline.db");

    // Create WAL and populate with N detection records.
    let wal = Arc::new(DetectionWal::open(&wal_path, None, 64 * 1024 * 1024).unwrap());

    let num_records = scale.records;
    let mut non_sentinel_count = 0u64;
    let mut appended_paths: Vec<String> = Vec::new();

    for i in 0..num_records {
        let is_sentinel = rng.chance(0.1);
        let rec = if is_sentinel {
            make_sentinel()
        } else {
            non_sentinel_count += 1;
            let path = format!("/chaos/pipeline/{}", i);
            appended_paths.push(path.clone());
            make_record(&path, Severity::High, DetectionSource::Realtime)
        };
        wal.append(&rec).unwrap();
    }

    artifacts.record(
        0,
        format!(
            "Appended {} records ({} non-sentinel)",
            num_records, non_sentinel_count
        ),
    );

    // Simulate crash-restart cycles.
    // We run AuditWriter, let it process some entries, stop it, then restart.
    let crash_cycles = (scale.iterations / 20).max(3);

    for cycle in 0..crash_cycles {
        engine.set_step(cycle + 1);
        artifacts.record(cycle + 1, format!("Crash-restart cycle {}", cycle));

        // Open fresh DB connections for each cycle (simulates process restart).
        let audit_conn = db::open_db_at(&audit_path, false).unwrap();
        db::schema::create_audit_tables(&audit_conn).unwrap();
        let baseline_conn = db::open_db_at(&baseline_path, false).unwrap();
        db::schema::create_baseline_tables(&baseline_conn).unwrap();

        let metrics = Arc::new(Metrics::new());
        let mut writer = AuditWriter::new(
            Arc::clone(&wal),
            audit_conn,
            audit_path.clone(),
            baseline_conn,
            None,
            metrics.clone(),
        )
        .unwrap();

        // Run recovery first (simulates restart after crash).
        let replayed = writer.recover().unwrap();
        artifacts.record(cycle + 1, format!("Recovery replayed {} entries", replayed));

        // Let writer run briefly then simulate crash by stopping it.
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let handle = writer.spawn(shutdown_clone).unwrap();

        // Let it process for a random short duration.
        let run_ms = 20 + rng.next_bounded(80);
        std::thread::sleep(Duration::from_millis(run_ms));

        // Signal shutdown (simulate graceful crash).
        shutdown.store(true, Ordering::Release);
        handle.join().expect("AuditWriter thread panicked");
    }

    // Final recovery pass — run writer until quiescent.
    artifacts.record(crash_cycles + 1, "Final recovery pass");
    engine.set_step(crash_cycles + 1);

    let audit_conn = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&audit_conn).unwrap();
    let baseline_conn = db::open_db_at(&baseline_path, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn).unwrap();

    let metrics = Arc::new(Metrics::new());
    let mut writer = AuditWriter::new(
        Arc::clone(&wal),
        audit_conn,
        audit_path.clone(),
        baseline_conn,
        None,
        metrics.clone(),
    )
    .unwrap();

    let _ = writer.recover().unwrap();

    // Let writer run until all entries are processed.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let handle = writer.spawn(shutdown_clone).unwrap();

    // Wait until pending count reaches 0 or timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(scale.duration_secs);
    loop {
        if wal.pending_count() == 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            artifacts.record(crash_cycles + 2, "Timeout waiting for quiescence");
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    shutdown.store(true, Ordering::Release);
    handle.join().expect("Final AuditWriter thread panicked");

    // --- Invariant checks ---
    engine.set_step(crash_cycles + 2);

    // Open a fresh connection for verification.
    let verify_conn = db::open_db_at(&audit_path, false).unwrap();

    // I3: Every non-sentinel WAL entry is present in audit DB at least once.
    let audit_entry_count = audit_count(&verify_conn);
    engine.check(
        InvariantId::I3NoPermanentLoss,
        audit_entry_count as u64 >= non_sentinel_count,
        format!(
            "Audit entries {} < expected non-sentinel count {}",
            audit_entry_count, non_sentinel_count
        ),
    );

    // I6: Sentinel entries are excluded from audit DB durability counts.
    // Sentinels should not appear in audit_log.
    let sentinel_in_audit: i64 = verify_conn
        .query_row("SELECT COUNT(*) FROM audit_log WHERE path = ''", [], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    engine.check(
        InvariantId::I6SentinelExcludedFromDurability,
        sentinel_in_audit == 0,
        format!("{} sentinel entries found in audit DB", sentinel_in_audit),
    );

    // I7: HMAC chain is contiguous and verifiable.
    let (total, valid, breaks, missing) = audit_ops::verify_chain(&verify_conn).unwrap();
    engine.check(
        InvariantId::I7AuditHmacChainNoGaps,
        breaks.is_empty(),
        format!(
            "HMAC chain has {} breaks (total={}, valid={}, missing={})",
            breaks.len(),
            total,
            valid,
            missing
        ),
    );

    // Check that all expected paths are present.
    for path in &appended_paths {
        let found: bool = verify_conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM audit_log WHERE path = ?1",
                [path],
                |r| r.get(0),
            )
            .unwrap_or(false);
        engine.check(
            InvariantId::I3NoPermanentLoss,
            found,
            format!("Path {} not found in audit DB", path),
        );
    }

    // Duplicate check: if duplicates exist, they must be bounded.
    let max_dupes: i64 = verify_conn
        .query_row(
            "SELECT MAX(cnt) FROM (SELECT COUNT(*) as cnt FROM audit_log GROUP BY timestamp, path)",
            [],
            |r| r.get(0),
        )
        .unwrap_or(1);
    // Duplicates bounded by crash_cycles (each crash can cause at most 1 retry per entry).
    engine.check_ctx(
        InvariantId::I3NoPermanentLoss,
        max_dupes <= (crash_cycles as i64 + 1),
        format!("Excessive duplicates: max {} per entry", max_dupes),
        vec![
            ("max_dupes", max_dupes.to_string()),
            ("crash_cycles", crash_cycles.to_string()),
        ],
    );

    // I10: WAL permissions intact.
    let mode = wal_file_mode(dir.path());
    engine.check(
        InvariantId::I10WalPermissions0600,
        mode == WAL_EXPECTED_MODE,
        format!("WAL mode {:o}", mode),
    );

    artifacts.set_wal_summary(wal.file_size(), wal.pending_count(), num_records as u64);
    artifacts.set_audit_summary(audit_entry_count, breaks.is_empty(), breaks.len());
    artifacts.write_on_failure(dir.path(), &engine);
    engine.assert_ok();
}
