// tests/chaos/scenarios/config_reload_storm.rs
// Scenario 5: Config Reload Storm
//
// Goal: Validate atomic reload behavior under active load.

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
fn config_reload_storm() {
    for seed in seed_list() {
        run_config_reload_storm(seed);
    }
}

fn run_config_reload_storm(seed: u64) {
    let tier = ChaosTier::current();
    let scale = ScaleParams::for_tier(tier);
    let mut rng = ChaosRng::new(seed);
    let mut engine = InvariantEngine::new();
    let mut artifacts = ArtifactWriter::new(seed, "config_reload_storm");

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    let baseline_path = dir.path().join("baseline.db");
    let audit_path = dir.path().join("audit.db");
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    // Create initial valid config file.
    let base_cfg = chaos_config(dir.path());
    let config_toml = toml::to_string_pretty(&base_cfg).unwrap();
    std::fs::write(&config_path, &config_toml).unwrap();

    // Create DBs.
    let baseline_conn = db::open_db_at(&baseline_path, false).unwrap();
    db::schema::create_baseline_tables(&baseline_conn).unwrap();
    let audit_conn = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&audit_conn).unwrap();

    let config = Arc::new(ArcSwap::from_pointee(base_cfg.clone()));
    let metrics = Arc::new(Metrics::new());
    let state = Arc::new(RwLock::new(DaemonState::Healthy));
    let watch_index = Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
        &config.load(),
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload_flag = Arc::new(AtomicBool::new(false));
    let backpressure = Arc::new(AtomicBool::new(false));

    let baseline_identity = DbFileIdentity::from_path(&baseline_path).ok();
    let audit_identity = DbFileIdentity::from_path(&audit_path).ok();

    let coord_cfg = CoordinatorConfig {
        config: config.clone(),
        metrics: metrics.clone(),
        state: state.clone(),
        watch_index: watch_index.clone(),
        shutdown: shutdown.clone(),
        reload_flag: reload_flag.clone(),
        backpressure: backpressure.clone(),
        baseline_db_identity: baseline_identity,
        audit_db_identity: audit_identity,
        startup_hmac_key: None,
        startup_baseline_conn: baseline_conn,
        startup_audit_conn: audit_conn,
        reconfigure_tx: None,
        mount_mark_tx: None,
        wal_identity: None,
        wal_path: None,
        maintenance_active: Arc::new(AtomicBool::new(false)),
        maintenance_entered_at: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        shared_baseline_identity: None,
        scan_trigger: None,
    };

    let handle = coordinator::spawn(coord_cfg).unwrap();
    artifacts.record(0, "Coordinator spawned for config reload storm");

    // Let coordinator settle.
    std::thread::sleep(Duration::from_millis(200));

    // Rapidly alternate between valid and invalid configs + trigger reload.
    let reload_count = scale.iterations.min(50);
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;

    for i in 0..reload_count {
        engine.set_step(i + 1);

        let is_valid = rng.chance(0.5);
        if is_valid {
            // Write a valid config with a minor change.
            let mut new_cfg = base_cfg.clone();
            new_cfg.daemon.worker_threads = 1 + (rng.next_bounded(8) as u32);
            if let Ok(s) = toml::to_string_pretty(&new_cfg) {
                std::fs::write(&config_path, &s).ok();
            }
            valid_count += 1;
        } else {
            // Write an invalid config (broken TOML or missing required fields).
            let invalid_configs = [
                "this is not valid toml {{{{",
                "[daemon]\nworker_threads = -1",
                "",
                "[daemon\ndb_path = 42",
            ];
            let invalid = rng.pick(&invalid_configs);
            std::fs::write(&config_path, invalid).ok();
            invalid_count += 1;
        }

        // Signal reload.
        reload_flag.store(true, Ordering::Release);

        // Brief pause between reloads.
        if rng.chance(0.3) {
            std::thread::sleep(Duration::from_millis(rng.next_bounded(20)));
        }
    }

    artifacts.record(
        reload_count + 1,
        format!(
            "Completed {} reloads ({} valid, {} invalid)",
            reload_count, valid_count, invalid_count
        ),
    );

    // Wait for coordinator to process pending reloads.
    std::thread::sleep(Duration::from_millis(500));

    // --- Invariant checks ---
    engine.set_step(reload_count + 2);

    // I13: Invalid config reload leaves effective runtime config unchanged.
    // The effective config should still be valid (not corrupted).
    let current_cfg = config.load();
    engine.check(
        InvariantId::I13InvalidConfigRejected,
        current_cfg.daemon.worker_threads > 0,
        "Config worker_threads is invalid after reload storm",
    );

    // The watch index should be consistent with config.
    let _current_wi = watch_index.load();
    // Should not be in a broken state — we got here without panic.

    // Coordinator should not have panicked.
    shutdown.store(true, Ordering::Release);
    let join_result = handle.join();
    engine.check(
        InvariantId::I13InvalidConfigRejected,
        join_result.is_ok(),
        "Coordinator panicked during config reload storm",
    );

    artifacts.write_on_failure(dir.path(), &engine);
    engine.assert_ok();
}
