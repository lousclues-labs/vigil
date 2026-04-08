use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::config::Config;
use crate::db;
use crate::doctor;
use crate::metrics::Metrics;
use crate::types::DaemonState;
use crate::watch_index::WatchGroupIndex;

use chrono::Utc;

pub fn spawn(
    config: Arc<ArcSwap<Config>>,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<DaemonState>>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
    backpressure: Arc<AtomicBool>,
) -> crate::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vigil-coordinator".into())
        .spawn(move || {
            // Trigger the first housekeeping/snapshot tick immediately on startup
            // so post-update doctor/status calls do not wait a full minute.
            let mut last_tick = std::time::Instant::now() - Duration::from_secs(60);
            let mut checkpoint_counter: u32 = 0;

            while !shutdown.load(Ordering::Acquire) {
                if reload_flag.swap(false, Ordering::AcqRel) {
                    match crate::config::load_config(None) {
                        Ok(new_cfg) => {
                            match crate::config::validate_config_deep(&new_cfg) {
                                Ok(warnings) => {
                                    for w in warnings {
                                        tracing::warn!(warning = %w, "config validation warning");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "reloaded config rejected by deep validation");
                                    continue;
                                }
                            }

                            let old_cfg = config.load();
                            let changes = crate::config::diff_config(&old_cfg, &new_cfg);
                            for c in changes {
                                tracing::info!(change = %c, "config reloaded");
                            }

                            config.store(Arc::new(new_cfg.clone()));
                            watch_index.store(Arc::new(WatchGroupIndex::from_config(&new_cfg)));
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "config reload failed");
                        }
                    }
                }

                if last_tick.elapsed() >= Duration::from_secs(60) {
                    let cfg = config.load();

                    match db::open_audit_db(&cfg) {
                        Ok(audit_conn) => {
                            match db::audit_ops::rotate_audit_log(&audit_conn, cfg.database.audit_retention_days) {
                                Ok(0) => {}
                                Ok(n) => tracing::info!(deleted = n, "rotated old audit entries"),
                                Err(e) => tracing::warn!(error = %e, "audit rotation failed"),
                            }
                        }
                        Err(e) => tracing::error!(error = %e, "failed to open audit database for rotation"),
                    }

                    if let Err(e) = write_metrics_snapshot(&cfg.daemon.runtime_dir, &metrics) {
                        tracing::warn!(error = %e, "failed to write metrics snapshot");
                    }

                    // Check for backpressure and update daemon state
                    if backpressure.load(Ordering::Relaxed) {
                        let mut s = state.write();
                        if matches!(*s, DaemonState::Healthy) {
                            *s = DaemonState::Degraded {
                                reason: "event_backpressure".into(),
                                since: Utc::now(),
                            };
                        }
                    }

                    if let Err(e) = write_state_snapshot(&cfg.daemon.runtime_dir, &state) {
                        tracing::warn!(error = %e, "failed to write state snapshot");
                    }
                    if let Err(e) = doctor::write_health_snapshot(&cfg) {
                        tracing::warn!(error = %e, "failed to write health snapshot");
                    }

                    // Periodic WAL checkpoint every 5 minutes
                    checkpoint_counter += 1;
                    if checkpoint_counter >= 5 {
                        checkpoint_counter = 0;
                        match db::open_baseline_db(&cfg) {
                            Ok(baseline_conn) => {
                                match baseline_conn.pragma_update(None, "wal_checkpoint", "PASSIVE") {
                                    Ok(()) => tracing::debug!("WAL checkpoint (baseline) completed"),
                                    Err(e) => tracing::warn!(error = %e, "WAL checkpoint (baseline) failed"),
                                }
                            }
                            Err(e) => tracing::error!(error = %e, "failed to open baseline database for WAL checkpoint"),
                        }
                        match db::open_audit_db(&cfg) {
                            Ok(audit_conn) => {
                                match audit_conn.pragma_update(None, "wal_checkpoint", "PASSIVE") {
                                    Ok(()) => tracing::debug!("WAL checkpoint (audit) completed"),
                                    Err(e) => tracing::warn!(error = %e, "WAL checkpoint (audit) failed"),
                                }
                            }
                            Err(e) => tracing::error!(error = %e, "failed to open audit database for WAL checkpoint"),
                        }
                    }

                    last_tick = std::time::Instant::now();
                }

                let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);

                std::thread::sleep(Duration::from_millis(1000));
            }
        })
        .map_err(|e| crate::VigilError::Daemon(format!("cannot spawn coordinator thread: {}", e)))
}

fn write_metrics_snapshot(runtime_dir: &std::path::Path, metrics: &Metrics) -> crate::Result<()> {
    std::fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join("metrics.json");
    let data = serde_json::to_vec_pretty(&metrics.snapshot())?;
    std::fs::write(path, data)?;
    Ok(())
}

fn write_state_snapshot(
    runtime_dir: &std::path::Path,
    state: &RwLock<DaemonState>,
) -> crate::Result<()> {
    std::fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join("state.json");

    let value = match &*state.read() {
        DaemonState::Healthy => serde_json::json!({
            "status": "healthy"
        }),
        DaemonState::Degraded { reason, since } => serde_json::json!({
            "status": "degraded",
            "reason": reason,
            "since": since,
        }),
    };

    std::fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}
