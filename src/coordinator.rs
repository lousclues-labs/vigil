use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::config::Config;
use crate::db;
use crate::metrics::Metrics;
use crate::types::DaemonState;
use crate::watch_index::WatchGroupIndex;

pub fn spawn(
    config: Arc<ArcSwap<Config>>,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<DaemonState>>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
) -> crate::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vigil-coordinator".into())
        .spawn(move || {
            let mut last_tick = std::time::Instant::now();

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

                    if let Ok(audit_conn) = db::open_audit_db(&cfg) {
                        match db::audit_ops::rotate_audit_log(&audit_conn, cfg.database.audit_retention_days) {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(deleted = n, "rotated old audit entries"),
                            Err(e) => tracing::warn!(error = %e, "audit rotation failed"),
                        }
                    }

                    if let Err(e) = write_metrics_snapshot(&cfg.daemon.runtime_dir, &metrics) {
                        tracing::debug!(error = %e, "failed to write metrics snapshot");
                    }
                    if let Err(e) = write_state_snapshot(&cfg.daemon.runtime_dir, &state) {
                        tracing::debug!(error = %e, "failed to write state snapshot");
                    }

                    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                    let _ = sd_notify::notify(
                        false,
                        &[sd_notify::NotifyState::Status("coordinator heartbeat")],
                    );

                    last_tick = std::time::Instant::now();
                }

                std::thread::sleep(Duration::from_millis(250));
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
