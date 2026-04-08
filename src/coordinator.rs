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

/// Source of a config reload request.
#[derive(Debug, Clone)]
pub enum ReloadSource {
    Signal,
    ControlSocket,
    Unknown,
}

pub fn spawn(
    config: Arc<ArcSwap<Config>>,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<DaemonState>>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
    backpressure: Arc<AtomicBool>,
) -> crate::Result<JoinHandle<()>> {
    // Compute initial config hash for integrity tracking
    let mut last_config_hash = config_file_hash();

    std::thread::Builder::new()
        .name("vigil-coordinator".into())
        .spawn(move || {
            // Trigger the first housekeeping/snapshot tick immediately on startup
            // so post-update doctor/status calls do not wait a full minute.
            let mut last_tick = std::time::Instant::now() - Duration::from_secs(60);
            let mut checkpoint_counter: u32 = 0;
            let mut last_dropped: u64 = 0;
            let mut last_rotation_timestamp = Utc::now().timestamp();

            while !shutdown.load(Ordering::Acquire) {
                if reload_flag.swap(false, Ordering::AcqRel) {
                    // Check config file integrity before reload
                    let new_config_hash = config_file_hash();
                    if new_config_hash != last_config_hash {
                        tracing::warn!(
                            old_hash = last_config_hash.as_deref().unwrap_or("none"),
                            new_hash = new_config_hash.as_deref().unwrap_or("none"),
                            "config file hash changed during reload"
                        );
                    }

                    // If HMAC signing is enabled, verify config HMAC
                    let cfg = config.load();
                    if cfg.security.hmac_signing {
                        if let Ok(key) = crate::hmac::load_hmac_key(&cfg.security.hmac_key_path) {
                            if let Some(content) = config_file_content() {
                                let current_hmac =
                                    crate::hmac::compute_hmac(&key, &content).unwrap_or_default();
                                // Load stored config HMAC from baseline db
                                if let Ok(baseline_conn) = db::open_baseline_db(&cfg) {
                                    let stored = crate::db::baseline_ops::get_config_state(
                                        &baseline_conn,
                                        "config_file_hmac",
                                    )
                                    .ok()
                                    .flatten();
                                    match stored {
                                        Some(ref expected) if expected != &current_hmac => {
                                            tracing::error!(
                                                "config reload REJECTED: config file HMAC \
                                                 verification failed. The config file may \
                                                 have been tampered with."
                                            );
                                            continue; // skip reload
                                        }
                                        None => {
                                            // Store initial config HMAC
                                            let _ =
                                                crate::db::baseline_ops::set_config_state(
                                                    &baseline_conn,
                                                    "config_file_hmac",
                                                    &current_hmac,
                                                );
                                        }
                                        _ => {} // HMAC matches, proceed
                                    }
                                }
                            }
                        }
                    }

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
                            last_config_hash = new_config_hash.clone();
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "config reload failed");
                        }
                    }
                }

                if last_tick.elapsed() >= Duration::from_secs(60) {
                    let cfg = config.load();

                    // Clock anomaly detection: if the wall clock has jumped forward
                    // by more than 1 hour since the last tick, skip audit rotation
                    // to prevent evidence destruction via clock manipulation.
                    let now_ts = Utc::now().timestamp();
                    let clock_delta = now_ts - last_rotation_timestamp;
                    if clock_delta > 3600 {
                        tracing::error!(
                            jump_secs = clock_delta,
                            "clock anomaly detected — skipping audit rotation to prevent evidence loss"
                        );
                    } else {
                        match db::open_audit_db(&cfg) {
                            Ok(audit_conn) => {
                                // Safety check: count total entries and compute how many
                                // would be deleted. Skip if > 50% would be removed.
                                let total: i64 = audit_conn
                                    .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
                                    .unwrap_or(0);
                                let cutoff = now_ts - (cfg.database.audit_retention_days as i64 * 86400);
                                let would_delete: i64 = audit_conn
                                    .query_row(
                                        "SELECT COUNT(*) FROM audit_log WHERE timestamp < ?1",
                                        rusqlite::params![cutoff],
                                        |row| row.get(0),
                                    )
                                    .unwrap_or(0);

                                if total > 0 && would_delete * 2 > total {
                                    tracing::error!(
                                        total = total,
                                        would_delete = would_delete,
                                        "audit rotation would delete >50% of entries — skipping (possible clock manipulation)"
                                    );
                                } else {
                                    match db::audit_ops::rotate_audit_log(&audit_conn, cfg.database.audit_retention_days) {
                                        Ok(0) => {}
                                        Ok(n) => tracing::info!(deleted = n, "rotated old audit entries"),
                                        Err(e) => tracing::warn!(error = %e, "audit rotation failed"),
                                    }
                                }
                            }
                            Err(e) => tracing::error!(error = %e, "failed to open audit database for rotation"),
                        }
                    }
                    last_rotation_timestamp = now_ts;

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

                    // Detect sustained event drops (possible evasion attack)
                    let current_dropped =
                        metrics.events_dropped.load(Ordering::Relaxed);
                    if current_dropped > last_dropped {
                        let delta = current_dropped - last_dropped;
                        tracing::error!(
                            dropped = delta,
                            total_dropped = current_dropped,
                            "filesystem events are being dropped — possible evasion attack or I/O overload"
                        );
                    }
                    last_dropped = current_dropped;

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

/// Compute the BLAKE3 hash of the current config file, if found.
fn config_file_hash() -> Option<String> {
    config_file_content().map(|content| crate::hash::blake3_hash_bytes(&content))
}

/// Read raw config file content from the standard search paths.
fn config_file_content() -> Option<Vec<u8>> {
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        if let Ok(content) = std::fs::read(&env_path) {
            return Some(content);
        }
    }
    std::fs::read("/etc/vigil/vigil.toml").ok()
}
