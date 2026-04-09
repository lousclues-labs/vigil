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

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    config: Arc<ArcSwap<Config>>,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<DaemonState>>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
    backpressure: Arc<AtomicBool>,
    baseline_db_identity: Option<crate::db::DbFileIdentity>,
    audit_db_identity: Option<crate::db::DbFileIdentity>,
    startup_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    startup_baseline_conn: rusqlite::Connection,
    startup_audit_conn: rusqlite::Connection,
) -> crate::Result<JoinHandle<()>> {
    // Compute initial config hash for integrity tracking
    let mut last_config_hash = config_file_hash();

    // Record initial mount set for bind-mount detection
    let initial_mounts: std::collections::HashSet<std::path::PathBuf> =
        crate::monitor::fanotify::parse_mountinfo()
            .unwrap_or_default()
            .into_iter()
            .collect();

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
                        if let Some(ref key) = startup_hmac_key {
                            if let Some(content) = config_file_content() {
                                let current_hmac =
                                    crate::hmac::compute_hmac(key, &content).unwrap_or_default();
                                // Load stored config HMAC from startup baseline connection
                                let stored = crate::db::baseline_ops::get_config_state(
                                    &startup_baseline_conn,
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
                                                &startup_baseline_conn,
                                                "config_file_hmac",
                                                &current_hmac,
                                            );
                                    }
                                    _ => {} // HMAC matches, proceed
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

                    // TOCTOU check: verify baseline DB has not been replaced since startup
                    if let Some(ref identity) = baseline_db_identity {
                        match identity.is_replaced(&cfg.daemon.db_path) {
                            Ok(true) => {
                                tracing::error!(
                                    "baseline database file replaced — possible tampering. \
                                     Inode/device changed since startup."
                                );
                                let mut s = state.write();
                                *s = DaemonState::Degraded {
                                    reason: "baseline_db_replaced".into(),
                                    since: Utc::now(),
                                };
                                // Skip all housekeeping when DB identity is compromised
                                last_tick = std::time::Instant::now();
                                continue;
                            }
                            Ok(false) => {} // identity matches, proceed
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "failed to stat baseline database for TOCTOU check"
                                );
                            }
                        }
                    }

                    // TOCTOU check: verify audit DB has not been replaced since startup
                    if let Some(ref identity) = audit_db_identity {
                        let audit_path = db::audit_db_path(&cfg);
                        match identity.is_replaced(&audit_path) {
                            Ok(true) => {
                                tracing::error!(
                                    "audit database file replaced — possible evidence \
                                     destruction. Inode/device changed since startup."
                                );
                                let mut s = state.write();
                                *s = DaemonState::Degraded {
                                    reason: "audit_db_replaced".into(),
                                    since: Utc::now(),
                                };
                                last_tick = std::time::Instant::now();
                                continue;
                            }
                            Ok(false) => {} // identity matches, proceed
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "failed to stat audit database for TOCTOU check"
                                );
                            }
                        }
                    }

                    // Bind-mount evasion detection: compare current mounts against
                    // the set established at startup. New mounts over watched paths
                    // could evade fanotify monitoring.
                    if let Some(current_mounts) = crate::monitor::fanotify::parse_mountinfo() {
                        let current_set: std::collections::HashSet<std::path::PathBuf> =
                            current_mounts.into_iter().collect();
                        let new_mounts: Vec<_> = current_set
                            .difference(&initial_mounts)
                            .collect();
                        if !new_mounts.is_empty() {
                            // Check if any new mount is over a watched path
                            for mount in &new_mounts {
                                for group in cfg.watch.values() {
                                    let expanded = crate::config::expand_user_paths(&group.paths);
                                    for watch_path in &expanded {
                                        if mount.starts_with(watch_path)
                                            || watch_path.starts_with(mount.as_path())
                                        {
                                            tracing::error!(
                                                mount = %mount.display(),
                                                watch_path = %watch_path.display(),
                                                "new mount detected over watched path — \
                                                 real-time monitoring may be compromised"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Clock anomaly detection: detect both forward and backward clock jumps.
                    // Forward jump > 1 hour or backward jump > 60 seconds indicates
                    // possible clock manipulation (replay or evidence destruction).
                    let now_ts = Utc::now().timestamp();
                    let clock_delta = now_ts - last_rotation_timestamp;
                    let clock_anomaly = if clock_delta > 3600 {
                        tracing::error!(
                            jump_secs = clock_delta,
                            "forward clock anomaly detected — skipping audit rotation to prevent evidence loss"
                        );
                        true
                    } else if clock_delta < -60 {
                        tracing::error!(
                            jump_secs = clock_delta,
                            "negative clock jump detected — skipping audit rotation (possible clock manipulation replay)"
                        );
                        true
                    } else {
                        false
                    };

                    if clock_anomaly {
                        // Do NOT update last_rotation_timestamp on any clock anomaly
                    } else {
                        // Use the startup audit connection — never re-open by path
                        {
                            // Safety check: count total entries and compute how many
                            // would be deleted. Skip if > 50% would be removed.
                            let total: i64 = startup_audit_conn
                                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
                                .unwrap_or(0);
                            let cutoff = now_ts - (cfg.database.audit_retention_days as i64 * 86400);
                            let would_delete: i64 = startup_audit_conn
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
                                match db::audit_ops::rotate_audit_log(&startup_audit_conn, cfg.database.audit_retention_days) {
                                    Ok(0) => {}
                                    Ok(n) => tracing::info!(deleted = n, "rotated old audit entries"),
                                    Err(e) => tracing::warn!(error = %e, "audit rotation failed"),
                                }
                            }
                        }
                        last_rotation_timestamp = now_ts;
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
                        // Use startup connections — never re-open by path
                        match startup_baseline_conn.pragma_update(None, "wal_checkpoint", "PASSIVE") {
                            Ok(()) => tracing::debug!("WAL checkpoint (baseline) completed"),
                            Err(e) => tracing::warn!(error = %e, "WAL checkpoint (baseline) failed"),
                        }
                        match startup_audit_conn.pragma_update(None, "wal_checkpoint", "PASSIVE") {
                            Ok(()) => tracing::debug!("WAL checkpoint (audit) completed"),
                            Err(e) => tracing::warn!(error = %e, "WAL checkpoint (audit) failed"),
                        }
                    }

                    last_tick = std::time::Instant::now();
                }

                if is_notify_socket_safe() {
                    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                }

                std::thread::sleep(Duration::from_millis(1000));
            }
        })
        .map_err(|e| crate::VigilError::Daemon(format!("cannot spawn coordinator thread: {}", e)))
}

fn write_metrics_snapshot(runtime_dir: &std::path::Path, metrics: &Metrics) -> crate::Result<()> {
    std::fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join("metrics.json");
    let data = serde_json::to_vec_pretty(&metrics.snapshot())?;
    atomic_write(&path, &data)?;
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

    atomic_write(&path, &serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

/// Atomically write data to a file by writing to a temp file in the same
/// directory, then rename(). rename() on the same filesystem is atomic on Linux.
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> crate::Result<()> {
    use std::io::Write;

    let dir = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/tmp"));

    // Build temp file name from target filename + PID + counter for uniqueness
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vigil".to_string());
    let tmp_name = format!(".{}.{}.tmp", file_name, std::process::id());
    let tmp_path = dir.join(&tmp_name);

    let mut f = std::fs::File::create(&tmp_path)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Compute the BLAKE3 hash of the current config file, if found.
fn config_file_hash() -> Option<String> {
    config_file_content().map(|content| crate::hash::blake3_hash_bytes(&content))
}

/// Read raw config file content from the standard search paths.
fn config_file_content() -> Option<Vec<u8>> {
    #[cfg(any(test, debug_assertions))]
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        if let Ok(content) = std::fs::read(&env_path) {
            return Some(content);
        }
    }
    #[cfg(not(any(test, debug_assertions)))]
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        // In production, validate ownership before reading
        use std::os::unix::fs::MetadataExt;
        let p = std::path::Path::new(&env_path);
        if let Ok(meta) = std::fs::metadata(p) {
            let mode = meta.mode() & 0o777;
            if meta.uid() == 0 && mode <= 0o644 {
                if let Ok(content) = std::fs::read(p) {
                    return Some(content);
                }
            }
        }
    }
    std::fs::read("/etc/vigil/vigil.toml").ok()
}

/// Validate that NOTIFY_SOCKET points to a safe systemd-controlled path.
/// Rejects non-standard paths to prevent lifecycle state leaks.
pub fn is_notify_socket_safe() -> bool {
    match std::env::var("NOTIFY_SOCKET") {
        Ok(val) => {
            // Abstract sockets (@-prefixed) are acceptable
            if val.starts_with('@') {
                return true;
            }
            // Only accept paths under /run/systemd/
            if val.starts_with("/run/systemd/") {
                return true;
            }
            tracing::warn!(
                socket = %val,
                "NOTIFY_SOCKET points to non-standard path — ignoring to prevent \
                 lifecycle state leak"
            );
            false
        }
        Err(_) => {
            // No NOTIFY_SOCKET set — sd_notify will be a no-op anyway
            true
        }
    }
}
