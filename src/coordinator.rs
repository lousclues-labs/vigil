use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::config::Config;
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

/// Arguments for spawning the coordinator thread.
pub struct CoordinatorConfig {
    pub config: Arc<ArcSwap<Config>>,
    pub metrics: Arc<Metrics>,
    pub state: Arc<RwLock<DaemonState>>,
    pub watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    pub shutdown: Arc<AtomicBool>,
    pub reload_flag: Arc<AtomicBool>,
    pub backpressure: Arc<AtomicBool>,
    pub baseline_db_identity: Option<crate::db::DbFileIdentity>,
    pub audit_db_identity: Option<crate::db::DbFileIdentity>,
    pub startup_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub startup_baseline_conn: rusqlite::Connection,
    pub startup_audit_conn: rusqlite::Connection,
    pub reconfigure_tx: Option<crossbeam_channel::Sender<Vec<std::path::PathBuf>>>,
    pub wal_identity: Option<crate::db::DbFileIdentity>,
    pub wal_path: Option<std::path::PathBuf>,
    pub maintenance_active: Arc<AtomicBool>,
    pub maintenance_entered_at: Arc<AtomicI64>,
}

struct Coordinator {
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
    reconfigure_tx: Option<crossbeam_channel::Sender<Vec<std::path::PathBuf>>>,
    wal_identity: Option<crate::db::DbFileIdentity>,
    wal_path: Option<std::path::PathBuf>,
    maintenance_active: Arc<AtomicBool>,
    maintenance_entered_at: Arc<AtomicI64>,
    last_config_hash: Option<String>,
    initial_mounts: std::collections::HashSet<std::path::PathBuf>,
    last_tick: std::time::Instant,
    checkpoint_counter: u32,
    last_dropped: u64,
    last_rotation_timestamp: i64,
}

pub fn spawn(cfg: CoordinatorConfig) -> crate::Result<std::thread::JoinHandle<()>> {
    let mut coordinator = Coordinator {
        config: cfg.config,
        metrics: cfg.metrics,
        state: cfg.state,
        watch_index: cfg.watch_index,
        shutdown: cfg.shutdown,
        reload_flag: cfg.reload_flag,
        backpressure: cfg.backpressure,
        baseline_db_identity: cfg.baseline_db_identity,
        audit_db_identity: cfg.audit_db_identity,
        startup_hmac_key: cfg.startup_hmac_key,
        startup_baseline_conn: cfg.startup_baseline_conn,
        startup_audit_conn: cfg.startup_audit_conn,
        reconfigure_tx: cfg.reconfigure_tx,
        wal_identity: cfg.wal_identity,
        wal_path: cfg.wal_path,
        maintenance_active: cfg.maintenance_active,
        maintenance_entered_at: cfg.maintenance_entered_at,
        last_config_hash: config_file_hash(),
        initial_mounts: crate::monitor::fanotify::parse_mountinfo()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        last_tick: std::time::Instant::now() - Duration::from_secs(60),
        checkpoint_counter: 0,
        last_dropped: 0,
        last_rotation_timestamp: Utc::now().timestamp(),
    };

    std::thread::Builder::new()
        .name("vigil-coordinator".into())
        .spawn(move || {
            while !coordinator.shutdown.load(Ordering::Acquire) {
                if coordinator.reload_flag.swap(false, Ordering::AcqRel) {
                    coordinator.handle_reload();
                }
                if coordinator.last_tick.elapsed() >= Duration::from_secs(60) {
                    coordinator.tick();
                }
                coordinator.notify_watchdog();
                std::thread::sleep(Duration::from_millis(1000));
            }
        })
        .map_err(|e| crate::VigilError::Daemon(format!("cannot spawn coordinator thread: {}", e)))
}

impl Coordinator {
    fn tick(&mut self) {
        if !self.check_baseline_db_identity() {
            return;
        }
        if !self.check_audit_db_identity() {
            return;
        }
        if !self.check_wal_identity() {
            return;
        }
        self.check_mount_evasion();
        self.notify_watchdog();
        let clock_anomaly = self.detect_clock_anomaly();
        if !clock_anomaly {
            self.rotate_audit_log();
        }
        self.notify_watchdog();
        self.write_snapshots();
        self.notify_watchdog();
        self.check_backpressure();
        self.check_event_drops();
        self.maybe_checkpoint_wal();
        self.check_maintenance_timeout();
        self.last_tick = std::time::Instant::now();
    }

    fn handle_reload(&mut self) {
        // Check config file integrity before reload
        let new_config_hash = config_file_hash();
        if new_config_hash != self.last_config_hash {
            tracing::warn!(
                old_hash = self.last_config_hash.as_deref().unwrap_or("none"),
                new_hash = new_config_hash.as_deref().unwrap_or("none"),
                "config file hash changed during reload"
            );
        }

        // If HMAC signing is enabled, verify config HMAC
        let cfg = self.config.load();
        if cfg.security.hmac_signing {
            if let Some(ref key) = self.startup_hmac_key {
                if let Some(content) = config_file_content() {
                    let current_hmac = crate::hmac::compute_hmac(key, &content).unwrap_or_default();
                    let stored = crate::db::baseline_ops::get_config_state(
                        &self.startup_baseline_conn,
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
                            return; // skip reload
                        }
                        None => {
                            // Store initial config HMAC
                            if let Err(e) = crate::db::baseline_ops::set_config_state(
                                &self.startup_baseline_conn,
                                "config_file_hmac",
                                &current_hmac,
                            ) {
                                tracing::error!(
                                    error = %e,
                                    "failed to store config file HMAC — tamper detection weakened"
                                );
                            }
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
                        return;
                    }
                }

                let old_cfg = self.config.load();
                let changes = crate::config::diff_config(&old_cfg, &new_cfg);
                for c in changes {
                    tracing::info!(change = %c, "config reloaded");
                }

                self.config.store(Arc::new(new_cfg.clone()));
                self.watch_index
                    .store(Arc::new(WatchGroupIndex::from_config(&new_cfg)));
                self.last_config_hash = new_config_hash.clone();

                // Notify the monitor to rebuild its Bloom filter with new watch paths
                if let Some(ref tx) = self.reconfigure_tx {
                    let new_paths = crate::monitor::collect_watch_paths(&new_cfg);
                    if let Err(e) = tx.send(new_paths) {
                        tracing::warn!(error = %e, "failed to send reconfigure to monitor");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "config reload failed");
            }
        }
    }

    /// Returns false if the DB identity check failed and tick should abort.
    fn check_baseline_db_identity(&mut self) -> bool {
        let cfg = self.config.load();
        if let Some(ref identity) = self.baseline_db_identity {
            match identity.is_replaced(&cfg.daemon.db_path) {
                Ok(true) => {
                    tracing::error!(
                        "baseline database file replaced — possible tampering. \
                         Inode/device changed since startup."
                    );
                    let mut s = self.state.write();
                    *s = DaemonState::Degraded {
                        reason: "baseline_db_replaced".into(),
                        since: Utc::now(),
                    };
                    self.last_tick = std::time::Instant::now();
                    return false;
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
        true
    }

    /// Returns false if the DB identity check failed and tick should abort.
    fn check_audit_db_identity(&mut self) -> bool {
        let cfg = self.config.load();
        if let Some(ref identity) = self.audit_db_identity {
            let audit_path = crate::db::audit_db_path(&cfg);
            match identity.is_replaced(&audit_path) {
                Ok(true) => {
                    tracing::error!(
                        "audit database file replaced — possible evidence \
                         destruction. Inode/device changed since startup."
                    );
                    let mut s = self.state.write();
                    *s = DaemonState::Degraded {
                        reason: "audit_db_replaced".into(),
                        since: Utc::now(),
                    };
                    self.last_tick = std::time::Instant::now();
                    return false;
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
        true
    }

    /// Returns false if WAL identity check failed and tick should abort.
    fn check_wal_identity(&mut self) -> bool {
        let (Some(identity), Some(path)) = (&self.wal_identity, &self.wal_path) else {
            return true;
        };

        match identity.is_replaced(path) {
            Ok(true) => {
                tracing::error!(
                    path = %path.display(),
                    "WAL file replaced — possible tampering. Inode/device changed since startup."
                );
                let mut s = self.state.write();
                *s = DaemonState::Degraded {
                    reason: "wal_file_replaced".into(),
                    since: Utc::now(),
                };
                self.last_tick = std::time::Instant::now();
                false
            }
            Ok(false) => true,
            Err(e) => {
                tracing::error!(error = %e, "failed to stat WAL file for TOCTOU check");
                true
            }
        }
    }

    fn check_mount_evasion(&self) {
        let cfg = self.config.load();
        if let Some(current_mounts) = crate::monitor::fanotify::parse_mountinfo() {
            let current_set: std::collections::HashSet<std::path::PathBuf> =
                current_mounts.into_iter().collect();
            let new_mounts: Vec<_> = current_set.difference(&self.initial_mounts).collect();
            if !new_mounts.is_empty() {
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
    }

    fn detect_clock_anomaly(&mut self) -> bool {
        let now_ts = Utc::now().timestamp();
        let clock_delta = now_ts - self.last_rotation_timestamp;
        if clock_delta > 3600 {
            tracing::error!(
                jump_secs = clock_delta,
                "forward clock anomaly detected — skipping audit rotation to prevent evidence loss"
            );
            self.last_rotation_timestamp = now_ts;
            true
        } else if clock_delta < -60 {
            tracing::error!(
                jump_secs = clock_delta,
                "negative clock jump detected — skipping audit rotation (possible clock manipulation replay)"
            );
            self.last_rotation_timestamp = now_ts;
            true
        } else {
            false
        }
    }

    fn rotate_audit_log(&mut self) {
        let cfg = self.config.load();
        let now_ts = Utc::now().timestamp();

        // Safety check: count total entries and compute how many
        // would be deleted. Skip if > 50% would be removed.
        let total: i64 = self
            .startup_audit_conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap_or(0);
        let cutoff = now_ts - (cfg.database.audit_retention_days as i64 * 86400);
        let would_delete: i64 = self
            .startup_audit_conn
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
            match crate::db::audit_ops::rotate_audit_log(
                &self.startup_audit_conn,
                cfg.database.audit_retention_days,
            ) {
                Ok(0) => {}
                Ok(n) => tracing::info!(deleted = n, "rotated old audit entries"),
                Err(e) => tracing::warn!(error = %e, "audit rotation failed"),
            }
        }
        self.last_rotation_timestamp = now_ts;
    }

    fn write_snapshots(&self) {
        let cfg = self.config.load();
        if let Err(e) = write_metrics_snapshot(&cfg.daemon.runtime_dir, &self.metrics) {
            tracing::warn!(error = %e, "failed to write metrics snapshot");
        }
        if let Err(e) = write_state_snapshot(&cfg.daemon.runtime_dir, &self.state) {
            tracing::warn!(error = %e, "failed to write state snapshot");
        }
        if let Err(e) = crate::doctor::write_health_snapshot(&cfg) {
            tracing::warn!(error = %e, "failed to write health snapshot");
        }
    }

    fn check_backpressure(&self) {
        if self.backpressure.load(Ordering::Relaxed) {
            let mut s = self.state.write();
            if matches!(*s, DaemonState::Healthy) {
                *s = DaemonState::Degraded {
                    reason: "event_backpressure".into(),
                    since: Utc::now(),
                };
            }
        }
    }

    fn check_event_drops(&mut self) {
        let current_dropped = self.metrics.events_dropped.load(Ordering::Relaxed);
        if current_dropped > self.last_dropped {
            let delta = current_dropped - self.last_dropped;
            tracing::error!(
                dropped = delta,
                total_dropped = current_dropped,
                "filesystem events are being dropped — possible evasion attack or I/O overload"
            );
        }
        self.last_dropped = current_dropped;
    }

    fn maybe_checkpoint_wal(&mut self) {
        self.checkpoint_counter += 1;
        if self.checkpoint_counter >= 5 {
            self.checkpoint_counter = 0;
            match self
                .startup_baseline_conn
                .pragma_update(None, "wal_checkpoint", "PASSIVE")
            {
                Ok(()) => tracing::debug!("WAL checkpoint (baseline) completed"),
                Err(e) => tracing::warn!(error = %e, "WAL checkpoint (baseline) failed"),
            }
            match self
                .startup_audit_conn
                .pragma_update(None, "wal_checkpoint", "PASSIVE")
            {
                Ok(()) => tracing::debug!("WAL checkpoint (audit) completed"),
                Err(e) => tracing::warn!(error = %e, "WAL checkpoint (audit) failed"),
            }
        }
    }

    fn notify_watchdog(&self) {
        if is_notify_socket_safe() {
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
        }
    }

    fn check_maintenance_timeout(&self) {
        if !self.maintenance_active.load(Ordering::Acquire) {
            return;
        }
        let entered_at = self.maintenance_entered_at.load(Ordering::Acquire);
        if entered_at == 0 {
            return;
        }
        let now = Utc::now().timestamp();
        let elapsed_secs = now - entered_at;
        // Auto-exit maintenance after 30 minutes (safety timeout)
        if elapsed_secs > 1800 {
            tracing::warn!(
                elapsed_secs = elapsed_secs,
                "maintenance window exceeded 30-minute safety timeout — auto-exiting"
            );
            self.maintenance_active.store(false, Ordering::Release);
            self.maintenance_entered_at.store(0, Ordering::Release);
        }
    }
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

/// rename() on the same filesystem is atomic on Linux.
pub(crate) fn atomic_write(path: &std::path::Path, data: &[u8]) -> crate::Result<()> {
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
pub(crate) fn is_notify_socket_safe() -> bool {
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
