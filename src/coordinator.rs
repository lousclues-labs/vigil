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
    pub mount_mark_tx:
        Option<crossbeam_channel::Sender<crate::monitor::fanotify::MountMarkRequest>>,
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
    startup_baseline_conn: Option<rusqlite::Connection>,
    startup_audit_conn: Option<rusqlite::Connection>,
    reconfigure_tx: Option<crossbeam_channel::Sender<Vec<std::path::PathBuf>>>,
    mount_mark_tx: Option<crossbeam_channel::Sender<crate::monitor::fanotify::MountMarkRequest>>,
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
    drift_samples: [u64; 5],
    drift_sample_idx: usize,
    last_changes_seen: u64,
    last_tick_monotonic: std::time::Instant,
    last_kernel_overflows: u64,
    clean_ticks_since_event_loss: u32,
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
        startup_baseline_conn: Some(cfg.startup_baseline_conn),
        startup_audit_conn: Some(cfg.startup_audit_conn),
        reconfigure_tx: cfg.reconfigure_tx,
        mount_mark_tx: cfg.mount_mark_tx,
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
        drift_samples: [0; 5],
        drift_sample_idx: 0,
        last_changes_seen: 0,
        last_tick_monotonic: std::time::Instant::now(),
        last_kernel_overflows: 0,
        clean_ticks_since_event_loss: 0,
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
        let tick_start = std::time::Instant::now();

        let t = std::time::Instant::now();
        if !self.check_baseline_db_identity() {
            return;
        }
        let baseline_check_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        if !self.check_audit_db_identity() {
            return;
        }
        let audit_check_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        if !self.check_wal_identity() {
            return;
        }
        let wal_check_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        self.check_mount_evasion();
        let mount_check_ms = t.elapsed().as_millis();

        self.notify_watchdog();

        let t = std::time::Instant::now();
        let clock_anomaly = self.detect_clock_anomaly();
        let clock_check_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        if !clock_anomaly {
            self.rotate_audit_log();
        }
        let rotation_ms = t.elapsed().as_millis();

        self.notify_watchdog();

        let t = std::time::Instant::now();
        self.write_snapshots();
        let snapshots_ms = t.elapsed().as_millis();

        self.notify_watchdog();

        let t = std::time::Instant::now();
        self.check_backpressure();
        let backpressure_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        self.check_event_drops();
        let drops_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        self.maybe_checkpoint_wal();
        let checkpoint_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        self.check_maintenance_timeout();
        let maintenance_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        self.check_drift_velocity();
        let drift_ms = t.elapsed().as_millis();

        let total_ms = tick_start.elapsed().as_millis();

        // Log individual sub-method timings if any exceeded 5 seconds
        let threshold_ms = 5000;
        for (name, dur) in [
            ("baseline_check", baseline_check_ms),
            ("audit_check", audit_check_ms),
            ("wal_check", wal_check_ms),
            ("mount_check", mount_check_ms),
            ("clock_check", clock_check_ms),
            ("rotation", rotation_ms),
            ("snapshots", snapshots_ms),
            ("backpressure", backpressure_ms),
            ("drops", drops_ms),
            ("checkpoint", checkpoint_ms),
            ("maintenance", maintenance_ms),
            ("drift", drift_ms),
        ] {
            if dur > threshold_ms {
                tracing::warn!(
                    method = name,
                    duration_ms = dur as u64,
                    "coordinator tick: {} took {}ms",
                    name,
                    dur
                );
            }
        }

        if total_ms > 10_000 {
            tracing::warn!(
                total_ms = total_ms as u64,
                baseline_check_ms = baseline_check_ms as u64,
                audit_check_ms = audit_check_ms as u64,
                wal_check_ms = wal_check_ms as u64,
                mount_check_ms = mount_check_ms as u64,
                clock_check_ms = clock_check_ms as u64,
                rotation_ms = rotation_ms as u64,
                snapshots_ms = snapshots_ms as u64,
                backpressure_ms = backpressure_ms as u64,
                drops_ms = drops_ms as u64,
                checkpoint_ms = checkpoint_ms as u64,
                maintenance_ms = maintenance_ms as u64,
                drift_ms = drift_ms as u64,
                "coordinator tick took {}ms",
                total_ms
            );
        }

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
                if let Some(ref conn) = self.startup_baseline_conn {
                    if let Some(content) = config_file_content() {
                        let current_hmac =
                            crate::hmac::compute_hmac(key, &content).unwrap_or_default();
                        let stored =
                            crate::db::baseline_ops::get_config_state(conn, "config_file_hmac")
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
                                    conn,
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
                } else {
                    // VIGIL-VULN-071: DB connection dropped after Degraded transition
                    tracing::warn!("skipping config HMAC check: baseline DB connection dropped (daemon degraded)");
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
                    // VIGIL-VULN-071: drop stale connection immediately
                    self.startup_baseline_conn = None;
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
                    // VIGIL-VULN-071: drop stale connection immediately
                    self.startup_audit_conn = None;
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
                // Expand watch paths once before checking against all new mounts
                let all_watch_paths: Vec<std::path::PathBuf> = cfg
                    .watch
                    .values()
                    .flat_map(|group| crate::config::expand_user_paths(&group.paths))
                    .collect();
                for mount in &new_mounts {
                    for watch_path in &all_watch_paths {
                        if mount.starts_with(watch_path) || watch_path.starts_with(mount.as_path())
                        {
                            tracing::error!(
                                mount = %mount.display(),
                                watch_path = %watch_path.display(),
                                "new mount detected over watched path — \
                                 real-time monitoring may be compromised"
                            );
                            // VIGIL-VULN-069: dynamically apply fanotify mark
                            // to the new mount so events under it are monitored.
                            if let Some(ref tx) = self.mount_mark_tx {
                                use crate::monitor::fanotify::{MountMarkOp, MountMarkRequest};
                                if let Err(e) = tx.send(MountMarkRequest {
                                    mount: mount.to_path_buf(),
                                    op: MountMarkOp::Add,
                                }) {
                                    tracing::error!(
                                        mount = %mount.display(),
                                        error = %e,
                                        "failed to send mount mark request to fanotify thread"
                                    );
                                    self.metrics
                                        .fanotify_mark_failures
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                // inotify backend or no channel — log degradation
                                tracing::error!(
                                    mount = %mount.display(),
                                    "mount evasion detected but no fanotify mark channel available — \
                                     modifications under new mount not monitored until next scan"
                                );
                            }
                        }
                    }
                }
            }
            // Check for disappeared overlapping mounts — remove marks
            let disappeared: Vec<_> = self.initial_mounts.difference(&current_set).collect();
            if !disappeared.is_empty() {
                if let Some(ref tx) = self.mount_mark_tx {
                    for mount in disappeared {
                        use crate::monitor::fanotify::{MountMarkOp, MountMarkRequest};
                        let _ = tx.send(MountMarkRequest {
                            mount: mount.to_path_buf(),
                            op: MountMarkOp::Remove,
                        });
                    }
                }
            }
        }
    }

    fn detect_clock_anomaly(&mut self) -> bool {
        let now_ts = Utc::now().timestamp();
        let wall_delta = now_ts - self.last_rotation_timestamp;
        let mono_delta = self.last_tick_monotonic.elapsed().as_secs() as i64;
        let clock_skew = wall_delta - mono_delta;

        // VIGIL-VULN-070: compare wall-clock delta against monotonic delta.
        // A 5-second tolerance handles normal NTP adjustments; anything larger
        // indicates active clock manipulation.
        if clock_skew.abs() > 5 {
            tracing::error!(
                wall_delta,
                mono_delta,
                clock_skew,
                "clock skew detected (wall vs monotonic) — skipping audit rotation"
            );
            let mut s = self.state.write();
            if matches!(*s, DaemonState::Healthy) {
                *s = DaemonState::Degraded {
                    reason: "clock_skew_detected".into(),
                    since: Utc::now(),
                };
            }
            self.last_rotation_timestamp = now_ts;
            self.last_tick_monotonic = std::time::Instant::now();
            return true;
        }

        // Coarse second-line checks for large jumps
        if wall_delta > 3600 {
            tracing::error!(
                jump_secs = wall_delta,
                "forward clock anomaly detected — skipping audit rotation to prevent evidence loss"
            );
            self.last_rotation_timestamp = now_ts;
            self.last_tick_monotonic = std::time::Instant::now();
            return true;
        }
        if wall_delta < -60 {
            tracing::error!(
                jump_secs = wall_delta,
                "negative clock jump detected — skipping audit rotation (possible clock manipulation replay)"
            );
            self.last_rotation_timestamp = now_ts;
            self.last_tick_monotonic = std::time::Instant::now();
            return true;
        }

        // VIGIL-VULN-070: refuse rotation when max audit timestamp is in the
        // future (indicates clock was rolled back past existing entries).
        if let Some(ref conn) = self.startup_audit_conn {
            match conn.query_row("SELECT MAX(timestamp) FROM audit_log", [], |row| {
                row.get::<_, Option<i64>>(0)
            }) {
                Ok(Some(max_ts)) if max_ts > now_ts => {
                    tracing::error!(
                        max_audit_ts = max_ts,
                        now = now_ts,
                        "max audit timestamp is in the future — refusing rotation (clock rollback)"
                    );
                    return true;
                }
                _ => {}
            }
        }

        self.last_tick_monotonic = std::time::Instant::now();
        false
    }

    fn rotate_audit_log(&mut self) {
        let conn = match self.startup_audit_conn.as_ref() {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "skipping audit rotation: audit DB connection dropped (daemon degraded)"
                );
                return;
            }
        };
        let cfg = self.config.load();
        let now_ts = Utc::now().timestamp();

        // Safety check: count total entries and compute how many
        // would be deleted. Skip if > 50% would be removed.
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap_or(0);
        let cutoff = now_ts - (cfg.database.audit_retention_days as i64 * 86400);
        let would_delete: i64 = conn
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
            match crate::db::audit_ops::rotate_audit_log(conn, cfg.database.audit_retention_days) {
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

        let drift_velocity = if self.drift_sample_idx >= 5 {
            Some(self.drift_samples.iter().sum::<u64>() / 5)
        } else {
            None
        };
        if let Err(e) = write_state_snapshot(&cfg.daemon.runtime_dir, &self.state, drift_velocity) {
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
        } else {
            let mut s = self.state.write();
            if let DaemonState::Degraded { reason, .. } = &*s {
                if reason == "event_backpressure" {
                    tracing::info!("backpressure resolved — returning to healthy state");
                    *s = DaemonState::Healthy;
                }
            }
        }
    }

    fn check_event_drops(&mut self) {
        let current_dropped = self.metrics.events_dropped.load(Ordering::Relaxed);
        let current_overflows = self.metrics.kernel_queue_overflows.load(Ordering::Relaxed);
        let drop_delta = current_dropped.saturating_sub(self.last_dropped);
        let overflow_delta = current_overflows.saturating_sub(self.last_kernel_overflows);

        if drop_delta > 0 || overflow_delta > 0 {
            tracing::error!(
                dropped = drop_delta,
                total_dropped = current_dropped,
                kernel_overflows = overflow_delta,
                "filesystem events are being dropped — possible evasion attack or I/O overload"
            );
        }

        let cfg = self.config.load();
        let threshold = cfg.monitor.event_loss_alert_threshold.unwrap_or(10);

        // VIGIL-VULN-072: transition to Degraded when event loss exceeds threshold
        if drop_delta > threshold || overflow_delta > threshold {
            self.clean_ticks_since_event_loss = 0;
            let mut s = self.state.write();
            if matches!(*s, DaemonState::Healthy) {
                *s = DaemonState::Degraded {
                    reason: "event_loss_detected".into(),
                    since: Utc::now(),
                };
                tracing::error!(
                    drop_delta,
                    overflow_delta,
                    threshold,
                    "event loss threshold exceeded — entering Degraded state"
                );
            }
        } else if drop_delta == 0 && overflow_delta == 0 {
            let s = self.state.read();
            if let DaemonState::Degraded { reason, .. } = &*s {
                if reason == "event_loss_detected" {
                    drop(s);
                    self.clean_ticks_since_event_loss += 1;
                    if self.clean_ticks_since_event_loss >= 5 {
                        let mut s = self.state.write();
                        if let DaemonState::Degraded { reason, .. } = &*s {
                            if reason == "event_loss_detected" {
                                tracing::info!(
                                    "event loss recovered for 5 consecutive ticks — returning to Healthy"
                                );
                                *s = DaemonState::Healthy;
                                self.clean_ticks_since_event_loss = 0;
                            }
                        }
                    }
                }
            }
        } else {
            self.clean_ticks_since_event_loss = 0;
        }

        self.last_dropped = current_dropped;
        self.last_kernel_overflows = current_overflows;
    }

    fn maybe_checkpoint_wal(&mut self) {
        self.checkpoint_counter += 1;
        if self.checkpoint_counter >= 5 {
            self.checkpoint_counter = 0;
            if let Some(ref conn) = self.startup_baseline_conn {
                match conn.pragma_update(None, "wal_checkpoint", "PASSIVE") {
                    Ok(()) => tracing::debug!("WAL checkpoint (baseline) completed"),
                    Err(e) => tracing::warn!(error = %e, "WAL checkpoint (baseline) failed"),
                }
            } else {
                tracing::warn!(
                    "skipping WAL checkpoint (baseline): DB connection dropped (daemon degraded)"
                );
            }
            if let Some(ref conn) = self.startup_audit_conn {
                match conn.pragma_update(None, "wal_checkpoint", "PASSIVE") {
                    Ok(()) => tracing::debug!("WAL checkpoint (audit) completed"),
                    Err(e) => tracing::warn!(error = %e, "WAL checkpoint (audit) failed"),
                }
            } else {
                tracing::warn!(
                    "skipping WAL checkpoint (audit): DB connection dropped (daemon degraded)"
                );
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
        let cfg = self.config.load();
        let max_seconds = cfg.maintenance.max_window_seconds as i64;
        let now = Utc::now().timestamp();
        let elapsed_secs = now - entered_at;
        if elapsed_secs > max_seconds {
            tracing::warn!(
                elapsed_secs = elapsed_secs,
                max_seconds,
                "maintenance window exceeded safety timeout — auto-exiting"
            );
            self.maintenance_active.store(false, Ordering::Release);
            self.maintenance_entered_at.store(0, Ordering::Release);
        }
    }

    fn check_drift_velocity(&mut self) {
        let current_total = self.metrics.changes_detected.load(Ordering::Relaxed);
        let delta = current_total.saturating_sub(self.last_changes_seen);
        self.last_changes_seen = current_total;

        self.drift_samples[self.drift_sample_idx % 5] = delta;
        self.drift_sample_idx += 1;

        // Only check after 5 samples (5 minutes of data)
        if self.drift_sample_idx >= 5 {
            let avg: u64 = self.drift_samples.iter().sum::<u64>() / 5;
            let cfg = self.config.load();
            let threshold = cfg.scanner.drift_velocity_threshold.unwrap_or(50);
            let in_maintenance = self.maintenance_active.load(Ordering::Acquire);

            if avg > threshold && !in_maintenance {
                tracing::error!(
                    avg_changes_per_tick = avg,
                    threshold = threshold,
                    "high baseline drift velocity — possible active compromise"
                );
            }
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
    drift_velocity: Option<u64>,
) -> crate::Result<()> {
    std::fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join("state.json");

    let mut value = match &*state.read() {
        DaemonState::Healthy => serde_json::json!({
            "status": "healthy"
        }),
        DaemonState::Degraded { reason, since } => serde_json::json!({
            "status": "degraded",
            "reason": reason,
            "since": since,
        }),
    };

    if let Some(dv) = drift_velocity {
        value["drift_velocity"] = serde_json::json!(dv);
    }

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
    crate::config::config_search_paths(None)
        .into_iter()
        .find(|p| p.exists())
        .and_then(|p| std::fs::read(p).ok())
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
