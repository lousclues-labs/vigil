//! Coordinator thread -- periodic maintenance for a running daemon.
//!
//! Ticks once per minute. Checks baseline/audit DB file identity (TOCTOU),
//! detects mount evasion and clock anomalies, rotates the audit log,
//! writes runtime snapshots (metrics, state, health), monitors backpressure
//! and event-drop rates, checkpoints the WAL, and enforces maintenance
//! window timeouts.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::types::{DaemonState, DegradedReason};
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
    baseline_db_identity: Option<crate::db::DbFileIdentity>,
    audit_db_identity: Option<crate::db::DbFileIdentity>,
    startup_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    startup_baseline_conn: Option<rusqlite::Connection>,
    startup_audit_conn: Option<rusqlite::Connection>,
    reconfigure_tx: Option<crossbeam_channel::Sender<Vec<std::path::PathBuf>>>,
    mount_mark_tx: Option<crossbeam_channel::Sender<crate::monitor::fanotify::MountMarkRequest>>,
    wal_identity: Option<crate::db::DbFileIdentity>,
    wal_path: Option<std::path::PathBuf>,
    wal_hmac_fingerprint: [u8; 16],
    maintenance_active: Arc<AtomicBool>,
    maintenance_entered_at: Arc<AtomicI64>,
    last_config_hash: Option<String>,
    last_accepted_config_hash: Option<String>,
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
    drop_rate_log_counter: u32,
}

pub fn spawn(cfg: CoordinatorConfig) -> crate::Result<std::thread::JoinHandle<()>> {
    // Shared state between guardian and maintenance threads.
    let config = cfg.config;
    let metrics = cfg.metrics;
    let state = cfg.state;
    let watch_index = cfg.watch_index;
    let shutdown = cfg.shutdown;
    let reload_flag = cfg.reload_flag;
    let backpressure = cfg.backpressure;
    let maintenance_active = cfg.maintenance_active.clone();
    let maintenance_entered_at = cfg.maintenance_entered_at.clone();

    let wal_hmac_fingerprint = cfg
        .startup_hmac_key
        .as_ref()
        .map(|k| crate::wal::fingerprint_for_key(k))
        .unwrap_or([0u8; 16]);

    // Guardian-specific: fast checks on 1-second cadence
    let _g_config = config.clone();
    let g_metrics = metrics.clone();
    let g_state = state.clone();
    let g_shutdown = shutdown.clone();
    let g_backpressure = backpressure.clone();

    // Maintenance-specific: heavy operations on 60-second cadence
    let mut coordinator = Coordinator {
        config: config.clone(),
        metrics: metrics.clone(),
        state: state.clone(),
        watch_index,
        shutdown: shutdown.clone(),
        reload_flag,
        baseline_db_identity: cfg.baseline_db_identity,
        audit_db_identity: cfg.audit_db_identity,
        wal_hmac_fingerprint,
        startup_hmac_key: cfg.startup_hmac_key,
        startup_baseline_conn: Some(cfg.startup_baseline_conn),
        startup_audit_conn: Some(cfg.startup_audit_conn),
        reconfigure_tx: cfg.reconfigure_tx,
        mount_mark_tx: cfg.mount_mark_tx,
        wal_identity: cfg.wal_identity,
        wal_path: cfg.wal_path,
        maintenance_active: maintenance_active.clone(),
        maintenance_entered_at: maintenance_entered_at.clone(),
        last_config_hash: config_file_hash(),
        last_accepted_config_hash: config_file_hash(),
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
        drop_rate_log_counter: 0,
    };

    // Clone identity data for guardian before coordinator is moved.
    let g_baseline_identity = coordinator.baseline_db_identity;
    let g_db_path = coordinator.config.load().daemon.db_path.clone();
    let g_runtime_dir = coordinator.config.load().daemon.runtime_dir.clone();

    // Spawn guardian thread (1-second cadence): identity checks, backpressure,
    // watchdog, state snapshot. Fast. Never blocks.
    let guardian_handle = std::thread::Builder::new()
        .name("vigil-guardian".into())
        .spawn(move || {
            while !g_shutdown.load(Ordering::Acquire) {
                // Notify watchdog on every 1-second tick.
                if is_notify_socket_safe() {
                    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                }

                // Fast identity checks.
                if let Some(ref identity) = g_baseline_identity {
                    if let Ok(true) = identity.is_replaced(&g_db_path) {
                        g_metrics
                            .inode_changes_rejected
                            .fetch_add(1, Ordering::Relaxed);
                        let mut s = g_state.write();
                        if matches!(*s, DaemonState::Healthy) {
                            *s = DaemonState::Degraded {
                                reason: DegradedReason::BaselineDbReplaced,
                                since: Utc::now(),
                            };
                        }
                    }
                }

                // Backpressure check.
                if g_backpressure.load(Ordering::Relaxed) {
                    let mut s = g_state.write();
                    if matches!(*s, DaemonState::Healthy) {
                        *s = DaemonState::Degraded {
                            reason: DegradedReason::EventBackpressure,
                            since: Utc::now(),
                        };
                    }
                } else {
                    let mut s = g_state.write();
                    if let DaemonState::Degraded { reason, .. } = &*s {
                        if matches!(reason, DegradedReason::EventBackpressure) {
                            tracing::info!("backpressure resolved; returning to healthy state");
                            *s = DaemonState::Healthy;
                        }
                    }
                }

                // Write state snapshot on every guardian tick for operator visibility.
                let drift_velocity = Some(serde_json::Value::Null); // guardian doesn't track drift
                let _ = write_state_snapshot(&g_runtime_dir, &g_state, drift_velocity);

                std::thread::sleep(Duration::from_millis(1000));
            }
        })
        .map_err(|e| crate::VigilError::Daemon(format!("cannot spawn guardian thread: {}", e)))?;

    // Spawn maintenance thread (60-second cadence): audit rotation, WAL checkpoint,
    // drift velocity, mount evasion, clock anomaly. Heavy. Allowed to take time.
    std::thread::Builder::new()
        .name("vigil-maintenance".into())
        .spawn(move || {
            while !coordinator.shutdown.load(Ordering::Acquire) {
                if coordinator.reload_flag.swap(false, Ordering::AcqRel) {
                    coordinator.handle_reload();
                }
                if coordinator.last_tick.elapsed() >= Duration::from_secs(60) {
                    coordinator.maintenance_tick();
                }
                std::thread::sleep(Duration::from_millis(1000));
            }
            // Wait for guardian to finish.
            let _ = guardian_handle.join();
        })
        .map_err(|e| crate::VigilError::Daemon(format!("cannot spawn maintenance thread: {}", e)))
}

/// Time a tick phase and record its name + duration.
macro_rules! time_phase {
    ($phases:expr, $name:expr, $body:expr) => {{
        let _t = std::time::Instant::now();
        let _result = $body;
        $phases.push(($name, _t.elapsed().as_millis()));
        _result
    }};
}

impl Coordinator {
    /// Maintenance tick: heavy operations on 60-second cadence.
    /// Guardian thread handles fast checks (watchdog, backpressure, state snapshot).
    fn maintenance_tick(&mut self) {
        let tick_start = std::time::Instant::now();
        let mut failed_phases: Vec<&str> = Vec::new();
        let mut phase_timings: Vec<(&str, u128)> = Vec::new();

        if !time_phase!(
            phase_timings,
            "baseline_check",
            self.check_baseline_db_identity()
        ) {
            failed_phases.push("baseline_check");
        }
        if !time_phase!(phase_timings, "audit_check", self.check_audit_db_identity()) {
            failed_phases.push("audit_check");
        }
        if !time_phase!(phase_timings, "wal_check", self.check_wal_identity()) {
            failed_phases.push("wal_check");
        }
        time_phase!(phase_timings, "mount_check", self.check_mount_evasion());

        let clock_anomaly = time_phase!(phase_timings, "clock_check", self.detect_clock_anomaly());
        time_phase!(phase_timings, "rotation", {
            if !clock_anomaly {
                self.rotate_audit_log();
            }
        });

        time_phase!(phase_timings, "snapshots", self.write_snapshots());

        time_phase!(phase_timings, "drops", self.check_event_drops());
        time_phase!(phase_timings, "checkpoint", self.maybe_checkpoint_wal());
        time_phase!(
            phase_timings,
            "maintenance",
            self.check_maintenance_timeout()
        );
        time_phase!(phase_timings, "drift", self.check_drift_velocity());

        let total_ms = tick_start.elapsed().as_millis();

        // Log individual sub-method timings if any exceeded 5 seconds
        let threshold_ms = 5000;
        for &(name, dur) in &phase_timings {
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
                phases = ?phase_timings,
                "coordinator tick took {}ms",
                total_ms
            );
        }

        if !failed_phases.is_empty() {
            tracing::warn!(
                failed = ?failed_phases,
                "coordinator tick completed with failed phases"
            );
        }

        self.last_tick = std::time::Instant::now();
    }

    fn handle_reload(&mut self) {
        // Check config file integrity before reload.
        // Always update last_config_hash to record what we observed,
        // regardless of whether reload succeeds or fails. This prevents
        // the warning from firing on every reload signal when config is
        // persistently broken.
        let new_config_hash = config_file_hash();
        if new_config_hash != self.last_config_hash {
            tracing::warn!(
                old_hash = self.last_config_hash.as_deref().unwrap_or("none"),
                new_hash = new_config_hash.as_deref().unwrap_or("none"),
                "config file hash changed during reload"
            );
        }
        self.last_config_hash = new_config_hash.clone();

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
                                        "failed to store config file HMAC; tamper detection weakened"
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
                self.last_accepted_config_hash = new_config_hash;

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
                    let old_inode = identity.inode;
                    // Attempt recovery: verify the new file has matching content.
                    if let Ok(new_identity) =
                        crate::db::DbFileIdentity::from_path(&cfg.daemon.db_path)
                    {
                        if self.try_recover_baseline_db(
                            &cfg.daemon.db_path,
                            new_identity,
                            old_inode,
                        ) {
                            return true;
                        }
                    }
                    tracing::error!(
                        "baseline database file replaced; content verification failed. \
                         Possible tampering. Inode/device changed since startup."
                    );
                    // VIGIL-VULN-071: drop stale connection immediately
                    self.startup_baseline_conn = None;
                    self.metrics
                        .inode_changes_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    let mut s = self.state.write();
                    *s = DaemonState::Degraded {
                        reason: DegradedReason::BaselineDbReplaced,
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

    /// Try to verify that a baseline DB with a new inode still has the expected
    /// schema and sentinel row. Returns true if the new file is accepted.
    fn try_recover_baseline_db(
        &mut self,
        path: &std::path::Path,
        new_identity: crate::db::DbFileIdentity,
        old_inode: u64,
    ) -> bool {
        // Check file permissions are still 0600.
        let mode = match std::fs::metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o777
            }
            Err(_) => return false,
        };
        if mode & 0o077 != 0 {
            tracing::warn!(
                mode = format!("{:04o}", mode),
                "baseline DB inode changed but new file has unsafe permissions. rejecting."
            );
            return false;
        }

        // Open the new file read-only and verify schema + sentinel.
        let verify_conn = match rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(_) => return false,
        };

        // Verify the baseline table exists with expected schema.
        let has_baseline_table: bool = verify_conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='baseline'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);

        if !has_baseline_table {
            return false;
        }

        // Verify the config_state table and sentinel row exist.
        let sentinel_ok = verify_conn
            .query_row(
                "SELECT value FROM config_state WHERE key = 'baseline_initialized'",
                [],
                |row| row.get::<_, String>(0),
            )
            .is_ok();

        if !sentinel_ok {
            return false;
        }

        // Verification passed. Accept the new inode.
        self.baseline_db_identity = Some(new_identity);
        self.metrics
            .inode_changes_recovered
            .fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            old_inode = old_inode,
            new_inode = new_identity.inode,
            "baseline DB inode changed but content verified. accepting new file."
        );
        true
    }

    /// Returns false if the DB identity check failed and tick should abort.
    fn check_audit_db_identity(&mut self) -> bool {
        let cfg = self.config.load();
        if let Some(ref identity) = self.audit_db_identity {
            let audit_path = crate::db::audit_db_path(&cfg);
            match identity.is_replaced(&audit_path) {
                Ok(true) => {
                    let old_inode = identity.inode;
                    // Attempt recovery: verify the new file has matching chain head.
                    if let Ok(new_identity) = crate::db::DbFileIdentity::from_path(&audit_path) {
                        if self.try_recover_audit_db(&audit_path, new_identity, old_inode) {
                            return true;
                        }
                    }
                    tracing::error!(
                        "audit database file replaced; content verification failed. \
                         Possible evidence destruction. Inode/device changed since startup."
                    );
                    // VIGIL-VULN-071: drop stale connection immediately
                    self.startup_audit_conn = None;
                    self.metrics
                        .inode_changes_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    let mut s = self.state.write();
                    *s = DaemonState::Degraded {
                        reason: DegradedReason::AuditDbReplaced,
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

    /// Try to verify that an audit DB with a new inode still has the expected
    /// chain head hash. Returns true if the new file is accepted.
    fn try_recover_audit_db(
        &mut self,
        path: &std::path::Path,
        new_identity: crate::db::DbFileIdentity,
        old_inode: u64,
    ) -> bool {
        // Check file permissions are still 0600.
        let mode = match std::fs::metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o777
            }
            Err(_) => return false,
        };
        if mode & 0o077 != 0 {
            return false;
        }

        // Read the chain head hash from the current (live) connection before
        // it is dropped, to compare against the new file.
        let expected_chain_head = match self.startup_audit_conn.as_ref() {
            Some(conn) => crate::db::audit_ops::get_last_chain_hash(conn)
                .ok()
                .flatten(),
            None => return false,
        };

        // Open the new file read-only and verify chain head matches.
        let verify_conn = match rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let new_chain_head = crate::db::audit_ops::get_last_chain_hash(&verify_conn)
            .ok()
            .flatten();

        if expected_chain_head != new_chain_head {
            tracing::warn!(
                expected = expected_chain_head.as_deref().unwrap_or("none"),
                found = new_chain_head.as_deref().unwrap_or("none"),
                "audit DB inode changed but chain head hash mismatch. rejecting."
            );
            return false;
        }

        // Verification passed. Accept the new inode.
        self.audit_db_identity = Some(new_identity);
        self.metrics
            .inode_changes_recovered
            .fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            old_inode = old_inode,
            new_inode = new_identity.inode,
            "audit DB inode changed but content verified. accepting new file."
        );
        true
    }

    /// Returns false if WAL identity check failed and tick should abort.
    fn check_wal_identity(&mut self) -> bool {
        let (Some(identity), Some(path)) = (&self.wal_identity, &self.wal_path) else {
            return true;
        };
        let path = path.clone();
        let identity = *identity;

        match identity.is_replaced(&path) {
            Ok(true) => {
                let old_inode = identity.inode;
                // Attempt recovery: verify WAL header magic, version, HMAC fingerprint.
                if let Ok(new_identity) = crate::db::DbFileIdentity::from_path(&path) {
                    if self.try_recover_wal(&path, new_identity, old_inode) {
                        return true;
                    }
                }
                tracing::error!(
                    path = %path.display(),
                    "WAL file replaced; content verification failed. Possible tampering. \
                     Inode/device changed since startup."
                );
                self.metrics
                    .inode_changes_rejected
                    .fetch_add(1, Ordering::Relaxed);
                let mut s = self.state.write();
                *s = DaemonState::Degraded {
                    reason: DegradedReason::WalFileReplaced,
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

    /// Try to verify that a WAL file with a new inode still has the expected
    /// header (magic, version, HMAC fingerprint). Returns true if accepted.
    fn try_recover_wal(
        &mut self,
        path: &std::path::Path,
        new_identity: crate::db::DbFileIdentity,
        old_inode: u64,
    ) -> bool {
        // Check file permissions are still 0600.
        let mode = match std::fs::metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o777
            }
            Err(_) => return false,
        };
        if mode & 0o077 != 0 {
            return false;
        }

        // Read and verify header identity.
        let (magic_ok, version_ok, fingerprint) = match crate::wal::read_header_identity(path) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if !magic_ok || !version_ok {
            return false;
        }

        if fingerprint != self.wal_hmac_fingerprint {
            tracing::warn!("WAL inode changed but HMAC fingerprint mismatch. rejecting.");
            return false;
        }

        // Verification passed. Accept the new inode.
        self.wal_identity = Some(new_identity);
        self.metrics
            .inode_changes_recovered
            .fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            old_inode = old_inode,
            new_inode = new_identity.inode,
            "WAL file inode changed but content verified. accepting new file."
        );
        true
    }

    fn check_mount_evasion(&self) {
        let cfg = self.config.load();
        if let Some(current_mounts) = crate::monitor::fanotify::parse_mountinfo() {
            let current_set: std::collections::HashSet<std::path::PathBuf> =
                current_mounts.into_iter().collect();

            let added: Vec<_> = current_set.difference(&self.initial_mounts).collect();
            let removed: Vec<_> = self.initial_mounts.difference(&current_set).collect();

            if !added.is_empty() {
                // Expand watch paths once before checking against all new mounts
                let all_watch_paths: Vec<std::path::PathBuf> = cfg
                    .watch
                    .values()
                    .flat_map(|group| crate::config::expand_user_paths(&group.paths))
                    .collect();
                for mount in &added {
                    for watch_path in &all_watch_paths {
                        if mount.starts_with(watch_path) || watch_path.starts_with(mount.as_path())
                        {
                            tracing::error!(
                                mount = %mount.display(),
                                watch_path = %watch_path.display(),
                                "new mount detected over watched path; \
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
                                // inotify backend or no channel; log degradation
                                tracing::error!(
                                    mount = %mount.display(),
                                    "mount evasion detected but no fanotify mark channel available; \
                                     modifications under new mount not monitored until next scan"
                                );
                            }
                        }
                    }
                }
            }
            // Check for disappeared overlapping mounts; remove marks
            if !removed.is_empty() {
                if let Some(ref tx) = self.mount_mark_tx {
                    for mount in removed {
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
                "clock skew detected (wall vs monotonic); skipping audit rotation"
            );
            let mut s = self.state.write();
            if matches!(*s, DaemonState::Healthy) {
                *s = DaemonState::Degraded {
                    reason: DegradedReason::ClockSkewDetected {
                        skew_secs: clock_skew,
                    },
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
                "forward clock anomaly detected; skipping audit rotation to prevent evidence loss"
            );
            self.last_rotation_timestamp = now_ts;
            self.last_tick_monotonic = std::time::Instant::now();
            return true;
        }
        if wall_delta < -60 {
            tracing::error!(
                jump_secs = wall_delta,
                "negative clock jump detected; skipping audit rotation (possible clock manipulation replay)"
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
                        "max audit timestamp is in the future; refusing rotation (clock rollback)"
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
                "audit rotation would delete >50% of entries; skipping (possible clock manipulation)"
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
            Some(serde_json::json!(
                self.drift_samples.iter().sum::<u64>() / 5
            ))
        } else {
            Some(serde_json::Value::Null)
        };
        if let Err(e) = write_state_snapshot(&cfg.daemon.runtime_dir, &self.state, drift_velocity) {
            tracing::warn!(error = %e, "failed to write state snapshot");
        }
        if let Err(e) = crate::doctor::write_health_snapshot(&cfg) {
            tracing::warn!(error = %e, "failed to write health snapshot");
        }
    }

    // check_backpressure moved to guardian thread.

    fn check_event_drops(&mut self) {
        let current_dropped = self.metrics.events_dropped.load(Ordering::Relaxed);
        let current_overflows = self.metrics.kernel_queue_overflows.load(Ordering::Relaxed);
        let drop_delta = current_dropped.saturating_sub(self.last_dropped);
        let overflow_delta = current_overflows.saturating_sub(self.last_kernel_overflows);

        let cfg = self.config.load();
        let threshold = cfg.monitor.event_loss_alert_threshold.unwrap_or(10);

        // VIGIL-VULN-072: transition to Degraded when event loss exceeds threshold
        if drop_delta > threshold || overflow_delta > threshold {
            self.clean_ticks_since_event_loss = 0;
            let mut s = self.state.write();
            if matches!(*s, DaemonState::Healthy) {
                *s = DaemonState::Degraded {
                    reason: DegradedReason::EventLossDetected {
                        drop_delta,
                        threshold,
                    },
                    since: Utc::now(),
                };
                tracing::error!(
                    drop_delta,
                    overflow_delta,
                    threshold,
                    "event loss threshold exceeded; entering Degraded state"
                );
                self.drop_rate_log_counter = 0;
            } else {
                // Already Degraded: rate-limited summary every 10 ticks.
                self.drop_rate_log_counter += 1;
                if self.drop_rate_log_counter % 10 == 0 {
                    tracing::warn!(
                        dropped = drop_delta,
                        total_dropped = current_dropped,
                        kernel_overflows = overflow_delta,
                        "event drops continue while Degraded"
                    );
                }
            }
        } else {
            // Recovery: allow deltas at or below the recovery threshold to count
            // as clean ticks. This tolerates low-rate jitter on busy hosts.
            let recovery_threshold = cfg.monitor.event_loss_recovery_threshold;
            if drop_delta <= recovery_threshold && overflow_delta <= recovery_threshold {
                let s = self.state.read();
                if let DaemonState::Degraded { reason, .. } = &*s {
                    if matches!(reason, DegradedReason::EventLossDetected { .. }) {
                        drop(s);
                        self.clean_ticks_since_event_loss += 1;
                        if self.clean_ticks_since_event_loss >= 5 {
                            let mut s = self.state.write();
                            if let DaemonState::Degraded { reason, .. } = &*s {
                                if matches!(reason, DegradedReason::EventLossDetected { .. }) {
                                    tracing::info!("event drops resolved; returning to Healthy");
                                    *s = DaemonState::Healthy;
                                    self.clean_ticks_since_event_loss = 0;
                                    self.drop_rate_log_counter = 0;
                                }
                            }
                        }
                    }
                }
            } else {
                self.clean_ticks_since_event_loss = 0;
            }
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

    // notify_watchdog moved to guardian thread.

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
                "maintenance window exceeded safety timeout; auto-exiting"
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
                    "high baseline drift velocity; possible active compromise"
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
    drift_velocity: Option<serde_json::Value>,
) -> crate::Result<()> {
    std::fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join("state.json");

    let mut value = match &*state.read() {
        DaemonState::Healthy => serde_json::json!({
            "status": "healthy"
        }),
        DaemonState::Degraded { reason, since } => serde_json::json!({
            "status": "degraded",
            "reason": reason.to_string(),
            "since": since,
        }),
    };

    // Always include drift_velocity (null when warming up, number once ready).
    if let Some(dv) = drift_velocity {
        value["drift_velocity"] = dv;
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
                "NOTIFY_SOCKET points to non-standard path; ignoring to prevent \
                 lifecycle state leak"
            );
            false
        }
        Err(_) => {
            // No NOTIFY_SOCKET set; sd_notify will be a no-op anyway
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[allow(dead_code)]
    fn test_coordinator(dir: &std::path::Path) -> Coordinator {
        let baseline_path = dir.join("baseline.db");
        let audit_path = dir.join("audit.db");

        let baseline_conn = rusqlite::Connection::open(&baseline_path).unwrap();
        crate::db::schema::create_baseline_tables(&baseline_conn).unwrap();
        // Insert the sentinel row that recovery checks for.
        baseline_conn
            .execute(
                "INSERT OR REPLACE INTO config_state (key, value, updated_at) VALUES ('baseline_initialized', '1', 0)",
                [],
            )
            .unwrap();

        let audit_conn = rusqlite::Connection::open(&audit_path).unwrap();
        crate::db::schema::create_audit_tables(&audit_conn).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o600));

        let cfg = crate::config::default_config();
        let mut full_cfg = cfg.clone();
        full_cfg.daemon.db_path = baseline_path;

        Coordinator {
            config: Arc::new(ArcSwap::from_pointee(full_cfg)),
            metrics: Arc::new(Metrics::new()),
            state: Arc::new(RwLock::new(DaemonState::Healthy)),
            watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(&cfg))),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            baseline_db_identity: crate::db::DbFileIdentity::from_path(
                &Arc::new(ArcSwap::from_pointee(crate::config::default_config()))
                    .load()
                    .daemon
                    .db_path,
            )
            .ok(),
            audit_db_identity: None,
            wal_hmac_fingerprint: [0u8; 16],
            startup_hmac_key: None,
            startup_baseline_conn: Some(baseline_conn),
            startup_audit_conn: Some(audit_conn),
            reconfigure_tx: None,
            mount_mark_tx: None,
            wal_identity: None,
            wal_path: None,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            maintenance_entered_at: Arc::new(AtomicI64::new(0)),
            last_config_hash: None,
            last_accepted_config_hash: None,
            initial_mounts: std::collections::HashSet::new(),
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
            drop_rate_log_counter: 0,
        }
    }

    #[test]
    fn inode_change_with_matching_content_recovers_without_degraded() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = dir.path().join("baseline.db");

        // Create baseline DB with sentinel row.
        let conn = rusqlite::Connection::open(&baseline_path).unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO config_state (key, value, updated_at) VALUES ('baseline_initialized', '1', 0)",
            [],
        )
        .unwrap();
        drop(conn);

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let identity = crate::db::DbFileIdentity::from_path(&baseline_path).unwrap();

        let cfg = crate::config::default_config();
        let mut full_cfg = cfg.clone();
        full_cfg.daemon.db_path = baseline_path.clone();

        let baseline_conn = rusqlite::Connection::open(&baseline_path).unwrap();
        crate::db::schema::create_baseline_tables(&baseline_conn).unwrap();

        let mut coordinator = Coordinator {
            config: Arc::new(ArcSwap::from_pointee(full_cfg)),
            metrics: Arc::new(Metrics::new()),
            state: Arc::new(RwLock::new(DaemonState::Healthy)),
            watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(&cfg))),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            baseline_db_identity: Some(identity),
            audit_db_identity: None,
            wal_hmac_fingerprint: [0u8; 16],
            startup_hmac_key: None,
            startup_baseline_conn: Some(baseline_conn),
            startup_audit_conn: None,
            reconfigure_tx: None,
            mount_mark_tx: None,
            wal_identity: None,
            wal_path: None,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            maintenance_entered_at: Arc::new(AtomicI64::new(0)),
            last_config_hash: None,
            last_accepted_config_hash: None,
            initial_mounts: std::collections::HashSet::new(),
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
            drop_rate_log_counter: 0,
        };

        // Simulate inode change by copying the file to a new one and replacing.
        let tmp_path = dir.path().join("baseline.db.tmp");
        std::fs::copy(&baseline_path, &tmp_path).unwrap();
        std::fs::rename(&tmp_path, &baseline_path).unwrap();
        std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // The identity check should recover without degrading.
        let result = coordinator.check_baseline_db_identity();
        assert!(result, "check should pass after recovery");
        assert!(
            matches!(*coordinator.state.read(), DaemonState::Healthy),
            "state should remain Healthy after successful recovery"
        );
        assert_eq!(
            coordinator
                .metrics
                .inode_changes_recovered
                .load(Ordering::Relaxed),
            1,
            "recovery metric should be incremented"
        );
    }

    #[test]
    fn inode_change_with_modified_content_degrades_as_today() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = dir.path().join("baseline.db");

        // Create baseline DB with sentinel.
        let conn = rusqlite::Connection::open(&baseline_path).unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO config_state (key, value, updated_at) VALUES ('baseline_initialized', '1', 0)",
            [],
        )
        .unwrap();
        drop(conn);

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let identity = crate::db::DbFileIdentity::from_path(&baseline_path).unwrap();

        let cfg = crate::config::default_config();
        let mut full_cfg = cfg.clone();
        full_cfg.daemon.db_path = baseline_path.clone();

        let baseline_conn = rusqlite::Connection::open(&baseline_path).unwrap();

        let mut coordinator = Coordinator {
            config: Arc::new(ArcSwap::from_pointee(full_cfg)),
            metrics: Arc::new(Metrics::new()),
            state: Arc::new(RwLock::new(DaemonState::Healthy)),
            watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(&cfg))),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            baseline_db_identity: Some(identity),
            audit_db_identity: None,
            wal_hmac_fingerprint: [0u8; 16],
            startup_hmac_key: None,
            startup_baseline_conn: Some(baseline_conn),
            startup_audit_conn: None,
            reconfigure_tx: None,
            mount_mark_tx: None,
            wal_identity: None,
            wal_path: None,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            maintenance_entered_at: Arc::new(AtomicI64::new(0)),
            last_config_hash: None,
            last_accepted_config_hash: None,
            initial_mounts: std::collections::HashSet::new(),
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
            drop_rate_log_counter: 0,
        };

        // Replace with an empty (no schema) SQLite database.
        let tmp_path = dir.path().join("baseline.db.tmp");
        let bad_conn = rusqlite::Connection::open(&tmp_path).unwrap();
        drop(bad_conn);
        std::fs::rename(&tmp_path, &baseline_path).unwrap();
        std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // The identity check should fail and degrade.
        let result = coordinator.check_baseline_db_identity();
        assert!(!result, "check should fail for tampered DB");
        assert!(
            matches!(*coordinator.state.read(), DaemonState::Degraded { .. }),
            "state should be Degraded after failed verification"
        );
        assert_eq!(
            coordinator
                .metrics
                .inode_changes_rejected
                .load(Ordering::Relaxed),
            1,
            "rejected metric should be incremented"
        );
    }
}
