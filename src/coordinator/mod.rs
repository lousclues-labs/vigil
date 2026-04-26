//! Coordinator thread -- periodic maintenance for a running daemon.
//!
//! Two loops: `vigil-guardian` (1s cadence) writes `guardian.json` and
//! handles watchdog, backpressure, and identity checks. `vigil-maintenance`
//! (60s cadence) writes `state.json`/`metrics.json`/`health.json`, checks
//! baseline/audit DB file identity (TOCTOU), detects mount evasion and
//! clock anomalies, rotates the audit log, tracks drift velocity as a
//! metric, checkpoints the WAL, and enforces maintenance window timeouts.

pub mod expectation;

pub use expectation::{ExpectationRegistry, FileChangeExpectation};

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::db::audit_path::AuditEventPath;

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::types::{DaemonState, DegradedReason};
use crate::watch_index::WatchGroupIndex;

use chrono::Utc;

/// Window during which an authorized baseline replacement is expected.
/// After this duration, any inode change is treated as unauthorized.
pub const BASELINE_REPLACEMENT_WINDOW: Duration = Duration::from_secs(30);

/// Thread-safe shared baseline identity for TOCTOU coordination between
/// the guardian thread and the control socket handler.
///
/// The control handler calls `expect_baseline_replacement()` immediately
/// before `fs::rename()` during a baseline refresh. The guardian thread
/// checks the deadline before degrading on inode change. If the deadline
/// is still in the future, the guardian accepts the new inode and resets
/// the deadline -- the replacement is authorized.
pub struct SharedBaselineIdentity {
    inode: AtomicU64,
    device: AtomicU64,
    /// Monotonic offset (nanos since `startup`) of the authorized-replacement
    /// deadline. 0 means no replacement is expected. Using monotonic time
    /// ensures an attacker who manipulates the system clock cannot shift
    /// the authorization window.
    replacement_deadline_offset: AtomicU64,
    /// Monotonic reference point captured at construction. All deadlines
    /// are encoded as nanos-since-startup for wall-clock independence.
    startup: std::time::Instant,
}

impl SharedBaselineIdentity {
    /// Create from an existing `DbFileIdentity`.
    pub fn new(identity: crate::db::DbFileIdentity) -> Self {
        Self {
            inode: AtomicU64::new(identity.inode),
            device: AtomicU64::new(identity.device),
            replacement_deadline_offset: AtomicU64::new(0),
            startup: std::time::Instant::now(),
        }
    }

    /// Signal that an authorized baseline replacement is in progress.
    /// The guardian thread will accept the next inode change if it occurs
    /// before `deadline`.
    pub fn expect_baseline_replacement(&self, deadline: std::time::Instant) {
        let offset = deadline.saturating_duration_since(self.startup).as_nanos() as u64;
        self.replacement_deadline_offset
            .store(offset, Ordering::Release);
    }

    /// Check whether the file at `path` has a different inode/device than
    /// the recorded identity. Returns `true` if replaced.
    pub fn is_replaced(&self, path: &std::path::Path) -> crate::Result<bool> {
        let current = crate::db::DbFileIdentity::from_path(path)?;
        let expected_inode = self.inode.load(Ordering::Acquire);
        let expected_device = self.device.load(Ordering::Acquire);
        Ok(current.inode != expected_inode || current.device != expected_device)
    }

    /// Check whether we are inside an authorized replacement window.
    pub fn is_replacement_authorized(&self) -> bool {
        let deadline_offset = self.replacement_deadline_offset.load(Ordering::Acquire);
        if deadline_offset == 0 {
            return false;
        }
        let now_offset = std::time::Instant::now()
            .saturating_duration_since(self.startup)
            .as_nanos() as u64;
        now_offset < deadline_offset
    }

    /// Accept the new identity after an authorized replacement and reset
    /// the deadline.
    pub fn accept_new_identity(&self, path: &std::path::Path) -> crate::Result<()> {
        let current = crate::db::DbFileIdentity::from_path(path)?;
        self.inode.store(current.inode, Ordering::Release);
        self.device.store(current.device, Ordering::Release);
        self.replacement_deadline_offset.store(0, Ordering::Release);
        Ok(())
    }

    /// Read the current deadline offset (nanos since startup). 0 means no window active.
    pub fn replacement_deadline_nanos(&self) -> u64 {
        self.replacement_deadline_offset.load(Ordering::Acquire)
    }
}

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
    pub shared_baseline_identity: Option<Arc<SharedBaselineIdentity>>,
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
    last_retention_sweep: std::time::Instant,
    audit_retention_skipped_count: u32,
    clean_ticks_since_clock_skew: u32,
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
        last_retention_sweep: std::time::Instant::now(),
        audit_retention_skipped_count: 0,
        clean_ticks_since_clock_skew: 0,
    };

    // Clone identity data for guardian before coordinator is moved.
    let g_shared_identity = cfg.shared_baseline_identity.clone();
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

                // Fast identity checks with refresh coordination.
                // If a replacement is authorized (deadline not expired), accept the
                // new inode and stay healthy. Otherwise, degrade.
                if let Some(ref shared_id) = g_shared_identity {
                    if let Ok(true) = shared_id.is_replaced(&g_db_path) {
                        if shared_id.is_replacement_authorized() {
                            // Authorized refresh: accept new identity, reset deadline.
                            if let Ok(()) = shared_id.accept_new_identity(&g_db_path) {
                                tracing::info!(
                                    "baseline DB inode change accepted (authorized refresh)"
                                );
                                g_metrics
                                    .inode_changes_recovered
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
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

                // Guardian owns guardian.json; maintenance owns state.json.
                if let Err(e) = write_guardian_snapshot(&g_runtime_dir, &g_state) {
                    tracing::debug!(error = %e, "failed to write guardian snapshot");
                }

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
fn time_phase<T>(
    phases: &mut Vec<(&'static str, u128)>,
    name: &'static str,
    f: impl FnOnce() -> T,
) -> T {
    let start = std::time::Instant::now();
    let result = f();
    phases.push((name, start.elapsed().as_millis()));
    result
}

impl Coordinator {
    /// Maintenance tick: heavy operations on 60-second cadence.
    /// Guardian thread handles fast checks (watchdog, backpressure, state snapshot).
    fn maintenance_tick(&mut self) {
        let tick_start = std::time::Instant::now();
        let mut failed_phases: Vec<&str> = Vec::new();
        let mut phase_timings: Vec<(&str, u128)> = Vec::new();

        if !time_phase(&mut phase_timings, "baseline_check", || {
            self.check_baseline_db_identity()
        }) {
            failed_phases.push("baseline_check");
        }
        if !time_phase(&mut phase_timings, "audit_check", || {
            self.check_audit_db_identity()
        }) {
            failed_phases.push("audit_check");
        }
        if !time_phase(&mut phase_timings, "wal_check", || {
            self.check_wal_identity()
        }) {
            failed_phases.push("wal_check");
        }
        time_phase(&mut phase_timings, "mount_check", || {
            self.check_mount_evasion()
        });

        let clock_anomaly = time_phase(&mut phase_timings, "clock_check", || {
            self.detect_clock_anomaly()
        });
        // Retention sweep handles audit pruning with chain-preserving
        // checkpoints. The old rotate_audit_log (bare DELETE) is removed
        // because it breaks chain integrity.
        time_phase(&mut phase_timings, "retention", || {
            if !clock_anomaly {
                self.retention_sweep();
            }
        });

        time_phase(&mut phase_timings, "snapshots", || self.write_snapshots());

        time_phase(&mut phase_timings, "drops", || self.check_event_drops());
        time_phase(&mut phase_timings, "checkpoint", || {
            self.maybe_checkpoint_wal()
        });
        time_phase(&mut phase_timings, "maintenance", || {
            self.check_maintenance_timeout()
        });
        time_phase(&mut phase_timings, "drift", || self.check_drift_velocity());

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
                        if let Err(e) = tx.send(MountMarkRequest {
                            mount: mount.to_path_buf(),
                            op: MountMarkOp::Remove,
                        }) {
                            tracing::warn!(mount = %mount.display(), error = %e, "failed to send mount mark removal request");
                        }
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

        let cfg = self.config.load();
        let threshold = cfg.security.clock_skew_threshold_seconds;
        let recovery_window = cfg.security.clock_skew_recovery_window;

        // Clock skew recovery: if we're degraded due to clock skew and have
        // seen enough clean ticks, self-clear the degraded state.
        if clock_skew.abs() <= threshold {
            let s = self.state.read();
            if let DaemonState::Degraded { reason, .. } = &*s {
                if matches!(reason, DegradedReason::ClockSkewDetected { .. }) {
                    drop(s);
                    self.clean_ticks_since_clock_skew += 1;
                    // Each tick is ~60s; recovery_window / 60 ticks.
                    let ticks_needed = (recovery_window / 60).max(1) as u32;
                    if self.clean_ticks_since_clock_skew >= ticks_needed {
                        let mut s = self.state.write();
                        if let DaemonState::Degraded { reason, .. } = &*s {
                            if matches!(reason, DegradedReason::ClockSkewDetected { .. }) {
                                tracing::info!(
                                    clean_ticks = self.clean_ticks_since_clock_skew,
                                    "clock skew resolved; returning to Healthy"
                                );
                                *s = DaemonState::Healthy;
                                self.clean_ticks_since_clock_skew = 0;
                            }
                        }
                    }
                }
            }
        } else {
            self.clean_ticks_since_clock_skew = 0;
        }

        // Rotation safety: refuse audit rotation when skew exceeds threshold.
        if clock_skew.abs() > threshold {
            tracing::error!(
                wall_delta,
                mono_delta,
                clock_skew,
                threshold,
                "clock skew detected (wall vs monotonic); skipping audit rotation"
            );
            // Daemon degradation fires only for skew larger than 2x threshold,
            // so normal NTP corrections don't page operators.
            if clock_skew.abs() > threshold * 2 {
                let mut s = self.state.write();
                if matches!(*s, DaemonState::Healthy) {
                    *s = DaemonState::Degraded {
                        reason: DegradedReason::ClockSkewDetected {
                            skew_secs: clock_skew,
                        },
                        since: Utc::now(),
                    };
                }
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

    /// Bounded audit retention sweep. Runs at most once per
    /// `audit.retention_check_interval`. Replaces old detection entries
    /// with a single AuditCheckpoint preserving the HMAC chain.
    fn retention_sweep(&mut self) {
        let cfg = self.config.load();
        let check_interval = cfg.audit.retention_check_duration();

        // Rate-limit: only run once per retention_check_interval
        if self.last_retention_sweep.elapsed() < check_interval {
            return;
        }
        self.last_retention_sweep = std::time::Instant::now();

        let conn = match self.startup_audit_conn.as_ref() {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "skipping retention sweep: audit DB connection dropped (daemon degraded)"
                );
                return;
            }
        };

        let now_ts = Utc::now().timestamp();
        let cutoff = now_ts - (cfg.audit.retention_days as i64 * 86400);

        // Identify what to prune
        let range = match crate::db::audit_ops::identify_prune_range(
            conn,
            cutoff,
            cfg.audit.min_entries_to_keep,
        ) {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::debug!("retention sweep: nothing to prune");
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "retention sweep: failed to identify prune range");
                return;
            }
        };

        let (first_id, last_id, entry_count) = range;

        // Safety check: refuse to prune more than 50% of entries in a single
        // sweep. This catches clock manipulation or mismatched retention settings.
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap_or(0);
        if total > 0 && entry_count * 2 > total {
            let percent = (entry_count * 100 / total) as u8;
            self.audit_retention_skipped_count += 1;
            self.metrics
                .audit_retention_skipped_total
                .fetch_add(1, Ordering::Relaxed);

            tracing::error!(
                total = total,
                would_delete = entry_count,
                percent = percent,
                skipped_count = self.audit_retention_skipped_count,
                retention_days = cfg.audit.retention_days,
                "audit retention skipped: {} of {} entries ({}%) exceeds 50% safety \
                 threshold (retention={} days). Run `vigil doctor` for recovery options.",
                entry_count,
                total,
                percent,
                cfg.audit.retention_days,
            );

            if self.audit_retention_skipped_count >= 2 {
                let mut s = self.state.write();
                if matches!(*s, DaemonState::Healthy) {
                    *s = DaemonState::Degraded {
                        reason: DegradedReason::RetentionPolicyMismatch {
                            skipped_count: self.audit_retention_skipped_count,
                            retention_days: cfg.audit.retention_days,
                            would_delete_pct: percent,
                        },
                        since: Utc::now(),
                    };
                }
            }
            return;
        }
        self.audit_retention_skipped_count = 0;

        // Read entries to compute pruned-range HMAC
        let entries = match crate::db::audit_ops::read_detection_range(conn, first_id, last_id) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(error = %e, "retention sweep: failed to read prune range");
                return;
            }
        };

        if entries.is_empty() {
            tracing::debug!("retention sweep: empty range, skipping");
            return;
        }

        let prev_chain = match crate::db::audit_ops::get_previous_chain_hash(conn, first_id) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "retention sweep: failed to get previous chain hash");
                return;
            }
        };

        // Compute pruned-range HMAC: rolling hash over canonical entry encodings
        let hmac_key_ref = self.startup_hmac_key.as_deref();
        let pruned_range_hmac = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(prev_chain.as_bytes());
            for e in &entries {
                // Canonical encoding: same fields used in compute_chain_hash
                let canonical = format!(
                    "{}|{}|{}|{}",
                    e.timestamp, e.path, e.changes_json, e.severity
                );
                hasher.update(canonical.as_bytes());
            }
            hasher.finalize().to_hex().to_string()
        };

        let first_ts = entries.first().unwrap().timestamp;
        let last_ts = entries.last().unwrap().timestamp;
        let bridge = entries.last().unwrap().chain_hash.clone();

        // Atomic transaction: delete originals, insert checkpoint
        let result: Result<(), rusqlite::Error> = (|| {
            conn.execute("BEGIN IMMEDIATE", [])?;

            // Delete the originals first (frees the id for the checkpoint)
            conn.execute(
                "DELETE FROM audit_log WHERE id >= ?1 AND id <= ?2 AND (record_type = 'detection' OR record_type IS NULL)",
                rusqlite::params![first_id, last_id],
            )?;

            // Insert checkpoint at the last pruned entry's id position
            let hmac_val = hmac_key_ref.map(|key| {
                let data = crate::db::audit_ops::build_checkpoint_hmac_data(
                    now_ts,
                    first_id,
                    last_id,
                    entry_count,
                    &pruned_range_hmac,
                    &prev_chain,
                );
                crate::hmac::compute_hmac(key, &data).unwrap_or_default()
            });

            conn.execute(
                "INSERT INTO audit_log (
                    id, timestamp, path, changes_json, severity, monitored_group,
                    process_json, package, maintenance, suppressed, hmac, chain_hash,
                    record_type, first_sequence, last_sequence, first_timestamp,
                    last_timestamp, entry_count, pruned_range_hmac
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, NULL,
                    NULL, NULL, 0, 0, ?6, ?7,
                    'checkpoint', ?8, ?9, ?10,
                    ?11, ?12, ?13
                )",
                rusqlite::params![
                    last_id,
                    now_ts,
                    AuditEventPath::checkpoint_path(first_id, last_id),
                    format!("{{\"previous_chain_hash\":\"{}\"}}", prev_chain),
                    "info",
                    hmac_val,
                    bridge,
                    first_id,
                    last_id,
                    first_ts,
                    last_ts,
                    entry_count,
                    pruned_range_hmac,
                ],
            )?;

            conn.execute("COMMIT", [])?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                tracing::debug!(
                    first_id = first_id,
                    last_id = last_id,
                    entries_pruned = entry_count,
                    "retention sweep: checkpoint created"
                );
            }
            Err(e) => {
                // Rollback on failure
                let _ = conn.execute("ROLLBACK", []);
                tracing::error!(
                    error = %e,
                    "retention sweep failed; will retry next cycle"
                );
            }
        }
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

        // Drift velocity is a metric, not a detection (Principle III).
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

/// Write guardian.json (1Hz cadence, guardian thread only).
/// Fast-changing fields: daemon state, watchdog timestamp.
fn write_guardian_snapshot(
    runtime_dir: &std::path::Path,
    state: &RwLock<DaemonState>,
) -> crate::Result<()> {
    std::fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join("guardian.json");

    let value = match &*state.read() {
        DaemonState::Healthy => serde_json::json!({
            "status": "healthy",
            "watchdog_timestamp": chrono::Utc::now().to_rfc3339(),
        }),
        DaemonState::Degraded { reason, since } => serde_json::json!({
            "status": "degraded",
            "reason": reason.to_string(),
            "since": since,
            "watchdog_timestamp": chrono::Utc::now().to_rfc3339(),
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

    // NamedTempFile guarantees a unique temp name per call.
    let mut f = tempfile::NamedTempFile::new_in(dir).map_err(|e| {
        crate::VigilError::Daemon(format!("atomic_write: temp file creation failed: {}", e))
    })?;
    f.write_all(data)?;
    f.as_file().sync_all()?;
    f.persist(path)
        .map_err(|e| crate::VigilError::Daemon(format!("atomic_write: persist failed: {}", e)))?;
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

    /// Test fixture builder for `Coordinator` with sane defaults.
    #[allow(dead_code)]
    struct CoordinatorBuilder {
        baseline_path: std::path::PathBuf,
        baseline_conn: Option<rusqlite::Connection>,
        baseline_identity: Option<crate::db::DbFileIdentity>,
        audit_conn: Option<rusqlite::Connection>,
        config: crate::config::Config,
        state: DaemonState,
    }

    #[allow(dead_code)]
    impl CoordinatorBuilder {
        fn new(dir: &std::path::Path) -> Self {
            let baseline_path = dir.join("baseline.db");
            let cfg = crate::config::default_config();
            Self {
                baseline_path,
                baseline_conn: None,
                baseline_identity: None,
                audit_conn: None,
                config: cfg,
                state: DaemonState::Healthy,
            }
        }

        fn with_baseline_db(mut self) -> Self {
            let conn = rusqlite::Connection::open(&self.baseline_path).unwrap();
            crate::db::schema::create_baseline_tables(&conn).unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO config_state (key, value, updated_at) VALUES ('baseline_initialized', '1', 0)",
                [],
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &self.baseline_path,
                std::fs::Permissions::from_mode(0o600),
            );
            self.baseline_conn = Some(conn);
            self
        }

        fn with_baseline_identity(mut self) -> Self {
            self.baseline_identity = crate::db::DbFileIdentity::from_path(&self.baseline_path).ok();
            self
        }

        fn with_audit_db(mut self, dir: &std::path::Path) -> Self {
            let audit_path = dir.join("audit.db");
            let conn = rusqlite::Connection::open(&audit_path).unwrap();
            crate::db::schema::create_audit_tables(&conn).unwrap();
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o600));
            self.audit_conn = Some(conn);
            self
        }

        fn with_state(mut self, state: DaemonState) -> Self {
            self.state = state;
            self
        }

        fn build(mut self) -> Coordinator {
            self.config.daemon.db_path = self.baseline_path;
            Coordinator {
                config: Arc::new(ArcSwap::from_pointee(self.config.clone())),
                metrics: Arc::new(Metrics::new()),
                state: Arc::new(RwLock::new(self.state)),
                watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(
                    &self.config,
                ))),
                shutdown: Arc::new(AtomicBool::new(false)),
                reload_flag: Arc::new(AtomicBool::new(false)),
                baseline_db_identity: self.baseline_identity,
                audit_db_identity: None,
                wal_hmac_fingerprint: [0u8; 16],
                startup_hmac_key: None,
                startup_baseline_conn: self.baseline_conn,
                startup_audit_conn: self.audit_conn,
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
                last_retention_sweep: std::time::Instant::now(),
                audit_retention_skipped_count: 0,
                clean_ticks_since_clock_skew: 0,
            }
        }
    }

    #[test]
    fn inode_change_with_matching_content_recovers_without_degraded() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = dir.path().join("baseline.db");

        let mut coordinator = CoordinatorBuilder::new(dir.path())
            .with_baseline_db()
            .with_baseline_identity()
            .build();

        // Simulate inode change by copying the file to a new one and replacing.
        let tmp_path = dir.path().join("baseline.db.tmp");
        std::fs::copy(&baseline_path, &tmp_path).unwrap();
        std::fs::rename(&tmp_path, &baseline_path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600)).unwrap();

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

        let mut coordinator = CoordinatorBuilder::new(dir.path())
            .with_baseline_db()
            .with_baseline_identity()
            .build();

        // Replace with an empty (no schema) SQLite database.
        let tmp_path = dir.path().join("baseline.db.tmp");
        let bad_conn = rusqlite::Connection::open(&tmp_path).unwrap();
        drop(bad_conn);
        std::fs::rename(&tmp_path, &baseline_path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&baseline_path, std::fs::Permissions::from_mode(0o600)).unwrap();

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
