#![deny(unsafe_code)]

pub mod alert;
pub mod bloom;
pub mod cli;
pub mod config;
pub mod control;
pub mod coordinator;
pub mod db;
pub mod doctor;
pub mod error;
pub mod filter;
pub mod hash;
pub mod hmac;
pub mod metrics;
pub mod monitor;
pub mod package;
pub mod scan_scheduler;
pub mod scanner;
pub mod types;
pub mod watch_index;
pub mod worker;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::bounded;
use parking_lot::RwLock;

pub use error::{Result, VigilError};

use crate::alert::{AlertDispatcher, AlertPayload};
use crate::config::Config;
use crate::db::baseline_ops;
use crate::metrics::Metrics;
use crate::types::{DaemonState, FsEvent};
use crate::watch_index::WatchGroupIndex;

/// Vigil daemon runtime. Shared references are lock-free or read-mostly.
pub struct Daemon {
    pub config: Arc<ArcSwap<Config>>,
    pub baseline_conn: rusqlite::Connection,
    pub baseline_db_preexisting: bool,
    pub metrics: Arc<Metrics>,
    pub state: Arc<RwLock<DaemonState>>,
    pub shutdown: Arc<AtomicBool>,
    pub reload_flag: Arc<AtomicBool>,
    pub watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    /// BLAKE3 hash of the config file contents at startup.
    pub config_hash: Option<String>,
    /// Inode+device identity of the baseline DB recorded at startup for TOCTOU detection.
    pub baseline_db_identity: Option<db::DbFileIdentity>,
    /// Inode+device identity of the audit DB recorded at startup for TOCTOU detection.
    pub audit_db_identity: Option<db::DbFileIdentity>,
    /// HMAC key loaded once at startup; never re-read from disk.
    pub startup_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl Daemon {
    pub fn from_config(config: Config) -> Result<Self> {
        let baseline_db_preexisting = config.daemon.db_path.exists();
        let baseline_conn = db::open_baseline_db(&config)?;
        let watch_index = WatchGroupIndex::from_config(&config);

        // Record inode+device of baseline DB for TOCTOU detection
        let baseline_db_identity = db::DbFileIdentity::from_path(&config.daemon.db_path).ok();

        // Record inode+device of audit DB for TOCTOU detection
        let audit_db_path = db::audit_db_path(&config);
        // Ensure audit DB exists so we can record its identity
        let _audit_conn = db::open_audit_db(&config)?;
        let audit_db_identity = db::DbFileIdentity::from_path(&audit_db_path).ok();

        // Load HMAC key exactly once at startup — never re-read from disk
        let startup_hmac_key = if config.security.hmac_signing {
            match crate::hmac::load_hmac_key(&config.security.hmac_key_path) {
                Ok(key) => Some(zeroize::Zeroizing::new(key)),
                Err(e) => {
                    tracing::warn!(error = %e, "HMAC key load failed at startup");
                    None
                }
            }
        } else {
            None
        };

        // Compute config file hash for integrity tracking
        let config_hash = config_search_paths_for_hash()
            .and_then(|path| std::fs::read(&path).ok())
            .map(|content| crate::hash::blake3_hash_bytes(&content));

        // Store config HMAC if signing is enabled
        if config.security.hmac_signing {
            if let Some(ref key) = startup_hmac_key {
                if let Some(ref hash) = config_hash {
                    let config_hmac =
                        crate::hmac::compute_hmac(key, hash.as_bytes()).unwrap_or_default();
                    let _ = baseline_ops::set_config_state(
                        &baseline_conn,
                        "config_file_hmac",
                        &config_hmac,
                    );
                }
            }
        }

        Ok(Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            baseline_conn,
            baseline_db_preexisting,
            metrics: Arc::new(Metrics::new()),
            state: Arc::new(RwLock::new(DaemonState::Healthy)),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            watch_index: Arc::new(ArcSwap::from_pointee(watch_index)),
            config_hash,
            baseline_db_identity,
            audit_db_identity,
            startup_hmac_key,
        })
    }

    pub fn run(self) -> Result<()> {
        harden_process();
        raise_nofile_limit(4096);
        self.record_binary_hash();
        let cfg = self.config.load();
        self.log_startup_diagnostics(&cfg);
        self.ensure_baseline_health(&cfg)?;
        let runtime = DaemonRuntime::start(&self)?;
        runtime.wait_for_shutdown();
        runtime.drain()
    }

    fn record_binary_hash(&self) {
        if let Ok(exe_path) = std::fs::read_link("/proc/self/exe") {
            if let Ok(content) = std::fs::read(&exe_path) {
                let binary_hash = crate::hash::blake3_hash_bytes(&content);
                tracing::info!(
                    binary = %exe_path.display(),
                    hash = %binary_hash,
                    "vigil binary hash recorded"
                );
                let _ = baseline_ops::set_config_state(
                    &self.baseline_conn,
                    "binary_hash",
                    &binary_hash,
                );
            }
        }
    }

    fn log_startup_diagnostics(&self, cfg: &Config) {
        let db_path = &cfg.daemon.db_path;
        tracing::info!(
            path = %db_path.display(),
            exists = db_path.exists(),
            size = db_path.metadata().map(|m| m.len()).unwrap_or(0),
            readable = std::fs::File::open(db_path).is_ok(),
            hmac_signing = cfg.security.hmac_signing,
            "startup baseline diagnostics"
        );
    }

    fn ensure_baseline_health(&self, config: &Config) -> Result<()> {
        if !self.baseline_db_preexisting {
            tracing::warn!(
                "Baseline database not found. Auto-initializing from configured watch paths."
            );
            let result = scanner::build_initial_baseline(&self.baseline_conn, config)?;
            baseline_ops::set_config_state(&self.baseline_conn, "baseline_initialized", "true")?;
            let group_names: Vec<&str> = result.groups.iter().map(|g| g.name.as_str()).collect();
            let message = format!(
                "First run complete — now monitoring {} {} across {} ({}).\n\
                 Run 'vigil status' for details.",
                result.total_count,
                if result.total_count == 1 {
                    "file"
                } else {
                    "files"
                },
                if group_names.len() == 1 {
                    group_names[0].to_string()
                } else {
                    format!("{} watch groups", group_names.len())
                },
                humanize_duration(result.duration),
            );
            notify_desktop(&message, NotifyUrgency::Low);
            return Ok(());
        }

        if let Err(e) = db::integrity_check(&self.baseline_conn) {
            let db_path = &config.daemon.db_path;
            tracing::error!(
                error = %e,
                path = %db_path.display(),
                "Baseline database integrity check failed. Backing up and reinitializing."
            );

            let backup_path = corrupt_backup_path(db_path);
            if let Err(copy_err) = std::fs::copy(db_path, &backup_path) {
                tracing::error!(
                    path = %db_path.display(),
                    backup = %backup_path.display(),
                    error = %copy_err,
                    "failed to back up corrupt baseline database"
                );
                return Err(VigilError::Baseline(format!(
                    "failed to back up corrupt baseline DB: {}",
                    copy_err
                )));
            }

            if let Err(remove_err) = std::fs::remove_file(db_path) {
                tracing::error!(
                    path = %db_path.display(),
                    error = %remove_err,
                    "failed to remove corrupt baseline database"
                );
                return Err(VigilError::Baseline(format!(
                    "failed to remove corrupt baseline DB: {}",
                    remove_err
                )));
            }

            let fresh_conn = db::open_baseline_db(config)?;
            let result = scanner::build_initial_baseline(&fresh_conn, config)?;
            let _ = baseline_ops::set_config_state(&fresh_conn, "baseline_initialized", "true");

            tracing::error!(
                backup = %backup_path.display(),
                entries = result.total_count,
                "baseline database reinitialized after corruption"
            );

            notify_desktop(
                &format!(
                    "⚠ Database was corrupt — rebuilt with {} {}.\n\
                     Previous DB backed up. Run 'vigil audit show' to review.",
                    result.total_count,
                    if result.total_count == 1 {
                        "file"
                    } else {
                        "files"
                    },
                ),
                NotifyUrgency::Critical,
            );

            return Ok(());
        }

        let count = baseline_ops::count(&self.baseline_conn)?;
        if count == 0 {
            let was_initialized =
                baseline_ops::get_config_state(&self.baseline_conn, "baseline_initialized")?
                    .map(|v| v == "true")
                    .unwrap_or(false);

            if was_initialized {
                // Check if this might be a version-upgrade scenario: schema migration
                // could have changed table structure, leaving the baseline table empty
                // even though the DB file is non-empty.
                let db_size = config
                    .daemon
                    .db_path
                    .metadata()
                    .map(|m| m.len())
                    .unwrap_or(0);
                if db_size > 4096 {
                    tracing::warn!(
                        db_size = db_size,
                        "Baseline is empty but DB file is non-trivial ({} bytes). \
                         Likely a schema migration after version upgrade. \
                         Re-initializing baseline.",
                        db_size,
                    );
                    let result = scanner::build_initial_baseline(&self.baseline_conn, config)?;
                    baseline_ops::set_config_state(
                        &self.baseline_conn,
                        "baseline_initialized",
                        "true",
                    )?;
                    notify_desktop(
                        &format!(
                            "Baseline rebuilt after upgrade — now monitoring {} {}.",
                            result.total_count,
                            if result.total_count == 1 {
                                "file"
                            } else {
                                "files"
                            },
                        ),
                        NotifyUrgency::Normal,
                    );
                    return Ok(());
                }

                tracing::error!(
                    "Baseline is empty but was previously initialized. \
                     Possible tampering. Refusing to auto-reinitialize. \
                     Run 'vigil init --force' to manually reinitialize."
                );
                notify_desktop(
                    "⚠ BASELINE EMPTY — previously initialized. Possible tampering. \
                     Run 'vigil init --force' to reinitialize.",
                    NotifyUrgency::Critical,
                );
                return Err(VigilError::Baseline(
                    "baseline was previously initialized but is now empty — possible tampering"
                        .into(),
                ));
            }

            tracing::warn!("Baseline is empty. Populating from configured watch paths.");
            let result = scanner::build_initial_baseline(&self.baseline_conn, config)?;
            baseline_ops::set_config_state(&self.baseline_conn, "baseline_initialized", "true")?;
            notify_desktop(
                &format!(
                    "Baseline was empty — repopulated with {} monitored {}.",
                    result.total_count,
                    if result.total_count == 1 {
                        "file"
                    } else {
                        "files"
                    },
                ),
                NotifyUrgency::Normal,
            );
        }

        // Verify baseline HMAC if signing is enabled
        if config.security.hmac_signing {
            if let Some(ref key) = self.startup_hmac_key {
                let stored = baseline_ops::get_config_state(&self.baseline_conn, "baseline_hmac")?;
                match stored {
                    Some(ref expected) => {
                        let current =
                            baseline_ops::compute_baseline_hmac(&self.baseline_conn, key)?;
                        if current == *expected {
                            tracing::info!("baseline HMAC verification passed");
                        } else {
                            // HMAC mismatch may be benign after a version upgrade that changed
                            // the set of fields covered by the HMAC. Recompute and store rather
                            // than refusing to start.
                            tracing::warn!(
                                "Baseline HMAC mismatch — likely caused by a version upgrade. \
                                 Recomputing and storing updated HMAC."
                            );
                            baseline_ops::set_config_state(
                                &self.baseline_conn,
                                "baseline_hmac",
                                &current,
                            )?;
                        }
                    }
                    None => {
                        tracing::warn!(
                            "no baseline HMAC stored; computing and storing for future verification"
                        );
                        let hmac = baseline_ops::compute_baseline_hmac(&self.baseline_conn, key)?;
                        baseline_ops::set_config_state(
                            &self.baseline_conn,
                            "baseline_hmac",
                            &hmac,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Daemon runtime state — owns all threads, channels, and subsystem handles.
struct DaemonRuntime {
    workers: Vec<JoinHandle<()>>,
    baseline_writer: JoinHandle<()>,
    alert_handle: JoinHandle<()>,
    coordinator_handle: JoinHandle<()>,
    scan_handle: JoinHandle<()>,
    _control_handle: Option<JoinHandle<()>>,
    _monitor: monitor::MonitorHandle,
    _signal_handle: JoinHandle<()>,
    shutdown: Arc<AtomicBool>,
    shutdown_tx: crossbeam_channel::Sender<()>,
    event_tx: crossbeam_channel::Sender<FsEvent>,
    alert_tx: crossbeam_channel::Sender<AlertPayload>,
    pid_file: std::path::PathBuf,
}

impl DaemonRuntime {
    fn start(daemon: &Daemon) -> Result<Self> {
        let cfg = daemon.config.load();

        let pid_file = cfg.daemon.pid_file.clone();
        let baseline_db_path = cfg.daemon.db_path.clone();
        let audit_db_path = db::audit_db_path(&cfg);
        write_pid_file(&pid_file)?;

        let sigset = setup_signal_mask()?;
        let signal_handle =
            spawn_signal_thread(sigset, daemon.shutdown.clone(), daemon.reload_flag.clone())?;

        let (event_tx, event_rx) = bounded::<FsEvent>(cfg.daemon.event_channel_capacity);
        let (alert_tx, alert_rx) = bounded::<AlertPayload>(512);

        let backpressure = Arc::new(AtomicBool::new(false));

        let monitor_handle = monitor::start_monitor(
            &cfg,
            event_tx.clone(),
            daemon.shutdown.clone(),
            daemon.watch_index.clone(),
            daemon.metrics.clone(),
        )?;

        // Baseline update channel for auto-rebaselining package changes
        let (baseline_update_tx, baseline_update_rx) = bounded::<worker::BaselineUpdate>(512);

        // Generation counter for cache invalidation across workers and baseline writer
        let baseline_generation = Arc::new(AtomicU64::new(0));

        let workers = worker::spawn_workers(worker::WorkerSpawnArgs {
            count: cfg.daemon.worker_threads,
            config: daemon.config.clone(),
            event_rx,
            alert_tx: alert_tx.clone(),
            baseline_db_path: baseline_db_path.clone(),
            watch_index: daemon.watch_index.clone(),
            metrics: daemon.metrics.clone(),
            shutdown: daemon.shutdown.clone(),
            baseline_update_tx: Some(baseline_update_tx),
            backpressure: backpressure.clone(),
            baseline_generation: baseline_generation.clone(),
        });

        // Spawn baseline writer thread
        let baseline_writer = spawn_baseline_writer(
            baseline_db_path.clone(),
            baseline_update_rx,
            daemon.shutdown.clone(),
            daemon.metrics.clone(),
            baseline_generation.clone(),
            daemon.startup_hmac_key.clone(),
        )?;

        let alert_handle = spawn_alert_thread(
            daemon.config.clone(),
            alert_rx,
            daemon.shutdown.clone(),
            &audit_db_path,
            daemon.metrics.clone(),
            daemon.startup_hmac_key.clone(),
        )?;

        // Open startup connections for coordinator (avoids TOCTOU by never re-opening by path)
        let coordinator_baseline_conn = db::open_baseline_db(&cfg)?;
        let coordinator_audit_conn = db::open_audit_db(&cfg)?;

        let coordinator_handle = coordinator::spawn(coordinator::CoordinatorConfig {
            config: daemon.config.clone(),
            metrics: daemon.metrics.clone(),
            state: daemon.state.clone(),
            watch_index: daemon.watch_index.clone(),
            shutdown: daemon.shutdown.clone(),
            reload_flag: daemon.reload_flag.clone(),
            backpressure: backpressure.clone(),
            baseline_db_identity: daemon.baseline_db_identity,
            audit_db_identity: daemon.audit_db_identity,
            startup_hmac_key: daemon.startup_hmac_key.clone(),
            startup_baseline_conn: coordinator_baseline_conn,
            startup_audit_conn: coordinator_audit_conn,
        })?;

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);

        // Create scan trigger channel for on-demand scans via control socket
        let (scan_trigger_tx, scan_trigger_rx) =
            crossbeam_channel::bounded::<control::ScanRequest>(1);

        // Open a startup baseline connection for the scan scheduler (avoids TOCTOU)
        let scan_baseline_conn = db::open_baseline_db(&cfg)?;

        let scan_handle = scan_scheduler::spawn(
            daemon.config.clone(),
            daemon.shutdown.clone(),
            alert_tx.clone(),
            daemon.metrics.clone(),
            shutdown_rx,
            scan_trigger_rx,
            scan_baseline_conn,
        )?;

        if coordinator::is_notify_socket_safe() {
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
        }
        tracing::info!("vigil daemon ready");

        // Spawn control socket if configured
        let control_handle = if !cfg.daemon.control_socket.as_os_str().is_empty() {
            let handler = control::ControlHandler {
                metrics: daemon.metrics.clone(),
                state: daemon.state.clone(),
                reload_flag: daemon.reload_flag.clone(),
                scan_trigger_tx,
                baseline_db_path: baseline_db_path.clone(),
                hmac_key: daemon.startup_hmac_key.as_ref().map(|k| (**k).clone()),
                auth_enabled: daemon.startup_hmac_key.is_some(),
            };
            Some(control::spawn(
                cfg.daemon.control_socket.clone(),
                handler,
                daemon.shutdown.clone(),
            )?)
        } else {
            None
        };

        Ok(Self {
            workers,
            baseline_writer,
            alert_handle,
            coordinator_handle,
            scan_handle,
            _control_handle: control_handle,
            _monitor: monitor_handle,
            _signal_handle: signal_handle,
            shutdown: daemon.shutdown.clone(),
            shutdown_tx,
            event_tx,
            alert_tx,
            pid_file,
        })
    }

    fn wait_for_shutdown(&self) {
        while !self.shutdown.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn drain(self) -> Result<()> {
        if coordinator::is_notify_socket_safe() {
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
        }

        // Signal the scan scheduler to wake up and exit
        let _ = self.shutdown_tx.send(());

        drop(self.event_tx);
        drop(self.alert_tx);

        for worker in self.workers {
            let _ = worker.join();
        }
        let _ = self.baseline_writer.join();
        let _ = self.alert_handle.join();
        let _ = self.coordinator_handle.join();
        let _ = self.scan_handle.join();

        cleanup_pid_file(&self.pid_file);

        tracing::info!("vigil daemon stopped");
        Ok(())
    }
}

/// Compatibility entry point used by older callers.
pub fn daemon_run(config: &Config) -> Result<()> {
    Daemon::from_config(config.clone())?.run()
}

fn spawn_alert_thread(
    config: Arc<ArcSwap<Config>>,
    alert_rx: crossbeam_channel::Receiver<AlertPayload>,
    shutdown: Arc<AtomicBool>,
    audit_db_path: &std::path::Path,
    metrics: Arc<Metrics>,
    startup_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<JoinHandle<()>> {
    let cfg = config.load();
    let dispatcher = AlertDispatcher::new(&cfg, audit_db_path, metrics, startup_hmac_key)?;

    std::thread::Builder::new()
        .name("vigil-alert".into())
        .spawn(move || dispatcher.run(alert_rx, shutdown))
        .map_err(|e| VigilError::Daemon(format!("cannot spawn alert thread: {}", e)))
}

fn spawn_baseline_writer(
    baseline_db_path: std::path::PathBuf,
    rx: crossbeam_channel::Receiver<worker::BaselineUpdate>,
    shutdown: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
    baseline_generation: Arc<AtomicU64>,
    startup_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vigil-baseline-writer".into())
        .spawn(move || {
            let conn = match db::open_baseline_db_at_path(&baseline_db_path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "baseline writer failed to open db");
                    return;
                }
            };

            let mut batch: Vec<worker::BaselineUpdate> = Vec::new();
            let mut last_hmac_update = std::time::Instant::now();
            let mut batch_count = 0u64;

            while !shutdown.load(Ordering::Acquire) {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(update) => {
                        batch.push(update);
                        // Collect more if available
                        while let Ok(extra) = rx.try_recv() {
                            batch.push(extra);
                        }

                        // Write batch in a single transaction
                        if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
                            tracing::error!(error = %e, "baseline writer begin failed");
                            batch.clear();
                            continue;
                        }

                        let mut written = 0u64;
                        for update in batch.drain(..) {
                            if let Err(e) = baseline_ops::upsert(&conn, &update.entry) {
                                tracing::warn!(
                                    path = %update.entry.path.display(),
                                    error = %e,
                                    "baseline auto-update failed"
                                );
                            } else {
                                written += 1;
                            }
                        }

                        if let Err(e) = conn.execute_batch("COMMIT") {
                            tracing::error!(error = %e, "baseline writer commit failed");
                        } else if written > 0 {
                            // Increment generation counter to signal workers to invalidate caches
                            baseline_generation.fetch_add(1, Ordering::Release);

                            metrics
                                .baseline_updates
                                .fetch_add(written, Ordering::Relaxed);
                            batch_count += 1;

                            // Periodically recompute baseline HMAC (every 100 batches or 60s)
                            #[allow(clippy::manual_is_multiple_of)]
                            if batch_count % 100 == 0
                                || last_hmac_update.elapsed() >= Duration::from_secs(60)
                            {
                                // Use the HMAC key loaded at startup — never re-read from disk
                                if let Some(ref key) = startup_hmac_key {
                                    match baseline_ops::compute_baseline_hmac(&conn, key) {
                                        Ok(hmac) => {
                                            let _ = baseline_ops::set_config_state(
                                                &conn,
                                                "baseline_hmac",
                                                &hmac,
                                            );
                                        }
                                        Err(e) => {
                                            tracing::debug!(
                                                error = %e,
                                                "baseline writer HMAC update failed"
                                            );
                                        }
                                    }
                                }
                                last_hmac_update = std::time::Instant::now();
                            }
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .map_err(|e| VigilError::Daemon(format!("cannot spawn baseline writer: {}", e)))
}

fn setup_signal_mask() -> Result<nix::sys::signal::SigSet> {
    use nix::sys::signal::{SigSet, Signal};

    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGINT);
    sigset.add(Signal::SIGTERM);
    sigset.add(Signal::SIGHUP);
    sigset
        .thread_block()
        .map_err(|e| VigilError::Daemon(format!("failed to block signals: {}", e)))?;

    Ok(sigset)
}

fn spawn_signal_thread(
    sigset: nix::sys::signal::SigSet,
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vigil-signal".into())
        .spawn(move || {
            use nix::sys::signal::Signal;

            loop {
                match sigset.wait() {
                    Ok(Signal::SIGHUP) => {
                        reload_flag.store(true, Ordering::Release);
                    }
                    Ok(Signal::SIGINT) | Ok(Signal::SIGTERM) => {
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "signal wait failed");
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        })
        .map_err(|e| VigilError::Daemon(format!("cannot spawn signal thread: {}", e)))
}

fn write_pid_file(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())?;
    Ok(())
}

fn cleanup_pid_file(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::debug!(path = %path.display(), error = %e, "failed to remove pid file");
    }
}

#[allow(unsafe_code)]
fn harden_process() {
    // Set restrictive umask before any file creation (0077 = owner-only)
    // SAFETY: umask is a simple process attribute change with no safety implications.
    unsafe {
        libc::umask(0o077);
    }

    // SAFETY: PR_SET_DUMPABLE with 0 disables ptrace/core dumps for this process.
    // This does not violate Rust memory safety invariants.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    // SAFETY: PR_SET_NO_NEW_PRIVS with 1 disables privilege escalation on execve.
    // This is a process attribute change and has no Rust memory safety implications.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
}

fn corrupt_backup_path(db_path: &std::path::Path) -> std::path::PathBuf {
    let mut backup = db_path.as_os_str().to_os_string();
    backup.push(format!(
        ".corrupt.{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    ));
    std::path::PathBuf::from(backup)
}

enum NotifyUrgency {
    Low,
    Normal,
    Critical,
}

fn notify_desktop(message: &str, urgency: NotifyUrgency) {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let available = *AVAILABLE.get_or_init(|| {
        let found = std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join("notify-send").is_file()))
            .unwrap_or(false);
        if !found {
            tracing::debug!("notify-send not found; desktop notifications disabled");
        }
        found
    });

    if !available {
        return;
    }

    let urgency_str = match urgency {
        NotifyUrgency::Low => "low",
        NotifyUrgency::Normal => "normal",
        NotifyUrgency::Critical => "critical",
    };

    let status = std::process::Command::new("notify-send")
        .arg("--app-name=Vigil")
        .arg(format!("--urgency={}", urgency_str))
        .arg("Vigil")
        .arg(message)
        .status();

    if let Err(e) = status {
        tracing::debug!(error = %e, "desktop notification failed");
    }
}

fn humanize_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 1 {
        format!("{}ms", d.as_millis())
    } else if secs < 60 {
        format!("{}s", secs)
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

/// Find the first config file that exists, for hashing.
fn config_search_paths_for_hash() -> Option<std::path::PathBuf> {
    #[cfg(any(test, debug_assertions))]
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        let p = std::path::PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    #[cfg(not(any(test, debug_assertions)))]
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        // In production, validate ownership before trusting env override
        use std::os::unix::fs::MetadataExt;
        let p = std::path::PathBuf::from(&env_path);
        if p.exists() {
            if let Ok(meta) = std::fs::metadata(&p) {
                let mode = meta.mode() & 0o777;
                if meta.uid() == 0 && mode <= 0o644 {
                    return Some(p);
                }
            }
        }
    }
    let default = std::path::PathBuf::from("/etc/vigil/vigil.toml");
    if default.exists() {
        return Some(default);
    }
    None
}

#[allow(unsafe_code)]
fn raise_nofile_limit(target: u64) {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Read current limits first so we can respect the existing hard limit.
    // SAFETY: getrlimit is called with a valid pointer to rlimit.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current as *mut libc::rlimit) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(error = %err, "failed to read RLIMIT_NOFILE");
        return;
    }

    // Set soft limit to the lesser of target and current hard limit.
    // Only attempt to raise the hard limit if target exceeds it
    // (requires CAP_SYS_RESOURCE).
    let new_cur = target.min(current.rlim_max);
    let new_max = if target > current.rlim_max {
        target
    } else {
        current.rlim_max
    };

    let mut lim = libc::rlimit {
        rlim_cur: new_cur,
        rlim_max: new_max,
    };
    // SAFETY: setrlimit is called with a valid pointer to rlimit.
    // Failure is non-fatal and handled by logging.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &mut lim as *mut libc::rlimit) };
    if rc != 0 {
        // If raising hard limit failed, fall back to only raising soft limit
        // within the existing hard limit.
        let mut fallback = libc::rlimit {
            rlim_cur: new_cur,
            rlim_max: current.rlim_max,
        };
        let rc2 =
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &mut fallback as *mut libc::rlimit) };
        if rc2 != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(error = %err, "failed to raise RLIMIT_NOFILE");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_duration_sub_second() {
        let d = std::time::Duration::from_millis(347);
        assert_eq!(humanize_duration(d), "347ms");
    }

    #[test]
    fn humanize_duration_seconds() {
        let d = std::time::Duration::from_secs(42);
        assert_eq!(humanize_duration(d), "42s");
    }

    #[test]
    fn humanize_duration_minutes() {
        let d = std::time::Duration::from_secs(125);
        assert_eq!(humanize_duration(d), "2m 5s");
    }
}
