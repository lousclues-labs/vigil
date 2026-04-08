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

use std::sync::atomic::{AtomicBool, Ordering};
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
}

impl Daemon {
    pub fn from_config(config: Config) -> Result<Self> {
        let baseline_db_preexisting = config.daemon.db_path.exists();
        let baseline_conn = db::open_baseline_db(&config)?;
        let watch_index = WatchGroupIndex::from_config(&config);

        // Compute config file hash for integrity tracking
        let config_hash = config_search_paths_for_hash()
            .and_then(|path| std::fs::read(&path).ok())
            .map(|content| crate::hash::blake3_hash_bytes(&content));

        // Store config HMAC if signing is enabled
        if config.security.hmac_signing {
            if let Ok(key) = crate::hmac::load_hmac_key(&config.security.hmac_key_path) {
                if let Some(ref hash) = config_hash {
                    let config_hmac =
                        crate::hmac::compute_hmac(&key, hash.as_bytes()).unwrap_or_default();
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
        })
    }

    pub fn run(self) -> Result<()> {
        harden_process();
        raise_nofile_limit(4096);

        let cfg = self.config.load();
        self.ensure_baseline_health(&cfg)?;

        let pid_file = cfg.daemon.pid_file.clone();
        let baseline_db_path = cfg.daemon.db_path.clone();
        let audit_db_path = db::audit_db_path(&cfg);
        write_pid_file(&pid_file)?;

        let sigset = setup_signal_mask()?;
        let _signal_handle =
            spawn_signal_thread(sigset, self.shutdown.clone(), self.reload_flag.clone())?;

        let (event_tx, event_rx) = bounded::<FsEvent>(cfg.daemon.event_channel_capacity);
        let (alert_tx, alert_rx) = bounded::<AlertPayload>(512);

        let backpressure = Arc::new(AtomicBool::new(false));

        let _monitor = monitor::start_monitor(
            &cfg,
            event_tx.clone(),
            self.shutdown.clone(),
            self.watch_index.clone(),
            self.metrics.clone(),
        )?;

        // Baseline update channel for auto-rebaselining package changes
        let (baseline_update_tx, baseline_update_rx) = bounded::<worker::BaselineUpdate>(512);

        let workers = worker::spawn_workers(
            cfg.daemon.worker_threads,
            self.config.clone(),
            event_rx,
            alert_tx.clone(),
            &baseline_db_path,
            self.watch_index.clone(),
            self.metrics.clone(),
            self.shutdown.clone(),
            Some(baseline_update_tx),
            backpressure.clone(),
        );

        // Spawn baseline writer thread
        let baseline_writer = spawn_baseline_writer(
            baseline_db_path.clone(),
            baseline_update_rx,
            self.shutdown.clone(),
            self.metrics.clone(),
        )?;

        let alert_handle = spawn_alert_thread(
            self.config.clone(),
            alert_rx,
            self.shutdown.clone(),
            &audit_db_path,
            self.metrics.clone(),
        )?;

        let coordinator_handle = coordinator::spawn(
            self.config.clone(),
            self.metrics.clone(),
            self.state.clone(),
            self.watch_index.clone(),
            self.shutdown.clone(),
            self.reload_flag.clone(),
            backpressure.clone(),
        )?;

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);

        // Create scan trigger channel for on-demand scans via control socket
        let (scan_trigger_tx, scan_trigger_rx) =
            crossbeam_channel::bounded::<control::ScanRequest>(1);

        let scan_handle = scan_scheduler::spawn(
            self.config.clone(),
            self.shutdown.clone(),
            alert_tx.clone(),
            self.metrics.clone(),
            shutdown_rx,
            scan_trigger_rx,
        )?;

        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
        tracing::info!("vigil daemon ready");

        // Spawn control socket if configured
        let _control_handle = if !cfg.daemon.control_socket.as_os_str().is_empty() {
            Some(control::spawn(
                cfg.daemon.control_socket.clone(),
                self.metrics.clone(),
                self.state.clone(),
                self.shutdown.clone(),
                self.reload_flag.clone(),
                scan_trigger_tx,
                &baseline_db_path,
            )?)
        } else {
            None
        };

        // Block until shutdown signal
        while !self.shutdown.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_secs(1));
        }

        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);

        // Signal the scan scheduler to wake up and exit
        let _ = shutdown_tx.send(());

        drop(event_tx);
        drop(alert_tx);

        for worker in workers {
            let _ = worker.join();
        }
        let _ = baseline_writer.join();
        let _ = alert_handle.join();
        let _ = coordinator_handle.join();
        let _ = scan_handle.join();

        cleanup_pid_file(&pid_file);

        tracing::info!("vigil daemon stopped");
        Ok(())
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
        if count <= 0 {
            let was_initialized =
                baseline_ops::get_config_state(&self.baseline_conn, "baseline_initialized")?
                    .map(|v| v == "true")
                    .unwrap_or(false);

            if was_initialized {
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
            if let Ok(key) = crate::hmac::load_hmac_key(&config.security.hmac_key_path) {
                let stored = baseline_ops::get_config_state(&self.baseline_conn, "baseline_hmac")?;
                match stored {
                    Some(ref expected) => {
                        let current =
                            baseline_ops::compute_baseline_hmac(&self.baseline_conn, &key)?;
                        if current == *expected {
                            tracing::info!("baseline HMAC verification passed");
                        } else {
                            tracing::error!(
                                "BASELINE TAMPER DETECTED: HMAC verification failed. \
                                 The baseline database has been modified outside of Vigil."
                            );
                            notify_desktop(
                                "⚠ BASELINE TAMPER DETECTED — HMAC mismatch. \
                                 Run 'vigil doctor' immediately.",
                                NotifyUrgency::Critical,
                            );
                            return Err(VigilError::Baseline(
                                "baseline HMAC verification failed — possible tampering".into(),
                            ));
                        }
                    }
                    None => {
                        tracing::warn!(
                            "no baseline HMAC stored; computing and storing for future verification"
                        );
                        let hmac = baseline_ops::compute_baseline_hmac(&self.baseline_conn, &key)?;
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
) -> Result<JoinHandle<()>> {
    let cfg = config.load();
    let dispatcher = AlertDispatcher::new(&cfg, audit_db_path, metrics)?;

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
                            metrics
                                .baseline_updates
                                .fetch_add(written, Ordering::Relaxed);
                            batch_count += 1;

                            // Periodically recompute baseline HMAC (every 100 batches or 60s)
                            #[allow(clippy::manual_is_multiple_of)]
                            if batch_count % 100 == 0
                                || last_hmac_update.elapsed() >= Duration::from_secs(60)
                            {
                                // Try to load HMAC key from the stored path
                                let hmac_key_path = std::path::PathBuf::from("/etc/vigil/hmac.key");
                                if hmac_key_path.exists() {
                                    if let Ok(key) = crate::hmac::load_hmac_key(&hmac_key_path) {
                                        match baseline_ops::compute_baseline_hmac(&conn, &key) {
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

fn harden_process() {
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
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        let p = std::path::PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    let default = std::path::PathBuf::from("/etc/vigil/vigil.toml");
    if default.exists() {
        return Some(default);
    }
    None
}

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
