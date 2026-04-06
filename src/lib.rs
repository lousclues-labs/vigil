pub mod alert;
pub mod bloom;
pub mod cli;
pub mod config;
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
}

impl Daemon {
    pub fn from_config(config: Config) -> Result<Self> {
        let baseline_db_preexisting = config.daemon.db_path.exists();
        let baseline_conn = db::open_baseline_db(&config)?;
        let watch_index = WatchGroupIndex::from_config(&config);

        Ok(Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            baseline_conn,
            baseline_db_preexisting,
            metrics: Arc::new(Metrics::new()),
            state: Arc::new(RwLock::new(DaemonState::Healthy)),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
            watch_index: Arc::new(ArcSwap::from_pointee(watch_index)),
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

        let (event_tx, event_rx) = bounded::<FsEvent>(1024);
        let (alert_tx, alert_rx) = bounded::<AlertPayload>(256);

        let _monitor = monitor::start_monitor(
            &cfg,
            event_tx.clone(),
            self.shutdown.clone(),
            self.watch_index.clone(),
            self.metrics.clone(),
        )?;

        let workers = worker::spawn_workers(
            cfg.daemon.worker_threads,
            self.config.clone(),
            event_rx,
            alert_tx.clone(),
            &baseline_db_path,
            self.watch_index.clone(),
            self.metrics.clone(),
            self.shutdown.clone(),
        );

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
        )?;

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);

        let scan_handle = scan_scheduler::spawn(
            self.config.clone(),
            self.shutdown.clone(),
            alert_tx.clone(),
            self.metrics.clone(),
            shutdown_rx,
        )?;

        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
        tracing::info!("vigil daemon ready");

        // Block until shutdown signal instead of polling every 250ms
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
            notify_desktop(&format!(
                "Vigil: Baseline auto-initialized with {} entries.",
                result.total_count
            ));
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

            tracing::error!(
                backup = %backup_path.display(),
                entries = result.total_count,
                "baseline database reinitialized after corruption"
            );

            notify_desktop(&format!(
                "Vigil: Baseline was corrupt. Backed up to {} and reinitialized with {} entries. Review the backup.",
                backup_path.display(),
                result.total_count
            ));

            return Ok(());
        }

        let count = baseline_ops::count(&self.baseline_conn)?;
        if count <= 0 {
            tracing::warn!("Baseline is empty. Populating from configured watch paths.");
            let _ = scanner::build_initial_baseline(&self.baseline_conn, config)?;
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

fn notify_desktop(message: &str) {
    let status = std::process::Command::new("notify-send")
        .arg("Vigil")
        .arg(message)
        .status();

    if let Err(e) = status {
        tracing::debug!(error = %e, "notify-send failed");
    }
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
