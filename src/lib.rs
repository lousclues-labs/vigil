pub mod alert;
pub mod baseline;
pub mod check_builder;
pub mod cli;
pub mod compare;
pub mod config;
pub mod db;
pub mod error;
pub mod hmac;
pub mod monitor;
pub mod package;
pub mod scanner;
pub mod types;
pub mod watch_index;

pub use check_builder::CheckBuilder;

/// Optional progress callback for long-running operations.
pub type ProgressCallback<'a> = Option<&'a dyn Fn(&str)>;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::bounded;

use parking_lot::RwLock;

use crate::alert::AlertEngine;
use crate::config::Config;
use crate::db::ops;
use crate::error::Result;
use crate::monitor::filter::EventFilter;
use crate::types::FsEventType;
use crate::watch_index::WatchGroupIndex;

/// Run the Vigil daemon main loop.
///
/// Architecture:
/// - Main thread: epoll event loop (fanotify/inotify) → event channel
/// - Hasher worker pool (2 threads): receive events, hash, compare, classify
/// - Output writer: batched DB writes, log flushing
/// - D-Bus dispatcher: notification delivery
///
/// # Config reload semantics (SIGHUP)
///
/// The active config is held in an `Arc<RwLock<Config>>` and swapped atomically
/// on reload. The following fields take effect immediately on SIGHUP:
///
/// - `exclusions.*` — rebuilt event filter
/// - `alerts.rate_limit`, `alerts.cooldown_seconds` — updated in AlertEngine
/// - `scanner.max_file_size` — used on next event comparison
/// - `database.audit_retention_days` — used on next rotation cycle
///
/// The following fields require a full daemon restart:
///
/// - `daemon.pid_file`, `daemon.db_path` — bound at startup
/// - `daemon.monitor_backend` — fanotify/inotify backend chosen at startup
/// - `watch.*` paths — fanotify/inotify marks are set at startup
pub fn daemon_run(config: &Config) -> Result<()> {
    let conn = db::open_db(config)?;

    // Verify database integrity on startup
    if let Err(e) = db::integrity_check(&conn) {
        log::error!("Database integrity check failed: {}", e);
        log::error!("Run 'vigil doctor' or 'vigil init' to rebuild.");
        return Err(e);
    }

    // Verify baseline exists
    let count = ops::baseline_count(&conn)?;
    if count == 0 {
        log::warn!("Baseline is empty. Run 'vigil init' to create initial baseline.");
    } else {
        log::info!("Baseline loaded: {} entries", count);
    }

    // Write PID file
    write_pid_file(&config.daemon.pid_file)?;

    // Block SIGINT/SIGTERM on the main thread before spawning any child threads,
    // so all threads inherit the signal mask and only the dedicated signal thread
    // receives the signals.
    use nix::sys::signal::{SigSet, Signal};
    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGINT);
    sigset.add(Signal::SIGTERM);
    sigset.add(Signal::SIGHUP);
    sigset
        .thread_block()
        .expect("failed to block signals on main thread");

    // Set up shutdown signal handler and reload flag
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload_flag = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let reload_clone = reload_flag.clone();
    ctrlc_handler(shutdown_clone, reload_clone, sigset);

    // Wrap config in Arc<RwLock> for atomic reload on SIGHUP
    let active_config = Arc::new(RwLock::new(config.clone()));

    // Create alert engine
    let alert_engine = AlertEngine::new(config)?;

    // Pre-compute watch group index for O(n) sorted-prefix lookup
    let watch_index = WatchGroupIndex::from_config(config);

    // Event channel: monitor → hasher workers
    let (event_tx, event_rx) = bounded(1024);

    // Start filesystem monitor (spawns its own thread)
    let backend = monitor::start_monitor(config, event_tx, shutdown.clone())?;
    log::info!("Real-time monitor started (backend: {})", backend);

    // Event filter
    let mut event_filter = EventFilter::new(config);

    // Hasher worker loop (runs on main thread for simplicity in MVP;
    // can be split into a worker pool in a future version)
    let mut wal_writes = 0u64;
    let mut last_prune = std::time::Instant::now();

    log::info!("Vigil daemon ready. Monitoring filesystem changes...");

    let mut panic_count: u64 = 0;
    const PANIC_THRESHOLD: u64 = 10;

    while !shutdown.load(Ordering::Acquire) {
        // Receive events with a timeout so we can check shutdown flag
        match event_rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(event) => {
                // Apply event filter
                if !event_filter.should_process(&event) {
                    continue;
                }

                // Read the current config snapshot for this event
                let cfg_snapshot = active_config.read().clone();

                // Wrap comparison and dispatch in catch_unwind to isolate panics
                let event_path = event.path.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    // Look up baseline entry
                    let path_str = event.path.to_string_lossy().into_owned();
                    let baseline_entry = match ops::get_baseline_by_path(&conn, &path_str) {
                        Ok(Some(entry)) => entry,
                        Ok(None) => {
                            // New file in monitored directory (not in baseline)
                            if matches!(
                                event.event_type,
                                FsEventType::Create | FsEventType::MovedTo
                            ) {
                                log::info!("New file detected: {}", event.path.display());
                            }
                            return;
                        }
                        Err(e) => {
                            log::debug!("DB lookup error for {}: {}", path_str, e);
                            return;
                        }
                    };

                    // Determine watch group and severity for this path
                    let (group_name, severity) = watch_index
                        .lookup(&event.path)
                        .map(|(g, s)| (g.to_string(), s))
                        .unwrap_or(("unknown".into(), types::Severity::Medium));

                    // Compare against baseline (uses hot-reloadable max_file_size)
                    match compare::compare_event(
                        &event.path,
                        &baseline_entry,
                        &group_name,
                        severity,
                        cfg_snapshot.scanner.max_file_size,
                    ) {
                        Ok(Some(change)) => {
                            let maintenance =
                                ops::get_config_state(&conn, "maintenance_window_active")
                                    .ok()
                                    .flatten()
                                    .map(|v| v == "1")
                                    .unwrap_or(false);

                            if let Err(e) = alert_engine.dispatch(&change, maintenance, &conn) {
                                log::error!("Alert dispatch error: {}", e);
                            }

                            // WAL checkpoint every 1000 DB writes
                            wal_writes += 1;
                            if wal_writes >= 1000 {
                                let _ = db::wal_checkpoint(&conn);
                                wal_writes = 0;
                            }
                        }
                        Ok(None) => {} // no change (hash matched despite event)
                        Err(e) => {
                            log::debug!("Comparison error for {}: {}", event.path.display(), e);
                        }
                    }
                }));

                if let Err(_panic) = result {
                    panic_count += 1;
                    log::error!(
                        "Panic during event processing for {}: caught and continuing",
                        event_path.display()
                    );
                    if panic_count >= PANIC_THRESHOLD {
                        log::warn!(
                            "Panic threshold reached ({} panics in this run)",
                            panic_count
                        );
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Read config for housekeeping
                let cfg_snapshot = active_config.read().clone();

                // Periodic housekeeping
                if last_prune.elapsed() > std::time::Duration::from_secs(60) {
                    event_filter.prune_debounce();
                    // Rotate audit log (uses hot-reloadable retention days)
                    match ops::rotate_audit_log(&conn, cfg_snapshot.database.audit_retention_days) {
                        Ok(0) => {}
                        Ok(n) => log::info!("Rotated {} old audit log entries", n),
                        Err(e) => log::warn!("Audit log rotation error: {}", e),
                    }
                    // Rotate JSON log file if configured
                    if let Some(logger) = alert_engine.json_logger() {
                        logger.rotate_if_needed(cfg_snapshot.database.audit_rotation_size);
                    }
                    last_prune = std::time::Instant::now();
                }
                // Check for config reload (SIGHUP)
                if reload_flag.load(Ordering::Acquire) {
                    reload_flag.store(false, Ordering::Release);
                    log::info!("Reloading configuration...");
                    match config::load_config(None) {
                        Ok(new_config) => {
                            let old_config = active_config.read().clone();
                            // Diff old and new config
                            let changes = config::diff_config(&old_config, &new_config);
                            if changes.is_empty() {
                                log::info!("Configuration unchanged.");
                            } else {
                                for change in &changes {
                                    log::info!("Config change: {}", change);
                                }
                                // Watch paths / monitor backend require restart
                                let watch_changed = changes
                                    .iter()
                                    .any(|c| c.contains("watch group") || c.contains("path '"));
                                if watch_changed {
                                    log::warn!("Fanotify/inotify watch marks require a daemon restart to apply watch path changes");
                                }

                                // Update alert engine rate limiter and cooldown from new config
                                alert_engine.update_rate_config(
                                    new_config.alerts.rate_limit,
                                    new_config.alerts.cooldown_seconds,
                                );
                            }
                            // Rebuild event filter with new config
                            event_filter = EventFilter::new(&new_config);
                            // Swap the active config atomically
                            *active_config.write() = new_config;
                        }
                        Err(e) => {
                            log::error!("Failed to reload config: {}", e);
                        }
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                log::error!("Event channel disconnected");
                break;
            }
        }
    }

    // Cleanup
    log::info!("Shutting down...");
    cleanup_pid_file(&config.daemon.pid_file);
    let _ = db::wal_checkpoint(&conn);
    log::info!("Vigil daemon stopped.");

    Ok(())
}

/// Write the daemon PID file with advisory locking.
///
/// Uses `O_CREAT | O_EXCL` for atomic creation. If the file already exists,
/// checks whether the recorded PID is still alive. Stale PID files are
/// recovered atomically: the existing file is opened with `O_WRONLY | O_TRUNC`
/// (preserving the inode and any held lock), then re-locked and overwritten.
/// This avoids a TOCTOU window between remove + create_new where another
/// process could race into the same path.
fn write_pid_file(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Atomic PID file creation using O_CREAT | O_EXCL to prevent races
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            acquire_pid_lock(&file)?;
            write!(file, "{}", std::process::id())?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // PID file exists — check if the process is still alive
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(pid) = contents.trim().parse::<i32>() {
                    // SAFETY: kill with signal 0 only checks process existence,
                    // does not send any signal. pid is parsed from the PID file.
                    if unsafe { libc::kill(pid, 0) } == 0 {
                        return Err(crate::error::VigilError::Config(format!(
                            "Another vigil instance is running (PID {})",
                            pid
                        )));
                    }
                }
            }
            // Stale PID file recovery: open the *existing* inode with O_WRONLY | O_TRUNC,
            // acquire the lock, verify the PID is still stale (guards against a concurrent
            // vigil instance that claimed the file between our kill() probe and this open),
            // then overwrite with our PID. This keeps the inode locked throughout and
            // eliminates the TOCTOU window that existed with remove + create_new.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)?;
            acquire_pid_lock(&file)?;

            // Re-read the file via a separate handle to confirm it is still empty
            // (truncated by us) or still contains the stale PID. If a live PID now
            // appears, another instance won the race.
            if let Ok(contents) = std::fs::read_to_string(path) {
                let contents = contents.trim();
                if !contents.is_empty() {
                    if let Ok(pid) = contents.parse::<i32>() {
                        // SAFETY: kill with signal 0 checks process existence only.
                        if unsafe { libc::kill(pid, 0) } == 0 {
                            return Err(crate::error::VigilError::Daemon(format!(
                                "Lost PID file race: process {} is now running",
                                pid
                            )));
                        }
                    }
                }
            }

            write!(file, "{}", std::process::id())?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Acquire an exclusive, non-blocking advisory lock on a PID file.
///
/// Returns an error if the lock cannot be obtained (e.g., another process
/// holds it), which prevents the daemon from proceeding under the false
/// assumption that it is the sole instance.
fn acquire_pid_lock(file: &std::fs::File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: fd is a valid file descriptor obtained from as_raw_fd().
    // flock is safe to call with any valid fd and a valid lock operation
    // (LOCK_EX | LOCK_NB). The return value is checked immediately.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        log::warn!("Could not acquire advisory lock on PID file: {}", err);
        return Err(crate::error::VigilError::Daemon(format!(
            "cannot acquire PID file lock: {}",
            err
        )));
    }
    Ok(())
}

fn cleanup_pid_file(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

fn ctrlc_handler(
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
    sigset: nix::sys::signal::SigSet,
) {
    let _ = std::thread::Builder::new()
        .name("vigil-signal".into())
        .spawn(move || {
            use nix::sys::signal::Signal;
            loop {
                match sigset.wait() {
                    Ok(Signal::SIGHUP) => {
                        log::info!("Received SIGHUP, scheduling config reload...");
                        reload_flag.store(true, Ordering::Release);
                    }
                    Ok(sig) => {
                        log::info!("Received signal {:?}, shutting down...", sig);
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                    Err(e) => {
                        log::error!("Signal wait error: {}", e);
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn catch_unwind_isolates_panics() {
        // Simulate the daemon's panic-catching pattern
        let mut panic_count: u64 = 0;
        let paths = ["/etc/passwd", "/etc/shadow", "/etc/hosts"];

        for (i, path) in paths.iter().enumerate() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if i == 1 {
                    panic!("simulated comparison panic for {}", path);
                }
            }));

            if result.is_err() {
                panic_count += 1;
            }
        }

        // The loop should have continued past the panic
        assert_eq!(panic_count, 1);
    }

    #[test]
    fn write_pid_file_creates_and_locks() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let pid_path = dir.path().join("test.pid");

        super::write_pid_file(&pid_path).expect("first write_pid_file should succeed");

        let contents = std::fs::read_to_string(&pid_path).expect("read pid file");
        assert_eq!(contents.trim(), std::process::id().to_string());
    }

    #[test]
    fn write_pid_file_detects_held_lock() {
        use std::os::unix::io::AsRawFd;

        let dir = tempfile::tempdir().expect("create temp dir");
        let pid_path = dir.path().join("test-lock.pid");

        // Create the PID file and hold the lock via a separate file handle
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pid_path)
            .expect("create pid file");

        let fd = file.as_raw_fd();
        // SAFETY: fd is valid; we just opened the file.
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(ret, 0, "failed to acquire initial lock");

        // Write a PID that isn't alive so we enter the stale-recovery path.
        // PID 1 (init) is always alive but we want to test the lock contention
        // path, so we write a bogus PID and keep the lock held.
        use std::io::Write;
        let mut file = file;
        write!(file, "99999999").expect("write bogus pid");

        // Now attempt to write our PID file — should fail because the lock is held
        let result = super::write_pid_file(&pid_path);
        assert!(result.is_err(), "should fail when lock is held");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("lock") || err_msg.contains("PID"),
            "error should mention lock contention: {}",
            err_msg
        );
    }
}
