pub mod alert;
pub mod baseline;
pub mod cli;
pub mod compare;
pub mod config;
pub mod db;
pub mod error;
pub mod monitor;
pub mod package;
pub mod scanner;
pub mod types;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::bounded;

use crate::alert::AlertEngine;
use crate::config::Config;
use crate::db::ops;
use crate::error::Result;
use crate::monitor::filter::EventFilter;
use crate::types::FsEventType;

/// Run the Vigil daemon main loop.
///
/// Architecture:
/// - Main thread: epoll event loop (fanotify/inotify) → event channel
/// - Hasher worker pool (2 threads): receive events, hash, compare, classify
/// - Output writer: batched DB writes, log flushing
/// - D-Bus dispatcher: notification delivery
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

    // Set up shutdown signal handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc_handler(shutdown_clone);

    // Create alert engine
    let alert_engine = AlertEngine::new(config)?;

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

    while !shutdown.load(Ordering::Relaxed) {
        // Receive events with a timeout so we can check shutdown flag
        match event_rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(event) => {
                // Apply event filter
                if !event_filter.should_process(&event) {
                    continue;
                }

                // Look up baseline entry
                let path_str = event.path.to_string_lossy().into_owned();
                let baseline_entry = match ops::get_baseline_by_path(&conn, &path_str) {
                    Ok(Some(entry)) => entry,
                    Ok(None) => {
                        // New file in monitored directory (not in baseline)
                        // Determine which watch group it belongs to
                        if matches!(event.event_type, FsEventType::Create | FsEventType::MovedTo) {
                            log::info!("New file detected: {}", event.path.display());
                        }
                        continue;
                    }
                    Err(e) => {
                        log::debug!("DB lookup error for {}: {}", path_str, e);
                        continue;
                    }
                };

                // Determine watch group and severity for this path
                let (group_name, severity) = find_watch_group(&event.path, config)
                    .unwrap_or(("unknown".into(), types::Severity::Medium));

                // Compare against baseline
                match compare::compare_event(&event.path, &baseline_entry, &group_name, severity) {
                    Ok(Some(change)) => {
                        let maintenance = ops::get_config_state(&conn, "maintenance_window_active")
                            .ok()
                            .flatten()
                            .map(|v| v == "1")
                            .unwrap_or(false);

                        if let Err(e) = alert_engine.dispatch(&change, maintenance, &conn) {
                            log::error!("Alert dispatch error: {}", e);
                        }
                    }
                    Ok(None) => {} // no change (hash matched despite event)
                    Err(e) => {
                        log::debug!("Comparison error for {}: {}", event.path.display(), e);
                    }
                }

                // WAL checkpoint every 1000 writes
                wal_writes += 1;
                if wal_writes >= 1000 {
                    let _ = db::wal_checkpoint(&conn);
                    wal_writes = 0;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Periodic housekeeping
                if last_prune.elapsed() > std::time::Duration::from_secs(60) {
                    event_filter.prune_debounce();
                    last_prune = std::time::Instant::now();
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

/// Find which watch group a path belongs to, returning (group_name, severity).
fn find_watch_group(path: &std::path::Path, config: &Config) -> Option<(String, types::Severity)> {
    let _path_str = path.to_string_lossy();

    for (group_name, group) in &config.watch {
        let expanded = config::expand_user_paths(&group.paths);
        for watch_path in &expanded {
            if path.starts_with(watch_path) || path == watch_path {
                return Some((group_name.clone(), group.severity));
            }
        }
    }

    None
}

fn write_pid_file(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}", std::process::id()))?;
    Ok(())
}

fn cleanup_pid_file(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

fn ctrlc_handler(shutdown: Arc<AtomicBool>) {
    let _ = std::thread::Builder::new()
        .name("vigil-signal".into())
        .spawn(move || {
            // Block on SIGINT/SIGTERM using nix
            use nix::sys::signal::{SigSet, Signal};
            let mut sigset = SigSet::empty();
            sigset.add(Signal::SIGINT);
            sigset.add(Signal::SIGTERM);
            sigset.thread_block().ok();

            // Wait for signal
            match sigset.wait() {
                Ok(sig) => {
                    log::info!("Received signal {:?}, shutting down...", sig);
                    shutdown.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    log::error!("Signal wait error: {}", e);
                    shutdown.store(true, Ordering::Relaxed);
                }
            }
        });
}
