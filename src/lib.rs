pub mod alert;
pub mod baseline;
pub mod check_builder;
pub mod cli;
pub mod compare;
pub mod config;
pub mod db;
pub mod error;
pub mod hmac;
pub mod metrics;
pub mod monitor;
pub mod package;
pub mod scanner;
pub mod types;
pub mod watch_index;

pub use check_builder::CheckBuilder;

/// Optional progress callback for long-running operations.
pub type ProgressCallback<'a> = Option<&'a dyn Fn(&str)>;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::bounded;

use parking_lot::{Mutex, RwLock};

use crate::alert::AlertEngine;
use crate::config::Config;
use crate::db::ops;
use crate::error::Result;
use crate::metrics::Metrics;
use crate::monitor::filter::EventFilter;
use crate::types::{ChangeResult, ChangeType, DaemonState, FsEvent, FsEventType, Severity};
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

    let metrics = Arc::new(Metrics::new());
    let panic_count = Arc::new(AtomicU64::new(0));
    let daemon_state = Arc::new(RwLock::new(DaemonState::Healthy));
    let pending_db_writes: Arc<Mutex<std::collections::VecDeque<ChangeResult>>> =
        Arc::new(Mutex::new(std::collections::VecDeque::new()));

    let daemon_binary_path = std::fs::read_link("/proc/self/exe")
        .unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));
    let mut daemon_binary_hash = hash_path_blake3(&daemon_binary_path).ok();
    if let Some(hash) = &daemon_binary_hash {
        log::info!("Daemon binary hash: {}", hash);
    }

    let config_file_path = resolve_config_path();
    let mut config_file_hash = if config.security.verify_config_integrity {
        hash_path_blake3(&config_file_path).ok()
    } else {
        None
    };

    let mut hmac_key_hash = if config.security.hmac_signing {
        hash_path_blake3(&config.security.hmac_key_path).ok()
    } else {
        None
    };

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
    let alert_engine = Arc::new(AlertEngine::new(config)?);

    // Pre-compute watch group index for O(log n) prefix lookup
    let watch_index = Arc::new(RwLock::new(WatchGroupIndex::from_config(config)));

    // Event channel: monitor → coordinator
    let (event_tx, event_rx) = bounded(8192);
    // Internal channel: coordinator → workers
    let (worker_tx, worker_rx) = bounded(2048);

    // Start filesystem monitor (spawns its own thread)
    let monitor_handle = monitor::start_monitor(
        config,
        event_tx,
        shutdown.clone(),
        watch_index.clone(),
        metrics.clone(),
    )?;
    let monitor_reconfigure_tx = monitor_handle.reconfigure_tx.clone();
    log::info!(
        "Real-time monitor started (backend: {})",
        monitor_handle.backend
    );

    // Event filter (coordinator thread only)
    let mut event_filter = EventFilter::with_metrics(config, Some(metrics.clone()));

    // Cached maintenance window state to avoid per-event DB query
    let maintenance_active = Arc::new(std::sync::atomic::AtomicBool::new(
        ops::get_config_state(&conn, "maintenance_window_active")?
            .map(|v| v == "1")
            .unwrap_or(false),
    ));

    // Scheduled scan tracking
    let mut last_scheduled_scan = Instant::now();
    let mut cron_schedule = match croner::Cron::new(&config.scanner.schedule).parse() {
        Ok(cron) => Some(cron),
        Err(e) => {
            log::warn!(
                "Invalid cron schedule '{}': {}. Scheduled scans disabled.",
                config.scanner.schedule,
                e
            );
            None
        }
    };
    let mut scan_mode = config.scanner.mode;

    // Spawn worker pool
    let mut worker_handles = Vec::new();
    for i in 0..config.daemon.worker_threads {
        let worker_name = format!("vigil-worker-{}", i);
        let rx = worker_rx.clone();
        let shutdown_flag = shutdown.clone();
        let worker_watch_index = watch_index.clone();
        let worker_alert_engine = alert_engine.clone();
        let worker_active_config = active_config.clone();
        let worker_maintenance = maintenance_active.clone();
        let worker_metrics = metrics.clone();
        let worker_daemon_state = daemon_state.clone();
        let worker_pending_db = pending_db_writes.clone();
        let worker_panic_count = panic_count.clone();

        let handle = std::thread::Builder::new()
            .name(worker_name)
            .spawn(move || {
                let cfg_snapshot = worker_active_config.read().clone();
                let conn = match db::open_db(&cfg_snapshot) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("Worker failed to open database connection: {}", e);
                        return;
                    }
                };
                let mut wal_writes = 0u64;
                let mut change_batch: Vec<(ChangeResult, bool)> = Vec::new();
                let mut last_batch_flush = Instant::now();

                loop {
                    if shutdown_flag.load(Ordering::Acquire) && rx.is_empty() {
                        break;
                    }

                    match rx.recv_timeout(Duration::from_millis(250)) {
                        Ok(event) => {
                            worker_metrics
                                .events_processed
                                .fetch_add(1, Ordering::Relaxed);

                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    process_worker_event(
                                        event,
                                        &conn,
                                        &worker_watch_index,
                                        &worker_active_config,
                                        &worker_maintenance,
                                        &worker_metrics,
                                        &mut change_batch,
                                        &mut wal_writes,
                                    );
                                }));

                            if result.is_err() {
                                worker_panic_count.fetch_add(1, Ordering::Relaxed);
                                worker_metrics.panics_caught.fetch_add(1, Ordering::Relaxed);
                                log::error!("Worker thread panic caught and isolated");
                            }

                            if change_batch.len() >= 50
                                || last_batch_flush.elapsed() >= Duration::from_millis(100)
                            {
                                flush_change_batch(
                                    &mut change_batch,
                                    &conn,
                                    &worker_alert_engine,
                                    &worker_metrics,
                                    &worker_daemon_state,
                                    &worker_pending_db,
                                );
                                last_batch_flush = Instant::now();
                            }
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                            if !change_batch.is_empty()
                                && last_batch_flush.elapsed() >= Duration::from_millis(100)
                            {
                                flush_change_batch(
                                    &mut change_batch,
                                    &conn,
                                    &worker_alert_engine,
                                    &worker_metrics,
                                    &worker_daemon_state,
                                    &worker_pending_db,
                                );
                                last_batch_flush = Instant::now();
                            }
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }

                    if wal_writes >= 1000 {
                        if let Err(e) = db::wal_checkpoint(&conn) {
                            log::debug!("Worker WAL checkpoint error: {}", e);
                        }
                        wal_writes = 0;
                    }
                }

                if let Err(e) = db::wal_checkpoint(&conn) {
                    log::debug!("Worker final WAL checkpoint error: {}", e);
                }

                if !change_batch.is_empty() {
                    flush_change_batch(
                        &mut change_batch,
                        &conn,
                        &worker_alert_engine,
                        &worker_metrics,
                        &worker_daemon_state,
                        &worker_pending_db,
                    );
                }
            })
            .map_err(|e| {
                crate::error::VigilError::Daemon(format!("cannot spawn worker thread: {}", e))
            })?;

        worker_handles.push(handle);
    }

    let mut last_housekeeping = Instant::now();
    let mut last_dropped_total = 0u64;
    let mut recovery_scan_pending = false;

    log::info!("Vigil daemon ready. Monitoring filesystem changes...");

    while !shutdown.load(Ordering::Acquire) {
        // Process pending debounced paths on coordinator, then forward to workers
        let pending = event_filter.drain_pending();
        for pending_path in pending {
            let synthetic = FsEvent {
                path: pending_path,
                event_type: FsEventType::Modify,
                timestamp: chrono::Utc::now(),
            };

            match worker_tx.send_timeout(synthetic, Duration::from_millis(100)) {
                Ok(()) => {}
                Err(crossbeam_channel::SendTimeoutError::Timeout(_)) => {
                    log::error!(
                        "Internal worker queue full for 100ms — dropping pending debounced event"
                    );
                    metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                    log::error!("Worker queue disconnected");
                    shutdown.store(true, Ordering::Release);
                    break;
                }
            }
        }

        // Receive monitor events and forward accepted events to workers
        match event_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                if !event_filter.should_process(&event) {
                    continue;
                }

                match worker_tx.send_timeout(event, Duration::from_millis(100)) {
                    Ok(()) => {}
                    Err(crossbeam_channel::SendTimeoutError::Timeout(event)) => {
                        log::error!(
                            "Internal worker queue full for 100ms — dropping filesystem event for {}",
                            event.path.display()
                        );
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                        log::error!("Worker queue disconnected");
                        shutdown.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                log::error!("Event channel disconnected");
                break;
            }
        }

        if last_housekeeping.elapsed() >= Duration::from_secs(60) {
            event_filter.prune_debounce();

            let cfg_for_housekeeping = active_config.read().clone();

            match ops::rotate_audit_log(&conn, cfg_for_housekeeping.database.audit_retention_days) {
                Ok(0) => {}
                Ok(n) => log::info!("Rotated {} old audit log entries", n),
                Err(e) => log::warn!("Audit log rotation error: {}", e),
            }
            if let Some(logger) = alert_engine.json_logger() {
                logger.rotate_if_needed(cfg_for_housekeeping.database.audit_rotation_size);
            }

            maintenance_active.store(
                ops::get_config_state(&conn, "maintenance_window_active")
                    .ok()
                    .flatten()
                    .map(|v| v == "1")
                    .unwrap_or(false),
                Ordering::Release,
            );

            let dropped_total = metrics.events_dropped.load(Ordering::Relaxed);
            let dropped_delta = dropped_total.saturating_sub(last_dropped_total);
            last_dropped_total = dropped_total;
            if dropped_delta > 0 {
                log::warn!(
                    "{} filesystem events were dropped in the last interval; scheduling recovery scan",
                    dropped_delta
                );
                recovery_scan_pending = true;
            }

            if recovery_scan_pending {
                match baseline::diff_baseline(&conn, &cfg_for_housekeeping) {
                    Ok(changes) => {
                        log::warn!("Recovery scan found {} change(s)", changes.len());
                        let maintenance = maintenance_active.load(Ordering::Acquire);
                        for change in changes {
                            dispatch_change(
                                &change,
                                maintenance,
                                &conn,
                                &alert_engine,
                                &metrics,
                                &daemon_state,
                                &pending_db_writes,
                            );
                        }
                        recovery_scan_pending = false;
                    }
                    Err(e) => {
                        log::error!("Recovery scan failed: {}", e);
                    }
                }
            }

            if let Some(ref cron) = cron_schedule {
                if last_scheduled_scan.elapsed() > Duration::from_secs(60) {
                    let now = chrono::Utc::now();
                    if cron.is_time_matching(&now).unwrap_or(false) {
                        log::info!("Running scheduled {} integrity scan", scan_mode);
                        match scanner::run_scan(
                            &conn,
                            &cfg_for_housekeeping,
                            &alert_engine,
                            scan_mode,
                            None,
                        ) {
                            Ok(result) => {
                                log::info!(
                                    "Scheduled scan complete: {} checked, {} changes, {} errors",
                                    result.total_checked,
                                    result.changes_found,
                                    result.errors,
                                );
                                let _ = ops::set_config_state(
                                    &conn,
                                    "last_baseline_refresh",
                                    &chrono::Utc::now().timestamp().to_string(),
                                );
                            }
                            Err(e) => {
                                log::error!("Scheduled scan failed: {}", e);
                            }
                        }
                        last_scheduled_scan = Instant::now();
                    }
                }
            }

            // Self-protection checks
            if let Some(expected) = daemon_binary_hash.clone() {
                if let Ok(found) = hash_path_blake3(&daemon_binary_path) {
                    if found != expected {
                        log::error!(
                            "CRITICAL: Daemon binary has been modified! Expected {}, found {}. Possible compromise.",
                            expected,
                            found
                        );
                        let change = ChangeResult {
                            path: daemon_binary_path.clone(),
                            change_types: vec![ChangeType::Modified],
                            severity: Severity::Critical,
                            old_hash: Some(expected.clone()),
                            new_hash: Some(found.clone()),
                            old_permissions: None,
                            new_permissions: None,
                            old_owner_uid: None,
                            new_owner_uid: None,
                            old_owner_gid: None,
                            new_owner_gid: None,
                            old_inode: None,
                            new_inode: None,
                            old_mtime: None,
                            new_mtime: None,
                            package: None,
                            package_update: false,
                            monitored_group: "self_protection".into(),
                        };
                        dispatch_change(
                            &change,
                            false,
                            &conn,
                            &alert_engine,
                            &metrics,
                            &daemon_state,
                            &pending_db_writes,
                        );
                        daemon_binary_hash = Some(found);
                    }
                }
            }

            if let Some(expected) = hmac_key_hash.clone() {
                if let Ok(found) = hash_path_blake3(&cfg_for_housekeeping.security.hmac_key_path) {
                    if found != expected {
                        log::error!(
                            "CRITICAL: HMAC key file has been modified: {}",
                            cfg_for_housekeeping.security.hmac_key_path.display()
                        );
                        hmac_key_hash = Some(found);
                    }
                }
            }

            if let Some(expected) = config_file_hash.clone() {
                if let Ok(found) = hash_path_blake3(&config_file_path) {
                    if found != expected {
                        log::error!(
                            "CRITICAL: Vigil config file has been modified: {}",
                            config_file_path.display()
                        );
                        config_file_hash = Some(found);
                    }
                }
            }

            if matches!(&*daemon_state.read(), DaemonState::Degraded { .. }) && test_write_ok(&conn)
            {
                let mut flushed = 0u64;
                loop {
                    let next = { pending_db_writes.lock().pop_front() };
                    let Some(change) = next else { break };
                    let maintenance = maintenance_active.load(Ordering::Acquire);
                    if let Err(e) = alert_engine.dispatch(&change, maintenance, &conn) {
                        if is_disk_full_error(&e) {
                            pending_db_writes.lock().push_front(change);
                            break;
                        }
                    } else {
                        flushed += 1;
                    }
                }

                *daemon_state.write() = DaemonState::Healthy;
                log::warn!(
                    "Daemon recovered from degraded mode; flushed {} queued writes",
                    flushed
                );
            }

            if let Err(e) = write_metrics_snapshot(&metrics) {
                log::debug!("Cannot write metrics snapshot: {}", e);
            }
            if let Err(e) = write_daemon_state_file(&daemon_state) {
                log::debug!("Cannot write daemon state file: {}", e);
            }

            last_housekeeping = Instant::now();
        }

        if reload_flag.load(Ordering::Acquire) {
            reload_flag.store(false, Ordering::Release);
            log::info!("Reloading configuration...");
            match config::load_config(None) {
                Ok(new_config) => {
                    match config::validate_config_deep(&new_config) {
                        Ok(warnings) => {
                            for warning in warnings {
                                log::warn!("Config validation warning: {}", warning);
                            }
                        }
                        Err(e) => {
                            log::error!("New config rejected by deep validation: {}", e);
                            continue;
                        }
                    }

                    let old_config = active_config.read().clone();
                    let changes = config::diff_config(&old_config, &new_config);
                    if changes.is_empty() {
                        log::info!("Configuration unchanged.");
                    } else {
                        for change in &changes {
                            log::info!("Config change: {}", change);
                        }
                        alert_engine.update_rate_config(
                            new_config.alerts.rate_limit,
                            new_config.alerts.cooldown_seconds,
                        );
                    }

                    event_filter = EventFilter::with_metrics(&new_config, Some(metrics.clone()));
                    watch_index.write().update_from_config(&new_config);
                    if let Some(tx) = &monitor_reconfigure_tx {
                        let new_watch_paths = monitor::collect_watch_paths(&new_config);
                        if let Err(e) = tx.send(new_watch_paths) {
                            log::warn!(
                                "Failed to update monitor watch paths dynamically: {}. Restart required.",
                                e
                            );
                        } else {
                            log::info!("Watch paths updated dynamically");
                        }
                    } else {
                        log::warn!("Monitor backend does not support dynamic reconfiguration");
                    }

                    cron_schedule = match croner::Cron::new(&new_config.scanner.schedule).parse() {
                        Ok(cron) => Some(cron),
                        Err(e) => {
                            log::warn!(
                                "Invalid cron schedule '{}': {}. Scheduled scans disabled.",
                                new_config.scanner.schedule,
                                e
                            );
                            None
                        }
                    };
                    scan_mode = new_config.scanner.mode;

                    *active_config.write() = new_config;
                }
                Err(e) => {
                    log::error!("Failed to reload config: {}", e);
                }
            }
        }
    }

    // Cleanup
    log::info!("Shutting down...");
    drop(worker_tx);
    for handle in worker_handles {
        let _ = handle.join();
    }
    cleanup_pid_file(&config.daemon.pid_file);
    let _ = db::wal_checkpoint(&conn);
    log::info!("Vigil daemon stopped.");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_worker_event(
    event: FsEvent,
    conn: &rusqlite::Connection,
    watch_index: &Arc<RwLock<WatchGroupIndex>>,
    active_config: &Arc<RwLock<Config>>,
    maintenance_active: &Arc<std::sync::atomic::AtomicBool>,
    metrics: &Arc<Metrics>,
    change_batch: &mut Vec<(ChangeResult, bool)>,
    wal_writes: &mut u64,
) {
    let path_str = event.path.to_string_lossy().into_owned();
    let baseline_entry = match ops::get_baseline_by_path(conn, &path_str) {
        Ok(entry) => entry,
        Err(e) => {
            log::debug!("DB lookup error for {}: {}", path_str, e);
            return;
        }
    };

    let group_lookup = watch_index
        .read()
        .lookup(&event.path)
        .map(|(group, severity)| (group.to_string(), severity));

    // New file alerting for Create/MovedTo events that are under watched paths.
    if baseline_entry.is_none() {
        if matches!(event.event_type, FsEventType::Create | FsEventType::MovedTo) {
            if let Some((group_name, severity)) = group_lookup {
                let cfg_snapshot = active_config.read().clone();
                match baseline::metadata::collect_file_metadata(
                    &event.path,
                    &cfg_snapshot,
                    Some(cfg_snapshot.scanner.max_file_size),
                ) {
                    Ok(file_meta) => {
                        metrics.hashes_computed.fetch_add(1, Ordering::Relaxed);
                        let package = crate::package::query_package_owner(
                            &event.path,
                            &cfg_snapshot.package_manager,
                        );
                        let change = build_created_change(
                            &event.path,
                            &file_meta,
                            group_name,
                            severity,
                            package,
                        );
                        let maintenance = maintenance_active.load(Ordering::Acquire);
                        change_batch.push((change, maintenance));
                    }
                    Err(e) => {
                        if !event.path.exists() {
                            log::debug!(
                                "New file vanished before hashing (race): {}",
                                event.path.display()
                            );
                        } else {
                            log::debug!(
                                "Cannot collect metadata for new file {}: {}",
                                event.path.display(),
                                e
                            );
                        }
                    }
                }
            }
        }
        return;
    }

    let baseline_entry = baseline_entry.expect("baseline checked above");
    let (group_name, severity) = group_lookup.unwrap_or(("unknown".into(), Severity::Medium));

    // Explicit deletion handling to avoid race with compare path
    if matches!(
        event.event_type,
        FsEventType::Delete | FsEventType::MovedFrom
    ) && !event.path.exists()
    {
        let change = build_deleted_change(&event.path, &baseline_entry, group_name, severity);
        let maintenance = maintenance_active.load(Ordering::Acquire);
        change_batch.push((change, maintenance));
        *wal_writes += 1;
        return;
    }

    let max_file_size = active_config.read().scanner.max_file_size;
    metrics.hashes_computed.fetch_add(1, Ordering::Relaxed);
    match compare::compare_event(
        &event.path,
        &baseline_entry,
        &group_name,
        severity,
        max_file_size,
    ) {
        Ok(Some(mut change)) => {
            let maintenance = maintenance_active.load(Ordering::Acquire);

            if change.package.is_some() && maintenance {
                let still_owned = crate::package::query_package_owner(
                    &event.path,
                    &active_config.read().package_manager,
                );
                if still_owned == change.package {
                    change.package_update = true;
                }
            }

            change_batch.push((change.clone(), maintenance));

            if change.package_update {
                let cfg_snapshot = active_config.read().clone();
                if cfg_snapshot.package_manager.auto_rebaseline {
                    match crate::baseline::add_file(conn, &change.path, &cfg_snapshot) {
                        Ok(()) => {
                            log::info!(
                                "Auto-rebaselined package-updated file: {}",
                                change.path.display()
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "Auto-rebaseline failed for {}: {}",
                                change.path.display(),
                                e
                            );
                        }
                    }
                }
            }

            *wal_writes += 1;
        }
        Ok(None) => {}
        Err(e) => {
            log::debug!("Comparison error for {}: {}", event.path.display(), e);
        }
    }
}

fn flush_change_batch(
    batch: &mut Vec<(ChangeResult, bool)>,
    conn: &rusqlite::Connection,
    alert_engine: &Arc<AlertEngine>,
    metrics: &Arc<Metrics>,
    daemon_state: &Arc<RwLock<DaemonState>>,
    pending_db_writes: &Arc<Mutex<std::collections::VecDeque<ChangeResult>>>,
) {
    if batch.is_empty() {
        return;
    }

    let mut drained = Vec::new();
    std::mem::swap(&mut drained, batch);

    let mut in_transaction = false;
    if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
        log::debug!("Could not begin worker batch transaction: {}", e);
    } else {
        in_transaction = true;
    }

    for (change, maintenance) in drained {
        dispatch_change(
            &change,
            maintenance,
            conn,
            alert_engine,
            metrics,
            daemon_state,
            pending_db_writes,
        );
    }

    if in_transaction {
        if let Err(e) = conn.execute_batch("COMMIT") {
            log::debug!("Worker batch COMMIT failed: {}", e);
            let _ = conn.execute_batch("ROLLBACK");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_change(
    change: &ChangeResult,
    maintenance: bool,
    conn: &rusqlite::Connection,
    alert_engine: &Arc<AlertEngine>,
    metrics: &Arc<Metrics>,
    daemon_state: &Arc<RwLock<DaemonState>>,
    pending_db_writes: &Arc<Mutex<std::collections::VecDeque<ChangeResult>>>,
) {
    metrics.changes_detected.fetch_add(1, Ordering::Relaxed);

    match alert_engine.dispatch(change, maintenance, conn) {
        Ok(()) => {
            metrics.alerts_dispatched.fetch_add(1, Ordering::Relaxed);
            metrics.db_writes.fetch_add(1, Ordering::Relaxed);
        }
        Err(e) => {
            metrics.db_errors.fetch_add(1, Ordering::Relaxed);
            if is_disk_full_error(&e) {
                log::error!(
                    "Storage full while writing alert/audit entry; entering degraded mode: {}",
                    e
                );
                *daemon_state.write() = DaemonState::Degraded {
                    reason: e.to_string(),
                    since: chrono::Utc::now(),
                };

                let mut queue = pending_db_writes.lock();
                if queue.len() >= 10_000 {
                    let _ = queue.pop_front();
                    log::error!("Pending DB queue full (10000); dropping oldest queued change");
                }
                queue.push_back(change.clone());
            } else {
                log::error!("Alert dispatch error: {}", e);
            }
        }
    }
}

fn build_created_change(
    path: &std::path::Path,
    meta: &crate::types::FileMetadata,
    group_name: String,
    severity: Severity,
    package: Option<String>,
) -> ChangeResult {
    ChangeResult {
        path: path.to_path_buf(),
        change_types: vec![ChangeType::Created],
        severity,
        old_hash: None,
        new_hash: Some(meta.hash.clone()),
        old_permissions: None,
        new_permissions: Some(meta.permissions),
        old_owner_uid: None,
        new_owner_uid: Some(meta.owner_uid),
        old_owner_gid: None,
        new_owner_gid: Some(meta.owner_gid),
        old_inode: None,
        new_inode: Some(meta.inode),
        old_mtime: None,
        new_mtime: Some(meta.mtime),
        package,
        package_update: false,
        monitored_group: group_name,
    }
}

fn build_deleted_change(
    path: &std::path::Path,
    baseline: &crate::types::BaselineEntry,
    group_name: String,
    severity: Severity,
) -> ChangeResult {
    ChangeResult {
        path: path.to_path_buf(),
        change_types: vec![ChangeType::Deleted],
        severity,
        old_hash: Some(baseline.hash.clone()),
        new_hash: None,
        old_permissions: Some(baseline.permissions),
        new_permissions: None,
        old_owner_uid: Some(baseline.owner_uid),
        new_owner_uid: None,
        old_owner_gid: Some(baseline.owner_gid),
        new_owner_gid: None,
        old_inode: Some(baseline.inode),
        new_inode: None,
        old_mtime: Some(baseline.mtime),
        new_mtime: None,
        package: baseline.package.clone(),
        package_update: false,
        monitored_group: group_name,
    }
}

fn is_disk_full_error(err: &crate::error::VigilError) -> bool {
    match err {
        crate::error::VigilError::Io(ioe) => ioe.raw_os_error() == Some(libc::ENOSPC),
        crate::error::VigilError::Database(rusqlite::Error::SqliteFailure(db_err, _)) => {
            db_err.code == rusqlite::ErrorCode::DiskFull
        }
        crate::error::VigilError::Alert(msg)
        | crate::error::VigilError::Baseline(msg)
        | crate::error::VigilError::Config(msg)
        | crate::error::VigilError::Daemon(msg) => {
            msg.contains("database or disk is full") || msg.contains("No space left")
        }
        _ => false,
    }
}

fn test_write_ok(conn: &rusqlite::Connection) -> bool {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _vigil_healthcheck (v INTEGER)",
        [],
    )
    .and_then(|_| conn.execute("INSERT INTO _vigil_healthcheck (v) VALUES (1)", []))
    .and_then(|_| conn.execute("DELETE FROM _vigil_healthcheck", []))
    .is_ok()
}

fn write_metrics_snapshot(metrics: &Metrics) -> Result<()> {
    let snapshot = metrics.snapshot();
    let json = serde_json::to_string_pretty(&snapshot)?;
    let path = std::path::PathBuf::from("/run/vigil/metrics.json");
    write_json_atomic(&path, &json)
}

fn write_daemon_state_file(state: &Arc<RwLock<DaemonState>>) -> Result<()> {
    let json = match &*state.read() {
        DaemonState::Healthy => serde_json::json!({
            "state": "healthy"
        }),
        DaemonState::Degraded { reason, since } => serde_json::json!({
            "state": "degraded",
            "reason": reason,
            "since": since,
        }),
    };

    let body = serde_json::to_string_pretty(&json)?;
    let path = std::path::PathBuf::from("/run/vigil/state.json");
    write_json_atomic(&path, &body)
}

fn write_json_atomic(path: &std::path::Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn hash_path_blake3(path: &std::path::Path) -> Result<String> {
    let file = std::fs::File::open(path)?;
    crate::baseline::hash::blake3_hash_file(&file)
}

fn resolve_config_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("VIGIL_CONFIG") {
        return std::path::PathBuf::from(path);
    }
    std::path::PathBuf::from("/etc/vigil/vigil.toml")
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
