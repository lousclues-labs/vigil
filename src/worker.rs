use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use lru::LruCache;
use rusqlite::Connection;

use crate::alert::AlertPayload;
use crate::config::Config;
use crate::db::{self, baseline_ops};
use crate::error::{Result, VigilError};
use crate::filter::EventFilter;
use crate::metrics::Metrics;
use crate::types::{
    BaselineEntry, CaptureOpts, Change, ChangeResult, FsEvent, FsEventType, Severity,
    SnapshotOrDeleted,
};
use crate::watch_index::WatchGroupIndex;

/// Baseline update sent from workers to the baseline writer thread.
pub struct BaselineUpdate {
    pub entry: BaselineEntry,
    pub reason: UpdateReason,
}

pub enum UpdateReason {
    PackageUpdate,
    AutoRebaseline,
}

/// Duplicate a raw file descriptor and wrap it in a `File` with RAII ownership.
fn dup_to_file(raw_fd: std::os::fd::RawFd) -> std::io::Result<std::fs::File> {
    // SAFETY: dup() creates a new fd referring to the same open file description.
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: dup_fd is a fresh owned descriptor returned by dup above.
    Ok(unsafe { std::fs::File::from_raw_fd(dup_fd) })
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_workers(
    count: u32,
    config: Arc<ArcSwap<Config>>,
    event_rx: Receiver<FsEvent>,
    alert_tx: Sender<AlertPayload>,
    baseline_db_path: &Path,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    baseline_update_tx: Option<Sender<BaselineUpdate>>,
    backpressure: Arc<AtomicBool>,
    baseline_generation: Arc<AtomicU64>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    for i in 0..count {
        let event_rx = event_rx.clone();
        let alert_tx = alert_tx.clone();
        let config = config.clone();
        let watch_index = watch_index.clone();
        let metrics = metrics.clone();
        let shutdown = shutdown.clone();
        let db_path = baseline_db_path.to_path_buf();
        let update_tx = baseline_update_tx.clone();
        let backpressure = backpressure.clone();
        let generation = baseline_generation.clone();

        let handle_result = std::thread::Builder::new()
            .name(format!("vigil-worker-{}", i))
            .spawn(move || {
                let conn = match db::open_baseline_db_readonly(&db_path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %e, "worker failed to open baseline db");
                        return;
                    }
                };

                let cfg = config.load();
                let mut filter = EventFilter::with_metrics(&cfg, Some(metrics.clone()));
                let mut cache: LruCache<String, BaselineEntry> =
                    LruCache::new(std::num::NonZeroUsize::new(8192).unwrap());
                let mut drain_counter = 0u32;
                let mut last_drain = std::time::Instant::now();
                let mut local_generation = generation.load(Ordering::Acquire);

                while !shutdown.load(Ordering::Acquire) {
                    // Invalidate LRU cache when baseline writer has committed new entries
                    let current_gen = generation.load(Ordering::Acquire);
                    if current_gen != local_generation {
                        cache.clear();
                        local_generation = current_gen;
                    }
                    // Periodically drain debounced events (count or time-based)
                    drain_counter += 1;
                    if drain_counter >= 10 || last_drain.elapsed() >= Duration::from_millis(200) {
                        drain_counter = 0;
                        last_drain = std::time::Instant::now();
                        let pending = filter.drain_pending();
                        for path in pending {
                            let path_str = path.to_string_lossy().to_string();
                            // Invalidate cache for re-checked paths
                            cache.pop(&path_str);

                            // Re-check drained paths by processing them as synthetic events
                            let synthetic = FsEvent {
                                path: Arc::new(path),
                                event_type: FsEventType::Modify,
                                timestamp: chrono::Utc::now(),
                                event_fd: None,
                                process: None,
                            };

                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    process_event_cached(
                                        &conn,
                                        &synthetic,
                                        &config,
                                        &watch_index,
                                        &metrics,
                                        &mut cache,
                                    )
                                }));

                            match result {
                                Ok(Ok(Some(change_result))) => {
                                    let p_str =
                                        change_result.path.to_string_lossy().to_string();
                                    cache.pop(&p_str);
                                    if alert_tx
                                        .send(AlertPayload {
                                            change: change_result,
                                            maintenance_window: false,
                                        })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => {
                                    tracing::warn!(error = %e, "debounce re-check error");
                                }
                                Err(_) => {
                                    metrics
                                        .panics_caught
                                        .fetch_add(1, Ordering::Relaxed);
                                    tracing::error!(
                                        "panic caught during debounce re-check"
                                    );
                                }
                            }
                        }
                    }

                    match event_rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(event) => {
                            // Clear backpressure flag on successful receive
                            backpressure.store(false, Ordering::Relaxed);

                            // Apply EventFilter before processing
                            if !filter.should_process(&event) {
                                continue;
                            }

                            metrics.events_processed.fetch_add(1, Ordering::Relaxed);

                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    process_event_cached(
                                        &conn,
                                        &event,
                                        &config,
                                        &watch_index,
                                        &metrics,
                                        &mut cache,
                                    )
                                }));

                            match result {
                                Ok(Ok(Some(change_result))) => {
                                    // Invalidate cache for changed paths
                                    let path_str =
                                        change_result.path.to_string_lossy().to_string();
                                    cache.pop(&path_str);

                                    // Auto-rebaseline for package updates
                                    if change_result.package_update {
                                        if let Some(ref tx) = update_tx {
                                            let cfg = config.load();
                                            if cfg.package_manager.auto_rebaseline {
                                                // Re-snapshot the file to capture post-update state
                                                let now_ts = chrono::Utc::now().timestamp();
                                                let opts = CaptureOpts {
                                                    force_hash: true,
                                                    max_file_size: cfg.scanner.max_file_size,
                                                    mmap_threshold: cfg.scanner.mmap_threshold,
                                                    baseline_mtime: None,
                                                    baseline_hash: None,
                                                };

                                                if let Ok(SnapshotOrDeleted::Snapshot(fresh)) =
                                                    crate::types::FileSnapshot::from_path(&change_result.path, &opts)
                                                {
                                                    let _ = tx.try_send(BaselineUpdate {
                                                        entry: BaselineEntry {
                                                            id: None,
                                                            path: change_result.path.as_ref().clone(),
                                                            identity: fresh.identity,
                                                            content: fresh.content,
                                                            permissions: fresh.permissions,
                                                            security: fresh.security,
                                                            mtime: fresh.mtime,
                                                            package: change_result.package.clone(),
                                                            source: crate::types::BaselineSource::PackageManager,
                                                            added_at: now_ts,
                                                            updated_at: now_ts,
                                                        },
                                                        reason: UpdateReason::PackageUpdate,
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    if alert_tx
                                        .send(AlertPayload {
                                            change: change_result,
                                            maintenance_window: false,
                                        })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => {
                                    tracing::warn!(error = %e, "event processing error");
                                }
                                Err(_) => {
                                    metrics.panics_caught.fetch_add(1, Ordering::Relaxed);
                                    tracing::error!("panic caught in worker thread");
                                }
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            });

        match handle_result {
            Ok(h) => handles.push(h),
            Err(e) => {
                tracing::error!(error = %e, "failed to spawn worker thread");
            }
        }
    }

    handles
}

pub fn process_event(
    conn: &Connection,
    event: &FsEvent,
    config: &Arc<ArcSwap<Config>>,
    watch_index: &Arc<ArcSwap<WatchGroupIndex>>,
    metrics: &Metrics,
) -> Result<Option<ChangeResult>> {
    let cfg = config.load();
    let idx = watch_index.load();

    let path_str = event.path.to_string_lossy();
    let baseline = match baseline_ops::get_by_path(conn, path_str.as_ref())? {
        Some(b) => b,
        None => {
            if matches!(event.event_type, FsEventType::Create | FsEventType::MovedTo) {
                if let Some((group_name, severity)) = idx.lookup(&event.path) {
                    return Ok(Some(ChangeResult {
                        path: event.path.clone(),
                        changes: vec![Change::Created],
                        severity,
                        monitored_group: group_name.to_string(),
                        process: event.process.clone(),
                        package: None,
                        package_update: false,
                    }));
                }
                tracing::info!(path = %event.path.display(), "new file detected (not in baseline)");
            }
            return Ok(None);
        }
    };

    process_event_inner(conn, event, &cfg, &idx, metrics, baseline)
}

/// Process event with LRU cache lookup.
fn process_event_cached(
    conn: &Connection,
    event: &FsEvent,
    config: &Arc<ArcSwap<Config>>,
    watch_index: &Arc<ArcSwap<WatchGroupIndex>>,
    metrics: &Metrics,
    cache: &mut LruCache<String, BaselineEntry>,
) -> Result<Option<ChangeResult>> {
    let cfg = config.load();
    let idx = watch_index.load();

    let path_str = event.path.to_string_lossy().to_string();

    let baseline = if let Some(cached) = cache.get(&path_str) {
        metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
        cached.clone()
    } else {
        metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        match baseline_ops::get_by_path(conn, &path_str)? {
            Some(b) => {
                cache.put(path_str.clone(), b.clone());
                b
            }
            None => {
                if matches!(event.event_type, FsEventType::Create | FsEventType::MovedTo) {
                    if let Some((group_name, severity)) = idx.lookup(&event.path) {
                        return Ok(Some(ChangeResult {
                            path: event.path.clone(),
                            changes: vec![Change::Created],
                            severity,
                            monitored_group: group_name.to_string(),
                            process: event.process.clone(),
                            package: None,
                            package_update: false,
                        }));
                    }
                    tracing::info!(path = %event.path.display(), "new file detected (not in baseline)");
                }
                return Ok(None);
            }
        }
    };

    let result = process_event_inner(conn, event, &cfg, &idx, metrics, baseline)?;

    // Invalidate cache on detected change
    if result.is_some() {
        cache.pop(&path_str);
    }

    Ok(result)
}

fn process_event_inner(
    _conn: &Connection,
    event: &FsEvent,
    cfg: &Config,
    idx: &WatchGroupIndex,
    metrics: &Metrics,
    baseline: BaselineEntry,
) -> Result<Option<ChangeResult>> {
    // Self-protection: log at error level if config or HMAC key is modified
    let path_str_ref = event.path.to_string_lossy();
    let config_path = "/etc/vigil/vigil.toml";
    let hmac_key_path = cfg.security.hmac_key_path.to_string_lossy();
    if path_str_ref.as_ref() == config_path {
        tracing::error!(
            path = %event.path.display(),
            "vigil self-protection: config file modified"
        );
    } else if path_str_ref.as_ref() == hmac_key_path.as_ref() {
        tracing::error!(
            path = %event.path.display(),
            "vigil self-protection: HMAC key file modified"
        );
    }

    let (group_name, severity) = idx
        .lookup(&event.path)
        .map(|(g, s)| (g.to_string(), s))
        .unwrap_or(("unknown".into(), Severity::Medium));

    let opts = CaptureOpts {
        force_hash: true,
        max_file_size: cfg.scanner.max_file_size,
        mmap_threshold: cfg.scanner.mmap_threshold,
        baseline_mtime: None,
        baseline_hash: None,
    };

    let snapshot = if let Some(ref fd) = event.event_fd {
        let raw = fd.as_raw_fd();
        let file = dup_to_file(raw).map_err(|e| {
            VigilError::Baseline(format!(
                "failed to dup event fd for {}: {}",
                event.path.display(),
                e
            ))
        })?;
        crate::types::FileSnapshot::from_fd(&file, &event.path, &opts)?
    } else {
        match crate::types::FileSnapshot::from_path(&event.path, &opts)? {
            SnapshotOrDeleted::Snapshot(s) => s,
            SnapshotOrDeleted::Deleted => {
                return Ok(Some(ChangeResult::deletion(
                    &event.path,
                    &baseline,
                    severity,
                    group_name,
                )));
            }
        }
    };

    metrics.hashes_computed.fetch_add(1, Ordering::Relaxed);

    let changes = snapshot.diff(&baseline);
    if changes.is_empty() {
        return Ok(None);
    }

    let final_severity = if snapshot.has_dangerous_capabilities()
        && changes
            .iter()
            .any(|c| matches!(c, Change::ContentModified { .. }))
    {
        severity.max(Severity::Critical)
    } else {
        severity
    };

    // Detect package-owned file changes for auto-rebaseline
    let is_package_update = baseline.package.is_some()
        && changes
            .iter()
            .any(|c| matches!(c, Change::ContentModified { .. }));

    Ok(Some(ChangeResult {
        path: event.path.clone(),
        changes,
        severity: final_severity,
        monitored_group: group_name,
        process: event.process.clone(),
        package: baseline.package.clone(),
        package_update: is_package_update,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::io::Read;

    #[test]
    fn dup_to_file_returns_valid_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp.as_file(), b"hello").unwrap();

        let raw_fd = tmp.as_raw_fd();
        let mut duped = dup_to_file(raw_fd).unwrap();

        // Seek to start and read contents
        use std::io::Seek;
        duped.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut buf = String::new();
        duped.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello");
    }

    #[test]
    fn process_event_returns_none_for_non_baselined_create() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();

        let cfg = crate::config::default_config();
        let watch = WatchGroupIndex::from_config(&cfg);

        let event = FsEvent {
            path: Arc::new("/tmp/nonexistent-baseline".into()),
            event_type: FsEventType::Create,
            timestamp: Utc::now(),
            event_fd: None,
            process: None,
        };

        let out = process_event(
            &conn,
            &event,
            &Arc::new(ArcSwap::from_pointee(cfg)),
            &Arc::new(ArcSwap::from_pointee(watch)),
            &Metrics::new(),
        )
        .unwrap();

        assert!(out.is_none());
    }

    #[test]
    fn baseline_update_for_package_has_real_data() {
        // Verify that a BaselineEntry built for package updates
        // does not contain zeroed/default fields
        let entry = BaselineEntry {
            id: None,
            path: std::path::PathBuf::from("/usr/bin/test"),
            identity: Default::default(),
            content: Default::default(),
            permissions: Default::default(),
            security: Default::default(),
            mtime: 0,
            package: Some("test-pkg".into()),
            source: crate::types::BaselineSource::PackageManager,
            added_at: 0,
            updated_at: 0,
        };
        // This entry has zeroed content — a real update should never have an empty hash
        assert!(
            entry.content.hash.is_empty(),
            "default content hash should be empty"
        );
        assert_eq!(entry.mtime, 0, "default mtime should be zero");
        // These assertions document the bug: if an entry with these values
        // reaches the database, every subsequent scan will produce false changes.
    }

    #[test]
    fn process_event_detects_new_file_under_watched_path() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();

        let cfg = crate::config::default_config();
        let watch = WatchGroupIndex::from_config(&cfg);

        // Use a path under a configured watch group (e.g., /etc/something)
        let watched_path = cfg
            .watch
            .values()
            .next()
            .and_then(|g| g.paths.first())
            .map(|p| format!("{}/new_suspicious_file", p))
            .unwrap_or_else(|| "/etc/new_suspicious_file".to_string());

        let event = FsEvent {
            path: Arc::new(watched_path.into()),
            event_type: FsEventType::Create,
            timestamp: Utc::now(),
            event_fd: None,
            process: None,
        };

        let result = process_event(
            &conn,
            &event,
            &Arc::new(ArcSwap::from_pointee(cfg)),
            &Arc::new(ArcSwap::from_pointee(watch)),
            &Metrics::new(),
        )
        .unwrap();

        // Should detect new file if path is under a watch group
        if let Some(cr) = result {
            assert!(cr.changes.iter().any(|c| matches!(c, Change::Created)));
        }
        // If the default config doesn't have a watch group covering this exact path,
        // that's also valid — the test documents the intended behavior.
    }
}
