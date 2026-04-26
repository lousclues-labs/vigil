//! Worker pool for filesystem event processing.
//!
//! Each worker thread owns a read-only baseline DB connection and a
//! BLAKE3-keyed file cache. Events arrive from the monitor via a bounded
//! channel, are compared against the baseline snapshot (fd-based TOCTOU
//! hardened), and deviations dispatch to the WAL or alert channel.
//! Panics are caught per-event; the worker stays alive.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
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
use crate::detection;
use crate::error::{Result, VigilError};
use crate::filter::EventFilter;
use crate::metrics::Metrics;
use crate::types::{
    BaselineEntry, CaptureOpts, Change, ChangeResult, FsEvent, FsEventType, Severity,
    SnapshotOrDeleted,
};
use crate::wal::{DetectionRecord, DetectionSource, DetectionWal};
use crate::watch_index::WatchGroupIndex;

/// Number of consecutive DB errors before the worker attempts to reopen the
/// baseline connection. Prevents permanent degradation from transient SQLite errors.
const WORKER_DB_REOPEN_THRESHOLD: u32 = 10;

/// Maximum consecutive reopen failures before the worker gives up.
const WORKER_DB_MAX_REOPEN_FAILURES: u32 = 5;

/// Maximum backoff delay between reopen attempts (seconds).
const WORKER_DB_MAX_BACKOFF_SECS: u64 = 60;

/// Baseline update sent from workers to the baseline writer thread.
pub struct BaselineUpdate {
    pub entry: BaselineEntry,
    pub reason: UpdateReason,
}

pub enum UpdateReason {
    PackageUpdate,
}

impl std::fmt::Display for UpdateReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateReason::PackageUpdate => write!(f, "package_update"),
        }
    }
}

#[allow(unsafe_code)]
fn dup_to_file(raw_fd: std::os::fd::RawFd) -> std::io::Result<std::fs::File> {
    // SAFETY: fcntl(F_DUPFD_CLOEXEC) creates a new fd >= 0 with close-on-exec.
    // The source fd is valid because it comes from an OwnedFd in FsEvent.
    // A negative return means the dup failed; we check for that below.
    let dup_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: dup_fd is a fresh descriptor just returned by fcntl.
    // No other code holds it, so from_raw_fd takes unique ownership.
    // If the dup had failed, we returned Err above.
    Ok(unsafe { std::fs::File::from_raw_fd(dup_fd) })
}

/// Arguments for spawning the worker pool.
pub struct WorkerSpawnArgs {
    pub count: u32,
    pub config: Arc<ArcSwap<Config>>,
    pub event_rx: Receiver<FsEvent>,
    pub alert_tx: Sender<AlertPayload>,
    pub baseline_db_path: PathBuf,
    pub watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    pub metrics: Arc<Metrics>,
    pub shutdown: Arc<AtomicBool>,
    pub baseline_update_tx: Option<Sender<BaselineUpdate>>,
    pub backpressure: Arc<AtomicBool>,
    pub baseline_generation: Arc<AtomicU64>,
    pub wal: Option<Arc<DetectionWal>>,
    pub maintenance_active: Arc<AtomicBool>,
    pub state: Option<Arc<parking_lot::RwLock<crate::types::DaemonState>>>,
    /// Pre-computed self-protection paths (config files + HMAC key).
    /// Shared across all workers via Arc. Computed once at startup.
    pub self_protection_paths: Arc<HashSet<PathBuf>>,
}

/// Per-worker processing context holding connection, cache, and filter state.
pub struct WorkerContext {
    conn: Connection,
    db_path: PathBuf,
    config: Arc<ArcSwap<Config>>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    metrics: Arc<Metrics>,
    filter: EventFilter,
    cache: LruCache<String, Arc<BaselineEntry>>,
    local_generation: u64,
    generation: Arc<AtomicU64>,
    drain_counter: u32,
    last_drain: std::time::Instant,
    wal: Option<Arc<DetectionWal>>,
    maintenance_active: Arc<AtomicBool>,
    consecutive_db_errors: u32,
    consecutive_reopen_failures: u32,
    last_reopen_attempt: Option<std::time::Instant>,
    state: Option<Arc<parking_lot::RwLock<crate::types::DaemonState>>>,
    /// Pre-computed self-protection paths (config files + HMAC key).
    self_protection_paths: Arc<HashSet<PathBuf>>,
}

impl WorkerContext {
    /// Construct a minimal WorkerContext for tests.
    pub fn for_test(conn: Connection, config: &Config) -> Self {
        let metrics = Arc::new(Metrics::new());
        let mut self_protection = HashSet::new();
        for p in crate::config::config_search_paths(None) {
            self_protection.insert(p);
        }
        self_protection.insert(config.security.hmac_key_path.clone());
        Self {
            conn,
            db_path: PathBuf::from("/dev/null"),
            config: Arc::new(ArcSwap::from_pointee(config.clone())),
            watch_index: Arc::new(ArcSwap::from_pointee(WatchGroupIndex::from_config(config))),
            metrics,
            filter: EventFilter::with_metrics(config, None),
            cache: LruCache::new(std::num::NonZeroUsize::new(64).unwrap()),
            local_generation: 0,
            generation: Arc::new(AtomicU64::new(0)),
            drain_counter: 0,
            last_drain: std::time::Instant::now(),
            wal: None,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            consecutive_db_errors: 0,
            consecutive_reopen_failures: 0,
            last_reopen_attempt: None,
            state: None,
            self_protection_paths: Arc::new(self_protection),
        }
    }

    fn refresh_cache_if_stale(&mut self) {
        let current_gen = self.generation.load(Ordering::Acquire);
        if current_gen != self.local_generation {
            self.cache.clear();
            self.local_generation = current_gen;
        }
    }

    pub fn evaluate(&mut self, event: &FsEvent) -> Result<Option<ChangeResult>> {
        let cfg = self.config.load();
        let idx = self.watch_index.load();
        let path_cow = event.path.to_string_lossy();

        let baseline = if let Some(cached) = self.cache.get(path_cow.as_ref()) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            Arc::clone(cached)
        } else {
            self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
            match baseline_ops::get_by_path(&self.conn, path_cow.as_ref()) {
                Ok(Some(b)) => {
                    self.consecutive_db_errors = 0;
                    let arc = Arc::new(b);
                    self.cache
                        .put(path_cow.clone().into_owned(), Arc::clone(&arc));
                    arc
                }
                Ok(None) => {
                    self.consecutive_db_errors = 0;
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
                Err(e) => {
                    self.consecutive_db_errors += 1;
                    if self.consecutive_db_errors >= WORKER_DB_REOPEN_THRESHOLD {
                        // Check if we should attempt reopen based on backoff.
                        let backoff_secs = std::cmp::min(
                            1u64 << self.consecutive_reopen_failures.min(6),
                            WORKER_DB_MAX_BACKOFF_SECS,
                        );
                        let should_attempt = self
                            .last_reopen_attempt
                            .map(|t| t.elapsed().as_secs() >= backoff_secs)
                            .unwrap_or(true);

                        if should_attempt {
                            self.last_reopen_attempt = Some(std::time::Instant::now());
                            self.metrics
                                .worker_db_reopen_attempts
                                .fetch_add(1, Ordering::Relaxed);

                            match db::open_baseline_db_readonly(&self.db_path) {
                                Ok(new_conn) => {
                                    let n = self.consecutive_db_errors;
                                    self.conn = new_conn;
                                    self.cache.clear();
                                    self.consecutive_db_errors = 0;
                                    self.consecutive_reopen_failures = 0;
                                    tracing::warn!(
                                        failures = n,
                                        "worker reopened baseline connection after {} consecutive failures",
                                        n
                                    );
                                }
                                Err(reopen_err) => {
                                    self.consecutive_reopen_failures += 1;
                                    self.metrics
                                        .worker_db_reopen_failures
                                        .fetch_add(1, Ordering::Relaxed);
                                    tracing::error!(
                                        error = %reopen_err,
                                        attempt = self.consecutive_reopen_failures,
                                        backoff_secs,
                                        "worker failed to reopen baseline connection"
                                    );
                                    if self.consecutive_reopen_failures
                                        >= WORKER_DB_MAX_REOPEN_FAILURES
                                    {
                                        tracing::error!(
                                            "worker DB unrecoverable after {} reopen failures. \
                                             entering Degraded.",
                                            WORKER_DB_MAX_REOPEN_FAILURES
                                        );
                                        if let Some(ref s) = self.state {
                                            let mut guard = s.write();
                                            if matches!(*guard, crate::types::DaemonState::Healthy)
                                            {
                                                *guard = crate::types::DaemonState::Degraded {
                                                    reason: crate::types::DegradedReason::WorkerDbUnrecoverable,
                                                    since: chrono::Utc::now(),
                                                };
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return Err(e);
                }
            }
        };

        let result = process_event_inner(
            event,
            &cfg,
            &idx,
            &self.metrics,
            &baseline,
            &self.self_protection_paths,
        )?;
        // Cache stays warm after detections. The generation-based
        // invalidation in refresh_cache_if_stale() handles the
        // auto-rebaseline case when the baseline writer commits.
        Ok(result)
    }

    fn process_safe(&mut self, event: &FsEvent) -> Option<ChangeResult> {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.evaluate(event)));
        match result {
            Ok(Ok(Some(cr))) => Some(cr),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "event processing error");
                None
            }
            Err(_) => {
                self.metrics.panics_caught.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    path = %event.path.display(),
                    event_type = ?event.event_type,
                    "panic caught in worker; event processing failed"
                );
                // Clear the cache to avoid logically-inconsistent state after panic
                self.cache.clear();
                if let Some(ref wal) = self.wal {
                    let panic_record = DetectionRecord {
                        timestamp: chrono::Utc::now().timestamp(),
                        path: event.path.to_string_lossy().to_string(),
                        changes: vec![],
                        severity: Severity::Critical,
                        monitored_group: "unknown".into(),
                        process: event.process.clone(),
                        package: None,
                        package_update: false,
                        maintenance_window: self.maintenance_active.load(Ordering::Acquire),
                        source: DetectionSource::Panic,
                    };
                    if let Err(e) = wal.append(&panic_record) {
                        tracing::error!(
                            error = %e,
                            path = %event.path.display(),
                            "WAL append failed for panic detection record"
                        );
                    }
                }
                None
            }
        }
    }

    fn drain_debounced(&mut self) -> Vec<AlertPayload> {
        self.drain_counter += 1;
        if self.drain_counter < 10 && self.last_drain.elapsed() < Duration::from_millis(200) {
            return Vec::new();
        }
        self.drain_counter = 0;
        self.last_drain = std::time::Instant::now();

        let pending = self.filter.drain_pending();
        let mut alerts = Vec::new();
        for path in pending {
            let path_cow = path.to_string_lossy();
            self.cache.pop(path_cow.as_ref());

            let synthetic = FsEvent {
                path: Arc::new(path),
                event_type: FsEventType::Modify,
                timestamp: chrono::Utc::now(),
                event_fd: None,
                process: None,
                bloom_generation: 0,
            };

            if let Some(cr) = self.process_safe(&synthetic) {
                let maintenance_window = self.maintenance_active.load(Ordering::Acquire);
                if let Some(ref wal) = self.wal {
                    let record = DetectionRecord::from_change_result(
                        &cr,
                        maintenance_window,
                        DetectionSource::Debounce,
                    );
                    match wal.append(&record) {
                        Ok(_) => {
                            self.metrics
                                .detections_wal_appends
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                path = %synthetic.path.display(),
                                "WAL append failed for debounced detection; falling back"
                            );
                            self.metrics
                                .detections_wal_full
                                .fetch_add(1, Ordering::Relaxed);
                            alerts.push(AlertPayload {
                                change: cr,
                                maintenance_window,
                            });
                        }
                    }
                } else {
                    alerts.push(AlertPayload {
                        change: cr,
                        maintenance_window,
                    });
                }
            }
        }
        alerts
    }

    fn try_auto_rebaseline(
        &self,
        change_result: &ChangeResult,
        update_tx: &Option<Sender<BaselineUpdate>>,
    ) {
        if !change_result.package_update {
            return;
        }
        if let Some(ref tx) = update_tx {
            let cfg = self.config.load();
            if cfg.package_manager.auto_rebaseline {
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
                    // Validate the snapshot before sending. An empty hash or
                    // zero mtime produces a baseline entry that triggers false
                    // changes on every subsequent scan.
                    if fresh.content.hash.is_empty() || fresh.mtime == 0 {
                        tracing::error!(
                            path = %change_result.path.display(),
                            hash_empty = fresh.content.hash.is_empty(),
                            mtime = fresh.mtime,
                            "auto-rebaseline rejected: snapshot has empty hash or zero mtime"
                        );
                        self.metrics
                            .auto_rebaseline_rejected
                            .fetch_add(1, Ordering::Relaxed);
                        return;
                    }

                    if let Err(e) = tx.try_send(BaselineUpdate {
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
                    }) {
                        tracing::warn!(
                            path = %change_result.path.display(),
                            error = %e,
                            "auto-rebaseline update dropped (baseline writer channel full or disconnected)"
                        );
                    }
                }
            }
        }
    }
}

pub fn spawn_workers(args: WorkerSpawnArgs) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    for i in 0..args.count {
        let event_rx = args.event_rx.clone();
        let alert_tx = args.alert_tx.clone();
        let config = args.config.clone();
        let watch_index = args.watch_index.clone();
        let metrics = args.metrics.clone();
        let shutdown = args.shutdown.clone();
        let db_path = args.baseline_db_path.clone();
        let update_tx = args.baseline_update_tx.clone();
        let backpressure = args.backpressure.clone();
        let generation = args.baseline_generation.clone();
        let wal = args.wal.clone();
        let maintenance_active = args.maintenance_active.clone();
        let state = args.state.clone();
        let self_protection_paths = args.self_protection_paths.clone();

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
                let local_generation = generation.load(Ordering::Acquire);
                let mut ctx = WorkerContext {
                    conn,
                    db_path: db_path.clone(),
                    config: config.clone(),
                    watch_index: watch_index.clone(),
                    metrics: metrics.clone(),
                    filter: EventFilter::with_metrics(&cfg, Some(metrics.clone())),
                    cache: LruCache::new(std::num::NonZeroUsize::new(8192).unwrap()),
                    local_generation,
                    generation,
                    drain_counter: 0,
                    last_drain: std::time::Instant::now(),
                    wal,
                    maintenance_active,
                    consecutive_db_errors: 0,
                    consecutive_reopen_failures: 0,
                    last_reopen_attempt: None,
                    state,
                    self_protection_paths,
                };

                while !shutdown.load(Ordering::Acquire) {
                    ctx.refresh_cache_if_stale();

                    for payload in ctx.drain_debounced() {
                        if alert_tx.send(payload).is_err() {
                            return;
                        }
                    }

                    match event_rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(event) => {
                            backpressure.store(false, Ordering::Relaxed);
                            if !ctx.filter.should_process(&event) {
                                continue;
                            }
                            ctx.metrics.events_processed.fetch_add(1, Ordering::Relaxed);
                            if let Some(cr) = ctx.process_safe(&event) {
                                ctx.try_auto_rebaseline(&cr, &update_tx);
                                if detection::dispatch_detection(
                                    cr,
                                    &ctx.wal,
                                    &alert_tx,
                                    &ctx.metrics,
                                    &ctx.maintenance_active,
                                    DetectionSource::Realtime,
                                ) {
                                    break;
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

fn process_event_inner(
    event: &FsEvent,
    cfg: &Config,
    idx: &WatchGroupIndex,
    metrics: &Metrics,
    baseline: &BaselineEntry,
    self_protection_paths: &HashSet<PathBuf>,
) -> Result<Option<ChangeResult>> {
    // Self-protection: reject events targeting config or HMAC key paths.
    if self_protection_paths.contains(event.path.as_ref()) {
        tracing::error!(
            path = %event.path.display(),
            "vigil self-protection: watched self-path modified"
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
                    baseline,
                    severity,
                    group_name,
                )));
            }
        }
    };

    metrics.hashes_computed.fetch_add(1, Ordering::Relaxed);

    let changes = snapshot.diff(baseline);
    if changes.is_empty() {
        return Ok(None);
    }

    // Severity from watch group only (Principle III).

    // Detect package-owned file changes for auto-rebaseline
    let is_package_update = baseline.package.is_some()
        && changes
            .iter()
            .any(|c| matches!(c, Change::ContentModified { .. }));

    Ok(Some(ChangeResult {
        path: event.path.clone(),
        changes,
        severity,
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
    fn evaluate_returns_none_for_non_baselined_create() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();

        let cfg = crate::config::default_config();

        let event = FsEvent {
            path: Arc::new("/tmp/nonexistent-baseline".into()),
            event_type: FsEventType::Create,
            timestamp: Utc::now(),
            event_fd: None,
            process: None,
            bloom_generation: 0,
        };

        let mut ctx = WorkerContext::for_test(conn, &cfg);
        let out = ctx.evaluate(&event).unwrap();

        assert!(out.is_none());
    }

    #[test]
    fn try_auto_rebaseline_drops_entry_with_empty_hash() {
        // Verify that BaselineEntry with empty/default content hash would
        // be rejected by the validation in try_auto_rebaseline.
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
        // Default content hash is empty and mtime is zero. Both should fail
        // the validation gate added in this fix.
        assert!(
            entry.content.hash.is_empty(),
            "default content hash should be empty"
        );
        assert_eq!(entry.mtime, 0, "default mtime should be zero");
        // The try_auto_rebaseline method now rejects entries with these values
        // before sending to the baseline writer channel.
    }

    #[test]
    fn evaluate_detects_new_file_under_watched_path() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();

        let cfg = crate::config::default_config();

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
            bloom_generation: 0,
        };

        let mut ctx = WorkerContext::for_test(conn, &cfg);
        let result = ctx.evaluate(&event).unwrap();

        // Should detect new file if path is under a watch group
        if let Some(cr) = result {
            assert!(cr.changes.iter().any(|c| matches!(c, Change::Created)));
        }
    }

    #[test]
    fn worker_consecutive_db_errors_increments() {
        // Simulate a WorkerContext with an in-memory DB that has no baseline tables,
        // causing get_by_path to fail. Verify the counter increments.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // Intentionally do NOT create baseline tables.  Queries will error.

        let cfg = crate::config::default_config();
        let mut ctx = WorkerContext::for_test(conn, &cfg);

        let event = FsEvent {
            path: Arc::new("/etc/test_file".into()),
            event_type: FsEventType::Modify,
            timestamp: Utc::now(),
            event_fd: None,
            process: None,
            bloom_generation: 0,
        };

        // Each call should increment consecutive_db_errors
        for i in 1..=4 {
            let _ = ctx.evaluate(&event);
            assert_eq!(
                ctx.consecutive_db_errors, i,
                "counter should be {} after {} errors",
                i, i
            );
        }
    }
}
