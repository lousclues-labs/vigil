use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use rusqlite::Connection;

use crate::alert::AlertPayload;
use crate::config::Config;
use crate::db::{self, baseline_ops};
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::{
    CaptureOpts, Change, ChangeResult, FsEvent, FsEventType, Severity, SnapshotOrDeleted,
};
use crate::watch_index::WatchGroupIndex;

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

                while !shutdown.load(Ordering::Acquire) {
                    match event_rx.recv_timeout(Duration::from_millis(500)) {
                        Ok(event) => {
                            metrics.events_processed.fetch_add(1, Ordering::Relaxed);

                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    process_event(&conn, &event, &config, &watch_index, &metrics)
                                }));

                            match result {
                                Ok(Ok(Some(change_result))) => {
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
                                    tracing::debug!(error = %e, "event processing error");
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
                tracing::info!(path = %event.path.display(), "new file detected (not in baseline)");
            }
            return Ok(None);
        }
    };

    let (group_name, severity) = idx
        .lookup(&event.path)
        .map(|(g, s)| (g.to_string(), s))
        .unwrap_or(("unknown".into(), Severity::Medium));

    let opts = CaptureOpts {
        force_hash: true,
        max_file_size: cfg.scanner.max_file_size,
        mmap_threshold: cfg.scanner.mmap_threshold,
    };

    let snapshot = if let Some(ref fd) = event.event_fd {
        let raw = fd.as_raw_fd();
        // SAFETY: dup() creates a new fd referring to the same open file description.
        // The returned fd is owned by this scope and converted into File.
        let dup_fd = unsafe { libc::dup(raw) };
        if dup_fd < 0 {
            return Err(VigilError::Baseline(format!(
                "failed to dup event fd for {}: {}",
                event.path.display(),
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: dup_fd is a fresh owned descriptor returned by dup above.
        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
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

    Ok(Some(ChangeResult {
        path: event.path.clone(),
        changes,
        severity: final_severity,
        monitored_group: group_name,
        process: event.process.clone(),
        package: baseline.package.clone(),
        package_update: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn process_event_returns_none_for_non_baselined_create() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();

        let cfg = crate::config::default_config();
        let watch = WatchGroupIndex::from_config(&cfg);

        let event = FsEvent {
            path: "/tmp/nonexistent-baseline".into(),
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
}
