//! Real-time filesystem monitor.
//!
//! Tries fanotify first (kernel-level, mount-scoped, supports fd-based
//! TOCTOU-safe hashing). Falls back to inotify when fanotify is unavailable
//! (no CAP_SYS_ADMIN). Returns a `MonitorHandle` with optional reconfigure
//! and mount-mark channels for dynamic watch updates.

pub mod fanotify;
pub mod inotify;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam_channel::Sender;
use parking_lot::RwLock;

use crate::bloom::BloomFilter;
use crate::config::Config;
use crate::error::Result;
use crate::metrics::Metrics;
use crate::types::{DaemonState, FsEvent, MonitorBackend};
use crate::watch_index::WatchGroupIndex;

pub struct MonitorHandle {
    pub backend: MonitorBackend,
    pub reconfigure_tx: Option<crossbeam_channel::Sender<Vec<PathBuf>>>,
    pub mount_mark_tx: Option<crossbeam_channel::Sender<fanotify::MountMarkRequest>>,
}

/// Start the real-time filesystem monitor and return backend handle.
pub fn start_monitor(
    config: &Config,
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    metrics: Arc<Metrics>,
    state: Option<Arc<RwLock<DaemonState>>>,
    scan_trigger: Option<Sender<crate::control::ScanRequest>>,
) -> Result<MonitorHandle> {
    // VIGIL-VULN-073: warn loudly if daemon state / scan trigger channels
    // are missing.  This disables VIGIL-VULN-064/066 protections silently.
    if state.is_none() {
        tracing::error!(
            "start_monitor called without daemon state handle. \
             Fanotify Degraded transitions (VIGIL-VULN-064/066) will not fire."
        );
    }
    if scan_trigger.is_none() {
        tracing::error!(
            "start_monitor called without scan trigger channel. \
             FAN_Q_OVERFLOW compensating scans (VIGIL-VULN-064) disabled."
        );
    }

    let watch_paths = collect_watch_paths(config);
    let bloom = Arc::new(BloomFilter::from_watch_paths(&watch_paths));

    // VIGIL-VULN-069: mount mark channel for dynamic fanotify marks on new mounts
    let (mount_mark_tx, mount_mark_rx) = crossbeam_channel::unbounded();

    match config.daemon.monitor_backend {
        MonitorBackend::Fanotify => {
            match fanotify::start(
                config,
                &watch_paths,
                event_tx.clone(),
                shutdown.clone(),
                watch_index,
                metrics.clone(),
                bloom,
                state,
                scan_trigger,
                Some(mount_mark_rx),
            ) {
                Ok(reconfigure_tx) => {
                    return Ok(MonitorHandle {
                        backend: MonitorBackend::Fanotify,
                        reconfigure_tx: Some(reconfigure_tx),
                        mount_mark_tx: Some(mount_mark_tx),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "fanotify unavailable (usually requires CAP_SYS_ADMIN), falling back to inotify"
                    );
                }
            }
        }
        MonitorBackend::Inotify => {}
    }

    let reconfigure_tx = inotify::start(config, &watch_paths, event_tx, shutdown, metrics)?;
    Ok(MonitorHandle {
        backend: MonitorBackend::Inotify,
        reconfigure_tx: Some(reconfigure_tx),
        mount_mark_tx: None,
    })
}

/// Collect all expanded watch paths from config.
pub fn collect_watch_paths(config: &Config) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for group in config.watch.values() {
        let expanded = crate::config::expand_user_paths(&group.paths);
        paths.extend(expanded);
    }
    paths.sort();
    paths.dedup();
    paths
}
