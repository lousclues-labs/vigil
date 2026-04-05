pub mod fanotify;
pub mod filter;
pub mod inotify;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crossbeam_channel::Sender;
use parking_lot::RwLock;

use crate::config::Config;
use crate::error::Result;
use crate::metrics::Metrics;
use crate::types::{FsEvent, MonitorBackend};
use crate::watch_index::WatchGroupIndex;

pub struct MonitorHandle {
    pub backend: MonitorBackend,
    pub reconfigure_tx: Option<crossbeam_channel::Sender<Vec<PathBuf>>>,
}

/// Start the real-time filesystem monitor.
/// Returns a receiver channel that yields filtered filesystem events.
///
/// Attempts fanotify first; falls back to inotify if fanotify is unavailable.
pub fn start_monitor(
    config: &Config,
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
    watch_index: Arc<RwLock<WatchGroupIndex>>,
    metrics: Arc<Metrics>,
) -> Result<MonitorHandle> {
    let watch_paths = collect_watch_paths(config);

    match config.daemon.monitor_backend {
        MonitorBackend::Fanotify => {
            match fanotify::start(
                config,
                &watch_paths,
                event_tx.clone(),
                shutdown.clone(),
                watch_index.clone(),
                metrics.clone(),
            ) {
                Ok(reconfigure_tx) => {
                    return Ok(MonitorHandle {
                        backend: MonitorBackend::Fanotify,
                        reconfigure_tx: Some(reconfigure_tx),
                    });
                }
                Err(e) => {
                    log::warn!(
                        "fanotify unavailable (requires CAP_SYS_ADMIN): {}. Falling back to inotify.",
                        e
                    );
                    log::warn!("Inotify fallback has reduced coverage:");
                    log::warn!("  - Cannot watch files owned by other users");
                    log::warn!("  - Subject to max_user_watches limit");
                    log::warn!(
                        "  - New subdirectories in monitored paths require manual watch registration"
                    );
                }
            }
        }
        MonitorBackend::Inotify => {}
    }

    // Fallback to inotify
    let reconfigure_tx = inotify::start(config, &watch_paths, event_tx, shutdown, metrics)?;
    Ok(MonitorHandle {
        backend: MonitorBackend::Inotify,
        reconfigure_tx: Some(reconfigure_tx),
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
