pub mod fanotify;
pub mod inotify;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam_channel::Sender;

use crate::config::Config;
use crate::error::Result;
use crate::metrics::Metrics;
use crate::types::{FsEvent, MonitorBackend};
use crate::watch_index::WatchGroupIndex;

pub struct MonitorHandle {
    pub backend: MonitorBackend,
    pub reconfigure_tx: Option<crossbeam_channel::Sender<Vec<PathBuf>>>,
}

/// Start the real-time filesystem monitor and return backend handle.
pub fn start_monitor(
    config: &Config,
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
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
                watch_index,
                metrics.clone(),
            ) {
                Ok(reconfigure_tx) => {
                    return Ok(MonitorHandle {
                        backend: MonitorBackend::Fanotify,
                        reconfigure_tx: Some(reconfigure_tx),
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
