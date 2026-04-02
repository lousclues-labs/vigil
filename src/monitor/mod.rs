pub mod fanotify;
pub mod filter;
pub mod inotify;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crossbeam_channel::Sender;

use crate::config::Config;
use crate::error::Result;
use crate::types::{FsEvent, MonitorBackend};

/// Start the real-time filesystem monitor.
/// Returns a receiver channel that yields filtered filesystem events.
///
/// Attempts fanotify first; falls back to inotify if fanotify is unavailable.
pub fn start_monitor(
    config: &Config,
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<MonitorBackend> {
    let watch_paths = collect_watch_paths(config);

    match config.daemon.monitor_backend {
        MonitorBackend::Fanotify => {
            match fanotify::start(config, &watch_paths, event_tx.clone(), shutdown.clone()) {
                Ok(()) => return Ok(MonitorBackend::Fanotify),
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
    inotify::start(config, &watch_paths, event_tx, shutdown)?;
    Ok(MonitorBackend::Inotify)
}

/// Collect all expanded watch paths from config.
fn collect_watch_paths(config: &Config) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for (_name, group) in &config.watch {
        let expanded = crate::config::expand_user_paths(&group.paths);
        paths.extend(expanded);
    }
    paths.sort();
    paths.dedup();
    paths
}
