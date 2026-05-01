//! Real-time filesystem monitor.
//!
//! Tries fanotify first (kernel-level, mount-scoped, supports fd-based
//! TOCTOU-safe hashing). Falls back to inotify when fanotify is unavailable
//! (no CAP_SYS_ADMIN). Returns a `MonitorHandle` with optional reconfigure
//! and mount-mark channels for dynamic watch updates.
//!
//! VIGIL-VULN-077: capability probe detects FID-mode support (Linux 5.1+)
//! for directory-modification events under closed-set watches.

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

/// VIGIL-VULN-077: Fanotify capability tiers, ordered from highest to lowest.
///
/// The capability probe tries each tier in order and returns the first
/// that succeeds. Higher tiers provide better coverage for closed-set
/// directory watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum FanotifyTier {
    /// Inotify fallback (no fanotify at all).
    Inotify = 0,
    /// Legacy fd-based events (current behavior pre-VIGIL-VULN-077).
    LegacyFd = 1,
    /// FID-mode: FAN_REPORT_FID | FAN_REPORT_DIR_FID (Linux 5.1+).
    Fid = 2,
    /// FID+DFID+NAME: FAN_REPORT_DFID_NAME | FAN_REPORT_FID (Linux 5.9+).
    FidDfidName = 3,
}

impl std::fmt::Display for FanotifyTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FanotifyTier::Inotify => write!(f, "inotify"),
            FanotifyTier::LegacyFd => write!(f, "legacy_fd"),
            FanotifyTier::Fid => write!(f, "fid"),
            FanotifyTier::FidDfidName => write!(f, "fid_dfid_name"),
        }
    }
}

impl std::str::FromStr for FanotifyTier {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "inotify" => Ok(FanotifyTier::Inotify),
            "legacy_fd" => Ok(FanotifyTier::LegacyFd),
            "fid" => Ok(FanotifyTier::Fid),
            "fid_dfid_name" => Ok(FanotifyTier::FidDfidName),
            _ => Err(format!("unknown fanotify tier: {}", s)),
        }
    }
}

/// VIGIL-VULN-077: Detect the highest fanotify tier the running kernel supports.
///
/// Probes init flags in descending order and returns the first that succeeds.
/// Each probed fd is closed immediately to prevent leaks. On complete failure,
/// returns `FanotifyTier::Inotify`.
#[allow(unsafe_code)]
pub fn detect_fanotify_tier() -> FanotifyTier {
    // Constants for FID-mode init flags (not in libc crate yet).
    const FAN_CLOEXEC: u32 = 0x0000_0001;
    const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
    const FAN_NONBLOCK: u32 = 0x0000_0002;
    const FAN_REPORT_FID: u32 = 0x0000_0200;
    const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
    const FAN_REPORT_DFID_NAME: u32 = 0x0000_1000;

    let base = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK;

    // Tier 3: FID+DFID+NAME (Linux 5.9+, ideal)
    let fd = unsafe {
        // SAFETY: fanotify_init returns a new fd or -1. We check below.
        libc::syscall(
            libc::SYS_fanotify_init,
            base | FAN_REPORT_DFID_NAME | FAN_REPORT_FID,
            libc::O_RDONLY | libc::O_LARGEFILE,
        )
    };
    if fd >= 0 {
        // SAFETY: fd is valid (>= 0) and owned by this scope.
        unsafe { libc::close(fd as i32) };
        return FanotifyTier::FidDfidName;
    }

    // Tier 2: FID + DIR_FID (Linux 5.1+)
    let fd = unsafe {
        // SAFETY: fanotify_init returns a new fd or -1. We check below.
        libc::syscall(
            libc::SYS_fanotify_init,
            base | FAN_REPORT_FID | FAN_REPORT_DIR_FID,
            libc::O_RDONLY | libc::O_LARGEFILE,
        )
    };
    if fd >= 0 {
        // SAFETY: fd is valid (>= 0) and owned by this scope.
        unsafe { libc::close(fd as i32) };
        return FanotifyTier::Fid;
    }

    // Tier 1: Legacy fd-based (current behavior)
    let fd = unsafe {
        // SAFETY: fanotify_init returns a new fd or -1. We check below.
        libc::syscall(
            libc::SYS_fanotify_init,
            base,
            libc::O_RDONLY | libc::O_LARGEFILE,
        )
    };
    if fd >= 0 {
        // SAFETY: fd is valid (>= 0) and owned by this scope.
        unsafe { libc::close(fd as i32) };
        return FanotifyTier::LegacyFd;
    }

    // Tier 0: No fanotify at all
    FanotifyTier::Inotify
}

/// Resolve the effective tier based on config and kernel capabilities.
pub fn resolve_fanotify_tier(config: &Config) -> FanotifyTier {
    let configured = &config.monitor.fanotify_tier;
    if configured == "auto" {
        detect_fanotify_tier()
    } else {
        match configured.parse::<FanotifyTier>() {
            Ok(tier) => tier,
            Err(_) => {
                tracing::warn!(
                    configured = %configured,
                    "unknown monitor.fanotify_tier value; falling back to auto-detect"
                );
                detect_fanotify_tier()
            }
        }
    }
}

pub struct MonitorHandle {
    pub backend: MonitorBackend,
    pub reconfigure_tx: Option<crossbeam_channel::Sender<Vec<PathBuf>>>,
    pub mount_mark_tx: Option<crossbeam_channel::Sender<fanotify::MountMarkRequest>>,
    /// VIGIL-VULN-077: the resolved fanotify tier for status/doctor visibility.
    pub fanotify_tier: FanotifyTier,
}

/// Start the real-time filesystem monitor and return backend handle.
pub fn start_monitor(
    config: &Config,
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<DaemonState>>,
    scan_trigger: Sender<crate::control::ScanRequest>,
) -> Result<MonitorHandle> {
    start_monitor_inner(
        config,
        event_tx,
        shutdown,
        watch_index,
        metrics,
        Some(state),
        Some(scan_trigger),
    )
}

/// Start monitor for tests with no-op state and scan trigger.
#[cfg(test)]
pub fn start_monitor_for_test(
    config: &Config,
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    metrics: Arc<Metrics>,
) -> Result<MonitorHandle> {
    start_monitor_inner(config, event_tx, shutdown, watch_index, metrics, None, None)
}

fn start_monitor_inner(
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

    // VIGIL-VULN-077: detect fanotify tier for visibility.
    let tier = resolve_fanotify_tier(config);
    tracing::info!(tier = %tier, "fanotify capability tier resolved");

    // Record tier as gauge metric (0=inotify, 1=legacy, 2=fid, 3=fid_dfid_name)
    metrics
        .fanotify_tier
        .store(tier as u64, std::sync::atomic::Ordering::Relaxed);

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
                tier,
            ) {
                Ok(reconfigure_tx) => {
                    return Ok(MonitorHandle {
                        backend: MonitorBackend::Fanotify,
                        reconfigure_tx: Some(reconfigure_tx),
                        mount_mark_tx: Some(mount_mark_tx),
                        fanotify_tier: tier,
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
        fanotify_tier: FanotifyTier::Inotify,
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
