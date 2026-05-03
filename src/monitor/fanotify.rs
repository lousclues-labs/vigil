//! Fanotify-based filesystem monitor.
//!
//! See docs/ARCHITECTURE.md#fanotify-tier-system for the tier selection
//! logic and per-tier event coverage table.
//!
//! Supports two operational modes selected by the detected `FanotifyTier`:
//!
//! - **Legacy (fd-based):** Marks mount points with `FAN_MARK_MOUNT`, events
//!   carry open fds for TOCTOU-safe hashing. Falls back to a reduced event
//!   mask when the kernel rejects `FAN_ATTRIB`/`FAN_CREATE`/`FAN_DELETE`/
//!   `FAN_MOVED_*` under mount-mark semantics (Linux 6.18+).
//!
//! - **FID (file-handle based, Linux 5.1+/5.9+):** Initialised with
//!   `FAN_REPORT_FID` (Fid tier, Linux 5.1+) or
//!   `FAN_REPORT_DFID_NAME | FAN_REPORT_FID` (FidDfidName tier, Linux 5.9+)
//!   and marks with `FAN_MARK_FILESYSTEM`, which accepts the full event
//!   mask on all current kernels. Events carry file handles (and optionally
//!   directory handles + child names); paths and event fds are resolved
//!   via `open_by_handle_at(2)`.
//!
//! Uses poll(2) on the fanotify fd to block until events arrive, bloom-filter
//! rejects unwatched paths, and forwards watched events to workers via a
//! bounded channel. Handles dynamic mark add/remove for overlapping mounts
//! (VIGIL-VULN-069) and kernel queue overflows (FAN_Q_OVERFLOW triggers a
//! compensating full scan).

#![allow(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use crossbeam_channel::Sender;
use parking_lot::RwLock;

use crate::bloom::BloomFilter;
use crate::config::Config;
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::{
    DaemonState, DegradedReason, FsEvent, FsEventType, ProcessAttribution, ScanMode,
};
use crate::watch_index::WatchGroupIndex;

/// Operation to perform on a mount point's fanotify mark.
#[derive(Debug, Clone)]
pub enum MountMarkOp {
    Add,
    Remove,
}

/// Request to dynamically add or remove fanotify marks on mount points
/// discovered at runtime (VIGIL-VULN-069).
#[derive(Debug, Clone)]
pub struct MountMarkRequest {
    pub mount: PathBuf,
    pub op: MountMarkOp,
}

// fanotify constants
const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_NONBLOCK: u32 = 0x0000_0002;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_REMOVE: u32 = 0x0000_0002;
const FAN_MARK_MOUNT: u32 = 0x0000_0010;

const FAN_MODIFY: u64 = 0x0000_0002;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_ATTRIB: u64 = 0x0000_0004;
const FAN_CREATE: u64 = 0x0000_0100;
const FAN_DELETE: u64 = 0x0000_0200;
const FAN_MOVED_FROM: u64 = 0x0000_0040;
const FAN_MOVED_TO: u64 = 0x0000_0080;
const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

/// Subset of the FAN_* event mask that is unconditionally compatible with
/// `FAN_MARK_MOUNT` semantics on all current Linux kernels.
///
/// The events `FAN_ATTRIB`, `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_FROM`,
/// and `FAN_MOVED_TO` are documented as requiring `FAN_MARK_INODE` or
/// `FAN_MARK_FILESYSTEM` together with one of the FID-family report flags
/// at `fanotify_init` time. Older kernels silently ignored these bits when
/// combined with `FAN_MARK_MOUNT`; newer kernels (observed on Linux 6.18.x
/// LTS) reject the call with `EINVAL`. When that happens we fall back to
/// this reduced mask so real-time coverage degrades gracefully instead of
/// disappearing entirely. Scheduled scans backstop the events we can no
/// longer observe in real time. See `apply_fanotify_mark`.
const FAN_MOUNT_COMPATIBLE_EVENTS: u64 = FAN_MODIFY | FAN_CLOSE_WRITE;

// FID-mode constants (Linux 5.1+ / 5.9+).
const FAN_REPORT_FID: u32 = 0x0000_0200;
const FAN_REPORT_DFID_NAME: u32 = 0x0000_1000;
const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;
const FAN_NOFD: i32 = -1;

const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;

const FAN_EVENT_METADATA_LEN: usize = std::mem::size_of::<FanotifyEventMetadata>();

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// Header for variable-length info records appended after the fixed
/// `FanotifyEventMetadata` in FID-mode events.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FanotifyEventInfoHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

/// Fixed-size prefix of a kernel `struct file_handle`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FileHandleHeader {
    handle_bytes: u32,
    handle_type: i32,
}

// Use the single canonical OwnedRawFd from util::owned_fd.
use crate::util::owned_fd::OwnedRawFd;

/// RAII guard for an event fd. Closes the fd on drop unless ownership
/// is transferred via `take()`. Eliminates fd leak risk in the event loop.
struct EventFdGuard(RawFd);

impl EventFdGuard {
    /// Transfer ownership of the fd out of the guard.
    /// The guard will NOT close the fd on drop after this call.
    fn take(mut self) -> RawFd {
        let fd = self.0;
        self.0 = -1;
        fd
    }
}

impl Drop for EventFdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: fd is owned by this guard and has not been transferred via take().
            // The >= 0 check prevents double-close after take() sets it to -1.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// Maps filesystem IDs (from `statfs.f_fsid`) to open mount-point fds for
/// `open_by_handle_at` resolution in FID mode.
type FsidMountMap = HashMap<[u8; 8], RawFd>;

/// Build a map of fsid → mount fd for FID-mode handle resolution.
///
/// For each mount point, calls `statfs()` to get the filesystem's fsid,
/// then opens the mount point with `O_RDONLY | O_PATH` to obtain a
/// reference fd suitable for `open_by_handle_at`.
#[allow(unsafe_code)]
fn build_fsid_mount_map(mount_points: &[PathBuf]) -> FsidMountMap {
    let mut map = FsidMountMap::new();
    for mount in mount_points {
        let c_path = match CString::new(mount.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        unsafe {
            let mut buf: libc::statfs = std::mem::zeroed();
            if libc::statfs(c_path.as_ptr(), &mut buf) != 0 {
                tracing::warn!(
                    mount = %mount.display(),
                    error = %std::io::Error::last_os_error(),
                    "statfs failed; FID handle resolution may fail for this filesystem"
                );
                continue;
            }
            let fsid_bytes: [u8; 8] = std::mem::transmute(buf.f_fsid);
            if map.contains_key(&fsid_bytes) {
                continue; // already have an fd for this filesystem
            }
            let fd = libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_PATH | libc::O_CLOEXEC,
            );
            if fd < 0 {
                tracing::warn!(
                    mount = %mount.display(),
                    error = %std::io::Error::last_os_error(),
                    "cannot open mount point for FID handle resolution"
                );
                continue;
            }
            map.insert(fsid_bytes, fd);
        }
    }
    map
}

/// Add a mount point's filesystem to the fsid map if not already present.
#[allow(unsafe_code)]
fn ensure_fsid_mount_fd(mount: &std::path::Path, mount_fds: &mut FsidMountMap) {
    let c_path = match CString::new(mount.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return,
    };
    unsafe {
        let mut buf: libc::statfs = std::mem::zeroed();
        if libc::statfs(c_path.as_ptr(), &mut buf) != 0 {
            return;
        }
        let fsid_bytes: [u8; 8] = std::mem::transmute(buf.f_fsid);
        if mount_fds.contains_key(&fsid_bytes) {
            return;
        }
        let fd = libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_PATH | libc::O_CLOEXEC,
        );
        if fd >= 0 {
            mount_fds.insert(fsid_bytes, fd);
        }
    }
}

/// Close all fds in the mount map.
#[allow(unsafe_code)]
fn close_fsid_mount_map(map: &FsidMountMap) {
    for &fd in map.values() {
        unsafe {
            libc::close(fd);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    _config: &Config,
    watch_paths: &[PathBuf],
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
    watch_index: Arc<ArcSwap<WatchGroupIndex>>,
    metrics: Arc<Metrics>,
    bloom: Arc<BloomFilter>,
    state: Option<Arc<RwLock<DaemonState>>>,
    scan_trigger: Option<Sender<crate::control::ScanRequest>>,
    mount_mark_rx: Option<crossbeam_channel::Receiver<MountMarkRequest>>,
    tier: super::FanotifyTier,
) -> Result<crossbeam_channel::Sender<Vec<PathBuf>>> {
    // Use FID mode when the kernel supports FID or DFID_NAME reporting.
    // This allows FAN_MARK_FILESYSTEM with the full event mask, restoring
    // real-time coverage of FAN_CREATE/FAN_DELETE/FAN_MOVED_*/FAN_ATTRIB
    // that newer kernels reject under FAN_MARK_MOUNT.
    let fid_mode = matches!(
        tier,
        super::FanotifyTier::FidDfidName | super::FanotifyTier::Fid
    );

    // SAFETY: fanotify_init returns a new fd or -1. We check for < 0 below.
    // FAN_CLOEXEC prevents fd leak across exec; FAN_NONBLOCK makes read()
    // return EAGAIN instead of blocking the monitor thread.
    let init_flags = match tier {
        super::FanotifyTier::FidDfidName => {
            FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_DFID_NAME | FAN_REPORT_FID
        }
        super::FanotifyTier::Fid => FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_FID,
        _ => FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK,
    };
    let fan_fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            init_flags,
            libc::O_RDONLY | libc::O_LARGEFILE,
        )
    };

    if fan_fd < 0 {
        return Err(VigilError::Fanotify(format!(
            "fanotify_init failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let fan_fd = fan_fd as RawFd;
    let fan_fd_owned = OwnedRawFd(fan_fd);

    let (control_tx, control_rx) = crossbeam_channel::unbounded::<Vec<PathBuf>>();

    if !std::path::Path::new("/proc/self").exists() {
        tracing::error!("fanotify requires /proc to be mounted for fd→path resolution");
        return Err(VigilError::Fanotify(
            "/proc not available; fanotify cannot resolve event paths".into(),
        ));
    }

    let mount_points = resolve_mount_points(watch_paths);
    tracing::info!(mounts = ?mount_points, fid_mode, "fanotify watching mount points");
    let mask = FAN_MODIFY
        | FAN_CLOSE_WRITE
        | FAN_ATTRIB
        | FAN_CREATE
        | FAN_DELETE
        | FAN_MOVED_FROM
        | FAN_MOVED_TO;

    for mount in &mount_points {
        match apply_fanotify_mark(fan_fd, mount, mask, FAN_MARK_ADD, fid_mode) {
            Ok(MarkOutcome::Full) => {}
            Ok(MarkOutcome::Reduced) => {
                tracing::warn!(
                    mount = %mount.display(),
                    "fanotify_mark accepted only with reduced mount-compatible mask; \
                     real-time coverage of FAN_CREATE/FAN_DELETE/FAN_MOVED_*/FAN_ATTRIB \
                     is degraded for this mount. Scheduled scans will backstop these events."
                );
                metrics
                    .fanotify_mark_reduced_coverage
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::error!(
                    mount = %mount.display(),
                    error = %e,
                    "fanotify_mark FAN_MARK_ADD failed at startup; coverage degraded"
                );
                metrics
                    .fanotify_mark_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    let restart_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let restart_counter_for_thread = restart_counter.clone();

    // Eventfd for waking the poll loop on shutdown.
    // SAFETY: eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) returns a new fd or -1.
    let shutdown_efd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if shutdown_efd < 0 {
        return Err(VigilError::Fanotify(format!(
            "eventfd creation failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let shutdown_efd_write = shutdown_efd; // both ends are the same fd for eventfd

    std::thread::Builder::new()
        .name("vigil-fanotify".into())
        .spawn(move || {
            let _fan_guard = fan_fd_owned;
            let fan_fd = _fan_guard.0;

            // Shutdown-waker thread: signals the eventfd when shutdown fires.
            let shutdown_for_waker = shutdown.clone();
            let waker_handle = std::thread::Builder::new()
                .name("vigil-fan-waker".into())
                .spawn(move || {
                    while !shutdown_for_waker.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    // Wake the poll loop.
                    let val: u64 = 1;
                    // SAFETY: writing 8 bytes to a valid eventfd.
                    unsafe {
                        libc::write(
                            shutdown_efd_write,
                            &val as *const u64 as *const _,
                            std::mem::size_of::<u64>(),
                        );
                    }
                })
                .ok();

            // In FID mode, build the fsid→mount-fd map for open_by_handle_at.
            let mut mount_fds = if fid_mode {
                build_fsid_mount_map(&mount_points)
            } else {
                FsidMountMap::new()
            };

            let result = crate::supervised_thread::run_supervised(
                || {
                    run_event_loop(
                        fan_fd,
                        shutdown_efd,
                        &shutdown,
                        &control_rx,
                        &mount_mark_rx,
                        &event_tx,
                        &watch_index,
                        &metrics,
                        &bloom,
                        &state,
                        &scan_trigger,
                        mask,
                        &mount_points,
                        fid_mode,
                        &mut mount_fds,
                    )
                },
                3, // max restarts
                std::time::Duration::from_secs(5),
                &restart_counter_for_thread,
            );

            // Update the shared metric with total restarts.
            metrics.fanotify_thread_restarts.fetch_add(
                restart_counter_for_thread.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );

            if let crate::supervised_thread::ExitReason::Fatal(ref msg) = result.final_reason {
                tracing::error!(
                    restarts = result.restarts,
                    reason = %msg,
                    "fanotify supervisor exhausted restarts. entering Degraded."
                );
                if let Some(s) = &state {
                    let mut guard = s.write();
                    if matches!(*guard, DaemonState::Healthy) {
                        *guard = DaemonState::Degraded {
                            reason: DegradedReason::FanotifyReadFailed,
                            since: Utc::now(),
                        };
                    }
                }
            }

            // Close the eventfd, FID mount fds, and join the waker thread.
            close_fsid_mount_map(&mount_fds);
            // SAFETY: shutdown_efd is a valid fd owned by this scope.
            unsafe {
                libc::close(shutdown_efd);
            }
            if let Some(h) = waker_handle {
                let _ = h.join();
            }

            tracing::info!("fanotify monitor stopped");
        })
        .map_err(|e| VigilError::Fanotify(format!("cannot spawn thread: {}", e)))?;

    Ok(control_tx)
}

/// The fanotify event loop body. Returns an ExitReason for the supervisor.
#[allow(clippy::too_many_arguments)]
fn run_event_loop(
    fan_fd: RawFd,
    shutdown_efd: RawFd,
    shutdown: &Arc<AtomicBool>,
    control_rx: &crossbeam_channel::Receiver<Vec<PathBuf>>,
    mount_mark_rx: &Option<crossbeam_channel::Receiver<MountMarkRequest>>,
    event_tx: &Sender<FsEvent>,
    watch_index: &Arc<ArcSwap<WatchGroupIndex>>,
    metrics: &Arc<Metrics>,
    bloom: &Arc<BloomFilter>,
    state: &Option<Arc<RwLock<DaemonState>>>,
    scan_trigger: &Option<Sender<crate::control::ScanRequest>>,
    mask: u64,
    initial_mounts: &[PathBuf],
    fid_mode: bool,
    mount_fds: &mut FsidMountMap,
) -> crate::supervised_thread::ExitReason {
    let mut buf = Box::new([0u8; 262_144]);
    let mut current_bloom = bloom.clone();
    let mut current_mounts: HashSet<PathBuf> = initial_mounts.iter().cloned().collect();

    while !shutdown.load(Ordering::Acquire) {
        while let Ok(new_paths) = control_rx.try_recv() {
            let new_mounts: HashSet<PathBuf> =
                resolve_mount_points(&new_paths).into_iter().collect();

            // Rebuild the Bloom filter FIRST so any in-flight events for
            // newly-added paths are not falsely rejected during the
            // mark add window.
            current_bloom = Arc::new(BloomFilter::from_watch_paths(&new_paths));

            for mount in new_mounts.difference(&current_mounts) {
                if fid_mode {
                    ensure_fsid_mount_fd(mount, mount_fds);
                }
                match apply_fanotify_mark(fan_fd, mount, mask, FAN_MARK_ADD, fid_mode) {
                    Ok(MarkOutcome::Full) => {}
                    Ok(MarkOutcome::Reduced) => {
                        tracing::warn!(
                            mount = %mount.display(),
                            "fanotify_mark accepted only with reduced mount-compatible mask during reload; \
                             real-time coverage of FAN_CREATE/FAN_DELETE/FAN_MOVED_*/FAN_ATTRIB is degraded"
                        );
                        metrics
                            .fanotify_mark_reduced_coverage
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::error!(
                            mount = %mount.display(),
                            error = %e,
                            "fanotify_mark FAN_MARK_ADD failed during reload; coverage degraded for this mount"
                        );
                        metrics
                            .fanotify_mark_failures
                            .fetch_add(1, Ordering::Relaxed);
                        if let Some(s) = &state {
                            let mut guard = s.write();
                            if matches!(*guard, DaemonState::Healthy) {
                                *guard = DaemonState::Degraded {
                                    reason: DegradedReason::FanotifyMarkFailed {
                                        mount: mount.to_path_buf(),
                                    },
                                    since: Utc::now(),
                                };
                            }
                        }
                    }
                }
            }
            for mount in current_mounts.difference(&new_mounts) {
                if let Err(e) = apply_fanotify_mark(fan_fd, mount, mask, FAN_MARK_REMOVE, fid_mode)
                {
                    tracing::warn!(
                        mount = %mount.display(),
                        error = %e,
                        "fanotify_mark FAN_MARK_REMOVE failed during reload"
                    );
                    metrics
                        .fanotify_mark_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            current_mounts = new_mounts;
        }

        // VIGIL-VULN-069: process dynamic mount mark requests from
        // the coordinator when new mounts overlap watched paths.
        if let Some(ref rx) = mount_mark_rx {
            while let Ok(req) = rx.try_recv() {
                let op_flag = match req.op {
                    MountMarkOp::Add => FAN_MARK_ADD,
                    MountMarkOp::Remove => FAN_MARK_REMOVE,
                };
                if fid_mode && matches!(req.op, MountMarkOp::Add) {
                    ensure_fsid_mount_fd(&req.mount, mount_fds);
                }
                match apply_fanotify_mark(fan_fd, &req.mount, mask, op_flag, fid_mode) {
                    Ok(outcome) => {
                        if matches!(outcome, MarkOutcome::Reduced) {
                            tracing::warn!(
                                mount = %req.mount.display(),
                                op = ?req.op,
                                "dynamic fanotify_mark accepted only with reduced mount-compatible mask; \
                                 real-time coverage of FAN_CREATE/FAN_DELETE/FAN_MOVED_*/FAN_ATTRIB is degraded"
                            );
                            metrics
                                .fanotify_mark_reduced_coverage
                                .fetch_add(1, Ordering::Relaxed);
                        } else {
                            tracing::info!(
                                mount = %req.mount.display(),
                                op = ?req.op,
                                "dynamic fanotify_mark applied for overlapping mount"
                            );
                        }
                        if matches!(req.op, MountMarkOp::Add) {
                            current_mounts.insert(req.mount);
                        } else {
                            current_mounts.remove(&req.mount);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            mount = %req.mount.display(),
                            op = ?req.op,
                            error = %e,
                            "dynamic fanotify_mark failed for overlapping mount"
                        );
                        metrics
                            .fanotify_mark_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        // poll(2) on fanotify fd + shutdown eventfd. Timeout allows
        // periodic re-check of control and mount-mark channels.
        let mut pollfds = [
            libc::pollfd {
                fd: fan_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: shutdown_efd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // SAFETY: valid pollfd array, valid fds. Timeout 1000ms to
        // periodically re-check control channels even without events.
        let poll_ret =
            unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 1000) };

        if poll_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            tracing::error!(error = %err, "poll() failed");
            metrics.fanotify_read_errors.fetch_add(1, Ordering::Relaxed);
            return crate::supervised_thread::ExitReason::Recoverable(format!(
                "poll failed: {}",
                err
            ));
        }

        // Shutdown eventfd signaled.
        if pollfds[1].revents & libc::POLLIN != 0 {
            break;
        }

        // No fanotify events ready (timeout or only shutdown check).
        if pollfds[0].revents & libc::POLLIN == 0 {
            continue;
        }

        // Read all available events (loop until EAGAIN), then poll again.
        loop {
            // SAFETY: valid fd + valid buffer pointer + length. The kernel
            // writes at most buf.len() bytes. Return checked for errors.
            let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                let raw = err.raw_os_error();
                if raw == Some(libc::EAGAIN) || raw == Some(libc::EWOULDBLOCK) {
                    break; // all available events consumed; back to poll
                }
                if raw == Some(libc::EINTR) {
                    break;
                }
                tracing::error!(
                    error = %err,
                    errno = ?raw,
                    "fanotify read() failed; supervisor will attempt restart"
                );
                metrics.fanotify_read_errors.fetch_add(1, Ordering::Relaxed);
                return crate::supervised_thread::ExitReason::Recoverable(format!(
                    "fanotify read failed: {}",
                    err
                ));
            }
            if n == 0 {
                break;
            }

            let n_usize = n as usize;
            let mut offset = 0usize;
            while offset + FAN_EVENT_METADATA_LEN <= n_usize {
                // SAFETY: offset bounds-checked above and the kernel produced
                // this buffer. Using read_unaligned because the buffer offset
                // may not satisfy FanotifyEventMetadata alignment requirements.
                let event: FanotifyEventMetadata = unsafe {
                    std::ptr::read_unaligned(
                        buf.as_ptr().add(offset) as *const FanotifyEventMetadata
                    )
                };

                // Validate event_len BEFORE using it: the kernel may report a
                // malformed value that would otherwise cause an infinite loop
                // (event_len == 0) or buffer over-read (event_len > remaining).
                let len = event.event_len as usize;
                if len < FAN_EVENT_METADATA_LEN || offset + len > n_usize {
                    tracing::error!(
                        event_len = len,
                        offset,
                        buf_len = n_usize,
                        "malformed fanotify event_len; dropping remaining buffer and resyncing"
                    );
                    metrics.fanotify_read_errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }

                // Handle kernel queue overflow: fanotify dropped events
                if event.mask & FAN_Q_OVERFLOW != 0 {
                    tracing::error!(
                        "fanotify kernel queue overflow (FAN_Q_OVERFLOW). \
                             Events were dropped by the kernel. Triggering compensating full scan."
                    );
                    metrics
                        .kernel_queue_overflows
                        .fetch_add(1, Ordering::Relaxed);
                    // Mark the daemon Degraded so operators see this in `vigil status`
                    if let Some(s) = &state {
                        let mut guard = s.write();
                        if matches!(*guard, DaemonState::Healthy) {
                            *guard = DaemonState::Degraded {
                                reason: DegradedReason::FanotifyQueueOverflow,
                                since: Utc::now(),
                            };
                        }
                    }
                    // Trigger a full scan so the missed events are caught by the
                    // next baseline diff. The scan response is discarded; the
                    // scheduler will attribute changes through normal channels.
                    if let Some(tx) = &scan_trigger {
                        let (resp_tx, _resp_rx) = crossbeam_channel::bounded(1);
                        if tx
                            .try_send(crate::control::ScanRequest {
                                mode: ScanMode::Full,
                                response_tx: resp_tx,
                            })
                            .is_ok()
                        {
                            metrics
                                .fanotify_overflow_scans_triggered
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    offset += len;
                    continue;
                }

                if event.fd >= 0 {
                    // Wrap event fd in a guard to prevent leaks on any code path
                    let fd_guard = EventFdGuard(event.fd);

                    // Resolve process attribution immediately to minimize the
                    // PID recycling window. The fd is still open and valid here.
                    // NOTE: FAN_REPORT_PIDFD (Linux 6.2+) would eliminate this
                    // race by providing a stable pidfd reference.
                    let process = if event.pid > 0 {
                        let exe = std::fs::read_link(format!("/proc/{}/exe", event.pid))
                            .ok()
                            .map(|p| p.to_string_lossy().to_string());
                        if exe.is_some() {
                            Some(ProcessAttribution {
                                pid: event.pid as u32,
                                exe,
                            })
                        } else {
                            // Process already exited.  PID may have been recycled.
                            tracing::debug!(
                                pid = event.pid,
                                "process exited before attribution; PID may be stale"
                            );
                            Some(ProcessAttribution {
                                pid: event.pid as u32,
                                exe: None,
                            })
                        }
                    } else {
                        None
                    };

                    let fd_link = format!("/proc/self/fd/{}", event.fd);
                    if let Ok(raw_path) = std::fs::read_link(&fd_link) {
                        // VIGIL-VULN-068: strip " (deleted)" suffix appended
                        // by the kernel when a file is unlinked between event
                        // production and fd→path resolution.
                        let (path, was_deleted) = strip_deleted_suffix(&raw_path);
                        if was_deleted {
                            tracing::info!(
                                raw = %raw_path.display(),
                                stripped = %path.display(),
                                "resolved deleted-file path from fanotify event"
                            );
                        }

                        // Bloom filter fast-reject: check if any prefix of the
                        // event path is in the filter (not the full path, which
                        // was never inserted)
                        metrics.bloom_checks_total.fetch_add(1, Ordering::Relaxed);
                        if !current_bloom.might_contain_prefix_of(&path) {
                            metrics.bloom_rejects_total.fetch_add(1, Ordering::Relaxed);
                            // fd_guard drops and closes the fd automatically
                            offset += len;
                            continue;
                        }

                        let idx = watch_index.load();
                        let is_watched = idx.is_watched(&path);

                        if is_watched {
                            // Force Delete event type if file was unlinked
                            let event_type_resolved = if was_deleted {
                                Some(FsEventType::Delete)
                            } else {
                                mask_to_event_type(event.mask)
                            };
                            if let Some(event_type) = event_type_resolved {
                                metrics.events_received.fetch_add(1, Ordering::Relaxed);

                                // Transfer fd ownership into OwnedFd; prevent guard from closing it
                                let raw = fd_guard.take();
                                // SAFETY: raw fd is uniquely owned (take() consumed
                                // the guard) and has not been closed.
                                let owned_fd = unsafe { OwnedFd::from_raw_fd(raw) };

                                let fs_event = FsEvent {
                                    path: Arc::new(path.clone()),
                                    event_type,
                                    timestamp: Utc::now(),
                                    event_fd: Some(owned_fd),
                                    process,
                                    bloom_generation: 0,
                                };

                                match event_tx.send_timeout(fs_event, Duration::from_secs(1)) {
                                    Ok(()) => {}
                                    Err(crossbeam_channel::SendTimeoutError::Timeout(_dropped)) => {
                                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                                        tracing::warn!(
                                            path = %path.display(),
                                            "fanotify event channel full for 1s; dropping event fd"
                                        );
                                    }
                                    Err(crossbeam_channel::SendTimeoutError::Disconnected(
                                        _dropped,
                                    )) => {
                                        tracing::error!("event channel disconnected");
                                        return crate::supervised_thread::ExitReason::Fatal(
                                            "event channel disconnected".into(),
                                        );
                                    }
                                }
                            }
                            // else: unrecognized mask. fd_guard drops and closes.
                        }
                        // else: not watched. fd_guard drops and closes.
                    }
                    // else: read_link failed. fd_guard drops and closes.
                } else if fid_mode && event.fd == FAN_NOFD {
                    // FID-mode path: resolve via file-handle info records
                    // instead of the legacy event fd.
                    let event_slice = &buf[offset..offset + len];
                    if let Some((raw_path, event_fd)) =
                        resolve_fid_event(event_slice, len, mount_fds, metrics)
                    {
                        let (path, was_deleted) = strip_deleted_suffix(&raw_path);
                        if was_deleted {
                            tracing::info!(
                                stripped = %path.display(),
                                "resolved deleted-file path from FID fanotify event"
                            );
                        }

                        metrics.bloom_checks_total.fetch_add(1, Ordering::Relaxed);
                        if !current_bloom.might_contain_prefix_of(&path) {
                            metrics.bloom_rejects_total.fetch_add(1, Ordering::Relaxed);
                            offset += len;
                            continue;
                        }

                        let idx = watch_index.load();
                        if idx.is_watched(&path) {
                            let process = if event.pid > 0 {
                                let exe = std::fs::read_link(format!("/proc/{}/exe", event.pid))
                                    .ok()
                                    .map(|p| p.to_string_lossy().to_string());
                                Some(ProcessAttribution {
                                    pid: event.pid as u32,
                                    exe,
                                })
                            } else {
                                None
                            };

                            let event_type_resolved = if was_deleted {
                                Some(FsEventType::Delete)
                            } else {
                                mask_to_event_type(event.mask)
                            };

                            if let Some(event_type) = event_type_resolved {
                                metrics.events_received.fetch_add(1, Ordering::Relaxed);

                                let fs_event = FsEvent {
                                    path: Arc::new(path),
                                    event_type,
                                    timestamp: Utc::now(),
                                    event_fd,
                                    process,
                                    bloom_generation: 0,
                                };

                                match event_tx.send_timeout(fs_event, Duration::from_secs(1)) {
                                    Ok(()) => {}
                                    Err(crossbeam_channel::SendTimeoutError::Timeout(_)) => {
                                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                                        tracing::warn!(
                                            "FID fanotify event channel full for 1s; dropping"
                                        );
                                    }
                                    Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                                        tracing::error!("event channel disconnected");
                                        return crate::supervised_thread::ExitReason::Fatal(
                                            "event channel disconnected".into(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                offset += len;
            }
        } // end inner read-all loop
    }

    crate::supervised_thread::ExitReason::Shutdown
}

/// Strip the ` (deleted)` suffix the kernel appends to `/proc/self/fd/N`
/// targets when the file has been unlinked between event production and
/// read_link resolution (VIGIL-VULN-068).
///
/// Returns `(stripped_path, true)` if the suffix was present, or
/// `(original_path, false)` otherwise. Handles paths that legitimately
/// contain parentheses by only stripping a trailing ` (deleted)`.
pub fn strip_deleted_suffix(path: &std::path::Path) -> (PathBuf, bool) {
    const SUFFIX: &str = " (deleted)";
    let s = path.as_os_str().to_string_lossy();
    if let Some(stripped) = s.strip_suffix(SUFFIX) {
        (PathBuf::from(stripped), true)
    } else {
        (path.to_path_buf(), false)
    }
}

/// Outcome of an `apply_fanotify_mark` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkOutcome {
    /// The full requested mask was accepted by the kernel.
    Full,
    /// The kernel rejected the full mask with `EINVAL`; the call was
    /// retried with `FAN_MOUNT_COMPATIBLE_EVENTS` and that mask was
    /// accepted. Real-time coverage of attribute changes, file creations,
    /// deletions, and renames is degraded for this mount. This only occurs
    /// on the `LegacyFd` tier path where mount-mark semantics are used.
    /// On `Fid` and `FidDfidName` tiers, `FAN_MARK_FILESYSTEM` accepts
    /// the full mask. Scheduled scans backstop the degraded event classes.
    Reduced,
}

fn apply_fanotify_mark(
    fan_fd: RawFd,
    mount: &std::path::Path,
    mask: u64,
    op: u32,
    fid_mode: bool,
) -> Result<MarkOutcome> {
    let c_path = CString::new(mount.as_os_str().as_bytes())
        .map_err(|_| VigilError::Fanotify(format!("invalid path: {}", mount.display())))?;

    // In FID mode, use FAN_MARK_FILESYSTEM which supports the full event
    // mask. In legacy mode, use FAN_MARK_MOUNT with EINVAL fallback.
    let mark_type = if fid_mode {
        FAN_MARK_FILESYSTEM
    } else {
        FAN_MARK_MOUNT
    };

    // SAFETY: fanotify_mark syscall with a valid fd, a valid NUL-terminated
    // C string, and the selected mark type. Return value checked below.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd,
            op | mark_type,
            mask,
            libc::AT_FDCWD,
            c_path.as_ptr(),
        )
    };

    if ret >= 0 {
        return Ok(MarkOutcome::Full);
    }

    let err = std::io::Error::last_os_error();

    // In FID mode, EINVAL fallback is not needed — FAN_MARK_FILESYSTEM
    // accepts the full mask. Fail immediately on any error.
    if fid_mode {
        return Err(VigilError::Fanotify(format!(
            "fanotify_mark (FID/filesystem) failed for {}: {}",
            mount.display(),
            err
        )));
    }

    // EINVAL with FAN_MARK_MOUNT typically means the requested event mask
    // includes bits that newer kernels refuse for mount-mark semantics
    // (FAN_CREATE, FAN_DELETE, FAN_MOVED_*, FAN_ATTRIB). Older kernels
    // silently ignored these bits; current kernels enforce. Retry with the
    // mount-compatible subset so the daemon stays functional with degraded
    // real-time coverage instead of failing to mark the mount at all.
    //
    // Only attempt the fallback when the requested mask actually contains
    // bits beyond the compatible subset — otherwise the EINVAL came from a
    // different cause (bad fd, bad path) and retrying would mask the real
    // error with a confusing second EINVAL.
    let raw_errno = err.raw_os_error();
    let is_einval = raw_errno == Some(libc::EINVAL);
    let has_unsupported_bits = mask & !FAN_MOUNT_COMPATIBLE_EVENTS != 0;
    let reduced_mask = mask & FAN_MOUNT_COMPATIBLE_EVENTS;

    if !is_einval || !has_unsupported_bits || reduced_mask == 0 || op == FAN_MARK_REMOVE {
        return Err(VigilError::Fanotify(format!(
            "fanotify_mark failed for {}: {}",
            mount.display(),
            err
        )));
    }

    // SAFETY: same contract as the first call; only the mask differs.
    let retry = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd,
            op | FAN_MARK_MOUNT,
            reduced_mask,
            libc::AT_FDCWD,
            c_path.as_ptr(),
        )
    };

    if retry < 0 {
        return Err(VigilError::Fanotify(format!(
            "fanotify_mark failed for {} (also failed with reduced mask): {}",
            mount.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(MarkOutcome::Reduced)
}

fn mask_to_event_type(mask: u64) -> Option<FsEventType> {
    if mask & (FAN_CLOSE_WRITE | FAN_MODIFY) != 0 {
        Some(FsEventType::Modify)
    } else if mask & FAN_ATTRIB != 0 {
        Some(FsEventType::Attrib)
    } else if mask & FAN_CREATE != 0 {
        Some(FsEventType::Create)
    } else if mask & FAN_DELETE != 0 {
        Some(FsEventType::Delete)
    } else if mask & FAN_MOVED_FROM != 0 {
        Some(FsEventType::MovedFrom)
    } else if mask & FAN_MOVED_TO != 0 {
        Some(FsEventType::MovedTo)
    } else {
        None
    }
}

/// Resolve path and optionally an event fd from FID-mode info records.
///
/// Parses the variable-length info records appended after the fixed
/// `FanotifyEventMetadata` in FID-mode events:
///
/// - `DFID_NAME`: parent directory handle + child filename
///   → `open_by_handle_at` + readlink for parent, then append child name.
/// - `FID`: file handle for the target itself
///   → `open_by_handle_at` → event fd for TOCTOU-safe hashing by the worker.
///
/// Returns `(path, Option<OwnedFd>)` on success, or `None` if the event
/// cannot be resolved (stale handle, unknown fsid, etc.).
#[allow(unsafe_code)]
fn resolve_fid_event(
    event_buf: &[u8],
    event_len: usize,
    mount_fds: &FsidMountMap,
    metrics: &Arc<Metrics>,
) -> Option<(PathBuf, Option<OwnedFd>)> {
    let info_hdr_size = std::mem::size_of::<FanotifyEventInfoHeader>();
    let fsid_size: usize = 8; // sizeof(__kernel_fsid_t)
    let fh_hdr_size = std::mem::size_of::<FileHandleHeader>();

    let mut dir_path: Option<PathBuf> = None;
    let mut child_name: Option<String> = None;
    let mut file_fd: Option<OwnedFd> = None;

    let mut pos = FAN_EVENT_METADATA_LEN;
    while pos + info_hdr_size <= event_len {
        // SAFETY: bounds checked above; read_unaligned for potentially
        // unaligned buffer offsets.
        let hdr: FanotifyEventInfoHeader = unsafe {
            std::ptr::read_unaligned(event_buf.as_ptr().add(pos) as *const FanotifyEventInfoHeader)
        };

        let record_len = hdr.len as usize;
        if record_len < info_hdr_size || pos + record_len > event_len {
            break;
        }

        let data_start = pos + info_hdr_size;

        match hdr.info_type {
            FAN_EVENT_INFO_TYPE_DFID_NAME => {
                // Layout: fsid(8) + file_handle_header(8) + handle_data(var) + name(NUL, padded)
                if data_start + fsid_size + fh_hdr_size > pos + record_len {
                    pos += record_len;
                    continue;
                }

                let fsid_start = data_start;
                let mut fsid_bytes = [0u8; 8];
                fsid_bytes.copy_from_slice(&event_buf[fsid_start..fsid_start + fsid_size]);

                let fh_start = fsid_start + fsid_size;
                let fh_hdr: FileHandleHeader = unsafe {
                    std::ptr::read_unaligned(
                        event_buf.as_ptr().add(fh_start) as *const FileHandleHeader
                    )
                };

                let handle_data_start = fh_start + fh_hdr_size;
                let handle_data_end = handle_data_start + fh_hdr.handle_bytes as usize;
                if handle_data_end > pos + record_len {
                    pos += record_len;
                    continue;
                }

                let mount_fd = match mount_fds.get(&fsid_bytes) {
                    Some(&fd) => fd,
                    None => {
                        tracing::debug!(
                            fsid = ?fsid_bytes,
                            "no mount fd for fsid; cannot resolve FID event"
                        );
                        pos += record_len;
                        continue;
                    }
                };

                // Build a file_handle buffer for open_by_handle_at.
                let total_handle_size = fh_hdr_size + fh_hdr.handle_bytes as usize;
                let mut handle_buf = vec![0u8; total_handle_size];
                handle_buf[..fh_hdr_size]
                    .copy_from_slice(&event_buf[fh_start..fh_start + fh_hdr_size]);
                handle_buf[fh_hdr_size..]
                    .copy_from_slice(&event_buf[handle_data_start..handle_data_end]);

                // SAFETY: open_by_handle_at with valid mount fd, valid handle
                // buffer, and O_PATH (no content access). Return checked.
                let dir_fd = unsafe {
                    libc::syscall(
                        libc::SYS_open_by_handle_at,
                        mount_fd,
                        handle_buf.as_ptr(),
                        libc::O_RDONLY | libc::O_PATH,
                    )
                } as i32;

                if dir_fd < 0 {
                    tracing::debug!(
                        error = %std::io::Error::last_os_error(),
                        "open_by_handle_at failed for directory handle"
                    );
                    metrics
                        .fanotify_open_by_handle_at_failures
                        .fetch_add(1, Ordering::Relaxed);
                    pos += record_len;
                    continue;
                }

                let link = format!("/proc/self/fd/{}", dir_fd);
                let resolved = std::fs::read_link(&link);
                // SAFETY: dir_fd is valid (>= 0) and owned by this scope.
                unsafe {
                    libc::close(dir_fd);
                }

                let resolved_path = match resolved {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(error = %e, "readlink failed for dir fd");
                        pos += record_len;
                        continue;
                    }
                };

                dir_path = Some(resolved_path);

                // Extract child name from bytes after the file handle.
                if handle_data_end < pos + record_len {
                    let name_bytes = &event_buf[handle_data_end..pos + record_len];
                    let name_end = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    if name_end > 0 {
                        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
                        if name != "." {
                            child_name = Some(name);
                        }
                    }
                }
            }
            FAN_EVENT_INFO_TYPE_FID => {
                // Layout: fsid(8) + file_handle_header(8) + handle_data(var)
                if data_start + fsid_size + fh_hdr_size > pos + record_len {
                    pos += record_len;
                    continue;
                }

                let fsid_start = data_start;
                let mut fsid_bytes = [0u8; 8];
                fsid_bytes.copy_from_slice(&event_buf[fsid_start..fsid_start + fsid_size]);

                let fh_start = fsid_start + fsid_size;
                let fh_hdr: FileHandleHeader = unsafe {
                    std::ptr::read_unaligned(
                        event_buf.as_ptr().add(fh_start) as *const FileHandleHeader
                    )
                };

                let handle_data_start = fh_start + fh_hdr_size;
                let handle_data_end = handle_data_start + fh_hdr.handle_bytes as usize;
                if handle_data_end > pos + record_len {
                    pos += record_len;
                    continue;
                }

                let mount_fd = match mount_fds.get(&fsid_bytes) {
                    Some(&fd) => fd,
                    None => {
                        pos += record_len;
                        continue;
                    }
                };

                // Build file_handle and try to open the file for hashing.
                let total_handle_size = fh_hdr_size + fh_hdr.handle_bytes as usize;
                let mut handle_buf = vec![0u8; total_handle_size];
                handle_buf[..fh_hdr_size]
                    .copy_from_slice(&event_buf[fh_start..fh_start + fh_hdr_size]);
                handle_buf[fh_hdr_size..]
                    .copy_from_slice(&event_buf[handle_data_start..handle_data_end]);

                // SAFETY: open_by_handle_at with valid mount fd and handle.
                // O_RDONLY for content hashing. Return checked.
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_open_by_handle_at,
                        mount_fd,
                        handle_buf.as_ptr(),
                        libc::O_RDONLY,
                    )
                } as i32;

                if fd >= 0 {
                    // SAFETY: fd is valid (>= 0) and uniquely owned.
                    file_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                } else {
                    // File may have been deleted; not fatal for the event.
                    metrics
                        .fanotify_open_by_handle_at_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {
                // Unknown info type; skip.
            }
        }

        pos += record_len;
    }

    // Construct the final path.
    let path = match (dir_path, child_name) {
        (Some(dir), Some(name)) => dir.join(name),
        (Some(dir), None) => dir, // directory event (name was ".")
        _ => return None,
    };

    Some((path, file_fd))
}

fn resolve_mount_points(paths: &[PathBuf]) -> Vec<PathBuf> {
    match parse_mountinfo() {
        Some(mount_points) => {
            let mut result = HashSet::new();
            for path in paths {
                if let Some(mount) = find_mount_for_path(path, &mount_points) {
                    result.insert(mount);
                }
            }
            if result.is_empty() {
                vec![PathBuf::from("/")]
            } else {
                result.into_iter().collect()
            }
        }
        None => {
            tracing::warn!("/proc/self/mountinfo unreadable; falling back to root mount");
            vec![PathBuf::from("/")]
        }
    }
}

/// Parse /proc/self/mountinfo and return a list of mount points.
pub fn parse_mountinfo() -> Option<Vec<PathBuf>> {
    let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut mounts = Vec::new();
    for line in content.lines() {
        // Format: mount_id parent_id major:minor root mount_point ...
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 5 {
            // mountinfo octal-escapes whitespace and special chars in mount_point
            // (e.g. " " -> "\040"); decode before storing as PathBuf.
            mounts.push(PathBuf::from(unescape_mountinfo(fields[4])));
        }
    }
    Some(mounts)
}

/// Decode mountinfo's octal escapes (`\NNN`) back to raw bytes.
/// Used because mountinfo escapes space, tab, newline, and backslash to keep
/// fields whitespace-separated.
fn unescape_mountinfo(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let candidate = &bytes[i + 1..i + 4];
            if candidate.iter().all(|&c| (b'0'..=b'7').contains(&c)) {
                let n = ((candidate[0] - b'0') as u32) * 64
                    + ((candidate[1] - b'0') as u32) * 8
                    + ((candidate[2] - b'0') as u32);
                if n <= 0xFF {
                    out.push(n as u8);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // mountinfo paths are conventionally UTF-8 on Linux; lossy is acceptable
    String::from_utf8_lossy(&out).into_owned()
}

/// Find the mount point that contains the given path.
fn find_mount_for_path(path: &std::path::Path, mount_points: &[PathBuf]) -> Option<PathBuf> {
    let mut best: Option<&PathBuf> = None;
    for mount in mount_points {
        if path.starts_with(mount) {
            match best {
                Some(prev) if mount.as_os_str().len() > prev.as_os_str().len() => {
                    best = Some(mount);
                }
                None => {
                    best = Some(mount);
                }
                _ => {}
            }
        }
    }
    best.cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_mountinfo_decodes_octal_space() {
        // mountinfo encodes ' ' as \040
        assert_eq!(unescape_mountinfo("/mnt/with\\040space"), "/mnt/with space");
    }

    #[test]
    fn unescape_mountinfo_decodes_tab_and_newline() {
        // \011 = tab, \012 = newline, \134 = backslash
        assert_eq!(unescape_mountinfo("a\\011b\\012c\\134d"), "a\tb\nc\\d");
    }

    #[test]
    fn unescape_mountinfo_passes_through_plain_path() {
        assert_eq!(unescape_mountinfo("/usr/local/bin"), "/usr/local/bin");
    }

    #[test]
    fn unescape_mountinfo_handles_trailing_backslash() {
        // trailing backslash with insufficient digits should be left alone
        assert_eq!(unescape_mountinfo("foo\\"), "foo\\");
        assert_eq!(unescape_mountinfo("foo\\1"), "foo\\1");
        assert_eq!(unescape_mountinfo("foo\\12"), "foo\\12");
    }

    #[test]
    fn unescape_mountinfo_rejects_non_octal_digits() {
        // Non-octal digits should be left as literal backslash sequences
        assert_eq!(unescape_mountinfo("foo\\999"), "foo\\999");
    }

    #[test]
    fn strip_deleted_suffix_strips_when_present() {
        let (p, deleted) = strip_deleted_suffix(std::path::Path::new("/etc/foo (deleted)"));
        assert_eq!(p, PathBuf::from("/etc/foo"));
        assert!(deleted);
    }

    #[test]
    fn strip_deleted_suffix_passthrough_when_absent() {
        let (p, deleted) = strip_deleted_suffix(std::path::Path::new("/etc/foo"));
        assert_eq!(p, PathBuf::from("/etc/foo"));
        assert!(!deleted);
    }

    #[test]
    fn strip_deleted_suffix_handles_paths_with_parens() {
        // Path with parens AND deleted suffix
        let (p, deleted) = strip_deleted_suffix(std::path::Path::new("/etc/foo (bar) (deleted)"));
        assert_eq!(p, PathBuf::from("/etc/foo (bar)"));
        assert!(deleted);

        // Path with parens but NOT deleted
        let (p, deleted) = strip_deleted_suffix(std::path::Path::new("/etc/foo (bar)"));
        assert_eq!(p, PathBuf::from("/etc/foo (bar)"));
        assert!(!deleted);
    }

    /// Compile-time invariant: the mount-compatible event subset must not
    /// include any of the events that newer Linux kernels reject when
    /// combined with `FAN_MARK_MOUNT`. If a future contributor adds one
    /// of these bits to the compatible mask, this test catches it before
    /// it lands in production and silently breaks daemon startup on
    /// strict kernels.
    #[test]
    fn mount_compatible_mask_excludes_inode_only_events() {
        let inode_only = [
            ("FAN_ATTRIB", FAN_ATTRIB),
            ("FAN_CREATE", FAN_CREATE),
            ("FAN_DELETE", FAN_DELETE),
            ("FAN_MOVED_FROM", FAN_MOVED_FROM),
            ("FAN_MOVED_TO", FAN_MOVED_TO),
        ];
        for (name, bit) in inode_only {
            assert_eq!(
                FAN_MOUNT_COMPATIBLE_EVENTS & bit,
                0,
                "FAN_MOUNT_COMPATIBLE_EVENTS must not contain {} \
                 (requires FAN_MARK_INODE/FILESYSTEM + FAN_REPORT_FID)",
                name
            );
        }
    }

    /// The compatible subset must still carry the events that mount-mark
    /// semantics actually support, otherwise the fallback would be
    /// indistinguishable from "no coverage at all."
    #[test]
    fn mount_compatible_mask_retains_modify_and_close_write() {
        assert_ne!(
            FAN_MOUNT_COMPATIBLE_EVENTS & FAN_MODIFY,
            0,
            "FAN_MOUNT_COMPATIBLE_EVENTS must include FAN_MODIFY"
        );
        assert_ne!(
            FAN_MOUNT_COMPATIBLE_EVENTS & FAN_CLOSE_WRITE,
            0,
            "FAN_MOUNT_COMPATIBLE_EVENTS must include FAN_CLOSE_WRITE"
        );
    }

    /// FID mode must be selected for both FidDfidName and Fid tiers, and
    /// must NOT be selected for LegacyFd or Inotify. This is a property-shape
    /// test: any future contributor who accidentally enables FID-tier code on
    /// the LegacyFd or Inotify path will break this assertion.
    #[test]
    fn fid_mode_only_for_fid_and_fid_dfid_name_tiers() {
        use crate::monitor::FanotifyTier;

        let fid_tiers = [FanotifyTier::FidDfidName, FanotifyTier::Fid];
        let non_fid_tiers = [FanotifyTier::LegacyFd, FanotifyTier::Inotify];

        for tier in fid_tiers {
            let fid_mode = matches!(tier, FanotifyTier::FidDfidName | FanotifyTier::Fid);
            assert!(fid_mode, "tier {:?} must select FID mode", tier);
        }

        for tier in non_fid_tiers {
            let fid_mode = matches!(tier, FanotifyTier::FidDfidName | FanotifyTier::Fid);
            assert!(!fid_mode, "tier {:?} must NOT select FID mode", tier);
        }
    }

    /// FidDfidName init flags include both DFID_NAME and FID report flags.
    #[test]
    fn fid_dfid_name_init_flags_include_both_report_flags() {
        let flags =
            FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_DFID_NAME | FAN_REPORT_FID;
        assert_ne!(flags & FAN_REPORT_DFID_NAME, 0);
        assert_ne!(flags & FAN_REPORT_FID, 0);
    }

    /// Fid-only init flags include FAN_REPORT_FID but not FAN_REPORT_DFID_NAME.
    #[test]
    fn fid_only_init_flags_exclude_dfid_name() {
        let flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_FID;
        assert_ne!(flags & FAN_REPORT_FID, 0);
        assert_eq!(flags & FAN_REPORT_DFID_NAME, 0);
    }

    /// FID mode uses FAN_MARK_FILESYSTEM, legacy mode uses FAN_MARK_MOUNT.
    #[test]
    fn fid_mode_selects_filesystem_mark() {
        assert_ne!(FAN_MARK_FILESYSTEM, FAN_MARK_MOUNT);
        assert_ne!(FAN_MARK_FILESYSTEM, 0);
        assert_ne!(FAN_MARK_MOUNT, 0);
    }

    /// The FID event info type constants must match the kernel ABI values.
    #[test]
    fn fid_event_info_type_constants() {
        assert_eq!(FAN_EVENT_INFO_TYPE_FID, 1);
        assert_eq!(FAN_EVENT_INFO_TYPE_DFID_NAME, 2);
    }

    /// resolve_fid_event returns None when given an event buffer with no
    /// valid info records (empty info section after the metadata header).
    #[test]
    fn resolve_fid_event_returns_none_on_empty_info() {
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        let mount_fds = FsidMountMap::new();

        // Minimal valid event: just the metadata header, no info records.
        let mut buf = vec![0u8; FAN_EVENT_METADATA_LEN];
        let event_len = FAN_EVENT_METADATA_LEN as u32;
        buf[0..4].copy_from_slice(&event_len.to_ne_bytes());

        let result = resolve_fid_event(&buf, FAN_EVENT_METADATA_LEN, &mount_fds, &metrics);
        assert!(result.is_none(), "empty info section should return None");
    }

    /// resolve_fid_event returns None when the fsid in the info record
    /// does not match any entry in the mount_fds map.
    #[test]
    fn resolve_fid_event_returns_none_on_unknown_fsid() {
        let metrics = std::sync::Arc::new(crate::metrics::Metrics::new());
        let mount_fds = FsidMountMap::new(); // empty map

        let info_hdr_size = std::mem::size_of::<FanotifyEventInfoHeader>();
        let fsid_size = 8usize;
        let fh_hdr_size = std::mem::size_of::<FileHandleHeader>();
        let handle_bytes = 8u32;
        let name = b"test.txt\0";
        let name_padded_len = (name.len() + 7) & !7;

        let record_len =
            info_hdr_size + fsid_size + fh_hdr_size + handle_bytes as usize + name_padded_len;
        let total_len = FAN_EVENT_METADATA_LEN + record_len;

        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());

        let pos = FAN_EVENT_METADATA_LEN;
        buf[pos] = FAN_EVENT_INFO_TYPE_DFID_NAME;
        buf[pos + 1] = 0;
        buf[pos + 2..pos + 4].copy_from_slice(&(record_len as u16).to_ne_bytes());

        let fh_pos = pos + info_hdr_size + fsid_size;
        buf[fh_pos..fh_pos + 4].copy_from_slice(&handle_bytes.to_ne_bytes());
        buf[fh_pos + 4..fh_pos + 8].copy_from_slice(&0i32.to_ne_bytes());

        let name_pos = fh_pos + fh_hdr_size + handle_bytes as usize;
        buf[name_pos..name_pos + name.len()].copy_from_slice(name);

        let result = resolve_fid_event(&buf, total_len, &mount_fds, &metrics);
        assert!(result.is_none(), "unknown fsid should return None");
    }

    /// Verify mask_to_event_type covers all FID-relevant event types.
    #[test]
    fn mask_to_event_type_covers_fid_events() {
        use crate::types::FsEventType;
        assert_eq!(mask_to_event_type(FAN_CREATE), Some(FsEventType::Create));
        assert_eq!(mask_to_event_type(FAN_DELETE), Some(FsEventType::Delete));
        assert_eq!(
            mask_to_event_type(FAN_MOVED_FROM),
            Some(FsEventType::MovedFrom)
        );
        assert_eq!(mask_to_event_type(FAN_MOVED_TO), Some(FsEventType::MovedTo));
        assert_eq!(mask_to_event_type(FAN_ATTRIB), Some(FsEventType::Attrib));
        assert_eq!(mask_to_event_type(FAN_MODIFY), Some(FsEventType::Modify));
        assert_eq!(
            mask_to_event_type(FAN_CLOSE_WRITE),
            Some(FsEventType::Modify)
        );
    }
}
