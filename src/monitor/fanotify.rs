#![allow(unsafe_code)]

use std::collections::HashSet;
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
use crate::types::{DaemonState, FsEvent, FsEventType, ProcessAttribution, ScanMode};
use crate::watch_index::WatchGroupIndex;

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

struct OwnedRawFd(RawFd);

impl Drop for OwnedRawFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: fd is owned by this RAII wrapper and valid when >= 0.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

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
            // SAFETY: fd is owned by this guard and has not been transferred.
            unsafe {
                libc::close(self.0);
            }
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
) -> Result<crossbeam_channel::Sender<Vec<PathBuf>>> {
    // SAFETY: fanotify_init syscall with valid flags; return value checked.
    let fan_fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK,
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
    tracing::info!(mounts = ?mount_points, "fanotify watching mount points");
    let mask = FAN_MODIFY
        | FAN_CLOSE_WRITE
        | FAN_ATTRIB
        | FAN_CREATE
        | FAN_DELETE
        | FAN_MOVED_FROM
        | FAN_MOVED_TO;

    for mount in &mount_points {
        if let Err(e) = apply_fanotify_mark(fan_fd, mount, mask, FAN_MARK_ADD) {
            tracing::error!(
                mount = %mount.display(),
                error = %e,
                "fanotify_mark FAN_MARK_ADD failed at startup — coverage degraded"
            );
            metrics
                .fanotify_mark_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    std::thread::Builder::new()
        .name("vigil-fanotify".into())
        .spawn(move || {
            let _fan_guard = fan_fd_owned;
            let fan_fd = _fan_guard.0;
            let mut buf = Box::new([0u8; 262_144]);
            let mut current_bloom = bloom;

            let mut current_mounts: HashSet<PathBuf> = mount_points.into_iter().collect();

            while !shutdown.load(Ordering::Acquire) {
                while let Ok(new_paths) = control_rx.try_recv() {
                    let new_mounts: HashSet<PathBuf> =
                        resolve_mount_points(&new_paths).into_iter().collect();

                    // Rebuild the Bloom filter FIRST so any in-flight events for
                    // newly-added paths are not falsely rejected during the
                    // mark add window.
                    current_bloom = Arc::new(BloomFilter::from_watch_paths(&new_paths));

                    for mount in new_mounts.difference(&current_mounts) {
                        if let Err(e) = apply_fanotify_mark(fan_fd, mount, mask, FAN_MARK_ADD) {
                            tracing::error!(
                                mount = %mount.display(),
                                error = %e,
                                "fanotify_mark FAN_MARK_ADD failed during reload — coverage degraded for this mount"
                            );
                            metrics
                                .fanotify_mark_failures
                                .fetch_add(1, Ordering::Relaxed);
                            if let Some(s) = &state {
                                let mut guard = s.write();
                                if matches!(*guard, DaemonState::Healthy) {
                                    *guard = DaemonState::Degraded {
                                        reason: format!(
                                            "fanotify_mark add failed for {}: {}",
                                            mount.display(),
                                            e
                                        ),
                                        since: Utc::now(),
                                    };
                                }
                            }
                        }
                    }
                    for mount in current_mounts.difference(&new_mounts) {
                        if let Err(e) = apply_fanotify_mark(fan_fd, mount, mask, FAN_MARK_REMOVE) {
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

                // SAFETY: valid fd + valid buffer pointer.
                let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    let raw = err.raw_os_error();
                    if raw == Some(libc::EAGAIN) || raw == Some(libc::EWOULDBLOCK) {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    if raw == Some(libc::EINTR) {
                        continue;
                    }
                    tracing::error!(
                        error = %err,
                        errno = ?raw,
                        "fanotify read() failed with non-recoverable error — stopping monitor"
                    );
                    metrics
                        .fanotify_read_errors
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(s) = &state {
                        let mut guard = s.write();
                        if matches!(*guard, DaemonState::Healthy) {
                            *guard = DaemonState::Degraded {
                                reason: format!("fanotify read failed: {}", err),
                                since: Utc::now(),
                            };
                        }
                    }
                    return;
                }
                if n == 0 {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }

                let n_usize = n as usize;
                let mut offset = 0usize;
                while offset + FAN_EVENT_METADATA_LEN <= n_usize {
                    // SAFETY: offset bounds checked and kernel produced this buffer.
                    // Using read_unaligned because the buffer offset may not be aligned.
                    let event: FanotifyEventMetadata =
                        unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FanotifyEventMetadata) };

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
                        metrics
                            .fanotify_read_errors
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }

                    // Handle kernel queue overflow: fanotify dropped events
                    if event.mask & FAN_Q_OVERFLOW != 0 {
                        tracing::error!(
                            "fanotify kernel queue overflow (FAN_Q_OVERFLOW) — \
                             events were dropped by the kernel. Triggering compensating full scan."
                        );
                        metrics
                            .kernel_queue_overflows
                            .fetch_add(1, Ordering::Relaxed);
                        // Mark the daemon Degraded so operators see this in `vigil status`
                        if let Some(s) = &state {
                            let mut guard = s.write();
                            if matches!(*guard, DaemonState::Healthy) {
                                *guard = DaemonState::Degraded {
                                    reason: "fanotify queue overflow — events dropped by kernel"
                                        .to_string(),
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
                        // race entirely by providing a stable pidfd reference.
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
                                // Process already exited — PID may have been recycled
                                tracing::debug!(
                                    pid = event.pid,
                                    "process exited before attribution — PID may be stale"
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
                        if let Ok(path) = std::fs::read_link(&fd_link) {
                            // Bloom filter fast-reject: check if any prefix of the
                            // event path is in the filter (not the full path, which
                            // was never inserted)
                            if !current_bloom.might_contain_prefix_of(&path) {
                                // fd_guard drops and closes the fd automatically
                                offset += len;
                                continue;
                            }

                            let idx = watch_index.load();
                            let is_watched = idx.is_watched(&path);

                            if is_watched {
                                if let Some(event_type) = mask_to_event_type(event.mask) {
                                    metrics
                                        .events_received
                                        .fetch_add(1, Ordering::Relaxed);

                                    // Transfer fd ownership into OwnedFd; prevent guard from closing it
                                    let raw = fd_guard.take();
                                    // SAFETY: raw fd is uniquely owned here and has not been closed.
                                    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw) };

                                    let fs_event = FsEvent {
                                        path: Arc::new(path.clone()),
                                        event_type,
                                        timestamp: Utc::now(),
                                        event_fd: Some(owned_fd),
                                        process,
                                    };

                                    match event_tx.send_timeout(fs_event, Duration::from_secs(1)) {
                                        Ok(()) => {}
                                        Err(crossbeam_channel::SendTimeoutError::Timeout(_dropped)) => {
                                            metrics
                                                .events_dropped
                                                .fetch_add(1, Ordering::Relaxed);
                                            tracing::warn!(
                                                path = %path.display(),
                                                "fanotify event channel full for 1s; dropping event fd"
                                            );
                                        }
                                        Err(crossbeam_channel::SendTimeoutError::Disconnected(_dropped)) => {
                                            tracing::error!("event channel disconnected");
                                            return;
                                        }
                                    }
                                }
                                // else: unrecognized mask — fd_guard drops and closes
                            }
                            // else: not watched — fd_guard drops and closes
                        }
                        // else: read_link failed — fd_guard drops and closes
                    }

                    offset += len;
                }
            }

            tracing::info!("fanotify monitor stopped");
        })
        .map_err(|e| VigilError::Fanotify(format!("cannot spawn thread: {}", e)))?;

    Ok(control_tx)
}

fn apply_fanotify_mark(fan_fd: RawFd, mount: &std::path::Path, mask: u64, op: u32) -> Result<()> {
    let c_path = CString::new(mount.as_os_str().as_bytes())
        .map_err(|_| VigilError::Fanotify(format!("invalid path: {}", mount.display())))?;

    // SAFETY: fanotify_mark syscall with valid fd and C string; result checked.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd,
            op | FAN_MARK_MOUNT,
            mask,
            libc::AT_FDCWD,
            c_path.as_ptr(),
        )
    };

    if ret < 0 {
        return Err(VigilError::Fanotify(format!(
            "fanotify_mark failed for {}: {}",
            mount.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
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
}
