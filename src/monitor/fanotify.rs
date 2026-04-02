use std::collections::HashSet;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::Utc;
use crossbeam_channel::Sender;

use crate::config::Config;
use crate::error::{Result, VigilError};
use crate::types::{FsEvent, FsEventType};

// fanotify constants (not all exposed by libc/nix)
const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_NONBLOCK: u32 = 0x0000_0002;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_MOUNT: u32 = 0x0000_0010;

const FAN_MODIFY: u64 = 0x0000_0002;
const FAN_ATTRIB: u64 = 0x0000_0004;
const FAN_CREATE: u64 = 0x0000_0100;
const FAN_DELETE: u64 = 0x0000_0200;
const FAN_MOVED_FROM: u64 = 0x0000_0040;
const FAN_MOVED_TO: u64 = 0x0000_0080;

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

/// Start fanotify-based filesystem monitoring on a background thread.
pub fn start(
    _config: &Config,
    watch_paths: &[PathBuf],
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    // Initialize fanotify fd
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

    // Determine unique mount points to mark
    let mount_points = resolve_mount_points(watch_paths);

    let mask = FAN_MODIFY | FAN_ATTRIB | FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO;

    for mount in &mount_points {
        let c_path = CString::new(mount.as_os_str().as_bytes()).map_err(|_| {
            VigilError::Fanotify(format!("invalid path: {}", mount.display()))
        })?;

        let ret = unsafe {
            libc::syscall(
                libc::SYS_fanotify_mark,
                fan_fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                mask,
                libc::AT_FDCWD,
                c_path.as_ptr(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            log::warn!(
                "fanotify_mark failed for {}: {}",
                mount.display(),
                err
            );
        } else {
            log::info!("fanotify watching mount: {}", mount.display());
        }
    }

    // Collect watch paths as a set for fast membership checking
    let watch_set: HashSet<PathBuf> = watch_paths.iter().cloned().collect();

    // Spawn event reader thread
    std::thread::Builder::new()
        .name("vigil-fanotify".into())
        .spawn(move || {
            let mut buf = vec![0u8; 4096];

            // Set up epoll
            let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if epoll_fd < 0 {
                log::error!("epoll_create1 failed: {}", std::io::Error::last_os_error());
                return;
            }

            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: fan_fd as u64,
            };
            unsafe {
                libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fan_fd, &mut ev);
            }

            let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];

            while !shutdown.load(Ordering::Relaxed) {
                let nfds = unsafe {
                    libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 1, 500) // 500ms timeout
                };

                if nfds <= 0 {
                    continue;
                }

                let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    continue;
                }

                let mut offset = 0;
                while offset + FAN_EVENT_METADATA_LEN <= n as usize {
                    let event = unsafe {
                        &*(buf.as_ptr().add(offset) as *const FanotifyEventMetadata)
                    };

                    if event.fd >= 0 {
                        // Read path from /proc/self/fd/<fd>
                        let fd_link = format!("/proc/self/fd/{}", event.fd);
                        if let Ok(path) = std::fs::read_link(&fd_link) {
                            // Check if path is in our watch set (or is a child of a watched dir)
                            let is_watched = watch_set.iter().any(|wp| {
                                path.starts_with(wp) || &path == wp
                            });

                            if is_watched {
                                if let Some(event_type) = mask_to_event_type(event.mask) {
                                    let _ = event_tx.try_send(FsEvent {
                                        path,
                                        event_type,
                                        timestamp: Utc::now(),
                                    });
                                }
                            }
                        }

                        // Close the event fd
                        unsafe { libc::close(event.fd) };
                    }

                    offset += event.event_len as usize;
                }
            }

            unsafe {
                libc::close(epoll_fd);
                libc::close(fan_fd);
            }
            log::info!("fanotify monitor stopped");
        })
        .map_err(|e| VigilError::Fanotify(format!("cannot spawn thread: {}", e)))?;

    Ok(())
}

fn mask_to_event_type(mask: u64) -> Option<FsEventType> {
    if mask & FAN_MODIFY != 0 {
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

/// Resolve watch paths to their mount points by reading /proc/self/mountinfo.
fn resolve_mount_points(watch_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut mount_points = HashSet::new();

    let mountinfo = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(m) => m,
        Err(_) => {
            // Fallback: use "/" and the paths themselves
            log::warn!("Cannot read /proc/self/mountinfo, using root mount");
            return vec![PathBuf::from("/")];
        }
    };

    // Parse mount points from mountinfo
    let known_mounts: Vec<PathBuf> = mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5 {
                Some(PathBuf::from(fields[4]))
            } else {
                None
            }
        })
        .collect();

    for watch_path in watch_paths {
        // Find the longest mount point that is a prefix of this watch path
        let mut best_mount = PathBuf::from("/");
        for mount in &known_mounts {
            if watch_path.starts_with(mount) && mount.as_os_str().len() > best_mount.as_os_str().len()
            {
                best_mount = mount.clone();
            }
        }
        mount_points.insert(best_mount);
    }

    mount_points.into_iter().collect()
}
