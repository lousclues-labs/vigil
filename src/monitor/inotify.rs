use std::collections::HashMap;
use std::os::unix::io::AsFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use crossbeam_channel::Sender;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};

use crate::config::Config;
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::{FsEvent, FsEventType};

pub fn start(
    _config: &Config,
    watch_paths: &[PathBuf],
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
) -> Result<crossbeam_channel::Sender<Vec<PathBuf>>> {
    let inotify = Inotify::init(InitFlags::IN_CLOEXEC)
        .map_err(|e| VigilError::Inotify(format!("inotify_init failed: {}", e)))?;

    let (control_tx, control_rx) = crossbeam_channel::unbounded::<Vec<PathBuf>>();

    let flags = AddWatchFlags::IN_MODIFY
        | AddWatchFlags::IN_ATTRIB
        | AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_DELETE
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_MOVED_TO;

    let mut wd_to_path: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

    for path in watch_paths {
        if path.is_dir() {
            if let Err(e) = add_directory_watches(&inotify, path, flags, &mut wd_to_path) {
                tracing::warn!(path = %path.display(), error = %e, "cannot watch directory");
            }
        } else if path.is_file() {
            if let Some(parent) = path.parent() {
                match inotify.add_watch(parent, flags) {
                    Ok(wd) => {
                        wd_to_path.insert(wd, parent.to_path_buf());
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "cannot watch file parent");
                    }
                }
            }
        }
    }

    std::thread::Builder::new()
        .name("vigil-inotify".into())
        .spawn(move || {
            let inotify_fd = inotify.as_fd();

            while !shutdown.load(Ordering::Acquire) {
                while let Ok(new_paths) = control_rx.try_recv() {
                    if let Err(e) = rebuild_watches(&inotify, &mut wd_to_path, &new_paths, flags) {
                        tracing::error!(error = %e, "failed to reconfigure inotify watches");
                    }
                }

                let mut fds = [PollFd::new(inotify_fd, PollFlags::POLLIN)];
                match poll(&mut fds, PollTimeout::from(500u16)) {
                    Ok(n) if n > 0 => match inotify.read_events() {
                        Ok(events) => {
                            for event in events {
                                let dir_path = match wd_to_path.get(&event.wd) {
                                    Some(p) => p,
                                    None => continue,
                                };

                                let file_path = if let Some(name) = &event.name {
                                    dir_path.join(name)
                                } else {
                                    dir_path.clone()
                                };

                                if event.mask.contains(AddWatchFlags::IN_CREATE)
                                    && event.mask.contains(AddWatchFlags::IN_ISDIR)
                                {
                                    let _ = add_directory_watches(&inotify, &file_path, flags, &mut wd_to_path);
                                }

                                if let Some(event_type) = inotify_mask_to_event_type(event.mask) {
                                    metrics.events_received.fetch_add(1, Ordering::Relaxed);

                                    let fs_event = FsEvent {
                                        path: std::sync::Arc::new(file_path.clone()),
                                        event_type,
                                        timestamp: Utc::now(),
                                        event_fd: None,
                                        process: None,
                                    };

                                    match event_tx.send_timeout(fs_event, Duration::from_secs(1)) {
                                        Ok(()) => {}
                                        Err(crossbeam_channel::SendTimeoutError::Timeout(_)) => {
                                            metrics
                                                .events_dropped
                                                .fetch_add(1, Ordering::Relaxed);
                                            tracing::warn!(path = %file_path.display(), "inotify channel full; dropping event");
                                        }
                                        Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                                            tracing::error!("event channel disconnected");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "inotify read error");
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    },
                    Ok(_) => continue,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => {
                        tracing::error!(error = %e, "poll error");
                        break;
                    }
                }
            }

            tracing::info!("inotify monitor stopped");
        })
        .map_err(|e| VigilError::Inotify(format!("cannot spawn thread: {}", e)))?;

    Ok(control_tx)
}

fn rebuild_watches(
    inotify: &Inotify,
    wd_map: &mut HashMap<WatchDescriptor, PathBuf>,
    watch_paths: &[PathBuf],
    flags: AddWatchFlags,
) -> Result<()> {
    let existing_wds: Vec<WatchDescriptor> = wd_map.keys().cloned().collect();
    for wd in existing_wds {
        let _ = inotify.rm_watch(wd);
    }
    wd_map.clear();

    for path in watch_paths {
        if path.is_dir() {
            let _ = add_directory_watches(inotify, path, flags, wd_map);
        } else if path.is_file() {
            if let Some(parent) = path.parent() {
                if let Ok(wd) = inotify.add_watch(parent, flags) {
                    wd_map.insert(wd, parent.to_path_buf());
                }
            }
        }
    }

    Ok(())
}

fn add_directory_watches(
    inotify: &Inotify,
    root: &std::path::Path,
    flags: AddWatchFlags,
    wd_map: &mut HashMap<WatchDescriptor, PathBuf>,
) -> Result<()> {
    if !root.is_dir() {
        return Ok(());
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        match inotify.add_watch(&dir, flags) {
            Ok(wd) => {
                wd_map.insert(wd, dir.clone());
            }
            Err(e) => {
                tracing::warn!(path = %dir.display(), error = %e, "cannot add watch");
            }
        }

        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                }
            }
        }
    }

    Ok(())
}

fn inotify_mask_to_event_type(mask: AddWatchFlags) -> Option<FsEventType> {
    if mask.contains(AddWatchFlags::IN_MODIFY) {
        Some(FsEventType::Modify)
    } else if mask.contains(AddWatchFlags::IN_ATTRIB) {
        Some(FsEventType::Attrib)
    } else if mask.contains(AddWatchFlags::IN_CREATE) {
        Some(FsEventType::Create)
    } else if mask.contains(AddWatchFlags::IN_DELETE) {
        Some(FsEventType::Delete)
    } else if mask.contains(AddWatchFlags::IN_MOVED_FROM) {
        Some(FsEventType::MovedFrom)
    } else if mask.contains(AddWatchFlags::IN_MOVED_TO) {
        Some(FsEventType::MovedTo)
    } else {
        None
    }
}
