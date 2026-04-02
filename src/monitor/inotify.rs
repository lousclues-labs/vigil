use std::collections::HashMap;
use std::os::unix::io::AsFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::Utc;
use crossbeam_channel::Sender;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};

use crate::config::Config;
use crate::error::{Result, VigilError};
use crate::types::{FsEvent, FsEventType};

/// Start inotify-based filesystem monitoring (fallback when fanotify is unavailable).
pub fn start(
    _config: &Config,
    watch_paths: &[PathBuf],
    event_tx: Sender<FsEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let inotify = Inotify::init(InitFlags::IN_CLOEXEC)
        .map_err(|e| VigilError::Inotify(format!("inotify_init failed: {}", e)))?;

    let flags = AddWatchFlags::IN_MODIFY
        | AddWatchFlags::IN_ATTRIB
        | AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_DELETE
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_MOVED_TO;

    // Map watch descriptors back to paths
    let mut wd_to_path: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
    let mut unwatched = Vec::new();

    for path in watch_paths {
        if path.is_dir() {
            match add_directory_watches(&inotify, path, flags, &mut wd_to_path) {
                Ok(_) => {}
                Err(e) => {
                    log::warn!("Cannot watch {}: {}", path.display(), e);
                    unwatched.push(path.clone());
                }
            }
        } else if path.is_file() {
            if let Some(parent) = path.parent() {
                match inotify.add_watch(parent, flags) {
                    Ok(wd) => {
                        wd_to_path.insert(wd, parent.to_path_buf());
                    }
                    Err(e) => {
                        log::warn!("Cannot watch {}: {}", path.display(), e);
                        unwatched.push(path.clone());
                    }
                }
            }
        } else if !path.exists() {
            log::warn!("Watch path does not exist: {}", path.display());
        }
    }

    if !unwatched.is_empty() {
        log::warn!("The following paths could not be watched:");
        for p in &unwatched {
            log::warn!("  {} — Permission denied", p.display());
        }
    }

    log::info!(
        "inotify watching {} directories ({} paths could not be watched)",
        wd_to_path.len(),
        unwatched.len()
    );

    // Spawn event reader thread
    std::thread::Builder::new()
        .name("vigil-inotify".into())
        .spawn(move || {
            let inotify_fd = inotify.as_fd();
            let poll_fd = PollFd::new(inotify_fd, PollFlags::POLLIN);

            while !shutdown.load(Ordering::Relaxed) {
                // Poll with 500ms timeout so we can check shutdown flag
                match poll(&mut [poll_fd], PollTimeout::from(500u16)) {
                    Ok(n) if n > 0 => {
                        match inotify.read_events() {
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

                                    let event_type = inotify_mask_to_event_type(event.mask);
                                    if let Some(et) = event_type {
                                        let fs_event = FsEvent {
                                            path: file_path.clone(),
                                            event_type: et,
                                            timestamp: Utc::now(),
                                        };
                                        match event_tx.try_send(fs_event) {
                                            Ok(()) => {}
                                            Err(crossbeam_channel::TrySendError::Full(_)) => {
                                                log::warn!("Event channel full — dropping filesystem event for {}", file_path.display());
                                            }
                                            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                                                log::error!("Event channel disconnected");
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("inotify read error: {}", e);
                                std::thread::sleep(std::time::Duration::from_secs(1));
                            }
                        }
                    }
                    Ok(_) => continue, // timeout, loop back to check shutdown
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => {
                        log::error!("poll error: {}", e);
                        break;
                    }
                }
            }

            log::info!("inotify monitor stopped");
        })
        .map_err(|e| VigilError::Inotify(format!("cannot spawn thread: {}", e)))?;

    Ok(())
}

fn add_directory_watches(
    inotify: &Inotify,
    dir: &std::path::Path,
    flags: AddWatchFlags,
    wd_map: &mut HashMap<WatchDescriptor, PathBuf>,
) -> Result<()> {
    let wd = inotify
        .add_watch(dir, flags)
        .map_err(|e| VigilError::Inotify(format!("{}: {}", dir.display(), e)))?;
    wd_map.insert(wd, dir.to_path_buf());

    // Recursively watch subdirectories
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    let _ = add_directory_watches(inotify, &entry.path(), flags, wd_map);
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
