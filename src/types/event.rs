//! Filesystem event from fanotify/inotify with optional fd and process attribution.

use chrono::{DateTime, Utc};
use std::os::unix::io::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

use crate::types::ProcessAttribution;

/// A raw filesystem event from fanotify or inotify.
pub struct FsEvent {
    pub path: Arc<PathBuf>,
    pub event_type: FsEventType,
    pub timestamp: DateTime<Utc>,
    /// Fanotify event fd, transferred to worker. The worker hashes via this fd
    /// (zero re-open TOCTOU). Inotify backend sets this to None.
    pub event_fd: Option<OwnedFd>,
    pub process: Option<ProcessAttribution>,
    /// Generation counter of the bloom filter that admitted this event.
    /// Workers reject events whose generation is older than the current
    /// WatchGroupIndex generation, eliminating transient false alerts after
    /// config reload.
    pub bloom_generation: u64,
}

// FsEvent contains OwnedFd which is Send but we need to make sure the
// struct as a whole is Send for crossbeam channels.
// SAFETY: OwnedFd is Send, all other fields are Send. The fd is transferred
// (moved) between threads, never shared.
#[allow(unsafe_code)]
unsafe impl Send for FsEvent {}

/// Filesystem event types from kernel monitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsEventType {
    Modify,
    Attrib,
    Create,
    Delete,
    MovedFrom,
    MovedTo,
}
