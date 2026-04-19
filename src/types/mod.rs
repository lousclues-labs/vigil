//! Domain types re-exported for crate-wide use.

pub mod alert;
pub mod baseline;
pub mod change;
pub mod config_types;
pub mod content;
pub mod event;
pub mod identity;
pub mod permissions;
pub mod security;
pub mod snapshot;

// Re-exports for convenience
pub use alert::{Alert, AlertContext, AlertFileInfo};
pub use baseline::BaselineEntry;
pub use change::{Change, ChangeResult, ProcessAttribution};
pub use config_types::{
    BaselineSource, DaemonState, DaemonStateHandle, DegradedReason, MonitorBackend, OutputFormat,
    PackageBackend, ScanMode, Severity,
};
pub use content::ContentFingerprint;
pub use event::{FsEvent, FsEventType};
pub use identity::{FileIdentity, FileType};
pub use permissions::PermissionState;
pub use security::SecurityState;
pub use snapshot::{CaptureOpts, FileSnapshot, SnapshotOrDeleted};
