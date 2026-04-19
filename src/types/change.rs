//! Change detection variants -- one per integrity dimension.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::types::{FileType, Severity};

/// A single detected change -- one variant per detection dimension.
/// Adding a new detection dimension = adding one variant. Zero impact on existing code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    ContentModified {
        old_hash: String,
        new_hash: String,
    },
    PermissionsChanged {
        old: u32,
        new: u32,
    },
    OwnerChanged {
        old_uid: u32,
        new_uid: u32,
        old_gid: u32,
        new_gid: u32,
    },
    InodeChanged {
        old: u64,
        new: u64,
    },
    TypeChanged {
        old: FileType,
        new: FileType,
    },
    SymlinkTargetChanged {
        old: PathBuf,
        new: PathBuf,
    },
    CapabilitiesChanged {
        old: Option<String>,
        new: Option<String>,
    },
    XattrChanged {
        key: String,
        old: Option<String>,
        new: Option<String>,
    },
    SecurityContextChanged {
        old: String,
        new: String,
    },
    SizeChanged {
        old: u64,
        new: u64,
    },
    DeviceChanged {
        old: u64,
        new: u64,
    },
    Deleted,
    Created,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Change::ContentModified { .. } => write!(f, "content_modified"),
            Change::PermissionsChanged { .. } => write!(f, "permissions_changed"),
            Change::OwnerChanged { .. } => write!(f, "owner_changed"),
            Change::InodeChanged { .. } => write!(f, "inode_changed"),
            Change::TypeChanged { .. } => write!(f, "type_changed"),
            Change::SymlinkTargetChanged { .. } => write!(f, "symlink_target_changed"),
            Change::CapabilitiesChanged { .. } => write!(f, "capabilities_changed"),
            Change::XattrChanged { .. } => write!(f, "xattr_changed"),
            Change::SecurityContextChanged { .. } => write!(f, "security_context_changed"),
            Change::SizeChanged { .. } => write!(f, "size_changed"),
            Change::DeviceChanged { .. } => write!(f, "device_changed"),
            Change::Deleted => write!(f, "deleted"),
            Change::Created => write!(f, "created"),
        }
    }
}

/// The result of comparing a file's current state to its baseline.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeResult {
    pub path: Arc<PathBuf>,
    pub changes: Vec<Change>,
    pub severity: Severity,
    pub monitored_group: String,
    pub process: Option<ProcessAttribution>,
    pub package: Option<String>,
    pub package_update: bool,
}

impl ChangeResult {
    /// Build a deletion ChangeResult from a baseline entry.
    pub fn deletion(
        path: &std::path::Path,
        baseline: &crate::types::BaselineEntry,
        severity: Severity,
        group_name: String,
    ) -> Self {
        Self {
            path: Arc::new(path.to_path_buf()),
            changes: vec![Change::Deleted],
            severity,
            monitored_group: group_name,
            process: None,
            package: baseline.package.clone(),
            package_update: false,
        }
    }

    /// Returns the primary change type for display/logging.
    pub fn primary_change_name(&self) -> &str {
        self.changes
            .first()
            .map(|c| match c {
                Change::ContentModified { .. } => "modified",
                Change::PermissionsChanged { .. } => "permissions_changed",
                Change::OwnerChanged { .. } => "owner_changed",
                Change::InodeChanged { .. } => "inode_changed",
                Change::TypeChanged { .. } => "type_changed",
                Change::SymlinkTargetChanged { .. } => "symlink_target_changed",
                Change::CapabilitiesChanged { .. } => "capabilities_changed",
                Change::XattrChanged { .. } => "xattr_changed",
                Change::SecurityContextChanged { .. } => "security_context_changed",
                Change::SizeChanged { .. } => "size_changed",
                Change::DeviceChanged { .. } => "device_changed",
                Change::Deleted => "deleted",
                Change::Created => "created",
            })
            .unwrap_or("unknown")
    }
}

/// Process attribution -- which process caused the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAttribution {
    pub pid: u32,
    pub exe: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_display() {
        assert_eq!(Change::Deleted.to_string(), "deleted");
        assert_eq!(Change::Created.to_string(), "created");
        assert_eq!(
            Change::ContentModified {
                old_hash: "a".into(),
                new_hash: "b".into()
            }
            .to_string(),
            "content_modified"
        );
    }

    #[test]
    fn change_serde_roundtrip() {
        let change = Change::PermissionsChanged {
            old: 0o644,
            new: 0o600,
        };
        let json = serde_json::to_string(&change).unwrap();
        let parsed: Change = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            Change::PermissionsChanged {
                old: 0o644,
                new: 0o600
            }
        ));
    }
}
