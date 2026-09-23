//! Change detection variants -- one per integrity dimension.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::types::{FileType, Severity};

/// A single detected change -- one variant per detection dimension.
/// Adding a new detection dimension = adding one variant. Zero impact on existing code.
///
/// `PartialEq` matters: the acceptance guard re-diffs a path immediately before
/// writing it to the baseline and requires the resulting change list to equal
/// the one the operator reviewed. Equality of this type is that check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The raw `readlink(2)` text of a symlink changed. Distinct from
    /// `SymlinkTargetChanged`, which compares fully resolved canonical targets:
    /// link text can change (`../a` to `/x/a`) while resolving identically, and
    /// the canonical target can change while the link text stays put.
    LinkTextChanged {
        old: PathBuf,
        new: PathBuf,
    },
    /// The symlink object itself is unchanged -- same link text, same `lstat`
    /// inode -- but the file it resolves to was replaced.
    ///
    /// This is an alias reference to a target change, not an independent
    /// replacement of the symlink. The underlying target observations
    /// (content, size, inode) are still recorded alongside this variant; this
    /// variant only states who actually changed.
    SymlinkTargetReplaced {
        /// Canonical path of the target that was replaced.
        target: PathBuf,
        old_target_inode: u64,
        new_target_inode: u64,
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

impl Change {
    /// The canonical wire name for this change dimension.
    ///
    /// Single source of truth. The audit log, the alert sinks, the WAL
    /// consumers and `Display` all read from here, because they must agree:
    /// a detection recorded as `content_modified` in the audit chain and
    /// announced as something else by a sink is one event wearing two names,
    /// and anything correlating the two would silently fail to match.
    ///
    /// Adding a `Change` variant is a compile error here until it is named.
    pub const fn name(&self) -> &'static str {
        match self {
            Change::ContentModified { .. } => "content_modified",
            Change::PermissionsChanged { .. } => "permissions_changed",
            Change::OwnerChanged { .. } => "owner_changed",
            Change::InodeChanged { .. } => "inode_changed",
            Change::TypeChanged { .. } => "type_changed",
            Change::SymlinkTargetChanged { .. } => "symlink_target_changed",
            Change::LinkTextChanged { .. } => "link_text_changed",
            Change::SymlinkTargetReplaced { .. } => "symlink_target_replaced",
            Change::CapabilitiesChanged { .. } => "capabilities_changed",
            Change::XattrChanged { .. } => "xattr_changed",
            Change::SecurityContextChanged { .. } => "security_context_changed",
            Change::SizeChanged { .. } => "size_changed",
            Change::DeviceChanged { .. } => "device_changed",
            Change::Deleted => "deleted",
            Change::Created => "created",
        }
    }
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
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
    /// Forensic disambiguation result for content mismatches, populated only
    /// when disambiguation was performed (CLI `--disambiguate-cause` or daemon
    /// `[detection].disambiguate_on_detection = true`). `None` when not run.
    ///
    /// IMPORTANT: this field is metadata about the detection. It is NOT part
    /// of the audit chain hash; adding it does not change chain semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disambiguation: Option<crate::hash::DisambiguationResult>,
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
            disambiguation: None,
        }
    }

    /// Returns the canonical target path when this detection is an alias
    /// reference: a symlink whose own object did not change, recorded because
    /// the file it resolves to was replaced.
    ///
    /// Callers use this to present the detection beneath the target's own
    /// change instead of as an independent replacement. The detection itself is
    /// unaffected -- it is still recorded, still carries its raw severity, and
    /// still lists every observed dimension.
    pub fn symlink_alias_target(&self) -> Option<&std::path::Path> {
        self.changes.iter().find_map(|c| match c {
            Change::SymlinkTargetReplaced { target, .. } => Some(target.as_path()),
            _ => None,
        })
    }

    /// Returns the primary change type for display/logging.
    ///
    /// Delegates to [`Change::name`]. This previously carried its own mapping
    /// that returned `"modified"` for a content change where every other
    /// mapping said `"content_modified"` -- two names for one dimension. The
    /// divergence went unnoticed because nothing called this.
    pub fn primary_change_name(&self) -> &'static str {
        self.changes.first().map(Change::name).unwrap_or("unknown")
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
