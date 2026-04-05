use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::error::{Result, VigilError};
use crate::types::{
    BaselineEntry, Change, ContentFingerprint, FileIdentity, FileType, PermissionState,
    SecurityState,
};

/// Options controlling file snapshot capture.
#[derive(Debug, Clone)]
pub struct CaptureOpts {
    /// Always compute hash even if metadata matches.
    pub force_hash: bool,
    /// Maximum file size to hash (bytes). Files larger are skipped.
    pub max_file_size: u64,
    /// Threshold above which mmap is used for hashing (bytes).
    pub mmap_threshold: u64,
}

/// Complete current state of a file, captured at a point in time.
#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub path: std::path::PathBuf,
    pub identity: FileIdentity,
    pub content: ContentFingerprint,
    pub permissions: PermissionState,
    pub security: SecurityState,
    pub mtime: i64,
}

/// Result of attempting to capture a snapshot for a path that may have been deleted.
pub enum SnapshotOrDeleted {
    Snapshot(FileSnapshot),
    Deleted,
}

impl FileSnapshot {
    /// Capture the complete current state of a file from an open fd.
    /// No path-based operations after the initial open.
    /// The fd is NOT closed — the caller owns it.
    pub fn from_fd(file: &File, path: &Path, opts: &CaptureOpts) -> Result<Self> {
        let meta = file.metadata()?;

        if meta.len() > opts.max_file_size {
            return Err(VigilError::Baseline(format!(
                "file too large: {} ({} bytes > {} max)",
                path.display(),
                meta.len(),
                opts.max_file_size
            )));
        }

        let file_type = if meta.is_symlink() {
            FileType::Symlink
        } else if meta.is_dir() {
            FileType::Directory
        } else {
            FileType::Regular
        };

        let symlink_target = if file_type == FileType::Symlink {
            std::fs::read_link(path).ok()
        } else {
            None
        };

        let hash = crate::hash::blake3_hash_fd(file, meta.len(), opts.mmap_threshold)?;

        let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let fd_path_ref = Path::new(&fd_path);

        let xattrs = read_xattrs_fd(fd_path_ref);
        let security_context = read_security_context_fd(fd_path_ref);
        let capabilities = read_capabilities_fd(fd_path_ref);

        Ok(FileSnapshot {
            path: path.to_path_buf(),
            identity: FileIdentity {
                inode: meta.ino(),
                device: meta.dev(),
                file_type,
                symlink_target,
            },
            content: ContentFingerprint {
                hash,
                size: meta.len(),
            },
            permissions: PermissionState {
                mode: meta.mode(),
                owner_uid: meta.uid(),
                owner_gid: meta.gid(),
                capabilities,
            },
            security: SecurityState {
                xattrs,
                security_context,
            },
            mtime: meta.mtime(),
        })
    }

    /// Capture by opening the path. Used for batch scanning.
    pub fn from_path(path: &Path, opts: &CaptureOpts) -> Result<SnapshotOrDeleted> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SnapshotOrDeleted::Deleted);
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(VigilError::Baseline(format!(
                    "permission denied: {}",
                    path.display()
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let snapshot = Self::from_fd(&file, path, opts)?;
        Ok(SnapshotOrDeleted::Snapshot(snapshot))
    }

    /// Diff this snapshot against a baseline entry. Pure function — no I/O.
    pub fn diff(&self, baseline: &BaselineEntry) -> Vec<Change> {
        let mut changes = Vec::new();

        if self.content.hash != baseline.content.hash {
            changes.push(Change::ContentModified {
                old_hash: baseline.content.hash.clone(),
                new_hash: self.content.hash.clone(),
            });
        }

        if self.permissions.mode != baseline.permissions.mode {
            changes.push(Change::PermissionsChanged {
                old: baseline.permissions.mode,
                new: self.permissions.mode,
            });
        }

        if self.permissions.owner_uid != baseline.permissions.owner_uid
            || self.permissions.owner_gid != baseline.permissions.owner_gid
        {
            changes.push(Change::OwnerChanged {
                old_uid: baseline.permissions.owner_uid,
                new_uid: self.permissions.owner_uid,
                old_gid: baseline.permissions.owner_gid,
                new_gid: self.permissions.owner_gid,
            });
        }

        if self.identity.inode != baseline.identity.inode {
            changes.push(Change::InodeChanged {
                old: baseline.identity.inode,
                new: self.identity.inode,
            });
        }

        if self.identity.file_type != baseline.identity.file_type {
            changes.push(Change::TypeChanged {
                old: baseline.identity.file_type,
                new: self.identity.file_type,
            });
        }

        if self.identity.symlink_target != baseline.identity.symlink_target {
            changes.push(Change::SymlinkTargetChanged {
                old: baseline.identity.symlink_target.clone().unwrap_or_default(),
                new: self.identity.symlink_target.clone().unwrap_or_default(),
            });
        }

        if self.permissions.capabilities != baseline.permissions.capabilities {
            changes.push(Change::CapabilitiesChanged {
                old: baseline.permissions.capabilities.clone(),
                new: self.permissions.capabilities.clone(),
            });
        }

        // Per-key xattr diff
        let all_keys: std::collections::BTreeSet<&String> = self
            .security
            .xattrs
            .keys()
            .chain(baseline.security.xattrs.keys())
            .collect();
        for key in all_keys {
            let old_val = baseline.security.xattrs.get(key);
            let new_val = self.security.xattrs.get(key);
            if old_val != new_val {
                changes.push(Change::XattrChanged {
                    key: key.to_string(),
                    old: old_val.cloned(),
                    new: new_val.cloned(),
                });
            }
        }

        if self.security.security_context != baseline.security.security_context {
            changes.push(Change::SecurityContextChanged {
                old: baseline.security.security_context.clone(),
                new: self.security.security_context.clone(),
            });
        }

        changes
    }

    /// Returns true if this snapshot has security-sensitive capabilities.
    pub fn has_dangerous_capabilities(&self) -> bool {
        self.permissions
            .capabilities
            .as_ref()
            .map(|c| {
                c.contains("cap_setuid")
                    || c.contains("cap_sys_admin")
                    || c.contains("cap_dac_override")
            })
            .unwrap_or(false)
    }
}

/// Read SELinux or AppArmor security context via /proc/self/fd/<fd>.
fn read_security_context_fd(fd_path: &Path) -> String {
    if let Ok(Some(val)) = xattr::get(fd_path, "security.selinux") {
        return String::from_utf8_lossy(&val)
            .trim_end_matches('\0')
            .to_string();
    }

    if let Ok(Some(val)) = xattr::get(fd_path, "security.apparmor") {
        return String::from_utf8_lossy(&val)
            .trim_end_matches('\0')
            .to_string();
    }

    String::new()
}

/// Read capabilities xattr via /proc/self/fd/<fd>.
fn read_capabilities_fd(fd_path: &Path) -> Option<String> {
    xattr::get(fd_path, "security.capability")
        .ok()
        .flatten()
        .map(|v| hex::encode(&v))
}

/// Read all non-system xattrs via /proc/self/fd/<fd> into a BTreeMap.
fn read_xattrs_fd(fd_path: &Path) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    if let Ok(attrs) = xattr::list(fd_path) {
        for attr in attrs {
            let name = attr.to_string_lossy().to_string();
            // Skip security.* (handled separately) and system.* (internal)
            if name.starts_with("system.") {
                continue;
            }
            if let Ok(Some(val)) = xattr::get(fd_path, &attr) {
                result.insert(name, String::from_utf8_lossy(&val).to_string());
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BaselineEntry, BaselineSource};
    use std::path::PathBuf;

    fn make_baseline() -> BaselineEntry {
        BaselineEntry {
            id: None,
            path: PathBuf::from("/etc/passwd"),
            identity: FileIdentity {
                inode: 100,
                device: 1,
                file_type: FileType::Regular,
                symlink_target: None,
            },
            content: ContentFingerprint {
                hash: "abc123".into(),
                size: 1024,
            },
            permissions: PermissionState {
                mode: 0o644,
                owner_uid: 0,
                owner_gid: 0,
                capabilities: None,
            },
            security: SecurityState::default(),
            mtime: 1000000,
            package: Some("base".into()),
            source: BaselineSource::AutoScan,
            added_at: 1000000,
            updated_at: 1000000,
        }
    }

    fn make_snapshot(baseline: &BaselineEntry) -> FileSnapshot {
        FileSnapshot {
            path: baseline.path.clone(),
            identity: baseline.identity.clone(),
            content: baseline.content.clone(),
            permissions: baseline.permissions.clone(),
            security: baseline.security.clone(),
            mtime: baseline.mtime,
        }
    }

    #[test]
    fn diff_no_changes() {
        let baseline = make_baseline();
        let snapshot = make_snapshot(&baseline);
        let changes = snapshot.diff(&baseline);
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_content_modified() {
        let baseline = make_baseline();
        let mut snapshot = make_snapshot(&baseline);
        snapshot.content.hash = "def456".into();
        let changes = snapshot.diff(&baseline);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::ContentModified { .. }));
    }

    #[test]
    fn diff_permissions_changed() {
        let baseline = make_baseline();
        let mut snapshot = make_snapshot(&baseline);
        snapshot.permissions.mode = 0o600;
        let changes = snapshot.diff(&baseline);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            Change::PermissionsChanged {
                old: 0o644,
                new: 0o600
            }
        ));
    }

    #[test]
    fn diff_owner_changed() {
        let baseline = make_baseline();
        let mut snapshot = make_snapshot(&baseline);
        snapshot.permissions.owner_uid = 1000;
        let changes = snapshot.diff(&baseline);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::OwnerChanged { .. }));
    }

    #[test]
    fn diff_multiple_changes() {
        let baseline = make_baseline();
        let mut snapshot = make_snapshot(&baseline);
        snapshot.content.hash = "new_hash".into();
        snapshot.permissions.mode = 0o777;
        snapshot.identity.inode = 999;
        let changes = snapshot.diff(&baseline);
        assert_eq!(changes.len(), 3);
    }

    #[test]
    fn has_dangerous_capabilities_detects_setuid() {
        let mut snapshot = make_snapshot(&make_baseline());
        snapshot.permissions.capabilities = Some("cap_setuid+ep".into());
        assert!(snapshot.has_dangerous_capabilities());
    }

    #[test]
    fn has_dangerous_capabilities_none_is_safe() {
        let snapshot = make_snapshot(&make_baseline());
        assert!(!snapshot.has_dangerous_capabilities());
    }
}
