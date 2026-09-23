//! Inode identity: device, inode number, file type, symlink target.
//!
//! # Symlink object versus symlink target
//!
//! For a symlink, four things can change independently and this struct keeps
//! them apart:
//!
//! - **Link text** (`link_text`): the raw bytes `readlink(2)` returns. Changing
//!   `../a` to `../b` is a link-text change even when both resolve alike.
//! - **Link object identity** (`link_inode` / `link_device`): the `lstat(2)`
//!   identity of the symlink itself. A new inode here means the symlink was
//!   unlinked and recreated.
//! - **Canonical target** (`symlink_target`): where the link resolves after the
//!   whole chain is followed. `None` means it does not resolve (broken link or
//!   a loop).
//! - **Target identity/content** (`inode`, `device`, and the entry's
//!   `ContentFingerprint`): the file the link resolves to. These come from a
//!   followed `stat`, so they change when the *target* is replaced even though
//!   the symlink object never moved.
//!
//! Keeping the first two separate from the last is what lets Vigil report a
//! package-replaced unit file once, with its `/etc/systemd` symlinks listed as
//! aliases, instead of reporting each alias as an independent replacement.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Immutable properties of an inode -- identity that does not change
/// unless the file is replaced (unlink + create).
///
/// The `link_*` fields are populated for symlinks only, and only by baselines
/// written since symlink object tracking landed. They are `None` on entries
/// carried over from an older baseline; comparison logic must treat `None` as
/// "unknown", never as "unchanged".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileIdentity {
    pub inode: u64,
    pub device: u64,
    pub file_type: FileType,
    /// Canonical target of a symlink, fully resolved. `None` when the link does
    /// not resolve (broken link or symlink loop) or when this is not a symlink.
    pub symlink_target: Option<PathBuf>,
    /// Raw `readlink(2)` text of the symlink object, unresolved.
    #[serde(default)]
    pub link_text: Option<PathBuf>,
    /// `lstat(2)` inode of the symlink object itself (not its target).
    #[serde(default)]
    pub link_inode: Option<u64>,
    /// `lstat(2)` device of the symlink object itself (not its target).
    #[serde(default)]
    pub link_device: Option<u64>,
}

impl Default for FileIdentity {
    fn default() -> Self {
        Self {
            inode: 0,
            device: 0,
            file_type: FileType::Regular,
            symlink_target: None,
            link_text: None,
            link_inode: None,
            link_device: None,
        }
    }
}

impl FileIdentity {
    /// Whether the symlink object itself is known to be unchanged relative to
    /// `other`: same link text and same `lstat` identity.
    ///
    /// Returns `false` when either side lacks the link fields. An entry written
    /// before symlink object tracking existed carries no link data, and absence
    /// of evidence is not evidence of sameness.
    pub fn symlink_object_unchanged(&self, other: &Self) -> bool {
        if self.file_type != FileType::Symlink || other.file_type != FileType::Symlink {
            return false;
        }
        let (Some(a_text), Some(b_text)) = (&self.link_text, &other.link_text) else {
            return false;
        };
        let (Some(a_ino), Some(b_ino)) = (self.link_inode, other.link_inode) else {
            return false;
        };
        let (Some(a_dev), Some(b_dev)) = (self.link_device, other.link_device) else {
            return false;
        };
        a_text == b_text && a_ino == b_ino && a_dev == b_dev
    }

    /// True when this entry carries the symlink object fields needed to tell a
    /// link-object change apart from a target change.
    pub fn has_link_object_data(&self) -> bool {
        self.link_text.is_some() && self.link_inode.is_some() && self.link_device.is_some()
    }
}

/// Filesystem object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    Regular,
    Symlink,
    Directory,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Regular => write!(f, "regular"),
            FileType::Symlink => write!(f, "symlink"),
            FileType::Directory => write!(f, "directory"),
        }
    }
}

impl std::str::FromStr for FileType {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "regular" | "file" => Ok(FileType::Regular),
            "symlink" => Ok(FileType::Symlink),
            "directory" | "dir" => Ok(FileType::Directory),
            _ => Err(format!("unknown file type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_display_roundtrip() {
        for ft in &[FileType::Regular, FileType::Symlink, FileType::Directory] {
            let s = ft.to_string();
            let parsed: FileType = s.parse().expect("should parse");
            assert_eq!(*ft, parsed);
        }
    }

    #[test]
    fn file_type_serde_roundtrip() {
        let ft = FileType::Symlink;
        let json = serde_json::to_string(&ft).unwrap();
        assert_eq!(json, "\"symlink\"");
        let parsed: FileType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, FileType::Symlink);
    }

    #[test]
    fn file_identity_serde_roundtrip() {
        let id = FileIdentity {
            inode: 12345,
            device: 1,
            file_type: FileType::Regular,
            symlink_target: None,
            link_text: None,
            link_inode: None,
            link_device: None,
        };
        let json = serde_json::to_string(&id).unwrap();
        let parsed: FileIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    /// Identity JSON written before symlink object tracking existed must still
    /// deserialize. The link fields default to `None`.
    #[test]
    fn file_identity_deserializes_pre_link_field_json() {
        let legacy =
            r#"{"inode":99,"device":2,"file_type":"symlink","symlink_target":"/etc/real"}"#;
        let parsed: FileIdentity = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.inode, 99);
        assert_eq!(parsed.symlink_target, Some(PathBuf::from("/etc/real")));
        assert_eq!(parsed.link_text, None);
        assert_eq!(parsed.link_inode, None);
        assert_eq!(parsed.link_device, None);
        assert!(!parsed.has_link_object_data());
    }

    fn symlink_identity(text: &str, ino: u64) -> FileIdentity {
        FileIdentity {
            inode: 500,
            device: 1,
            file_type: FileType::Symlink,
            symlink_target: Some(PathBuf::from("/lib/systemd/system/rsyslog.service")),
            link_text: Some(PathBuf::from(text)),
            link_inode: Some(ino),
            link_device: Some(1),
        }
    }

    #[test]
    fn symlink_object_unchanged_when_text_and_inode_match() {
        let a = symlink_identity("/lib/systemd/system/rsyslog.service", 42);
        let mut b = symlink_identity("/lib/systemd/system/rsyslog.service", 42);
        // Target got a new inode; the link object did not move.
        b.inode = 999;
        assert!(a.symlink_object_unchanged(&b));
    }

    #[test]
    fn symlink_object_changed_when_link_text_differs() {
        let a = symlink_identity("/lib/systemd/system/rsyslog.service", 42);
        let b = symlink_identity("/tmp/evil.service", 42);
        assert!(!a.symlink_object_unchanged(&b));
    }

    #[test]
    fn symlink_object_changed_when_link_inode_differs() {
        let a = symlink_identity("/lib/systemd/system/rsyslog.service", 42);
        let b = symlink_identity("/lib/systemd/system/rsyslog.service", 43);
        assert!(!a.symlink_object_unchanged(&b));
    }

    /// Absence of link data is not evidence that the link object is unchanged.
    #[test]
    fn symlink_object_unchanged_is_false_without_link_data() {
        let a = symlink_identity("/lib/systemd/system/rsyslog.service", 42);
        let mut legacy = a.clone();
        legacy.link_text = None;
        legacy.link_inode = None;
        legacy.link_device = None;
        assert!(!a.symlink_object_unchanged(&legacy));
        assert!(!legacy.symlink_object_unchanged(&a));
    }

    #[test]
    fn symlink_object_unchanged_is_false_for_non_symlinks() {
        let mut a = symlink_identity("/lib/systemd/system/rsyslog.service", 42);
        let mut b = a.clone();
        a.file_type = FileType::Regular;
        b.file_type = FileType::Regular;
        assert!(!a.symlink_object_unchanged(&b));
    }
}
