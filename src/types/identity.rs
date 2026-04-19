//! Inode identity: device, inode number, file type, symlink target.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Immutable properties of an inode -- identity that does not change
/// unless the file is replaced (unlink + create).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileIdentity {
    pub inode: u64,
    pub device: u64,
    pub file_type: FileType,
    pub symlink_target: Option<PathBuf>,
}

impl Default for FileIdentity {
    fn default() -> Self {
        Self {
            inode: 0,
            device: 0,
            file_type: FileType::Regular,
            symlink_target: None,
        }
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
        };
        let json = serde_json::to_string(&id).unwrap();
        let parsed: FileIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }
}
