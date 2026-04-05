use serde::{Deserialize, Serialize};

/// Permission state of a file — mode bits, ownership, and Linux capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionState {
    pub mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    /// Raw security.capability xattr hex, if present.
    #[serde(default)]
    pub capabilities: Option<String>,
}
