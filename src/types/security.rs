//! Security state: extended attributes and SELinux/AppArmor context.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Security state: extended attributes and MAC security context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SecurityState {
    /// Extended attributes as key-value pairs (NOT a JSON string).
    /// Serialization to JSON happens at the database layer only.
    #[serde(default)]
    pub xattrs: BTreeMap<String, String>,
    /// SELinux or AppArmor security context label.
    #[serde(default)]
    pub security_context: String,
}
