use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::types::{
    BaselineSource, ContentFingerprint, FileIdentity, PermissionState, SecurityState,
};

/// A baseline entry representing the trusted state of a monitored file.
/// Stored in baseline.db with JSON blob columns for sub-structs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub id: Option<i64>,
    pub path: PathBuf,
    pub identity: FileIdentity,
    pub content: ContentFingerprint,
    pub permissions: PermissionState,
    pub security: SecurityState,
    pub mtime: i64,
    pub package: Option<String>,
    pub source: BaselineSource,
    pub added_at: i64,
    pub updated_at: i64,
}
