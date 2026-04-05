use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::PathBuf;

use crate::types::Severity;

/// A fully formed alert ready for dispatch to output channels.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub version: u32,
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub severity: Severity,
    pub change_type: String,
    pub file: AlertFileInfo,
    pub context: AlertContext,
}

/// File information included in an alert.
#[derive(Debug, Clone, Serialize)]
pub struct AlertFileInfo {
    pub path: PathBuf,
    pub changes_json: String,
    pub package: Option<String>,
    pub package_update: bool,
    pub responsible_pid: Option<u32>,
    pub responsible_exe: Option<String>,
}

/// Alert context (hostname, group, maintenance state).
#[derive(Debug, Clone, Serialize)]
pub struct AlertContext {
    pub hostname: String,
    pub monitored_group: String,
    pub maintenance_window: bool,
}
