use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

// ── Daemon State ───────────────────────────────────────────

/// Tracks whether the daemon is operating normally or in a degraded state.
#[derive(Debug, Clone)]
pub enum DaemonState {
    Healthy,
    Degraded { reason: String, since: DateTime<Utc> },
}

// ── Severity ────────────────────────────────────────────────

/// Alert severity levels, ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!("unknown severity: {}", s)),
        }
    }
}

// ── Change Type ────────────────────────────────────────────

/// Types of changes detected on monitored files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Modified,
    Deleted,
    Created,
    PermissionsChanged,
    OwnerChanged,
    InodeChanged,
    XattrChanged,
    SecurityContextChanged,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangeType::Modified => write!(f, "modified"),
            ChangeType::Deleted => write!(f, "deleted"),
            ChangeType::Created => write!(f, "created"),
            ChangeType::PermissionsChanged => write!(f, "permissions_changed"),
            ChangeType::OwnerChanged => write!(f, "owner_changed"),
            ChangeType::InodeChanged => write!(f, "inode_changed"),
            ChangeType::XattrChanged => write!(f, "xattr_changed"),
            ChangeType::SecurityContextChanged => write!(f, "security_context_changed"),
        }
    }
}

// ── Baseline Source ────────────────────────────────────────

/// How a baseline entry was added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineSource {
    PackageManager,
    Manual,
    AutoScan,
}

impl fmt::Display for BaselineSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaselineSource::PackageManager => write!(f, "package_manager"),
            BaselineSource::Manual => write!(f, "manual"),
            BaselineSource::AutoScan => write!(f, "auto_scan"),
        }
    }
}

impl std::str::FromStr for BaselineSource {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "package_manager" => Ok(BaselineSource::PackageManager),
            "manual" => Ok(BaselineSource::Manual),
            "auto_scan" => Ok(BaselineSource::AutoScan),
            _ => Err(format!("unknown baseline source: {}", s)),
        }
    }
}

// ── Baseline Entry ─────────────────────────────────────────

/// A single baseline entry representing the trusted state of a monitored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub id: Option<i64>,
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub permissions: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mtime: i64,
    pub inode: u64,
    pub device: u64,
    pub xattrs: String,
    pub security_context: String,
    pub package: Option<String>,
    pub source: BaselineSource,
    pub added_at: i64,
    pub updated_at: i64,
}

// ── File Metadata ──────────────────────────────────────────

/// Current observed state of a file on disk.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub permissions: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mtime: i64,
    pub inode: u64,
    pub device: u64,
    pub xattrs: String,
    pub security_context: String,
}

// ── Change Result ──────────────────────────────────────────

/// The result of comparing a file's current state to its baseline.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeResult {
    pub path: PathBuf,
    pub change_types: Vec<ChangeType>,
    pub severity: Severity,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub old_permissions: Option<u32>,
    pub new_permissions: Option<u32>,
    pub old_owner_uid: Option<u32>,
    pub new_owner_uid: Option<u32>,
    pub old_owner_gid: Option<u32>,
    pub new_owner_gid: Option<u32>,
    pub old_inode: Option<u64>,
    pub new_inode: Option<u64>,
    pub old_mtime: Option<i64>,
    pub new_mtime: Option<i64>,
    pub package: Option<String>,
    pub package_update: bool,
    pub monitored_group: String,
}

// ── Alert ──────────────────────────────────────────────────

/// A fully formed alert ready for dispatch to output channels.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub version: u32,
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub severity: Severity,
    pub change_type: ChangeType,
    pub file: AlertFileInfo,
    pub context: AlertContext,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertFileInfo {
    pub path: PathBuf,
    pub baseline_hash: Option<String>,
    pub current_hash: Option<String>,
    pub baseline_size: Option<u64>,
    pub current_size: Option<u64>,
    pub baseline_permissions: Option<String>,
    pub current_permissions: Option<String>,
    pub baseline_owner: Option<String>,
    pub current_owner: Option<String>,
    pub inode_changed: bool,
    pub mtime_changed: bool,
    pub package: Option<String>,
    pub package_update: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertContext {
    pub hostname: String,
    pub monitored_group: String,
    pub maintenance_window: bool,
}

// ── Monitor Backend ────────────────────────────────────────

/// Which filesystem monitoring backend is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MonitorBackend {
    Fanotify,
    Inotify,
}

impl fmt::Display for MonitorBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MonitorBackend::Fanotify => write!(f, "fanotify"),
            MonitorBackend::Inotify => write!(f, "inotify"),
        }
    }
}

// ── Raw filesystem event ───────────────────────────────────

/// A raw filesystem event from fanotify or inotify before filtering.
#[derive(Debug, Clone)]
pub struct FsEvent {
    pub path: PathBuf,
    pub event_type: FsEventType,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsEventType {
    Modify,
    Attrib,
    Create,
    Delete,
    MovedFrom,
    MovedTo,
}

// ── Package Manager Backend ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageBackend {
    Auto,
    Dpkg,
    Rpm,
    Pacman,
}

impl fmt::Display for PackageBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageBackend::Auto => write!(f, "auto"),
            PackageBackend::Dpkg => write!(f, "dpkg"),
            PackageBackend::Rpm => write!(f, "rpm"),
            PackageBackend::Pacman => write!(f, "pacman"),
        }
    }
}

// ── Output Format ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Table,
}

// ── Scan Mode ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Incremental,
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_display_roundtrip() {
        for sev in &[
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let s = sev.to_string();
            let parsed: Severity = s.parse().unwrap();
            assert_eq!(*sev, parsed);
        }
    }

    #[test]
    fn severity_parse_case_insensitive() {
        assert_eq!("LOW".parse::<Severity>().unwrap(), Severity::Low);
        assert_eq!("Critical".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("MEDIUM".parse::<Severity>().unwrap(), Severity::Medium);
    }

    #[test]
    fn severity_parse_invalid() {
        assert!("unknown".parse::<Severity>().is_err());
        assert!("".parse::<Severity>().is_err());
    }

    #[test]
    fn change_type_display() {
        assert_eq!(ChangeType::Modified.to_string(), "modified");
        assert_eq!(ChangeType::Deleted.to_string(), "deleted");
        assert_eq!(ChangeType::Created.to_string(), "created");
        assert_eq!(
            ChangeType::PermissionsChanged.to_string(),
            "permissions_changed"
        );
        assert_eq!(ChangeType::OwnerChanged.to_string(), "owner_changed");
        assert_eq!(ChangeType::InodeChanged.to_string(), "inode_changed");
        assert_eq!(ChangeType::XattrChanged.to_string(), "xattr_changed");
        assert_eq!(
            ChangeType::SecurityContextChanged.to_string(),
            "security_context_changed"
        );
    }

    #[test]
    fn baseline_source_display_roundtrip() {
        for src in &[
            BaselineSource::PackageManager,
            BaselineSource::Manual,
            BaselineSource::AutoScan,
        ] {
            let s = src.to_string();
            let parsed: BaselineSource = s.parse().unwrap();
            assert_eq!(*src, parsed);
        }
    }

    #[test]
    fn baseline_source_parse_invalid() {
        assert!("unknown".parse::<BaselineSource>().is_err());
    }

    #[test]
    fn severity_serde_json_roundtrip() {
        let sev = Severity::Critical;
        let json = serde_json::to_string(&sev).unwrap();
        assert_eq!(json, "\"critical\"");
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Severity::Critical);
    }

    #[test]
    fn change_type_serde_json_roundtrip() {
        let ct = ChangeType::PermissionsChanged;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"permissions_changed\"");
        let parsed: ChangeType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ChangeType::PermissionsChanged);
    }

    #[test]
    fn security_context_changed_serde_roundtrip() {
        let ct = ChangeType::SecurityContextChanged;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"security_context_changed\"");
        let parsed: ChangeType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ChangeType::SecurityContextChanged);
    }

    #[test]
    fn monitor_backend_display() {
        assert_eq!(MonitorBackend::Fanotify.to_string(), "fanotify");
        assert_eq!(MonitorBackend::Inotify.to_string(), "inotify");
    }

    #[test]
    fn package_backend_display() {
        assert_eq!(PackageBackend::Pacman.to_string(), "pacman");
        assert_eq!(PackageBackend::Dpkg.to_string(), "dpkg");
        assert_eq!(PackageBackend::Rpm.to_string(), "rpm");
        assert_eq!(PackageBackend::Auto.to_string(), "auto");
    }
}
