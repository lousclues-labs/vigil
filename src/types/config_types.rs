use serde::{Deserialize, Serialize};
use std::fmt;

use chrono::{DateTime, Utc};

// ── Daemon State ───────────────────────────────────────────

/// Tracks whether the daemon is operating normally or in a degraded state.
#[derive(Debug, Clone)]
pub enum DaemonState {
    Healthy,
    Degraded {
        reason: String,
        since: DateTime<Utc>,
    },
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

// ── Monitor Backend ────────────────────────────────────────

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
    Brief,
}

// ── Scan Mode ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Incremental,
    Full,
}

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanMode::Incremental => write!(f, "incremental"),
            ScanMode::Full => write!(f, "full"),
        }
    }
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
    fn severity_serde_json_roundtrip() {
        let sev = Severity::Critical;
        let json = serde_json::to_string(&sev).unwrap();
        assert_eq!(json, "\"critical\"");
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Severity::Critical);
    }
}
