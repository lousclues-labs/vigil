//! Runtime enums: DaemonState, Severity, ScanMode, MonitorBackend.

use serde::{Deserialize, Serialize};
use std::fmt;

use chrono::{DateTime, Utc};

// ── Daemon State ───────────────────────────────────────────

/// Why the daemon is in a degraded state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DegradedReason {
    BaselineDbReplaced,
    AuditDbReplaced,
    WalFileReplaced,
    EventBackpressure,
    EventLossDetected {
        drop_delta: u64,
        threshold: u64,
    },
    ClockSkewDetected {
        skew_secs: i64,
    },
    FanotifyMarkFailed {
        mount: std::path::PathBuf,
    },
    FanotifyReadFailed,
    WorkerDbUnrecoverable,
    BaselineHmacMismatch,
    FanotifyQueueOverflow,
    AuditLogFull,
    RetentionPolicyMismatch {
        skipped_count: u32,
        retention_days: u32,
        would_delete_pct: u8,
    },
    /// VIGIL-VULN-075: User-space event channel saturated, compensating scan triggered.
    UserspaceEventDrops {
        dropped: u64,
        window_secs: u64,
    },
}

impl std::fmt::Display for DegradedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DegradedReason::BaselineDbReplaced => write!(f, "baseline_db_replaced"),
            DegradedReason::AuditDbReplaced => write!(f, "audit_db_replaced"),
            DegradedReason::WalFileReplaced => write!(f, "wal_file_replaced"),
            DegradedReason::EventBackpressure => write!(f, "event_backpressure"),
            DegradedReason::EventLossDetected {
                drop_delta,
                threshold,
            } => write!(
                f,
                "event_loss_detected (drop_delta={}, threshold={})",
                drop_delta, threshold
            ),
            DegradedReason::ClockSkewDetected { skew_secs } => {
                write!(f, "clock_skew_detected (skew={}s)", skew_secs)
            }
            DegradedReason::FanotifyMarkFailed { mount } => {
                write!(f, "fanotify_mark_failed ({})", mount.display())
            }
            DegradedReason::FanotifyReadFailed => write!(f, "fanotify_read_failed"),
            DegradedReason::WorkerDbUnrecoverable => write!(f, "worker_db_unrecoverable"),
            DegradedReason::BaselineHmacMismatch => write!(f, "baseline_hmac_mismatch"),
            DegradedReason::FanotifyQueueOverflow => write!(f, "fanotify_queue_overflow"),
            DegradedReason::AuditLogFull => write!(f, "audit_log_full"),
            DegradedReason::RetentionPolicyMismatch {
                skipped_count,
                retention_days,
                would_delete_pct,
            } => write!(
                f,
                "retention_policy_mismatch (skipped={}, retention={}d, would_delete={}%)",
                skipped_count, retention_days, would_delete_pct
            ),
            DegradedReason::UserspaceEventDrops {
                dropped,
                window_secs,
            } => write!(
                f,
                "userspace_event_drops (dropped={}, window={}s)",
                dropped, window_secs
            ),
        }
    }
}

/// Tracks whether the daemon is operating normally or in a degraded state.
#[derive(Debug, Clone)]
pub enum DaemonState {
    Healthy,
    Degraded {
        reason: DegradedReason,
        since: DateTime<Utc>,
    },
}

/// Thread-safe handle for reading and transitioning daemon state.
/// Wraps the shared RwLock and provides typed transition methods.
#[derive(Clone)]
pub struct DaemonStateHandle(pub std::sync::Arc<parking_lot::RwLock<DaemonState>>);

impl Default for DaemonStateHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonStateHandle {
    pub fn new() -> Self {
        Self(std::sync::Arc::new(parking_lot::RwLock::new(
            DaemonState::Healthy,
        )))
    }

    /// Transition to Degraded if currently Healthy. Returns true if the
    /// transition happened.
    pub fn degrade_if_healthy(&self, reason: DegradedReason) -> bool {
        let mut guard = self.0.write();
        if matches!(*guard, DaemonState::Healthy) {
            *guard = DaemonState::Degraded {
                reason,
                since: Utc::now(),
            };
            true
        } else {
            false
        }
    }

    /// Recover to Healthy if currently Degraded for the given reason.
    /// Returns true if recovery happened.
    pub fn recover_if_degraded_for(&self, match_fn: impl Fn(&DegradedReason) -> bool) -> bool {
        let mut guard = self.0.write();
        if let DaemonState::Degraded { reason, .. } = &*guard {
            if match_fn(reason) {
                *guard = DaemonState::Healthy;
                return true;
            }
        }
        false
    }

    /// Take a snapshot of the current state.
    pub fn snapshot(&self) -> DaemonState {
        self.0.read().clone()
    }

    /// Read-lock access to the underlying RwLock.
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, DaemonState> {
        self.0.read()
    }

    /// Write-lock access to the underlying RwLock.
    pub fn write(&self) -> parking_lot::RwLockWriteGuard<'_, DaemonState> {
        self.0.write()
    }
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

    /// Schema stability test: DegradedReason Display strings must not change
    /// because downstream consumers of state.json parse them.
    #[test]
    fn degraded_reason_display_schema_stability() {
        let cases = vec![
            (DegradedReason::BaselineDbReplaced, "baseline_db_replaced"),
            (DegradedReason::AuditDbReplaced, "audit_db_replaced"),
            (DegradedReason::WalFileReplaced, "wal_file_replaced"),
            (DegradedReason::EventBackpressure, "event_backpressure"),
            (
                DegradedReason::EventLossDetected {
                    drop_delta: 100,
                    threshold: 10,
                },
                "event_loss_detected (drop_delta=100, threshold=10)",
            ),
            (
                DegradedReason::ClockSkewDetected { skew_secs: 42 },
                "clock_skew_detected (skew=42s)",
            ),
            (DegradedReason::FanotifyReadFailed, "fanotify_read_failed"),
            (
                DegradedReason::WorkerDbUnrecoverable,
                "worker_db_unrecoverable",
            ),
            (
                DegradedReason::BaselineHmacMismatch,
                "baseline_hmac_mismatch",
            ),
            (
                DegradedReason::FanotifyQueueOverflow,
                "fanotify_queue_overflow",
            ),
            (DegradedReason::AuditLogFull, "audit_log_full"),
            (
                DegradedReason::RetentionPolicyMismatch {
                    skipped_count: 3,
                    retention_days: 7,
                    would_delete_pct: 80,
                },
                "retention_policy_mismatch (skipped=3, retention=7d, would_delete=80%)",
            ),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                reason.to_string(),
                expected,
                "DegradedReason::Display schema changed for {:?}",
                reason
            );
        }
    }
}
