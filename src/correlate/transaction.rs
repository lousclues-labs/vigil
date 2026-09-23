//! Normalized package-manager transactions.
//!
//! APT, dpkg, and snapd record transactions in different shapes. This module
//! flattens them into one structure so the correlation engine has a single
//! thing to reason about, and so a transaction assembled from a test fixture is
//! indistinguishable from one read off a live system.

use serde::Serialize;

use super::error::EvidenceSource;

/// Which local subsystem produced a transaction record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionSource {
    /// An APT run, reconstructed from the apt history log.
    Apt,
    /// A dpkg invocation, reconstructed from the dpkg log. Covers transactions
    /// driven by something other than APT.
    Dpkg,
    /// A snapd change.
    Snap,
}

impl TransactionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dpkg => "dpkg",
            Self::Snap => "snap",
        }
    }

    /// The evidence source this record was read from.
    pub const fn evidence(self) -> EvidenceSource {
        match self {
            Self::Apt => EvidenceSource::AptHistory,
            Self::Dpkg => EvidenceSource::DpkgLog,
            Self::Snap => EvidenceSource::SnapdChanges,
        }
    }
}

impl std::fmt::Display for TransactionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a transaction ended.
///
/// `Unknown` is a real answer and is never upgraded to `Completed` by default.
/// A transaction whose end record is missing did not necessarily finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    /// An explicit successful end record was found.
    Completed,
    /// An explicit error was recorded.
    Failed,
    /// A start record with no end record: the transaction was cut short, or is
    /// still running.
    Interrupted,
    /// No end-state evidence either way.
    Unknown,
}

impl TransactionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Unknown => "unknown",
        }
    }

    /// Only an explicit completion counts. Anything else is a reason to lower
    /// confidence, never a reason to raise it.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a transaction did to one package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageAction {
    Install,
    Upgrade,
    Downgrade,
    Reinstall,
    Remove,
    Purge,
    /// A snap refresh: one revision replaces another.
    Refresh,
}

impl PackageAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Downgrade => "downgrade",
            Self::Reinstall => "reinstall",
            Self::Remove => "remove",
            Self::Purge => "purge",
            Self::Refresh => "refresh",
        }
    }

    /// Whether this action is expected to delete files the old version owned.
    pub const fn removes_files(self) -> bool {
        matches!(self, Self::Remove | Self::Purge | Self::Refresh)
    }
}

impl std::fmt::Display for PackageAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One package's version transition inside a transaction.
///
/// For snaps, the version fields carry revisions (`"150"`, `"188"`), which is
/// what snapd's own records use to identify what was replaced.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PackageTransition {
    /// Package or snap name, with any architecture suffix stripped.
    pub name: String,
    pub action: PackageAction,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    /// Whether the package database reports this package in a fully installed
    /// state now. `None` when the installed state could not be read.
    pub installed_complete: Option<bool>,
    /// Locally identifiable origin (an APT repository, or a snap publisher).
    pub origin: Option<String>,
}

impl PackageTransition {
    pub fn new(name: impl Into<String>, action: PackageAction) -> Self {
        Self {
            name: name.into(),
            action,
            old_version: None,
            new_version: None,
            installed_complete: None,
            origin: None,
        }
    }

    pub fn with_versions(
        mut self,
        old: Option<impl Into<String>>,
        new: Option<impl Into<String>>,
    ) -> Self {
        self.old_version = old.map(Into::into);
        self.new_version = new.map(Into::into);
        self
    }

    /// Human-readable version transition, e.g. `1.2 -> 1.3` or `revision 150 -> 188`.
    pub fn version_summary(&self) -> String {
        match (&self.old_version, &self.new_version) {
            (Some(o), Some(n)) => format!("{o} -> {n}"),
            (None, Some(n)) => n.clone(),
            (Some(o), None) => format!("{o} -> (removed)"),
            (None, None) => "(version unrecorded)".to_string(),
        }
    }
}

/// A transaction as recorded by the local package manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionRecord {
    pub source: TransactionSource,
    /// Transaction identifier when the subsystem assigns one (snapd change id).
    pub id: Option<String>,
    /// Unix timestamp of the first record belonging to this transaction.
    pub start: i64,
    /// Unix timestamp of the end record, when there is one.
    pub end: Option<i64>,
    pub status: TransactionStatus,
    /// The command line that drove the transaction, when recorded.
    pub command: Option<String>,
    /// Who authorized it, when the log records it. Never inferred from a
    /// process name.
    pub actor: Option<String>,
    /// Packages touched, sorted by name for deterministic output.
    pub packages: Vec<PackageTransition>,
    /// Errors the transaction itself recorded.
    pub errors: Vec<String>,
}

impl TransactionRecord {
    pub fn new(source: TransactionSource, start: i64) -> Self {
        Self {
            source,
            id: None,
            start,
            end: None,
            status: TransactionStatus::Unknown,
            command: None,
            actor: None,
            packages: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Sort packages by name so equal evidence always yields equal records.
    pub fn normalize(&mut self) {
        self.packages.sort();
        self.packages.dedup();
        self.errors.sort();
        self.errors.dedup();
    }

    /// The transition for `package`, if this transaction touched it.
    pub fn package(&self, name: &str) -> Option<&PackageTransition> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// Whether `timestamp` falls inside the transaction window, widened by
    /// `slack_secs` on both ends.
    ///
    /// The slack absorbs the ordinary gap between a package manager writing its
    /// log line and the filesystem settling, and coarse log timestamps that
    /// only resolve to whole seconds. It is deliberately a parameter rather
    /// than a hidden constant so the caller decides how much benefit of the
    /// doubt to extend.
    pub fn contains(&self, timestamp: i64, slack_secs: i64) -> bool {
        let end = self.end.unwrap_or(self.start);
        timestamp >= self.start - slack_secs && timestamp <= end + slack_secs
    }

    /// Window duration in seconds, when the transaction has an end record.
    pub fn duration_secs(&self) -> Option<i64> {
        self.end.map(|e| (e - self.start).max(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> TransactionRecord {
        let mut r = TransactionRecord::new(TransactionSource::Apt, 1_000);
        r.end = Some(1_010);
        r
    }

    #[test]
    fn window_membership_respects_slack() {
        let r = record();
        assert!(r.contains(1_000, 0));
        assert!(r.contains(1_010, 0));
        assert!(!r.contains(999, 0));
        assert!(!r.contains(1_011, 0));
        assert!(r.contains(995, 5));
        assert!(r.contains(1_015, 5));
        assert!(!r.contains(994, 5));
    }

    #[test]
    fn a_transaction_without_an_end_is_a_point_in_time() {
        let mut r = record();
        r.end = None;
        assert!(r.contains(1_000, 0));
        assert!(!r.contains(1_005, 0));
        assert_eq!(r.duration_secs(), None);
    }

    #[test]
    fn only_completed_counts_as_success() {
        assert!(TransactionStatus::Completed.is_success());
        assert!(!TransactionStatus::Failed.is_success());
        assert!(!TransactionStatus::Interrupted.is_success());
        assert!(!TransactionStatus::Unknown.is_success());
    }

    #[test]
    fn normalize_is_deterministic() {
        let mut a = TransactionRecord::new(TransactionSource::Apt, 1);
        a.packages
            .push(PackageTransition::new("zlib", PackageAction::Upgrade));
        a.packages
            .push(PackageTransition::new("acl", PackageAction::Upgrade));
        a.normalize();

        let mut b = TransactionRecord::new(TransactionSource::Apt, 1);
        b.packages
            .push(PackageTransition::new("acl", PackageAction::Upgrade));
        b.packages
            .push(PackageTransition::new("zlib", PackageAction::Upgrade));
        b.normalize();

        assert_eq!(a, b);
        assert_eq!(a.packages[0].name, "acl");
    }

    #[test]
    fn version_summary_states_what_is_known() {
        let t = PackageTransition::new("ghostscript", PackageAction::Upgrade)
            .with_versions(Some("9.55"), Some("9.56"));
        assert_eq!(t.version_summary(), "9.55 -> 9.56");

        let unknown = PackageTransition::new("x", PackageAction::Upgrade);
        assert_eq!(unknown.version_summary(), "(version unrecorded)");
    }
}
