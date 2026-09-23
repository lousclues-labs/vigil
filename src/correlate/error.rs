//! Structured failures from evidence collectors.
//!
//! Principle: fail visibly. A collector that could not read a log, could not
//! run a tool, or could not make sense of what it read must say so in a form
//! the presenter can show the operator. Nothing here is ever swallowed into a
//! success-shaped default, because "we could not check" and "we checked and it
//! was fine" are opposite statements.

use serde::Serialize;

/// A local source of evidence used to explain raw detections.
///
/// Every source is on this machine. Correlation never contacts a network
/// service, and no path, hash, or package name leaves the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// `/var/log/apt/history.log` and its rotations.
    AptHistory,
    /// `/var/log/dpkg.log` and its rotations.
    DpkgLog,
    /// `/var/lib/dpkg/status`: installed state and conffile digests.
    DpkgStatus,
    /// File-to-package ownership from the local package database.
    PackageOwnership,
    /// Per-package content verification (dpkg md5sums, `rpm -V`, `pacman -Qkk`).
    PackageVerification,
    /// snapd change/task history.
    SnapdChanges,
    /// On-disk snap revision state: current revision links and mount units.
    SnapdRevisionState,
    /// Locally configured repository/publisher metadata.
    RepositoryMetadata,
    /// Filesystem timestamps of the changed paths themselves.
    FilesystemTimestamps,
}

impl EvidenceSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AptHistory => "apt history log",
            Self::DpkgLog => "dpkg log",
            Self::DpkgStatus => "dpkg status database",
            Self::PackageOwnership => "package ownership",
            Self::PackageVerification => "package verification",
            Self::SnapdChanges => "snapd change history",
            Self::SnapdRevisionState => "snap revision state",
            Self::RepositoryMetadata => "repository metadata",
            Self::FilesystemTimestamps => "filesystem timestamps",
        }
    }
}

impl std::fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a collector could not produce evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorErrorKind {
    /// The log, database, or tool is not present on this system.
    Unavailable,
    /// Present but unreadable with current privileges.
    PermissionDenied,
    /// Present and readable but not parseable.
    Parse,
    /// Readable but incomplete: rotated away, size-capped, or cut mid-record.
    Truncated,
    /// A subprocess exceeded its time budget.
    Timeout,
    /// Sources disagree with each other.
    Inconsistent,
}

impl CollectorErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::PermissionDenied => "permission denied",
            Self::Parse => "parse error",
            Self::Truncated => "truncated",
            Self::Timeout => "timeout",
            Self::Inconsistent => "inconsistent",
        }
    }

    /// Whether this failure means privileges, rather than absence, blocked the
    /// read. Reported separately so the operator knows a re-run with more
    /// privilege would answer the question.
    pub const fn is_privilege_problem(self) -> bool {
        matches!(self, Self::PermissionDenied)
    }
}

impl std::fmt::Display for CollectorErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single collector failure, carried through to presentation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CollectorError {
    pub source: EvidenceSource,
    pub kind: CollectorErrorKind,
    /// Operator-facing detail. Built from local state only.
    pub detail: String,
}

impl CollectorError {
    pub fn new(
        source: EvidenceSource,
        kind: CollectorErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            source,
            kind,
            detail: detail.into(),
        }
    }

    pub fn unavailable(source: EvidenceSource, detail: impl Into<String>) -> Self {
        Self::new(source, CollectorErrorKind::Unavailable, detail)
    }

    pub fn parse(source: EvidenceSource, detail: impl Into<String>) -> Self {
        Self::new(source, CollectorErrorKind::Parse, detail)
    }

    pub fn truncated(source: EvidenceSource, detail: impl Into<String>) -> Self {
        Self::new(source, CollectorErrorKind::Truncated, detail)
    }

    /// Classify an I/O failure without losing the distinction between "absent"
    /// and "present but forbidden".
    pub fn from_io(source: EvidenceSource, path: &std::path::Path, e: &std::io::Error) -> Self {
        let kind = match e.kind() {
            std::io::ErrorKind::NotFound => CollectorErrorKind::Unavailable,
            std::io::ErrorKind::PermissionDenied => CollectorErrorKind::PermissionDenied,
            _ => CollectorErrorKind::Parse,
        };
        Self::new(source, kind, format!("{}: {}", path.display(), e))
    }
}

impl std::fmt::Display for CollectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.source, self.kind, self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn io_errors_keep_absence_and_permission_apart() {
        let missing = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let forbidden = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");

        let a = CollectorError::from_io(EvidenceSource::AptHistory, Path::new("/x"), &missing);
        let b = CollectorError::from_io(EvidenceSource::AptHistory, Path::new("/x"), &forbidden);

        assert_eq!(a.kind, CollectorErrorKind::Unavailable);
        assert_eq!(b.kind, CollectorErrorKind::PermissionDenied);
        assert!(!a.kind.is_privilege_problem());
        assert!(b.kind.is_privilege_problem());
    }

    #[test]
    fn errors_render_with_source_and_kind() {
        let e = CollectorError::truncated(EvidenceSource::DpkgLog, "rotated away");
        assert_eq!(e.to_string(), "dpkg log [truncated]: rotated away");
    }
}
