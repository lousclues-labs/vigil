//! The derived correlation event.
//!
//! A [`CorrelatedEvent`] is an *explanation*, not an observation. It references
//! raw detections by identity and never contains, replaces, or edits them. Raw
//! severity is carried through untouched; the event adds a separate dimension
//! ("what explains this, and how well") alongside it.
//!
//! Nothing here participates in baseline verification. Correlation is not an
//! input to the HMAC chain, to baseline signing, or to acceptance decisions.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::package::PackageVerification;
use crate::types::Severity;

use super::error::{CollectorError, EvidenceSource};
use super::transaction::{PackageTransition, TransactionRecord, TransactionStatus};

/// What kind of causal event this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// An APT or dpkg transaction.
    AptTransaction,
    /// A snapd change, typically a refresh.
    SnapRefresh,
    /// Changes that clearly arrived together but that no transaction explains.
    UnknownBatch,
}

impl EventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AptTransaction => "apt transaction",
            Self::SnapRefresh => "snap refresh",
            Self::UnknownBatch => "unexplained batch",
        }
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How well the evidence explains the raw detections in an event.
///
/// Deliberately absent: any value meaning "safe". The strongest statement this
/// vocabulary can make is that independent local records consistently attribute
/// the changes to a package transaction. That is a claim about *provenance*,
/// not about whether the delivered software is benign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Independent local sources agree, and content verification passed for
    /// every member that the package manager holds a digest for.
    VerifiedTransaction,
    /// The transaction matches on timing, ownership, and versions, but content
    /// verification was unavailable or only partially covered.
    StronglyCorrelated,
    /// A transaction explains some members; others are not accounted for.
    PartiallyExplained,
    /// A transaction is suspected but the supporting evidence is missing.
    Unverified,
    /// Sources contradict each other, or verification actively failed.
    ConflictingEvidence,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedTransaction => "verified package transaction",
            Self::StronglyCorrelated => "strongly correlated",
            Self::PartiallyExplained => "partially explained",
            Self::Unverified => "unverified",
            Self::ConflictingEvidence => "conflicting evidence",
        }
    }

    /// Short label for dense output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::VerifiedTransaction => "VERIFIED",
            Self::StronglyCorrelated => "CORRELATED",
            Self::PartiallyExplained => "PARTIAL",
            Self::Unverified => "UNVERIFIED",
            Self::ConflictingEvidence => "CONFLICTING",
        }
    }

    /// Ordering for presentation: the events an operator most needs to look at
    /// sort first. Conflicting evidence outranks everything.
    pub const fn attention_rank(self) -> u8 {
        match self {
            Self::ConflictingEvidence => 0,
            Self::Unverified => 1,
            Self::PartiallyExplained => 2,
            Self::StronglyCorrelated => 3,
            Self::VerifiedTransaction => 4,
        }
    }

    /// Whether this confidence level still demands individual review.
    pub const fn needs_investigation(self) -> bool {
        matches!(
            self,
            Self::ConflictingEvidence | Self::Unverified | Self::PartiallyExplained
        )
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of one verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    Failed,
    /// The check could not run. Not a pass.
    Unavailable,
}

impl CheckOutcome {
    /// Marker glyph. Deliberately not a green tick for `Unavailable`.
    pub const fn marker(self) -> &'static str {
        match self {
            Self::Passed => "+",
            Self::Failed => "x",
            Self::Unavailable => "?",
        }
    }
}

/// One named check contributing to an event's confidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct VerificationCheck {
    pub name: String,
    pub outcome: CheckOutcome,
    pub detail: String,
}

impl VerificationCheck {
    pub fn passed(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: CheckOutcome::Passed,
            detail: detail.into(),
        }
    }

    pub fn failed(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: CheckOutcome::Failed,
            detail: detail.into(),
        }
    }

    pub fn unavailable(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: CheckOutcome::Unavailable,
            detail: detail.into(),
        }
    }
}

/// The set of checks performed for an event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VerificationResult {
    pub checks: Vec<VerificationCheck>,
}

impl VerificationResult {
    pub fn push(&mut self, check: VerificationCheck) {
        self.checks.push(check);
    }

    pub fn any_failed(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.outcome == CheckOutcome::Failed)
    }

    pub fn any_unavailable(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.outcome == CheckOutcome::Unavailable)
    }

    pub fn all_passed(&self) -> bool {
        !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|c| c.outcome == CheckOutcome::Passed)
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut passed = 0;
        let mut failed = 0;
        let mut unavailable = 0;
        for c in &self.checks {
            match c.outcome {
                CheckOutcome::Passed => passed += 1,
                CheckOutcome::Failed => failed += 1,
                CheckOutcome::Unavailable => unavailable += 1,
            }
        }
        (passed, failed, unavailable)
    }
}

/// A stable reference to one raw detection.
///
/// This is a *pointer*, not a copy of the detection. `index` identifies the
/// detection's position in the scan it came from; `audit_sequence` carries the
/// audit-log sequence number when correlating records that have already been
/// persisted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RawRef {
    /// Position in the originating scan's change list.
    pub index: usize,
    pub path: PathBuf,
    pub severity: Severity,
    /// Names of the change dimensions observed, in the order detected.
    pub changes: Vec<String>,
    /// Audit-log sequence number, when this detection has been persisted.
    pub audit_sequence: Option<i64>,
}

/// Why a particular raw detection belongs to an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// A file the transaction's package owns.
    PackageFile,
    /// An unchanged symlink whose target the transaction replaced.
    SymlinkAlias,
    /// A systemd unit generated for a snap revision.
    SnapMountUnit,
    /// A `*.target.wants` symlink for a snap mount unit.
    SnapMountSymlink,
    /// Data or state belonging to a snap revision that was cleaned up.
    SnapRevisionData,
}

impl MemberRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PackageFile => "package file",
            Self::SymlinkAlias => "symlink alias",
            Self::SnapMountUnit => "snap mount unit",
            Self::SnapMountSymlink => "snap mount symlink",
            Self::SnapRevisionData => "snap revision data",
        }
    }
}

/// One raw detection attached to an event, with the reasoning that attached it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct EventMember {
    pub raw: RawRef,
    pub role: MemberRole,
    /// Owning package or snap name, when known.
    pub package: Option<String>,
    /// Per-path content verification verdict. Reuses the package module's
    /// vocabulary so "unknown" keeps meaning "we could not check".
    pub verification: PackageVerification,
    /// For a [`MemberRole::SymlinkAlias`], the canonical path it resolves to.
    pub canonical_path: Option<PathBuf>,
}

impl EventMember {
    /// Whether this member's content was positively verified against package
    /// metadata. Delegates to the package module so there is one definition of
    /// proof in the codebase.
    pub fn is_verified(&self) -> bool {
        self.verification.is_proof()
    }
}

/// A raw detection the event could not account for, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct UnexplainedChange {
    pub raw: RawRef,
    /// Why this change is not attributed to the transaction.
    pub reason: String,
}

/// A derived, evidence-backed explanation for a group of raw detections.
///
/// Construct via [`CorrelatedEventBuilder`] so the deterministic identifier is
/// always derived from the same inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CorrelatedEvent {
    /// Deterministic identifier derived from the evidence. The same evidence
    /// always yields the same id, on any machine.
    pub event_id: String,
    pub kind: EventKind,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub transaction_id: Option<String>,
    /// Command line that drove the transaction, when the log recorded one.
    pub command: Option<String>,
    /// Authorizing actor, only when a log records it explicitly.
    pub actor: Option<String>,
    pub packages: Vec<PackageTransition>,
    pub status: TransactionStatus,
    pub verification: VerificationResult,
    pub confidence: Confidence,
    pub members: Vec<EventMember>,
    pub unexplained: Vec<UnexplainedChange>,
    pub collector_errors: Vec<CollectorError>,
    pub evidence_sources: Vec<EvidenceSource>,
}

impl CorrelatedEvent {
    /// Total raw detections attached to this event, explained or not.
    pub fn detection_count(&self) -> usize {
        self.members.len() + self.unexplained.len()
    }

    /// Raw severity counts across all attached detections, most severe first.
    ///
    /// Raw severity is never rewritten by correlation, so these are the same
    /// numbers the ungrouped view shows.
    pub fn raw_severity_counts(&self) -> Vec<(Severity, usize)> {
        self.tally(
            self.members
                .iter()
                .map(|m| m.raw.severity)
                .chain(self.unexplained.iter().map(|u| u.raw.severity)),
        )
    }

    /// Raw severity counts across the detections this event *explains*.
    ///
    /// Distinct from [`Self::raw_severity_counts`], which also counts the
    /// members it failed to explain. A summary that states both in one line
    /// would be counting the unexplained twice, since they are named
    /// separately.
    pub fn member_severity_counts(&self) -> Vec<(Severity, usize)> {
        self.tally(self.members.iter().map(|m| m.raw.severity))
    }

    /// Shared tally so the two counts above cannot disagree about ordering.
    fn tally(&self, severities: impl Iterator<Item = Severity>) -> Vec<(Severity, usize)> {
        let mut counts: std::collections::BTreeMap<Severity, usize> = Default::default();
        for s in severities {
            *counts.entry(s).or_insert(0) += 1;
        }
        counts.into_iter().rev().collect()
    }

    /// Highest raw severity attached to this event.
    pub fn max_raw_severity(&self) -> Option<Severity> {
        self.members
            .iter()
            .map(|m| m.raw.severity)
            .chain(self.unexplained.iter().map(|u| u.raw.severity))
            .max()
    }

    /// Detections grouped by owning package, sorted by name.
    pub fn members_by_package(&self) -> Vec<(String, Vec<&EventMember>)> {
        let mut by_pkg: std::collections::BTreeMap<String, Vec<&EventMember>> = Default::default();
        for m in &self.members {
            let key = m
                .package
                .clone()
                .unwrap_or_else(|| "(unattributed)".to_string());
            by_pkg.entry(key).or_default().push(m);
        }
        by_pkg.into_iter().collect()
    }

    /// Alias members resolving to `target`.
    pub fn aliases_for(&self, target: &Path) -> Vec<&EventMember> {
        self.members
            .iter()
            .filter(|m| {
                m.role == MemberRole::SymlinkAlias && m.canonical_path.as_deref() == Some(target)
            })
            .collect()
    }

    /// Whether every attached detection was attributed to the transaction.
    pub fn fully_explained(&self) -> bool {
        self.unexplained.is_empty() && !self.members.is_empty()
    }
}

/// Builds a [`CorrelatedEvent`] and derives its deterministic identifier.
pub struct CorrelatedEventBuilder {
    kind: EventKind,
    transaction: Option<TransactionRecord>,
    members: Vec<EventMember>,
    unexplained: Vec<UnexplainedChange>,
    verification: VerificationResult,
    collector_errors: Vec<CollectorError>,
    evidence_sources: BTreeSet<EvidenceSource>,
    confidence: Confidence,
}

impl CorrelatedEventBuilder {
    pub fn new(kind: EventKind) -> Self {
        Self {
            kind,
            transaction: None,
            members: Vec::new(),
            unexplained: Vec::new(),
            verification: VerificationResult::default(),
            collector_errors: Vec::new(),
            evidence_sources: BTreeSet::new(),
            confidence: Confidence::Unverified,
        }
    }

    pub fn transaction(mut self, tx: TransactionRecord) -> Self {
        self.evidence_sources.insert(tx.source.evidence());
        self.transaction = Some(tx);
        self
    }

    pub fn member(mut self, member: EventMember) -> Self {
        self.members.push(member);
        self
    }

    pub fn unexplained(mut self, item: UnexplainedChange) -> Self {
        self.unexplained.push(item);
        self
    }

    pub fn check(mut self, check: VerificationCheck) -> Self {
        self.verification.push(check);
        self
    }

    pub fn collector_error(mut self, err: CollectorError) -> Self {
        self.evidence_sources.insert(err.source);
        self.collector_errors.push(err);
        self
    }

    pub fn evidence(mut self, source: EvidenceSource) -> Self {
        self.evidence_sources.insert(source);
        self
    }

    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Finalize the event, sorting every collection and deriving the id.
    pub fn build(mut self) -> CorrelatedEvent {
        self.members.sort();
        self.unexplained.sort();
        self.collector_errors.sort();
        self.collector_errors.dedup();
        self.verification.checks.sort();
        self.verification.checks.dedup();

        let (started_at, completed_at, transaction_id, command, actor, packages, status) =
            match &self.transaction {
                Some(tx) => (
                    Some(tx.start),
                    tx.end,
                    tx.id.clone(),
                    tx.command.clone(),
                    tx.actor.clone(),
                    tx.packages.clone(),
                    tx.status,
                ),
                None => (
                    None,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    TransactionStatus::Unknown,
                ),
            };

        let event_id = derive_event_id(
            self.kind,
            transaction_id.as_deref(),
            started_at,
            completed_at,
            &packages,
            &self.members,
            &self.unexplained,
        );

        CorrelatedEvent {
            event_id,
            kind: self.kind,
            started_at,
            completed_at,
            transaction_id,
            command,
            actor,
            packages,
            status,
            verification: self.verification,
            confidence: self.confidence,
            members: self.members,
            unexplained: self.unexplained,
            collector_errors: self.collector_errors,
            evidence_sources: self.evidence_sources.into_iter().collect(),
        }
    }
}

/// Derive a stable event identifier from the evidence that produced it.
///
/// Deterministic and reproducible: the same evidence yields the same id on any
/// machine, which is what lets an acceptance receipt name the event it acted
/// on. Field lengths are included so distinct inputs cannot be made to collide
/// by moving a separator into a value.
fn derive_event_id(
    kind: EventKind,
    transaction_id: Option<&str>,
    started_at: Option<i64>,
    completed_at: Option<i64>,
    packages: &[PackageTransition],
    members: &[EventMember],
    unexplained: &[UnexplainedChange],
) -> String {
    use std::os::unix::ffi::OsStrExt;

    // Length-prefixed fields so "ab" + "c" cannot hash the same as "a" + "bc".
    fn put(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    let mut hasher = blake3::Hasher::new();
    put(&mut hasher, b"vigil-correlated-event-v1");
    put(&mut hasher, kind.as_str().as_bytes());
    put(&mut hasher, transaction_id.unwrap_or("").as_bytes());
    put(&mut hasher, &started_at.unwrap_or(0).to_le_bytes());
    put(&mut hasher, &completed_at.unwrap_or(0).to_le_bytes());

    put(&mut hasher, &(packages.len() as u64).to_le_bytes());
    for p in packages {
        put(&mut hasher, p.name.as_bytes());
        put(&mut hasher, p.action.as_str().as_bytes());
        put(
            &mut hasher,
            p.old_version.as_deref().unwrap_or("").as_bytes(),
        );
        put(
            &mut hasher,
            p.new_version.as_deref().unwrap_or("").as_bytes(),
        );
    }

    put(&mut hasher, &(members.len() as u64).to_le_bytes());
    for m in members {
        put(&mut hasher, m.raw.path.as_os_str().as_bytes());
        put(&mut hasher, m.role.as_str().as_bytes());
    }

    put(&mut hasher, &(unexplained.len() as u64).to_le_bytes());
    for u in unexplained {
        put(&mut hasher, u.raw.path.as_os_str().as_bytes());
    }

    hasher.finalize().to_hex()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::transaction::{PackageAction, TransactionSource};

    fn raw(index: usize, path: &str, severity: Severity) -> RawRef {
        RawRef {
            index,
            path: PathBuf::from(path),
            severity,
            changes: vec!["content_modified".into()],
            audit_sequence: None,
        }
    }

    fn member(index: usize, path: &str, severity: Severity) -> EventMember {
        EventMember {
            raw: raw(index, path, severity),
            role: MemberRole::PackageFile,
            package: Some("ghostscript".into()),
            verification: PackageVerification::Verified,
            canonical_path: None,
        }
    }

    fn transaction() -> TransactionRecord {
        let mut tx = TransactionRecord::new(TransactionSource::Apt, 1_000);
        tx.end = Some(1_010);
        tx.status = TransactionStatus::Completed;
        tx.packages.push(
            PackageTransition::new("ghostscript", PackageAction::Upgrade)
                .with_versions(Some("9.55"), Some("9.56")),
        );
        tx
    }

    #[test]
    fn event_id_is_deterministic_for_identical_evidence() {
        let build = || {
            CorrelatedEventBuilder::new(EventKind::AptTransaction)
                .transaction(transaction())
                .member(member(0, "/usr/bin/gs", Severity::Critical))
                .member(member(1, "/usr/lib/x.so", Severity::Critical))
                .build()
        };
        assert_eq!(build().event_id, build().event_id);
    }

    /// Member order must not change the identifier: the builder sorts first.
    #[test]
    fn event_id_is_independent_of_member_insertion_order() {
        let a = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .member(member(1, "/usr/lib/x.so", Severity::Critical))
            .build();
        let b = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(1, "/usr/lib/x.so", Severity::Critical))
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .build();
        assert_eq!(a.event_id, b.event_id);
    }

    #[test]
    fn event_id_changes_when_membership_changes() {
        let a = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .build();
        let b = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .member(member(1, "/usr/bin/other", Severity::Critical))
            .build();
        assert_ne!(a.event_id, b.event_id);
    }

    /// Raw severities are reported as observed. Correlation adds a dimension;
    /// it does not rewrite this one.
    #[test]
    fn raw_severity_counts_are_preserved() {
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .member(member(1, "/usr/bin/gs2", Severity::Critical))
            .member(member(2, "/etc/systemd/x", Severity::High))
            .confidence(Confidence::VerifiedTransaction)
            .build();

        let counts = event.raw_severity_counts();
        assert_eq!(counts, vec![(Severity::Critical, 2), (Severity::High, 1)]);
        assert_eq!(event.max_raw_severity(), Some(Severity::Critical));
        assert_eq!(event.detection_count(), 3);
    }

    #[test]
    fn unexplained_members_prevent_full_explanation() {
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .unexplained(UnexplainedChange {
                raw: raw(1, "/usr/bin/evil", Severity::Critical),
                reason: "not owned by any package in the transaction".into(),
            })
            .build();

        assert!(!event.fully_explained());
        assert_eq!(event.detection_count(), 2);
    }

    #[test]
    fn confidence_orders_conflicts_first() {
        let mut levels = [
            Confidence::VerifiedTransaction,
            Confidence::ConflictingEvidence,
            Confidence::PartiallyExplained,
        ];
        levels.sort_by_key(|c| c.attention_rank());
        assert_eq!(levels[0], Confidence::ConflictingEvidence);
        assert!(Confidence::ConflictingEvidence.needs_investigation());
        assert!(!Confidence::VerifiedTransaction.needs_investigation());
    }

    #[test]
    fn verification_unavailable_is_not_a_pass() {
        let mut v = VerificationResult::default();
        v.push(VerificationCheck::passed("a", ""));
        v.push(VerificationCheck::unavailable("b", "tool missing"));
        assert!(!v.all_passed());
        assert!(v.any_unavailable());
        assert!(!v.any_failed());
        assert_eq!(v.counts(), (1, 0, 1));
    }
}
