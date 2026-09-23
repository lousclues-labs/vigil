//! Correlation engine behaviour, driven entirely from fixtures.
//!
//! No test here needs a package manager, a privileged process, or a modified
//! host. The engine is a pure function of its evidence, so the evidence is
//! constructed directly.
//!
//! The recurring assertion across this file: correlation may only ever *add* an
//! explanation. It must never downgrade a severity, drop a detection, or turn
//! missing evidence into a pass.

use std::path::PathBuf;
use std::sync::Arc;

use vigil::correlate::{
    correlate, CollectorError, Confidence, CorrelationInput, EventKind, EvidenceSource, MemberRole,
    PackageAction, PackageTransition, TransactionRecord, TransactionSource, TransactionStatus,
};
use vigil::package::PackageVerification;
use vigil::types::{Change, ChangeResult, Severity};

const T0: i64 = 1_758_326_834; // arbitrary fixed point, inside no real window

// ── fixture helpers ────────────────────────────────────────

fn change_at(path: &str, severity: Severity) -> ChangeResult {
    ChangeResult {
        path: Arc::new(PathBuf::from(path)),
        changes: vec![Change::ContentModified {
            old_hash: "old".into(),
            new_hash: "new".into(),
        }],
        severity,
        monitored_group: "system".into(),
        process: None,
        package: None,
        package_update: false,
        disambiguation: None,
    }
}

fn deletion_at(path: &str, severity: Severity) -> ChangeResult {
    let mut c = change_at(path, severity);
    c.changes = vec![Change::Deleted];
    c
}

fn alias_at(path: &str, target: &str, severity: Severity) -> ChangeResult {
    let mut c = change_at(path, severity);
    c.changes.insert(
        0,
        Change::SymlinkTargetReplaced {
            target: PathBuf::from(target),
            old_target_inode: 111,
            new_target_inode: 222,
        },
    );
    c
}

fn apt_transaction(packages: &[(&str, &str, &str)]) -> TransactionRecord {
    let mut tx = TransactionRecord::new(TransactionSource::Apt, T0);
    tx.end = Some(T0 + 2);
    tx.status = TransactionStatus::Completed;
    tx.command = Some("apt upgrade".into());
    tx.actor = Some("operator (1000)".into());
    for (name, old, new) in packages {
        let mut t = PackageTransition::new(*name, PackageAction::Upgrade)
            .with_versions(Some(*old), Some(*new));
        t.installed_complete = Some(true);
        tx.packages.push(t);
    }
    tx.normalize();
    tx
}

/// An input where every check that can pass, passes.
struct Fixture {
    input: CorrelationInput,
}

impl Fixture {
    fn new() -> Self {
        Self {
            input: CorrelationInput::new(),
        }
    }

    fn transaction(mut self, tx: TransactionRecord) -> Self {
        self.input.transactions.push(tx);
        self
    }

    fn owns(mut self, path: &str, package: &str) -> Self {
        self.input
            .ownership
            .insert(PathBuf::from(path), vec![package.to_string()]);
        self
    }

    fn verifies(mut self, path: &str, verdict: PackageVerification) -> Self {
        self.input.verification.insert(path.to_string(), verdict);
        self
    }

    fn observed(mut self, path: &str, ts: i64) -> Self {
        self.input
            .observed_change_time
            .insert(PathBuf::from(path), ts);
        self
    }

    fn installed(mut self, package: &str, version: &str) -> Self {
        self.input
            .installed
            .insert(package.to_string(), version.to_string());
        self
    }

    fn collector_error(mut self, err: CollectorError) -> Self {
        self.input.collector_errors.push(err);
        self
    }

    fn snap_state(mut self, name: &str, current: &str, present: &[&str]) -> Self {
        self.input.snap_states.insert(
            name.to_string(),
            vigil::correlate::snap::SnapRevisionState {
                current: Some(current.to_string()),
                present: present.iter().map(|s| s.to_string()).collect(),
            },
        );
        self
    }

    fn input(&self) -> &CorrelationInput {
        &self.input
    }
}

/// Register a package file: ownership, verification, and a timestamp inside the
/// transaction window.
fn package_file(f: Fixture, path: &str, package: &str, verdict: PackageVerification) -> Fixture {
    f.owns(path, package)
        .verifies(path, verdict)
        .observed(path, T0 + 1)
}

// ── APT / dpkg ─────────────────────────────────────────────

#[test]
fn apt_1_successful_upgrade_replacing_multiple_executables_is_one_verified_event() {
    let changes = vec![
        change_at("/usr/bin/gs", Severity::Critical),
        change_at("/usr/bin/gsc", Severity::Critical),
        change_at("/usr/lib/libgs.so.9", Severity::Critical),
    ];

    let mut f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    for c in &changes {
        f = package_file(
            f,
            c.path.to_str().unwrap(),
            "ghostscript",
            PackageVerification::Verified,
        );
    }

    let result = correlate(&changes, f.input());

    assert_eq!(result.events.len(), 1, "one transaction, one event");
    let event = &result.events[0];
    assert_eq!(event.kind, EventKind::AptTransaction);
    assert_eq!(event.confidence, Confidence::VerifiedTransaction);
    assert_eq!(event.detection_count(), 3);
    assert!(event.fully_explained());
    assert!(result.uncorrelated.is_empty());

    // Raw severity is carried through exactly as observed.
    assert_eq!(event.raw_severity_counts(), vec![(Severity::Critical, 3)]);
    assert_eq!(event.max_raw_severity(), Some(Severity::Critical));
}

#[test]
fn apt_2_many_files_from_one_package_group_under_that_package() {
    let paths: Vec<String> = (0..27).map(|i| format!("/usr/share/gs/file{i}")).collect();
    let changes: Vec<ChangeResult> = paths
        .iter()
        .map(|p| change_at(p, Severity::Critical))
        .collect();

    let mut f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    for p in &paths {
        f = package_file(f, p, "ghostscript", PackageVerification::Verified);
    }

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    let by_package = event.members_by_package();
    assert_eq!(by_package.len(), 1);
    assert_eq!(by_package[0].0, "ghostscript");
    assert_eq!(by_package[0].1.len(), 27);
    assert_eq!(event.detection_count(), 27);
}

#[test]
fn apt_3_multiple_packages_in_one_transaction_stay_one_event() {
    let changes = vec![
        change_at("/usr/bin/gs", Severity::Critical),
        change_at("/usr/bin/gio", Severity::Critical),
        change_at("/usr/bin/xmllint", Severity::Critical),
    ];

    let f = Fixture::new()
        .transaction(apt_transaction(&[
            ("ghostscript", "9.55", "9.56"),
            ("libglib2.0-bin", "2.72", "2.73"),
            ("libxml2-utils", "2.9", "2.10"),
        ]))
        .installed("ghostscript", "9.56")
        .installed("libglib2.0-bin", "2.73")
        .installed("libxml2-utils", "2.10");

    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );
    let f = package_file(
        f,
        "/usr/bin/gio",
        "libglib2.0-bin",
        PackageVerification::Verified,
    );
    let f = package_file(
        f,
        "/usr/bin/xmllint",
        "libxml2-utils",
        PackageVerification::Verified,
    );

    let result = correlate(&changes, f.input());
    assert_eq!(result.events.len(), 1);
    let event = &result.events[0];
    assert_eq!(event.packages.len(), 3);
    assert_eq!(event.members_by_package().len(), 3);
    assert_eq!(event.confidence, Confidence::VerifiedTransaction);
}

#[test]
fn apt_4_package_owned_path_without_a_transaction_is_never_explained() {
    let changes = vec![change_at("/usr/bin/sudo", Severity::Critical)];

    // Ownership is known. There is simply no transaction.
    let f = Fixture::new()
        .owns("/usr/bin/sudo", "sudo")
        .verifies("/usr/bin/sudo", PackageVerification::Verified)
        .observed("/usr/bin/sudo", T0 + 1);

    let result = correlate(&changes, f.input());

    assert!(
        result.events.is_empty(),
        "ownership alone must not manufacture an explanation"
    );
    assert_eq!(
        result.uncorrelated,
        vec![0],
        "the detection stays raw and prominent"
    );
}

#[test]
fn apt_5_verification_mismatch_yields_conflicting_evidence() {
    let changes = vec![
        change_at("/usr/bin/gs", Severity::Critical),
        change_at("/usr/bin/gsc", Severity::Critical),
    ];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );
    // One package-owned executable fails verification inside an otherwise
    // clean transaction. This is the highest-signal case in the tool.
    let f = package_file(
        f,
        "/usr/bin/gsc",
        "ghostscript",
        PackageVerification::Mismatch,
    );

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::ConflictingEvidence);
    assert!(event.confidence.needs_investigation());
    assert!(
        event.verification.any_failed(),
        "the failing check must be visible: {:?}",
        event.verification
    );

    // The mismatching member is individually identifiable.
    let bad = event
        .members
        .iter()
        .find(|m| m.verification == PackageVerification::Mismatch)
        .expect("mismatch member present");
    assert_eq!(bad.raw.path, PathBuf::from("/usr/bin/gsc"));
    assert!(!bad.is_verified());
}

#[test]
fn apt_6_failed_transaction_is_conflicting_not_explained() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];

    let mut tx = apt_transaction(&[("ghostscript", "9.55", "9.56")]);
    tx.status = TransactionStatus::Failed;
    tx.errors.push("dpkg returned an error code (1)".into());

    let f = Fixture::new()
        .transaction(tx)
        .installed("ghostscript", "9.56");
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.status, TransactionStatus::Failed);
    assert_eq!(event.confidence, Confidence::ConflictingEvidence);
}

#[test]
fn apt_6b_interrupted_transaction_is_unverified_not_verified() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];

    let mut tx = apt_transaction(&[("ghostscript", "9.55", "9.56")]);
    tx.status = TransactionStatus::Interrupted;
    tx.end = None;

    let f = Fixture::new()
        .transaction(tx)
        .installed("ghostscript", "9.56");
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    )
    .observed("/usr/bin/gs", T0);

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::Unverified);
    assert!(event.confidence.needs_investigation());
}

#[test]
fn apt_7_missing_logs_are_reported_and_cap_confidence() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56")
        .collector_error(CollectorError::truncated(
            EvidenceSource::DpkgLog,
            "dpkg.log rotated; earlier entries unavailable",
        ));
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(
        event.confidence,
        Confidence::StronglyCorrelated,
        "a truncated log must not leave a verified verdict standing"
    );
    assert!(
        !event.collector_errors.is_empty(),
        "the collector failure must remain visible on the event"
    );
}

#[test]
fn apt_7b_unavailable_verification_never_becomes_verified() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    // Unknown: the package holds no digest for this path.
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Unknown,
    );

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::StronglyCorrelated);
    assert!(
        event.verification.any_unavailable(),
        "the gap in coverage must be stated, not hidden"
    );
    assert!(!event.verification.all_passed());
}

#[test]
fn apt_8_change_outside_the_transaction_window_is_not_attributed() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56")
        .owns("/usr/bin/gs", "ghostscript")
        .verifies("/usr/bin/gs", PackageVerification::Verified)
        // Two hours after the transaction ended.
        .observed("/usr/bin/gs", T0 + 7200);

    let result = correlate(&changes, f.input());

    assert!(
        result.events.is_empty(),
        "a package-owned file touched long after the transaction is not part of it"
    );
    assert_eq!(result.uncorrelated, vec![0]);
}

#[test]
fn apt_9_version_disagreement_is_conflicting_evidence() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        // The transaction says 9.56 was installed; the database says otherwise.
        .installed("ghostscript", "9.99");
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::ConflictingEvidence);
    let failed: Vec<_> = event
        .verification
        .checks
        .iter()
        .filter(|c| c.outcome == vigil::correlate::CheckOutcome::Failed)
        .collect();
    assert!(
        failed.iter().any(|c| c.detail.contains("9.99")),
        "the disagreement must name both versions: {failed:?}"
    );
}

#[test]
fn apt_10_mixed_explained_and_unexplained_is_partially_explained() {
    let changes = vec![
        change_at("/usr/bin/gs", Severity::Critical),
        // Same window, different package, not in the transaction.
        change_at("/usr/bin/unrelated", Severity::Critical),
    ];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56")
        .owns("/usr/bin/unrelated", "some-other-package")
        .observed("/usr/bin/unrelated", T0 + 1);
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::PartiallyExplained);
    assert!(!event.fully_explained());
    assert_eq!(event.members.len(), 1);
    assert_eq!(event.unexplained.len(), 1);
    assert_eq!(
        event.unexplained[0].raw.path,
        PathBuf::from("/usr/bin/unrelated")
    );
    assert!(
        event.unexplained[0].reason.contains("some-other-package"),
        "the reason must say why: {}",
        event.unexplained[0].reason
    );
    // The unexplained change keeps its raw severity.
    assert_eq!(event.unexplained[0].raw.severity, Severity::Critical);
}

/// The scenario from the brief: 22 packages, 42 detections, three of which are
/// unchanged `/etc/systemd` symlinks resolving to replaced rsyslog units.
#[test]
fn apt_end_to_end_symlink_aliases_group_under_their_target_package() {
    let mut changes = vec![
        change_at("/lib/systemd/system/rsyslog.service", Severity::High),
        change_at("/usr/sbin/rsyslogd", Severity::Critical),
    ];
    for wants in [
        "/etc/systemd/system/multi-user.target.wants/rsyslog.service",
        "/etc/systemd/system/syslog.service",
        "/etc/systemd/system/graphical.target.wants/rsyslog.service",
    ] {
        changes.push(alias_at(
            wants,
            "/lib/systemd/system/rsyslog.service",
            Severity::High,
        ));
    }

    let f = Fixture::new()
        .transaction(apt_transaction(&[("rsyslog", "8.2112", "8.2312")]))
        .installed("rsyslog", "8.2312");
    let f = package_file(
        f,
        "/lib/systemd/system/rsyslog.service",
        "rsyslog",
        PackageVerification::Verified,
    );
    let f = package_file(
        f,
        "/usr/sbin/rsyslogd",
        "rsyslog",
        PackageVerification::Verified,
    );

    let result = correlate(&changes, f.input());
    assert_eq!(result.events.len(), 1);
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::VerifiedTransaction);
    assert_eq!(event.detection_count(), 5);

    let aliases: Vec<_> = event
        .members
        .iter()
        .filter(|m| m.role == MemberRole::SymlinkAlias)
        .collect();
    assert_eq!(aliases.len(), 3, "all three aliases attributed");
    for alias in &aliases {
        assert_eq!(
            alias.canonical_path,
            Some(PathBuf::from("/lib/systemd/system/rsyslog.service")),
            "each alias names the target it resolves to"
        );
        assert_eq!(alias.package.as_deref(), Some("rsyslog"));
        // Raw severity untouched.
        assert_eq!(alias.raw.severity, Severity::High);
    }

    assert_eq!(
        event
            .aliases_for(std::path::Path::new("/lib/systemd/system/rsyslog.service"))
            .len(),
        3
    );

    // Raw counts still add up to what the ungrouped view would show.
    assert_eq!(
        event.raw_severity_counts(),
        vec![(Severity::Critical, 1), (Severity::High, 4)]
    );
}

// ── Snap ───────────────────────────────────────────────────

/// Build the snapd change from the brief: two snaps, old revisions removed.
fn snap_refresh_transaction() -> TransactionRecord {
    let mut tx = TransactionRecord::new(TransactionSource::Snap, T0);
    tx.end = Some(T0 + 12);
    tx.status = TransactionStatus::Completed;
    tx.id = Some("40".into());
    tx.command =
        Some("Auto-refresh snaps \"desktop-security-center\", \"prompting-client\"".into());
    tx.packages.push(
        PackageTransition::new("desktop-security-center", PackageAction::Refresh)
            .with_versions(Some("150"), Some("188")),
    );
    tx.packages.push(
        PackageTransition::new("prompting-client", PackageAction::Refresh)
            .with_versions(Some("204"), Some("228")),
    );
    tx.normalize();
    tx
}

/// The six mount artifacts snapd removes when two old revisions go away.
fn snap_mount_deletions() -> Vec<ChangeResult> {
    vec![
        deletion_at(
            "/etc/systemd/system/snap-desktop\\x2dsecurity\\x2dcenter-150.mount",
            Severity::High,
        ),
        deletion_at(
            "/etc/systemd/system/multi-user.target.wants/snap-desktop\\x2dsecurity\\x2dcenter-150.mount",
            Severity::High,
        ),
        deletion_at(
            "/etc/systemd/system/snapd.mounts.target.wants/snap-desktop\\x2dsecurity\\x2dcenter-150.mount",
            Severity::High,
        ),
        deletion_at(
            "/etc/systemd/system/snap-prompting\\x2dclient-204.mount",
            Severity::High,
        ),
        deletion_at(
            "/etc/systemd/system/multi-user.target.wants/snap-prompting\\x2dclient-204.mount",
            Severity::High,
        ),
        deletion_at(
            "/etc/systemd/system/snapd.mounts.target.wants/snap-prompting\\x2dclient-204.mount",
            Severity::High,
        ),
    ]
}

#[test]
fn snap_1_and_2_successful_refresh_is_one_event_covering_six_mount_artifacts() {
    let changes = snap_mount_deletions();

    let f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "188", &["188"])
        .snap_state("prompting-client", "228", &["228"]);

    let result = correlate(&changes, f.input());

    assert_eq!(result.events.len(), 1, "one refresh, one event");
    let event = &result.events[0];
    assert_eq!(event.kind, EventKind::SnapRefresh);
    assert_eq!(
        event.detection_count(),
        6,
        "all six deletions retained beneath the event"
    );
    assert!(result.uncorrelated.is_empty());
    assert_eq!(event.packages.len(), 2);

    // Every deletion is still individually present with its raw severity.
    assert_eq!(event.raw_severity_counts(), vec![(Severity::High, 6)]);

    let units = event
        .members
        .iter()
        .filter(|m| m.role == MemberRole::SnapMountUnit)
        .count();
    let symlinks = event
        .members
        .iter()
        .filter(|m| m.role == MemberRole::SnapMountSymlink)
        .count();
    assert_eq!(units, 2, "two mount units");
    assert_eq!(symlinks, 4, "four target.wants symlinks");

    assert_eq!(event.confidence, Confidence::StronglyCorrelated);
}

#[test]
fn snap_3_disabled_previous_revision_retained_is_not_a_conflict() {
    let changes = snap_mount_deletions();

    // The old revision directory is still on disk (kept for rollback) while the
    // new one is current.
    let f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "188", &["150", "188"])
        .snap_state("prompting-client", "228", &["204", "228"]);

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_ne!(
        event.confidence,
        Confidence::ConflictingEvidence,
        "retaining a previous revision is normal snapd behaviour"
    );
    assert_eq!(event.detection_count(), 6);
}

#[test]
fn snap_4_failed_refresh_task_is_conflicting_evidence() {
    let changes = snap_mount_deletions();

    let mut tx = snap_refresh_transaction();
    tx.status = TransactionStatus::Failed;
    tx.errors.push("Setup snap security profiles failed".into());

    let f = Fixture::new()
        .transaction(tx)
        .snap_state("desktop-security-center", "188", &["188"])
        .snap_state("prompting-client", "228", &["228"]);

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::ConflictingEvidence);
    assert!(event.verification.any_failed());
    assert_eq!(
        event.detection_count(),
        6,
        "a failed refresh still keeps every raw deletion"
    );
}

#[test]
fn snap_5_missing_replacement_revision_is_conflicting_evidence() {
    let changes = snap_mount_deletions();

    // snapd says 188 replaced 150, but 188 is nowhere on disk.
    let f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "150", &["150"])
        .snap_state("prompting-client", "228", &["228"]);

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::ConflictingEvidence);
    let failures: Vec<_> = event
        .verification
        .checks
        .iter()
        .filter(|c| c.outcome == vigil::correlate::CheckOutcome::Failed)
        .collect();
    assert!(
        failures
            .iter()
            .any(|c| c.detail.contains("desktop-security-center")),
        "the missing revision must be named: {failures:?}"
    );
}

#[test]
fn snap_6_unavailable_change_history_leaves_deletions_unexplained() {
    let changes = snap_mount_deletions();

    // snapd present but its history could not be read: no transactions at all.
    let f = Fixture::new().collector_error(CollectorError::new(
        EvidenceSource::SnapdChanges,
        vigil::correlate::CollectorErrorKind::PermissionDenied,
        "snap changes: requires administrator privileges",
    ));

    let result = correlate(&changes, f.input());

    assert!(
        result.events.is_empty(),
        "without change history nothing may be explained"
    );
    assert_eq!(
        result.uncorrelated.len(),
        6,
        "every deletion stays individually visible"
    );
    assert!(
        result
            .collector_errors
            .iter()
            .any(|e| e.kind.is_privilege_problem()),
        "the privilege problem must be reported to the operator"
    );
}

#[test]
fn snap_6b_revision_state_unavailable_prevents_a_verified_verdict() {
    let changes = snap_mount_deletions();

    // Change history present; on-disk revision state unreadable.
    let f = Fixture::new().transaction(snap_refresh_transaction());

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_ne!(event.confidence, Confidence::VerifiedTransaction);
    assert!(
        event.verification.any_unavailable(),
        "the unreadable state must appear as unavailable, not as a pass"
    );
}

#[test]
fn snap_7_multiple_snaps_in_one_change_share_one_event() {
    let changes = snap_mount_deletions();

    let f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "188", &["188"])
        .snap_state("prompting-client", "228", &["228"]);

    let result = correlate(&changes, f.input());
    assert_eq!(result.events.len(), 1);

    let event = &result.events[0];
    let names: Vec<&str> = event.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["desktop-security-center", "prompting-client"]);
    assert_eq!(
        event.packages[0].version_summary(),
        "150 -> 188",
        "snap revisions are carried as the version transition"
    );
}

#[test]
fn snap_8_user_initiated_refresh_is_recorded_when_evidence_names_it() {
    let changes = snap_mount_deletions();

    let mut auto = snap_refresh_transaction();
    auto.command = Some("Auto-refresh snaps \"desktop-security-center\"".into());
    let auto_result = correlate(
        &changes,
        Fixture::new()
            .transaction(auto)
            .snap_state("desktop-security-center", "188", &["188"])
            .snap_state("prompting-client", "228", &["228"])
            .input(),
    );
    assert!(auto_result.events[0]
        .command
        .as_deref()
        .unwrap()
        .contains("Auto-refresh"));

    let mut manual = snap_refresh_transaction();
    manual.command = Some("Refresh snap \"desktop-security-center\"".into());
    manual.actor = Some("operator (1000)".into());
    let manual_result = correlate(
        &changes,
        Fixture::new()
            .transaction(manual)
            .snap_state("desktop-security-center", "188", &["188"])
            .snap_state("prompting-client", "228", &["228"])
            .input(),
    );
    assert_eq!(
        manual_result.events[0].actor.as_deref(),
        Some("operator (1000)"),
        "an actor is reported only because the record named one"
    );
}

// ── Cross-cutting invariants ───────────────────────────────

#[test]
fn correlation_is_deterministic_for_identical_evidence() {
    let changes = snap_mount_deletions();
    let build = || {
        Fixture::new()
            .transaction(snap_refresh_transaction())
            .snap_state("desktop-security-center", "188", &["188"])
            .snap_state("prompting-client", "228", &["228"])
    };

    let a = correlate(&changes, build().input());
    let b = correlate(&changes, build().input());

    assert_eq!(a.events.len(), b.events.len());
    assert_eq!(a.events[0].event_id, b.events[0].event_id);
    assert_eq!(a.uncorrelated, b.uncorrelated);
}

#[test]
fn correlation_never_alters_the_raw_detections_it_reads() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];
    let before = format!("{:?}", changes);

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let _ = correlate(&changes, f.input());

    assert_eq!(
        before,
        format!("{:?}", changes),
        "raw detections are read-only input to correlation"
    );
    assert_eq!(changes[0].severity, Severity::Critical);
}

#[test]
fn every_detection_is_either_in_an_event_or_in_uncorrelated() {
    let mut changes = snap_mount_deletions();
    changes.push(change_at("/usr/bin/gs", Severity::Critical));
    changes.push(change_at("/home/user/notes.txt", Severity::Low));

    let f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "188", &["188"])
        .snap_state("prompting-client", "228", &["228"]);

    let result = correlate(&changes, f.input());

    let mut seen: Vec<usize> = result
        .events
        .iter()
        .flat_map(|e| {
            e.members
                .iter()
                .map(|m| m.raw.index)
                .chain(e.unexplained.iter().map(|u| u.raw.index))
        })
        .chain(result.uncorrelated.iter().copied())
        .collect();
    seen.sort();
    seen.dedup();

    assert_eq!(
        seen.len(),
        changes.len(),
        "no detection may be lost between the two buckets"
    );
    assert_eq!(seen, (0..changes.len()).collect::<Vec<_>>());
}

#[test]
fn events_needing_attention_sort_before_settled_ones() {
    // A conflicting apt transaction and a clean snap refresh in one scan.
    let mut changes = snap_mount_deletions();
    changes.push(change_at("/usr/bin/gs", Severity::Critical));

    let f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "188", &["188"])
        .snap_state("prompting-client", "228", &["228"])
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Mismatch,
    );

    let result = correlate(&changes, f.input());
    assert_eq!(result.events.len(), 2);
    assert_eq!(
        result.events[0].confidence,
        Confidence::ConflictingEvidence,
        "the conflicting event must be presented first"
    );
}

#[test]
fn an_empty_scan_produces_no_events() {
    let input = CorrelationInput::new();
    let result = correlate(&[], &input);
    assert!(result.events.is_empty());
    assert!(result.uncorrelated.is_empty());
}

#[test]
fn ownership_without_window_evidence_is_attributed_but_not_verified() {
    let changes = vec![change_at("/usr/bin/gs", Severity::Critical)];

    // Ownership and transaction line up, but no filesystem timestamp exists.
    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56")
        .owns("/usr/bin/gs", "ghostscript")
        .verifies("/usr/bin/gs", PackageVerification::Verified);

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(
        event.confidence,
        Confidence::StronglyCorrelated,
        "an unchecked window is not a checked one"
    );
    assert!(event
        .verification
        .checks
        .iter()
        .any(|c| c.outcome == vigil::correlate::CheckOutcome::Unavailable
            && c.name.contains("window")));
}

#[test]
fn unowned_path_in_the_window_is_flagged_as_unexplained_not_absorbed() {
    let changes = vec![
        change_at("/usr/bin/gs", Severity::Critical),
        change_at("/tmp/dropper", Severity::Critical),
    ];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56")
        // No ownership for the dropper; it merely landed in the same window.
        .observed("/tmp/dropper", T0 + 1);
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    assert_eq!(event.confidence, Confidence::PartiallyExplained);
    assert_eq!(event.unexplained.len(), 1);
    assert_eq!(event.unexplained[0].raw.path, PathBuf::from("/tmp/dropper"));
    assert!(event.unexplained[0]
        .reason
        .contains("not owned by any package"));
}

/// On a machine with both dpkg and snapd, the dpkg installed-package map is
/// populated but never contains snap names. Grading a snap refresh against it
/// reported a healthy refresh as "packages not fully installed" — a false
/// alarm on exactly the clean transaction this feature exists to explain.
///
/// Snap state is verified by revision presence, not by the dpkg database.
#[test]
fn snap_events_are_not_graded_against_the_dpkg_package_database() {
    let changes = snap_mount_deletions();

    let mut f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "188", &["188"])
        .snap_state("prompting-client", "228", &["228"]);
    // A realistic dpkg database: full of packages, none of them snaps.
    for pkg in ["ghostscript", "rsyslog", "libglib2.0-bin", "coreutils"] {
        f = f.installed(pkg, "1.0");
    }

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    let failed: Vec<&str> = event
        .verification
        .checks
        .iter()
        .filter(|c| c.outcome == vigil::correlate::CheckOutcome::Failed)
        .map(|c| c.name.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "a healthy snap refresh must not report failed checks: {failed:?}"
    );

    assert!(
        !event
            .verification
            .checks
            .iter()
            .any(|c| c.name.contains("complete state")),
        "dpkg installed-state has no bearing on a snap refresh: {:?}",
        event.verification.checks
    );
    assert_ne!(event.confidence, Confidence::ConflictingEvidence);
}

/// A snap artifact's name proves *which* revision it belongs to, not *when* it
/// changed. Attribution on path shape alone let a file modified today be folded
/// into a refresh from five days ago, and the report then asserted it fell
/// inside that transaction's window.
#[test]
fn snap_data_modified_outside_the_window_is_not_attributed() {
    let changes = vec![change_at(
        "/var/snap/firefox/common/payload",
        Severity::Critical,
    )];

    let mut tx = TransactionRecord::new(TransactionSource::Snap, T0);
    tx.end = Some(T0 + 12);
    tx.status = TransactionStatus::Completed;
    tx.packages.push(
        PackageTransition::new("firefox", PackageAction::Refresh)
            .with_versions(Some("100"), Some("101")),
    );
    tx.normalize();

    let f = Fixture::new()
        .transaction(tx)
        .snap_state("firefox", "101", &["101"])
        // Five days after the refresh completed.
        .observed("/var/snap/firefox/common/payload", T0 + 5 * 24 * 3600);

    let result = correlate(&changes, f.input());

    assert!(
        result.events.is_empty(),
        "a change five days outside the window is not part of that refresh"
    );
    assert_eq!(result.uncorrelated, vec![0]);
}

/// A deleted mount unit has no mtime left to compare, so the window cannot be
/// checked for it. The event must say so rather than assert a passed check.
#[test]
fn deleted_snap_artifacts_report_the_window_as_unverified() {
    let changes = snap_mount_deletions();

    let f = Fixture::new()
        .transaction(snap_refresh_transaction())
        .snap_state("desktop-security-center", "188", &["188"])
        .snap_state("prompting-client", "228", &["228"]);

    let result = correlate(&changes, f.input());
    let event = &result.events[0];

    let window = event
        .verification
        .checks
        .iter()
        .find(|c| c.name.contains("window"))
        .expect("a window check must be present");
    assert_eq!(
        window.outcome,
        vigil::correlate::CheckOutcome::Unavailable,
        "the window was never checked for deleted paths, so it cannot be a pass: {window:?}"
    );
    assert_ne!(event.confidence, Confidence::VerifiedTransaction);
}

/// `dpkg --verify` compares md5sums only. A file whose *bytes* match what the
/// package shipped verifies clean even if someone added a setuid bit
/// afterwards, and `chmod` moves ctime rather than mtime, so the file still
/// looks like it was written during the transaction.
///
/// Presenting that as a verified package change would hand an attacker the
/// exact cover this feature is supposed to remove.
#[test]
fn setuid_added_to_a_package_file_is_never_a_verified_transaction() {
    let mut change = change_at("/usr/bin/gs", Severity::Critical);
    change.changes = vec![Change::PermissionsChanged {
        old: 0o100755,
        new: 0o104755, // setuid gained
    }];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    // Content verification passes: the bytes really are the package's.
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&[change], f.input());
    let event = &result.events[0];

    assert_eq!(
        event.confidence,
        Confidence::ConflictingEvidence,
        "a privilege boundary moved on a package file; the transaction cannot explain it"
    );
    assert!(event.confidence.needs_investigation());

    let failed: Vec<&str> = event
        .verification
        .checks
        .iter()
        .filter(|c| c.outcome == vigil::correlate::CheckOutcome::Failed)
        .map(|c| c.name.as_str())
        .collect();
    assert!(
        failed.contains(&"no privilege-relevant changes"),
        "the privilege change must be named as a failed check: {failed:?}"
    );
}

#[test]
fn capability_added_to_a_package_file_is_conflicting() {
    let mut change = change_at("/usr/bin/ping", Severity::Critical);
    change.changes = vec![Change::CapabilitiesChanged {
        old: None,
        new: Some("cap_net_raw+ep".into()),
    }];

    let f = Fixture::new()
        .transaction(apt_transaction(&[(
            "iputils-ping",
            "3:20211215",
            "3:20240117",
        )]))
        .installed("iputils-ping", "3:20240117");
    let f = package_file(
        f,
        "/usr/bin/ping",
        "iputils-ping",
        PackageVerification::Verified,
    );

    let result = correlate(&[change], f.input());
    assert_eq!(result.events[0].confidence, Confidence::ConflictingEvidence);
}

/// A non-privilege metadata dimension still is not covered by a content
/// digest, so it downgrades -- but it is not escalated to a contradiction.
#[test]
fn a_plain_metadata_change_is_partially_explained_not_verified() {
    let mut change = change_at("/usr/share/doc/gs/readme", Severity::Low);
    change.changes = vec![Change::XattrChanged {
        key: "user.comment".into(),
        old: None,
        new: Some("x".into()),
    }];

    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    let f = package_file(
        f,
        "/usr/share/doc/gs/readme",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&[change], f.input());
    let event = &result.events[0];
    assert_eq!(event.confidence, Confidence::PartiallyExplained);
    assert_ne!(event.confidence, Confidence::VerifiedTransaction);
}

/// The ordinary case must stay verified: a content-only change to a package
/// file inside a completed transaction is exactly what this feature exists to
/// explain, and over-flagging it would reintroduce the alert fatigue.
#[test]
fn a_content_only_package_change_remains_verified() {
    let f = Fixture::new()
        .transaction(apt_transaction(&[("ghostscript", "9.55", "9.56")]))
        .installed("ghostscript", "9.56");
    let f = package_file(
        f,
        "/usr/bin/gs",
        "ghostscript",
        PackageVerification::Verified,
    );

    let result = correlate(&[change_at("/usr/bin/gs", Severity::Critical)], f.input());
    assert_eq!(result.events[0].confidence, Confidence::VerifiedTransaction);
}
