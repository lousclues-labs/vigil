//! The correlation engine.
//!
//! Maps raw detections onto package-manager transactions and decides, from the
//! evidence alone, how well the transaction accounts for them.
//!
//! Three rules govern everything here:
//!
//! 1. Raw detections are read-only inputs. Nothing in this module edits a
//!    detection, its severity, or its audit record.
//! 2. Missing evidence lowers confidence. It never raises it, and it never
//!    becomes a pass.
//! 3. Ownership alone proves nothing. A path mapping to a package is one
//!    signal; a high-confidence verdict needs several that agree.
//!
//! The engine is a pure function of its input, so a fixture-built input and a
//! live-system input are handled identically.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::package::PackageVerification;
use crate::types::{Change, ChangeResult};

use super::error::{CollectorError, CollectorErrorKind, EvidenceSource};
use super::event::{
    Confidence, CorrelatedEvent, CorrelatedEventBuilder, EventKind, EventMember, MemberRole,
    RawRef, UnexplainedChange, VerificationCheck,
};
use super::snap::{self, SnapRevisionState};
use super::transaction::{TransactionRecord, TransactionSource, TransactionStatus};

/// Default slack applied to transaction windows, in seconds.
///
/// Package managers log to whole seconds and the filesystem settles after the
/// log line is written. Thirty seconds absorbs that without being wide enough
/// to swallow an unrelated change made minutes later.
pub const DEFAULT_WINDOW_SLACK_SECS: i64 = 30;

/// Evidence handed to the engine.
///
/// Every field is optional in the sense that an empty collection means "we have
/// none of this", which the engine reports as reduced confidence rather than
/// treating as agreement.
#[derive(Debug, Default)]
pub struct CorrelationInput {
    /// Normalized transactions from every collector.
    pub transactions: Vec<TransactionRecord>,
    /// Path to its candidate owning packages, resolved in batch.
    ///
    /// A list, not a single name: `dpkg -S` reports several packages for a
    /// shared path, and reports multi-arch packages as `libc6:amd64` while the
    /// transaction logs and the package database both say `libc6`. Names here
    /// are normalized so they compare equal to the names transactions use.
    pub ownership: HashMap<PathBuf, Vec<String>>,
    /// Per-path content verification verdicts, keyed by path string.
    pub verification: HashMap<String, PackageVerification>,
    /// Observed inode *change* time (ctime) per path, used for window matching.
    ///
    /// Deliberately ctime, not mtime. dpkg restores the mtime recorded in the
    /// package archive, which is the upstream build date: on a real system a
    /// freshly upgraded `/usr/bin/gs` carries an mtime days before the
    /// transaction that installed it, so an mtime window test rejects every
    /// genuine package file. ctime is the timestamp that actually moves when
    /// dpkg writes the inode.
    ///
    /// ctime is also the harder of the two to forge: `utimes(2)` lets a
    /// caller set mtime to any value, which would let an attacker place a
    /// tampered file inside a transaction window and borrow its explanation.
    /// Nothing can set ctime directly.
    pub observed_change_time: HashMap<PathBuf, i64>,
    /// Packages the local database reports as fully installed, with versions.
    pub installed: HashMap<String, String>,
    /// On-disk snap revision state, keyed by snap name.
    pub snap_states: BTreeMap<String, SnapRevisionState>,
    /// Failures accumulated while collecting the above.
    pub collector_errors: Vec<CollectorError>,
    /// Window slack in seconds.
    pub window_slack_secs: i64,
}

impl CorrelationInput {
    pub fn new() -> Self {
        Self {
            window_slack_secs: DEFAULT_WINDOW_SLACK_SECS,
            ..Default::default()
        }
    }
}

/// What correlation concluded about one scan.
#[derive(Debug, Default)]
pub struct CorrelationResult {
    /// Events, sorted so the ones needing attention come first.
    pub events: Vec<CorrelatedEvent>,
    /// Indices of raw detections no event accounts for. These render exactly as
    /// they always have.
    pub uncorrelated: Vec<usize>,
    /// Collector failures that apply to the whole run.
    pub collector_errors: Vec<CollectorError>,
}

impl CorrelationResult {
    /// Index of the event containing raw detection `index`, if any.
    pub fn event_for_index(&self, index: usize) -> Option<&CorrelatedEvent> {
        self.events.iter().find(|e| {
            e.members.iter().any(|m| m.raw.index == index)
                || e.unexplained.iter().any(|u| u.raw.index == index)
        })
    }

    /// Raw detections accounted for by some event.
    pub fn correlated_count(&self) -> usize {
        self.events.iter().map(|e| e.detection_count()).sum()
    }

    /// Whether anything at all was explained.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Build a [`RawRef`] for a detection.
fn raw_ref(index: usize, change: &ChangeResult) -> RawRef {
    RawRef {
        index,
        path: change.path.as_ref().clone(),
        severity: change.severity,
        changes: change.changes.iter().map(|c| c.to_string()).collect(),
        audit_sequence: None,
    }
}

/// How a path was tied to a transaction.
struct Attribution {
    transaction: usize,
    role: MemberRole,
    package: Option<String>,
    canonical_path: Option<PathBuf>,
    /// Whether this member's timestamp was actually compared against the
    /// transaction window. A deleted file has no mtime left to check, so the
    /// window claim cannot be made for it and must not be asserted.
    window_checked: bool,
}

/// Attribute one detection to a snap transaction, if its path identifies a snap
/// revision that transaction touched.
fn attribute_snap(
    change: &ChangeResult,
    transactions: &[TransactionRecord],
    input: &CorrelationInput,
) -> Option<Attribution> {
    let path = change.path.as_ref();

    // A snap artifact names its own revision, which is strong attribution. It
    // is not, on its own, evidence about *when* the change happened. Where a
    // timestamp survives, it must agree with the transaction window; where the
    // file is gone there is nothing left to compare, and the event says so
    // rather than claiming a check it never ran.
    let observed = input.observed_change_time.get(path).copied();
    let window_ok = |tx: &TransactionRecord| match observed {
        Some(ts) => tx.contains(ts, input.window_slack_secs),
        None => true,
    };

    // Generated systemd mount units and their target.wants symlinks encode the
    // snap name and revision in the unit name.
    if let Some((name, revision)) = snap::snap_mount_unit_identity(path) {
        let role = if snap::is_target_wants_path(path) {
            MemberRole::SnapMountSymlink
        } else {
            MemberRole::SnapMountUnit
        };
        let idx = transactions.iter().position(|tx| {
            tx.source == TransactionSource::Snap
                && tx.package(&name).is_some_and(|p| {
                    p.old_version.as_deref() == Some(revision.as_str())
                        || p.new_version.as_deref() == Some(revision.as_str())
                })
                && window_ok(tx)
        })?;
        return Some(Attribution {
            transaction: idx,
            role,
            package: Some(name),
            canonical_path: None,
            window_checked: observed.is_some(),
        });
    }

    // Revision data directories under /snap or /var/snap.
    let text = path.to_str()?;
    for prefix in ["/snap/", "/var/snap/"] {
        let Some(rest) = text.strip_prefix(prefix) else {
            continue;
        };
        let name = rest.split('/').next()?.to_string();
        if name.is_empty() {
            continue;
        }
        let idx = transactions.iter().position(|tx| {
            tx.source == TransactionSource::Snap && tx.package(&name).is_some() && window_ok(tx)
        })?;
        return Some(Attribution {
            transaction: idx,
            role: MemberRole::SnapRevisionData,
            package: Some(name),
            canonical_path: None,
            window_checked: observed.is_some(),
        });
    }

    None
}

/// Attribute one detection to an APT/dpkg transaction.
///
/// Requires two independent signals: the path is owned by a package the
/// transaction touched, *and* the change's timestamp falls inside the
/// transaction's window. Ownership alone is never enough.
fn attribute_package(
    change: &ChangeResult,
    transactions: &[TransactionRecord],
    input: &CorrelationInput,
) -> Option<Attribution> {
    let path = change.path.as_ref();

    // A symlink whose own object did not change is an alias: it is explained by
    // whatever replaced its target, so ownership is resolved on the target.
    let alias_target = change.symlink_alias_target().map(Path::to_path_buf);
    let ownership_path = alias_target.clone().unwrap_or_else(|| path.to_path_buf());
    let role = if alias_target.is_some() {
        MemberRole::SymlinkAlias
    } else {
        MemberRole::PackageFile
    };

    let candidates = input.ownership.get(&ownership_path)?;

    // Timestamp evidence: prefer the target's mtime for an alias, since the
    // symlink's own mtime did not move.
    let observed = input
        .observed_change_time
        .get(&ownership_path)
        .or_else(|| input.observed_change_time.get(path))
        .copied();

    // A path may have several candidate owners. Attribute it to whichever one
    // the transaction actually touched rather than assuming the first listed.
    let mut matched_package = None;
    let idx = transactions.iter().position(|tx| {
        if tx.source == TransactionSource::Snap {
            return false;
        }
        let Some(candidate) = candidates.iter().find(|c| tx.package(c).is_some()) else {
            return false;
        };
        let in_window = match observed {
            Some(ts) => tx.contains(ts, input.window_slack_secs),
            // Without a timestamp the window cannot be checked. Attribution is
            // still allowed so the operator sees the candidate explanation, but
            // the missing check is recorded and caps confidence below verified.
            None => true,
        };
        if in_window {
            matched_package = Some(candidate.clone());
        }
        in_window
    })?;

    Some(Attribution {
        transaction: idx,
        role,
        package: matched_package,
        canonical_path: alias_target,
        window_checked: observed.is_some(),
    })
}

/// A detection that landed inside a transaction's window but that the
/// transaction does not own.
fn falls_in_window_only(
    change: &ChangeResult,
    tx: &TransactionRecord,
    input: &CorrelationInput,
) -> bool {
    input
        .observed_change_time
        .get(change.path.as_ref())
        .is_some_and(|ts| tx.contains(*ts, input.window_slack_secs))
}

/// Correlate raw detections against collected evidence.
///
/// `changes` is borrowed and never modified.
pub fn correlate(changes: &[ChangeResult], input: &CorrelationInput) -> CorrelationResult {
    let mut transactions = input.transactions.clone();
    transactions.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.id.cmp(&b.id))
    });

    // Attribute every detection.
    let mut per_transaction: BTreeMap<usize, Vec<(usize, Attribution)>> = BTreeMap::new();
    let mut attributed: HashSet<usize> = HashSet::new();

    for (index, change) in changes.iter().enumerate() {
        let attribution = attribute_snap(change, &transactions, input)
            .or_else(|| attribute_package(change, &transactions, input));
        if let Some(attribution) = attribution {
            attributed.insert(index);
            per_transaction
                .entry(attribution.transaction)
                .or_default()
                .push((index, attribution));
        }
    }

    // Detections that no transaction owns, but that landed inside one's window,
    // are attached to that event as explicitly unexplained. Being inside the
    // window is exactly why they deserve prominence: they arrived with the
    // transaction but are not part of it.
    let mut window_only: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, change) in changes.iter().enumerate() {
        if attributed.contains(&index) {
            continue;
        }
        for (tx_index, tx) in transactions.iter().enumerate() {
            if !per_transaction.contains_key(&tx_index) {
                continue;
            }
            if falls_in_window_only(change, tx, input) {
                window_only.entry(tx_index).or_default().push(index);
                break;
            }
        }
    }

    let mut events = Vec::new();
    for (tx_index, members) in &per_transaction {
        let tx = &transactions[*tx_index];
        let extra = window_only.get(tx_index).cloned().unwrap_or_default();
        events.push(build_event(tx, members, &extra, changes, input));
    }

    // Everything an event touches is correlated; the rest renders untouched.
    let mut covered: HashSet<usize> = attributed;
    for indices in window_only.values() {
        covered.extend(indices.iter().copied());
    }
    let uncorrelated: Vec<usize> = (0..changes.len())
        .filter(|i| !covered.contains(i))
        .collect();

    // Most-alarming first, then oldest first for stability.
    events.sort_by(|a, b| {
        a.confidence
            .attention_rank()
            .cmp(&b.confidence.attention_rank())
            .then_with(|| a.started_at.cmp(&b.started_at))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });

    let mut collector_errors = input.collector_errors.clone();
    collector_errors.sort();
    collector_errors.dedup();

    CorrelationResult {
        events,
        uncorrelated,
        collector_errors,
    }
}

/// Assemble one event and grade its confidence.
fn build_event(
    tx: &TransactionRecord,
    members: &[(usize, Attribution)],
    window_only: &[usize],
    changes: &[ChangeResult],
    input: &CorrelationInput,
) -> CorrelatedEvent {
    let kind = match tx.source {
        TransactionSource::Snap => EventKind::SnapRefresh,
        _ => EventKind::AptTransaction,
    };

    let mut builder = CorrelatedEventBuilder::new(kind).transaction(tx.clone());

    // ── Members ────────────────────────────────────────────
    let mut verdicts: Vec<PackageVerification> = Vec::new();
    let mut verified_paths = 0usize;
    let mut alias_count = 0usize;

    for (index, attribution) in members {
        let change = &changes[*index];
        let lookup_path = attribution
            .canonical_path
            .clone()
            .unwrap_or_else(|| change.path.as_ref().clone());
        let verification = input
            .verification
            .get(&lookup_path.to_string_lossy().to_string())
            .copied()
            .unwrap_or(PackageVerification::Unknown);

        if attribution.role == MemberRole::SymlinkAlias {
            alias_count += 1;
        }
        if verification.is_proof() {
            verified_paths += 1;
        }
        verdicts.push(verification);

        builder = builder.member(EventMember {
            raw: raw_ref(*index, change),
            role: attribution.role,
            package: attribution.package.clone(),
            verification,
            canonical_path: attribution.canonical_path.clone(),
        });
    }

    // Dimensions the transaction's content verification never examined.
    let mut metadata_members: Vec<(String, Vec<&'static str>)> = Vec::new();
    let mut privilege_members: Vec<String> = Vec::new();
    for (index, _) in members {
        let change = &changes[*index];
        let dims = unexplained_dimensions(change);
        if !dims.is_empty() {
            metadata_members.push((change.path.to_string_lossy().into_owned(), dims));
        }
        if crosses_privilege_boundary(change) {
            privilege_members.push(change.path.to_string_lossy().into_owned());
        }
    }
    metadata_members.sort();
    privilege_members.sort();

    // ── Unexplained members ────────────────────────────────
    for index in window_only {
        let change = &changes[*index];
        let owner = input.ownership.get(change.path.as_ref());
        let reason = match owner.and_then(|candidates| candidates.first()) {
            Some(pkg) => format!("owned by '{pkg}', which this transaction did not touch"),
            None => "not owned by any package in this transaction".to_string(),
        };
        builder = builder.unexplained(UnexplainedChange {
            raw: raw_ref(*index, change),
            reason,
        });
    }

    // ── Checks ─────────────────────────────────────────────
    let member_count = members.len();
    let unexplained_count = window_only.len();

    builder = match tx.status {
        TransactionStatus::Completed => builder.check(VerificationCheck::passed(
            "transaction completed",
            format!("{} recorded a successful end", tx.source),
        )),
        TransactionStatus::Failed => builder.check(VerificationCheck::failed(
            "transaction completed",
            format!("{} recorded an error", tx.source),
        )),
        TransactionStatus::Interrupted => builder.check(VerificationCheck::failed(
            "transaction completed",
            "started but never recorded an end".to_string(),
        )),
        TransactionStatus::Unknown => builder.check(VerificationCheck::unavailable(
            "transaction completed",
            "no end-state record found".to_string(),
        )),
    };

    // Content verification, split so a partial pass is never stated as a full one.
    let mismatches = verdicts
        .iter()
        .filter(|v| matches!(v, PackageVerification::Mismatch))
        .count();
    let unknowns = verdicts
        .iter()
        .filter(|v| matches!(v, PackageVerification::Unknown))
        .count();
    let conffiles = verdicts
        .iter()
        .filter(|v| matches!(v, PackageVerification::Conffile))
        .count();
    let missing = verdicts
        .iter()
        .filter(|v| matches!(v, PackageVerification::Missing))
        .count();

    if mismatches > 0 {
        builder = builder.check(VerificationCheck::failed(
            "files match installed package metadata",
            format!("{mismatches} of {member_count} failed content verification"),
        ));
    }
    if verified_paths > 0 {
        builder = builder.check(VerificationCheck::passed(
            "files match installed package metadata",
            format!("{verified_paths} of {member_count} verified"),
        ));
    }
    if unknowns > 0 {
        builder = builder.check(VerificationCheck::unavailable(
            "content verification coverage",
            format!("{unknowns} of {member_count} have no digest to check against"),
        ));
    }
    if conffiles > 0 {
        builder = builder.check(VerificationCheck::unavailable(
            "conffile content",
            format!("{conffiles} locally-modified conffile(s); package digests do not apply"),
        ));
    }
    if missing > 0 {
        builder = builder.check(VerificationCheck::failed(
            "package files present",
            format!("{missing} file(s) the package expects are missing"),
        ));
    }

    if alias_count > 0 {
        builder = builder.check(VerificationCheck::passed(
            "symlink aliases resolve to transaction files",
            format!("{alias_count} unchanged symlink(s) resolve to replaced targets"),
        ));
    }

    if !privilege_members.is_empty() {
        builder = builder.check(VerificationCheck::failed(
            "no privilege-relevant changes",
            format!(
                "{} path(s) changed a privilege boundary (setuid/setgid, world-write, \
                 capabilities, ownership involving root, or file type); package \
                 verification does not examine these: {}",
                privilege_members.len(),
                privilege_members.join(", ")
            ),
        ));
    } else if !metadata_members.is_empty() {
        let summary: Vec<String> = metadata_members
            .iter()
            .map(|(path, dims)| format!("{path} ({})", dims.join(", ")))
            .collect();
        builder = builder.check(VerificationCheck::failed(
            "package metadata covers every changed dimension",
            format!(
                "{} path(s) changed a dimension package verification does not check: {}",
                metadata_members.len(),
                summary.join("; ")
            ),
        ));
    }

    // Installed-state and version evidence come from the *package database*,
    // which is dpkg's. A snap name never appears there, so grading a snap
    // refresh against it would report a healthy refresh as incomplete. Snap
    // state is confirmed by revision presence instead, below.
    let dpkg_backed = tx.source != TransactionSource::Snap;

    let (complete, incomplete, unknown_state) = if dpkg_backed {
        installed_state_counts(tx, input)
    } else {
        (0, 0, 0)
    };

    if dpkg_backed {
        if incomplete > 0 {
            builder = builder.check(VerificationCheck::failed(
                "packages reached a complete state",
                format!("{incomplete} package(s) are not fully installed"),
            ));
        } else if unknown_state > 0 {
            builder = builder.check(VerificationCheck::unavailable(
                "packages reached a complete state",
                format!("installed state unreadable for {unknown_state} package(s)"),
            ));
        } else if complete > 0 {
            builder = builder.check(VerificationCheck::passed(
                "packages reached a complete state",
                format!("{complete} package(s) fully installed"),
            ));
        }
    }

    // Version agreement between the transaction record and current state.
    let mut versions_disagree = false;
    if dpkg_backed {
        let version_check = version_agreement(tx, input);
        builder = builder.check(version_check.0);
        versions_disagree = version_check.1;
    }

    // Snap-specific: replacement revisions must actually be present.
    let mut snap_state_conflict = false;
    if tx.source == TransactionSource::Snap {
        let (check, conflict) = snap_revision_check(tx, input);
        if let Some(check) = check {
            builder = builder.check(check);
        }
        snap_state_conflict = conflict;
    }

    if unexplained_count > 0 {
        builder = builder.check(VerificationCheck::failed(
            "no unexplained files",
            format!("{unexplained_count} change(s) in this window are not part of the transaction"),
        ));
    } else if member_count > 0 {
        builder = builder.check(VerificationCheck::passed(
            "no unexplained files",
            "every change in this window is attributed".to_string(),
        ));
    }

    // Window evidence: say so when timestamps were unavailable.
    let missing_times = members
        .iter()
        .filter(|(_, attribution)| !attribution.window_checked)
        .count();
    if missing_times > 0 {
        builder = builder.check(VerificationCheck::unavailable(
            "changes fall inside the transaction window",
            format!("no timestamp available for {missing_times} path(s)"),
        ));
    } else if member_count > 0 {
        builder = builder.check(VerificationCheck::passed(
            "changes fall inside the transaction window",
            match tx.duration_secs() {
                Some(d) => format!("all {member_count} within the {d}s window"),
                None => format!("all {member_count} within the recorded window"),
            },
        ));
    }

    // Collector errors relevant to this event's sources.
    let relevant: Vec<&CollectorError> = input
        .collector_errors
        .iter()
        .filter(|e| relevant_to(e.source, tx.source))
        .collect();
    let has_blocking_error = relevant.iter().any(|e| e.kind != CollectorErrorKind::Parse);
    for err in relevant {
        builder = builder.collector_error(err.clone());
    }

    builder = builder
        .evidence(EvidenceSource::PackageOwnership)
        .evidence(EvidenceSource::FilesystemTimestamps);
    if !verdicts.is_empty() {
        builder = builder.evidence(EvidenceSource::PackageVerification);
    }

    // ── Confidence ─────────────────────────────────────────
    let conflicting = mismatches > 0
        || missing > 0
        || tx.status == TransactionStatus::Failed
        || versions_disagree
        || snap_state_conflict
        // A privilege boundary moved on a file the transaction supposedly
        // explains. Content verification never looked at that dimension, so
        // the transaction cannot account for it.
        || !privilege_members.is_empty();

    let confidence = if conflicting {
        Confidence::ConflictingEvidence
    } else if unexplained_count > 0 || !metadata_members.is_empty() {
        Confidence::PartiallyExplained
    } else if !tx.status.is_success() {
        // Started but unconfirmed. A suspected transaction, nothing more.
        Confidence::Unverified
    } else if incomplete > 0 || unknown_state > 0 || missing_times > 0 || has_blocking_error {
        Confidence::StronglyCorrelated
    } else if unknowns > 0 || conffiles > 0 || verified_paths < member_count {
        // Some members had nothing to verify against. The transaction lines up,
        // but the content claim cannot be made for every file.
        Confidence::StronglyCorrelated
    } else if verified_paths == member_count && member_count > 0 {
        Confidence::VerifiedTransaction
    } else {
        Confidence::StronglyCorrelated
    };

    builder.confidence(confidence).build()
}

/// Dimensions a package transaction's content verification cannot vouch for.
///
/// `dpkg --verify` compares recorded md5sums; it does not check mode, owner,
/// capabilities, xattrs, or file type. A file whose *bytes* match what the
/// package shipped therefore verifies clean even if its permissions were
/// changed afterwards, because nothing in the package metadata disagrees.
///
/// Those dimensions are exactly where post-install tampering hides, so they are
/// reported as dimensions the transaction does not explain rather than being
/// carried silently under a content verdict that never looked at them.
fn unexplained_dimensions(change: &ChangeResult) -> Vec<&'static str> {
    let mut dims = Vec::new();
    for c in &change.changes {
        let name = match c {
            Change::PermissionsChanged { .. } => "mode",
            Change::OwnerChanged { .. } => "owner",
            Change::CapabilitiesChanged { .. } => "capabilities",
            Change::XattrChanged { .. } => "xattr",
            Change::SecurityContextChanged { .. } => "security context",
            Change::TypeChanged { .. } => "file type",
            Change::DeviceChanged { .. } => "device",
            _ => continue,
        };
        if !dims.contains(&name) {
            dims.push(name);
        }
    }
    dims
}

/// Whether a changed dimension crosses a privilege boundary.
///
/// These are the changes that grant something: a setuid or setgid bit, a
/// world-writable system file, a file capability, a change of ownership
/// involving root, or a change of file type. A package transaction happening
/// nearby is not an explanation for any of them.
fn crosses_privilege_boundary(change: &ChangeResult) -> bool {
    change.changes.iter().any(|c| match c {
        Change::PermissionsChanged { old, new } => {
            let gained = |bit: u32| (old & bit) == 0 && (new & bit) != 0;
            // setuid, setgid, or world-writable newly present.
            gained(0o4000) || gained(0o2000) || gained(0o002)
        }
        Change::OwnerChanged {
            old_uid, new_uid, ..
        } => *old_uid == 0 || *new_uid == 0,
        Change::CapabilitiesChanged { old, new } => old != new,
        Change::SecurityContextChanged { .. } => true,
        Change::TypeChanged { .. } => true,
        _ => false,
    })
}

/// Whether a collector failure bears on a transaction from `source`.
fn relevant_to(error_source: EvidenceSource, tx_source: TransactionSource) -> bool {
    match tx_source {
        TransactionSource::Snap => matches!(
            error_source,
            EvidenceSource::SnapdChanges | EvidenceSource::SnapdRevisionState
        ),
        TransactionSource::Apt | TransactionSource::Dpkg => matches!(
            error_source,
            EvidenceSource::AptHistory
                | EvidenceSource::DpkgLog
                | EvidenceSource::DpkgStatus
                | EvidenceSource::PackageOwnership
                | EvidenceSource::PackageVerification
        ),
    }
}

/// Count packages by installed-state evidence: (complete, incomplete, unknown).
fn installed_state_counts(
    tx: &TransactionRecord,
    input: &CorrelationInput,
) -> (usize, usize, usize) {
    let mut complete = 0;
    let mut incomplete = 0;
    let mut unknown = 0;

    for pkg in &tx.packages {
        // A removal has no installed end-state to confirm.
        if pkg.action.removes_files() && pkg.new_version.is_none() {
            continue;
        }
        match pkg.installed_complete {
            Some(true) => complete += 1,
            Some(false) => incomplete += 1,
            None => {
                if input.installed.contains_key(&pkg.name) {
                    complete += 1;
                } else if input.installed.is_empty() {
                    unknown += 1;
                } else {
                    incomplete += 1;
                }
            }
        }
    }

    (complete, incomplete, unknown)
}

/// Compare the versions the transaction recorded against what is installed now.
fn version_agreement(
    tx: &TransactionRecord,
    input: &CorrelationInput,
) -> (VerificationCheck, bool) {
    if input.installed.is_empty() {
        return (
            VerificationCheck::unavailable(
                "installed versions match the transaction",
                "package database unreadable".to_string(),
            ),
            false,
        );
    }

    let mut checked = 0usize;
    let mut disagreements = Vec::new();

    for pkg in &tx.packages {
        let Some(expected) = pkg.new_version.as_deref() else {
            continue;
        };
        let Some(actual) = input.installed.get(&pkg.name) else {
            continue;
        };
        checked += 1;
        if actual != expected {
            disagreements.push(format!("{}: expected {expected}, found {actual}", pkg.name));
        }
    }

    if !disagreements.is_empty() {
        return (
            VerificationCheck::failed(
                "installed versions match the transaction",
                disagreements.join("; "),
            ),
            true,
        );
    }
    if checked == 0 {
        return (
            VerificationCheck::unavailable(
                "installed versions match the transaction",
                "no comparable version recorded".to_string(),
            ),
            false,
        );
    }

    (
        VerificationCheck::passed(
            "installed versions match the transaction",
            format!("{checked} package version(s) agree"),
        ),
        false,
    )
}

/// Confirm each refreshed snap's replacement revision is actually present and
/// current, and that the old revision is gone or explicitly retained.
fn snap_revision_check(
    tx: &TransactionRecord,
    input: &CorrelationInput,
) -> (Option<VerificationCheck>, bool) {
    if input.snap_states.is_empty() {
        return (
            Some(VerificationCheck::unavailable(
                "replacement revision active",
                "snap revision state unreadable".to_string(),
            )),
            false,
        );
    }

    let mut confirmed = 0usize;
    let mut problems = Vec::new();

    for pkg in &tx.packages {
        let Some(state) = input.snap_states.get(&pkg.name) else {
            problems.push(format!("{}: revision state unavailable", pkg.name));
            continue;
        };
        let Some(expected) = pkg.new_version.as_deref() else {
            continue;
        };

        if !state.has_revision(expected) {
            problems.push(format!(
                "{}: replacement revision {expected} is not present",
                pkg.name
            ));
            continue;
        }
        match state.current.as_deref() {
            Some(current) if current == expected => confirmed += 1,
            Some(current) => problems.push(format!(
                "{}: current revision is {current}, expected {expected}",
                pkg.name
            )),
            None => problems.push(format!("{}: no current revision link", pkg.name)),
        }
    }

    if !problems.is_empty() {
        return (
            Some(VerificationCheck::failed(
                "replacement revision active",
                problems.join("; "),
            )),
            true,
        );
    }

    if confirmed == 0 {
        return (
            Some(VerificationCheck::unavailable(
                "replacement revision active",
                "no replacement revision recorded to confirm".to_string(),
            )),
            false,
        );
    }

    (
        Some(VerificationCheck::passed(
            "replacement revision active",
            format!("{confirmed} snap(s) running the new revision"),
        )),
        false,
    )
}
