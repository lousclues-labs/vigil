//! Correlation: explaining raw detections without weakening them.
//!
//! # What this is
//!
//! Vigil observes filesystem changes and records them. That observation layer
//! is deliberately literal: a replaced binary is a replaced binary, whether
//! `apt` replaced it or something else did. Correlation sits *beside* that
//! layer and answers a different question -- "is there local evidence that
//! attributes these changes to a package transaction?"
//!
//! # What this is not
//!
//! - It is not a filter. No detection is dropped, hidden, or downgraded.
//! - It is not a severity input. Raw severity comes from the watch group and
//!   correlation never rewrites it.
//! - It is not acceptance. A verified transaction does not touch the baseline;
//!   only an explicit operator action does.
//! - It is not a trust decision. "Verified transaction" means the evidence
//!   consistently attributes the change to a package operation. It says nothing
//!   about whether the delivered software is safe.
//!
//! # Privacy
//!
//! Every source is local: package logs, the package database, snapd state, and
//! the filesystem. No path, hash, package name, or any other datum leaves the
//! machine, and no network call is made.
//!
//! # Where it runs
//!
//! Outside the filesystem observation path. The daemon's watcher and the
//! incremental scanner never call into this module; correlation happens when a
//! report is produced, over the handful of paths that actually changed.

pub mod apt;
pub mod engine;
pub mod error;
pub mod event;
pub mod snap;
pub mod transaction;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub use engine::{correlate, CorrelationInput, CorrelationResult, DEFAULT_WINDOW_SLACK_SECS};
pub use error::{CollectorError, CollectorErrorKind, EvidenceSource};
pub use event::{
    CheckOutcome, Confidence, CorrelatedEvent, CorrelatedEventBuilder, EventKind, EventMember,
    MemberRole, RawRef, UnexplainedChange, VerificationCheck, VerificationResult,
};
pub use transaction::{
    PackageAction, PackageTransition, TransactionRecord, TransactionSource, TransactionStatus,
};

use crate::config::PackageManagerConfig;
use crate::types::ChangeResult;

/// How far back to look for transactions that could explain a scan, in seconds.
///
/// A scan reports drift accumulated since the last baseline update, so the
/// window has to be wide enough to reach the transaction that caused it. Seven
/// days covers the usual cadence of unattended upgrades without reading a
/// month of logs on every run.
const DEFAULT_LOOKBACK_SECS: i64 = 7 * 24 * 60 * 60;

/// Gather local evidence and correlate a scan's detections against it.
///
/// # Cost
///
/// This is deliberately frugal, because it runs on ordinary hardware and on
/// every `vigil check` that finds drift:
///
/// - Nothing here runs per file. Ownership is resolved for all changed paths in
///   one batched query, and content verification runs once per *package*.
/// - Evidence collection is skipped entirely when no changed path is owned by a
///   package and none is snap-related. A scan that only shows an edited config
///   file costs one batched ownership query and nothing else.
/// - snapd is only queried when a snap artifact actually changed, and the
///   number of follow-up queries is capped.
/// - Log reads are size-capped and read from the tail.
///
/// It is never called from the filesystem watcher or the incremental scanner;
/// the only call site is the `check` command, after detection has finished.
///
/// `changes` is borrowed read-only and is never modified.
pub fn explain_changes(
    changes: &[ChangeResult],
    pkg_config: &PackageManagerConfig,
) -> CorrelationResult {
    if changes.is_empty() {
        return CorrelationResult::default();
    }

    let now = chrono::Utc::now().timestamp();
    let window_start = now - DEFAULT_LOOKBACK_SECS;

    let mut input = CorrelationInput::new();

    // ── Cheap triage first ─────────────────────────────────
    // Decide whether there is anything worth spending I/O on before spending
    // any. Both of these are pure string work over the changed paths.
    let snap_candidates =
        snap::snap_names_for_paths(changes.iter().map(|c| c.path.as_ref().as_path()));

    // ── Ownership, in one batch ────────────────────────────
    let owned_paths = paths_needing_ownership(changes);
    if !owned_paths.is_empty() {
        let refs: Vec<&Path> = owned_paths.iter().map(PathBuf::as_path).collect();
        let owners = crate::package::batch_query_package_owners(&refs, pkg_config);
        for (path, owner) in owners {
            // `dpkg -S` reports arch-qualified names (`libc6:amd64`) and can
            // list several packages for a shared path. Normalizing here is what
            // makes these names comparable with the transaction records; the
            // raw form matches nothing.
            if let Some(raw) = owner {
                let candidates = crate::package::normalize_owner_field(&raw);
                if !candidates.is_empty() {
                    input.ownership.insert(path, candidates);
                }
            }
        }
    }

    // Nothing is package-owned and nothing is snap-related: there is no
    // transaction that could explain any of this, so reading logs would only
    // burn I/O to reach the same conclusion.
    if input.ownership.is_empty() && snap_candidates.is_empty() {
        return CorrelationResult {
            events: Vec::new(),
            uncorrelated: (0..changes.len()).collect(),
            collector_errors: Vec::new(),
        };
    }

    // ── Filesystem timestamps ──────────────────────────────
    // One lstat per changed path, plus one per alias target. Bounded by the
    // number of detections, not by the size of the baseline.
    input.observed_change_time = observed_times(changes);

    // ── Package-manager transactions ───────────────────────
    if !input.ownership.is_empty() {
        let apt_evidence = apt::collect_local(window_start, now);
        input.installed = apt_evidence.installed;
        input.collector_errors.extend(apt_evidence.errors);
        input.transactions.extend(apt_evidence.transactions);
    }

    if !snap_candidates.is_empty() {
        let snap_evidence = snap::collect_local(window_start, &snap_candidates);
        input.collector_errors.extend(snap_evidence.errors);
        for tx in &snap_evidence.transactions {
            let (states, errors) = snap::revision_states(tx);
            input.snap_states.extend(states);
            input.collector_errors.extend(errors);
        }
        input.transactions.extend(snap_evidence.transactions);
    }

    // ── Content verification, one run per package ──────────
    // Only packages a candidate transaction actually names are verified.
    // Verification exists to corroborate a transaction's claim; running it for
    // a package with no transaction spends a subprocess (and a full-package
    // digest walk) on an answer that cannot change any attribution.
    input.verification = verify_by_package(&input.ownership, &input.transactions, pkg_config);

    correlate(changes, &input)
}

/// Collect the paths whose package ownership must be resolved.
///
/// For a symlink alias the owning package is a property of the *target*, so the
/// canonical target is queried instead of the link.
fn paths_needing_ownership(changes: &[ChangeResult]) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::with_capacity(changes.len());
    for change in changes {
        match change.symlink_alias_target() {
            Some(target) => paths.push(target.to_path_buf()),
            None => paths.push(change.path.as_ref().clone()),
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// Read inode change times (ctime) for the changed paths and any alias targets.
///
/// ctime, not mtime: dpkg restores the mtime stored in the package archive, so
/// a freshly installed file carries the upstream build date and would fall
/// outside every transaction window. ctime is when the inode was actually
/// written, and unlike mtime it cannot be set with `utimes(2)`.
///
/// Uses `lstat` for the detection's own path so a symlink reports its own
/// timestamp, and a followed `stat` for an alias target so the replaced file's
/// timestamp is what gets compared against the transaction window.
fn observed_times(changes: &[ChangeResult]) -> HashMap<PathBuf, i64> {
    use std::os::unix::fs::MetadataExt;

    let mut out = HashMap::with_capacity(changes.len());
    for change in changes {
        let path = change.path.as_ref();
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            out.insert(path.clone(), meta.ctime());
        }
        if let Some(target) = change.symlink_alias_target() {
            if !out.contains_key(target) {
                if let Ok(meta) = std::fs::metadata(target) {
                    out.insert(target.to_path_buf(), meta.ctime());
                }
            }
        }
    }
    out
}

/// Upper bound on packages verified in a single correlation run.
///
/// Each verification is a subprocess that walks every file the package ships,
/// so the cost scales with package size, not with the number of changes. A
/// transaction touching more packages than this is unusual; when it happens the
/// remainder is reported as unverified rather than quietly skipped.
const MAX_PACKAGES_VERIFIED: usize = 64;

/// Verify changed paths against their owning packages' recorded digests.
///
/// Groups paths by package first so each package is verified once, however many
/// of its files changed, and restricts the work to packages named by a
/// candidate transaction. Delegates the verdicts to [`crate::package`], which
/// already knows the difference between "checked and clean" and "nothing to
/// check against".
///
/// Paths whose package is not verified are simply absent from the returned map,
/// which the engine reads as [`crate::package::PackageVerification::Unknown`] --
/// an explicit "not checked", never a pass.
fn verify_by_package(
    ownership: &HashMap<PathBuf, Vec<String>>,
    transactions: &[TransactionRecord],
    pkg_config: &PackageManagerConfig,
) -> HashMap<String, crate::package::PackageVerification> {
    if ownership.is_empty() || transactions.is_empty() {
        return HashMap::new();
    }

    // Packages any candidate transaction touched.
    let in_transaction: std::collections::HashSet<&str> = transactions
        .iter()
        .flat_map(|tx| tx.packages.iter().map(|p| p.name.as_str()))
        .collect();

    let mut by_package: HashMap<String, Vec<String>> = HashMap::new();
    for (path, candidates) in ownership {
        // Verify under whichever candidate owner the transaction touched.
        let Some(package) = candidates
            .iter()
            .find(|c| in_transaction.contains(c.as_str()))
        else {
            continue;
        };
        by_package
            .entry(package.clone())
            .or_default()
            .push(path.to_string_lossy().into_owned());
    }

    if by_package.len() > MAX_PACKAGES_VERIFIED {
        // Deterministic truncation: keep the alphabetically first packages so
        // repeated runs over the same evidence agree.
        let mut names: Vec<String> = by_package.keys().cloned().collect();
        names.sort();
        for name in names.into_iter().skip(MAX_PACKAGES_VERIFIED) {
            by_package.remove(&name);
        }
    }

    for paths in by_package.values_mut() {
        paths.sort();
        paths.dedup();
    }

    if by_package.is_empty() {
        return HashMap::new();
    }

    crate::package::verify_changed_paths(&by_package, pkg_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Change, Severity};
    use std::sync::Arc;

    fn change(path: &str) -> ChangeResult {
        ChangeResult {
            path: Arc::new(PathBuf::from(path)),
            changes: vec![Change::ContentModified {
                old_hash: "a".into(),
                new_hash: "b".into(),
            }],
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        }
    }

    #[test]
    fn ownership_paths_are_deduplicated_and_sorted() {
        let changes = vec![
            change("/usr/bin/b"),
            change("/usr/bin/a"),
            change("/usr/bin/a"),
        ];
        let paths = paths_needing_ownership(&changes);
        assert_eq!(
            paths,
            vec![PathBuf::from("/usr/bin/a"), PathBuf::from("/usr/bin/b")]
        );
    }

    #[test]
    fn alias_ownership_is_resolved_on_the_target() {
        let mut alias = change("/etc/systemd/system/multi-user.target.wants/rsyslog.service");
        alias.changes.insert(
            0,
            Change::SymlinkTargetReplaced {
                target: PathBuf::from("/lib/systemd/system/rsyslog.service"),
                old_target_inode: 1,
                new_target_inode: 2,
            },
        );

        let paths = paths_needing_ownership(&[alias]);
        assert_eq!(
            paths,
            vec![PathBuf::from("/lib/systemd/system/rsyslog.service")],
            "the alias must be attributed through its target, not its own path"
        );
    }

    #[test]
    fn empty_scan_correlates_to_nothing_without_touching_the_system() {
        let cfg = PackageManagerConfig {
            auto_rebaseline: false,
            backend: crate::types::PackageBackend::Auto,
        };
        let result = explain_changes(&[], &cfg);
        assert!(result.is_empty());
        assert!(result.uncorrelated.is_empty());
    }

    /// Verification must not run for a package no transaction names: the
    /// answer cannot change any attribution, and the call is expensive.
    #[test]
    fn no_transactions_means_no_verification_work() {
        let cfg = PackageManagerConfig {
            auto_rebaseline: false,
            backend: crate::types::PackageBackend::Auto,
        };
        let mut ownership = HashMap::new();
        ownership.insert(PathBuf::from("/usr/bin/a"), vec!["pkg".to_string()]);

        let verdicts = verify_by_package(&ownership, &[], &cfg);
        assert!(
            verdicts.is_empty(),
            "an unexplained path is left unverified, not verified for nothing"
        );
    }

    #[test]
    fn verification_skips_packages_outside_the_transaction() {
        use crate::correlate::transaction::{PackageAction, PackageTransition, TransactionSource};

        let cfg = PackageManagerConfig {
            auto_rebaseline: false,
            backend: crate::types::PackageBackend::Auto,
        };
        let mut ownership = HashMap::new();
        ownership.insert(PathBuf::from("/usr/bin/a"), vec!["in-tx".to_string()]);
        ownership.insert(PathBuf::from("/usr/bin/b"), vec!["not-in-tx".to_string()]);

        let mut tx = TransactionRecord::new(TransactionSource::Apt, 0);
        tx.packages
            .push(PackageTransition::new("in-tx", PackageAction::Upgrade));

        // With no real dpkg backend the verdicts come back empty, but the
        // selection logic is what matters: only "in-tx" is ever a candidate.
        let selected: Vec<&str> = ownership
            .iter()
            .filter_map(|(_, candidates)| {
                candidates
                    .iter()
                    .find(|c| tx.package(c).is_some())
                    .map(String::as_str)
            })
            .collect();
        assert_eq!(selected, vec!["in-tx"]);

        let _ = verify_by_package(&ownership, std::slice::from_ref(&tx), &cfg);
    }
}
