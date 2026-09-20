//! Package content verification: the difference between "a package owns this
//! path" and "a package wrote these bytes".
//!
//! Ownership is a claim about where a file lives. Verification is a claim
//! about what is in it. Before these tests existed, a baseline refresh
//! classified any changed file under a package-owned path as a routine
//! package update and absorbed it silently, which meant a tampered
//! `/usr/bin/sudo` was laundered into the new baseline by the next `apt
//! upgrade` (AF-010).

use std::collections::HashMap;

use vigil::baseline_diff::{compute_diff, split_by_verification, ChangedEntry, SnapshotEntry};
use vigil::package::PackageVerification;

fn entry(hash: &str, package: Option<&str>) -> SnapshotEntry {
    SnapshotEntry {
        hash: hash.to_string(),
        package: package.map(|s| s.to_string()),
    }
}

fn changed(path: &str, package: Option<&str>) -> ChangedEntry {
    ChangedEntry {
        path: path.to_string(),
        old_hash: "old".into(),
        new_hash: "new".into(),
        package: package.map(|s| s.to_string()),
    }
}

/// The shape of a routine `apt upgrade`: many package files rewritten, all of
/// them matching the digests their packages recorded. None of these should
/// reach the operator.
#[test]
fn a_clean_package_upgrade_produces_nothing_the_operator_must_read() {
    let changes: Vec<ChangedEntry> = (0..250)
        .map(|i| changed(&format!("/usr/bin/tool-{i}"), Some("coreutils")))
        .collect();

    let verdicts: HashMap<String, PackageVerification> = changes
        .iter()
        .map(|c| (c.path.clone(), PackageVerification::Verified))
        .collect();

    let split = split_by_verification(&changes, &verdicts);

    assert_eq!(split.verified.len(), 250);
    assert_eq!(
        split.unproven_count(),
        0,
        "250 files that match their package's own digest are 250 files the \
         operator never needs to see"
    );
}

/// The case that matters: one file among hundreds whose content is not what
/// its package shipped. It must survive the flood.
#[test]
fn one_tampered_binary_survives_a_flood_of_legitimate_updates() {
    let mut changes: Vec<ChangedEntry> = (0..250)
        .map(|i| changed(&format!("/usr/bin/tool-{i}"), Some("coreutils")))
        .collect();
    changes.push(changed("/usr/bin/sudo", Some("sudo")));

    let mut verdicts: HashMap<String, PackageVerification> = changes
        .iter()
        .map(|c| (c.path.clone(), PackageVerification::Verified))
        .collect();
    verdicts.insert("/usr/bin/sudo".into(), PackageVerification::Mismatch);

    let split = split_by_verification(&changes, &verdicts);

    assert_eq!(split.verified.len(), 250);
    assert_eq!(split.mismatch.len(), 1);
    assert_eq!(split.mismatch[0].path, "/usr/bin/sudo");
    assert_eq!(
        split.unproven_count(),
        1,
        "the operator reads exactly one line, not 251"
    );
}

/// A config file the package marks operator-editable is expected to diverge.
/// Reporting those would rebuild the noise this exists to remove.
#[test]
fn operator_edited_config_files_are_not_treated_as_findings() {
    let changes = vec![
        changed("/etc/sudoers", Some("sudo")),
        changed("/etc/ssh/sshd_config", Some("openssh-server")),
    ];
    let verdicts: HashMap<String, PackageVerification> = changes
        .iter()
        .map(|c| (c.path.clone(), PackageVerification::Conffile))
        .collect();

    let split = split_by_verification(&changes, &verdicts);

    assert_eq!(split.conffile.len(), 2);
    assert_eq!(
        split.unproven_count(),
        0,
        "the operator editing their own sshd_config is not a security event"
    );
    assert!(split.mismatch.is_empty());
}

/// Silence from the verifier is not a pass. A path with no recorded verdict
/// must land in `unverifiable`, never in `verified`.
#[test]
fn a_path_with_no_verdict_is_never_counted_as_verified() {
    let changes = vec![changed("/usr/bin/mystery", Some("ghost-package"))];
    let verdicts = HashMap::new();

    let split = split_by_verification(&changes, &verdicts);

    assert!(
        split.verified.is_empty(),
        "absence of a verdict must never be read as proof"
    );
    assert_eq!(split.unverifiable.len(), 1);
    assert_eq!(split.unproven_count(), 1);
}

/// A file the package manager reports as gone is a finding, not a shrug.
#[test]
fn a_missing_package_file_is_a_finding() {
    let changes = vec![changed("/usr/bin/deleted", Some("somepkg"))];
    let mut verdicts = HashMap::new();
    verdicts.insert("/usr/bin/deleted".to_string(), PackageVerification::Missing);

    let split = split_by_verification(&changes, &verdicts);

    assert_eq!(split.mismatch.len(), 1);
    assert!(split.verified.is_empty());
}

/// The diff groups changed paths by owning package so verification runs once
/// per package rather than once per file. A 250-file upgrade of two packages
/// must produce two verification calls, not 250.
#[test]
fn changed_paths_are_grouped_by_package_for_verification() {
    let mut old = HashMap::new();
    let mut new = HashMap::new();

    for i in 0..100 {
        let path = format!("/usr/bin/a-{i}");
        old.insert(path.clone(), entry("old", Some("pkg-a")));
        new.insert(path, entry("new", Some("pkg-a")));
    }
    for i in 0..150 {
        let path = format!("/usr/lib/b-{i}.so");
        old.insert(path.clone(), entry("old", Some("pkg-b")));
        new.insert(path, entry("new", Some("pkg-b")));
    }
    // An unattributed change must not be grouped under any package.
    old.insert("/usr/local/bin/x".to_string(), entry("old", None));
    new.insert("/usr/local/bin/x".to_string(), entry("new", None));

    let diff = compute_diff(&old, &new);
    let grouped = diff.changed_paths_by_package();

    assert_eq!(grouped.len(), 2, "one verification call per package");
    assert_eq!(grouped["pkg-a"].len(), 100);
    assert_eq!(grouped["pkg-b"].len(), 150);
    assert_eq!(diff.changed_unattributed.len(), 1);
    assert_eq!(diff.changed_unattributed[0].path, "/usr/local/bin/x");
}

/// The diff must carry the hashes forward so a mismatch can be recorded with
/// the evidence attached, not just the path.
#[test]
fn a_mismatch_carries_the_old_and_new_hash_for_the_audit_record() {
    let old: HashMap<String, SnapshotEntry> = [(
        "/usr/bin/sudo".to_string(),
        entry("baseline-hash", Some("sudo")),
    )]
    .into_iter()
    .collect();
    let new: HashMap<String, SnapshotEntry> = [(
        "/usr/bin/sudo".to_string(),
        entry("tampered-hash", Some("sudo")),
    )]
    .into_iter()
    .collect();

    let diff = compute_diff(&old, &new);
    let mut verdicts = HashMap::new();
    verdicts.insert("/usr/bin/sudo".to_string(), PackageVerification::Mismatch);
    let split = split_by_verification(&diff.changed_pkg, &verdicts);

    assert_eq!(split.mismatch.len(), 1);
    let finding = &split.mismatch[0];
    assert_eq!(finding.old_hash, "baseline-hash");
    assert_eq!(finding.new_hash, "tampered-hash");
    assert_eq!(finding.package.as_deref(), Some("sudo"));
}
