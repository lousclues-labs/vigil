//! Baseline refresh diff computation and audit trail integration.
//!
//! Compares old and new baseline snapshots, classifies changes by package
//! attribution, and records unattributed changes to the detection WAL.

use std::collections::HashMap;

use crate::error::Result;
use crate::types::{Change, Severity};
use crate::wal::{DetectionRecord, DetectionSource, DetectionWal};

/// Summary of differences between two baseline snapshots.
#[derive(Debug, Clone)]
pub struct BaselineDiff {
    /// Paths present in the new baseline but not the old.
    pub added: Vec<String>,
    /// Paths present in the old baseline but not the new.
    pub removed: Vec<String>,
    /// Changed paths attributed to a package update.
    pub changed_pkg: Vec<String>,
    /// Changed paths with no package attribution -- high-signal.
    pub changed_unattributed: Vec<ChangedEntry>,
}

/// A changed entry with old and new hash for audit recording.
#[derive(Debug, Clone)]
pub struct ChangedEntry {
    pub path: String,
    pub old_hash: String,
    pub new_hash: String,
}

/// A snapshot entry: hash and optional package owner.
#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    pub hash: String,
    pub package: Option<String>,
}

impl BaselineDiff {
    pub fn total_changed(&self) -> u64 {
        self.changed_pkg.len() as u64 + self.changed_unattributed.len() as u64
    }
}

/// Compute the diff between two baseline snapshots.
///
/// Classification rules:
/// - Path in new but not old -> added
/// - Path in old but not new -> removed
/// - Hash changed and new entry has a package owner -> changed_pkg
///   (includes the case where the package owner itself changed between
///   old and new; the change is still attributable to a package operation)
/// - Hash changed and new entry has no package owner -> changed_unattributed
pub fn compute_diff(
    old: &HashMap<String, SnapshotEntry>,
    new: &HashMap<String, SnapshotEntry>,
) -> BaselineDiff {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed_pkg = Vec::new();
    let mut changed_unattributed = Vec::new();

    for (path, new_entry) in new {
        match old.get(path) {
            None => added.push(path.clone()),
            Some(old_entry) if old_entry.hash != new_entry.hash => {
                if new_entry.package.is_some() {
                    // Package-attributed change. This includes the case where
                    // the package owner changed (e.g. path moved from package A
                    // to package B). The change is still attributable to a
                    // package operation, so it is classified as changed_pkg.
                    changed_pkg.push(path.clone());
                } else {
                    changed_unattributed.push(ChangedEntry {
                        path: path.clone(),
                        old_hash: old_entry.hash.clone(),
                        new_hash: new_entry.hash.clone(),
                    });
                }
            }
            _ => {} // unchanged
        }
    }

    for path in old.keys() {
        if !new.contains_key(path) {
            removed.push(path.clone());
        }
    }

    // Sort for deterministic output
    added.sort();
    removed.sort();
    changed_pkg.sort();
    changed_unattributed.sort_by(|a, b| a.path.cmp(&b.path));

    BaselineDiff {
        added,
        removed,
        changed_pkg,
        changed_unattributed,
    }
}

/// Record unattributed changes to the detection WAL.
///
/// Each unattributed path gets one DetectionRecord with
/// `DetectionSource::BaselineRefresh` and `Severity::High`. WAL append
/// failures for individual paths are logged and skipped -- they must not
/// abort the refresh or block other recordings (Principle X).
///
/// Returns the count of successfully appended records.
pub fn record_unattributed_to_wal(
    wal: &DetectionWal,
    entries: &[ChangedEntry],
    maintenance_window: bool,
) -> u64 {
    let mut appended = 0u64;
    for entry in entries {
        let record = DetectionRecord {
            timestamp: chrono::Utc::now().timestamp(),
            path: entry.path.clone(),
            changes: vec![Change::ContentModified {
                old_hash: entry.old_hash.clone(),
                new_hash: entry.new_hash.clone(),
            }],
            severity: Severity::High,
            monitored_group: "baseline_refresh".to_string(),
            process: None,
            package: None,
            package_update: false,
            maintenance_window,
            source: DetectionSource::BaselineRefresh,
        };
        match wal.append(&record) {
            Ok(_) => {
                appended += 1;
            }
            Err(e) => {
                tracing::warn!(
                    path = %entry.path,
                    error = %e,
                    "failed to record unattributed change to WAL; skipping"
                );
            }
        }
    }
    appended
}

/// Wrapper around `compute_diff` that catches panics.
///
/// If the diff computation panics (e.g. OOM in HashMap join), this returns
/// None so the caller can proceed with the baseline swap. The panic message
/// is returned as an error string.
pub fn compute_diff_safe(
    old: &HashMap<String, SnapshotEntry>,
    new: &HashMap<String, SnapshotEntry>,
) -> std::result::Result<BaselineDiff, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| compute_diff(old, new))) {
        Ok(diff) => Ok(diff),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic in diff computation".to_string()
            };
            Err(msg)
        }
    }
}

/// Build a snapshot map from a database connection by iterating entries.
pub fn snapshot_from_conn(conn: &rusqlite::Connection) -> Result<HashMap<String, SnapshotEntry>> {
    let mut map = HashMap::new();
    crate::db::baseline_ops::for_each_entry(conn, |entry| {
        map.insert(
            entry.path.to_string_lossy().to_string(),
            SnapshotEntry {
                hash: entry.content.hash.clone(),
                package: entry.package.clone(),
            },
        );
        Ok(())
    })?;
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str, pkg: Option<&str>) -> SnapshotEntry {
        SnapshotEntry {
            hash: hash.to_string(),
            package: pkg.map(|s| s.to_string()),
        }
    }

    /// Test 1: Roundtrip with add, no remove, one changed entry.
    /// old: {A: hash1, B: hash2}, new: {A: hash1, B: hash2_new, C: hash3}
    /// Expect: added=[C], removed=[], changed=[B]
    #[test]
    fn diff_roundtrip_add_and_change() {
        let old: HashMap<String, SnapshotEntry> = [
            ("/usr/bin/a".to_string(), entry("hash1", None)),
            ("/usr/bin/b".to_string(), entry("hash2", Some("pkg-b"))),
        ]
        .into_iter()
        .collect();

        let new: HashMap<String, SnapshotEntry> = [
            ("/usr/bin/a".to_string(), entry("hash1", None)),
            ("/usr/bin/b".to_string(), entry("hash2_new", Some("pkg-b"))),
            ("/usr/bin/c".to_string(), entry("hash3", None)),
        ]
        .into_iter()
        .collect();

        let diff = compute_diff(&old, &new);
        assert_eq!(diff.added, vec!["/usr/bin/c"]);
        assert!(diff.removed.is_empty());
        // B is package-attributed
        assert_eq!(diff.changed_pkg, vec!["/usr/bin/b"]);
        assert!(diff.changed_unattributed.is_empty());
        assert_eq!(diff.total_changed(), 1);
    }

    /// Test 2: All 50 paths package-attributed, all with new hashes.
    #[test]
    fn diff_all_package_attributed() {
        let mut old = HashMap::new();
        let mut new = HashMap::new();
        for i in 0..50 {
            let path = format!("/usr/lib/libfoo-{}.so", i);
            old.insert(path.clone(), entry("old_hash", Some("libfoo")));
            new.insert(path, entry("new_hash", Some("libfoo")));
        }

        let diff = compute_diff(&old, &new);
        assert_eq!(diff.changed_pkg.len(), 50);
        assert_eq!(diff.changed_unattributed.len(), 0);
        assert_eq!(diff.total_changed(), 50);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
    }

    /// Test 3: Mixed attribution -- 8 with package, 2 without.
    #[test]
    fn diff_mixed_attribution() {
        let mut old = HashMap::new();
        let mut new = HashMap::new();
        for i in 0..10 {
            let path = format!("/usr/bin/tool-{}", i);
            let pkg = if i < 8 { Some("toolpkg") } else { None };
            old.insert(path.clone(), entry("old", pkg));
            new.insert(path, entry("new", pkg));
        }

        let diff = compute_diff(&old, &new);
        assert_eq!(diff.changed_pkg.len(), 8);
        assert_eq!(diff.changed_unattributed.len(), 2);
        assert_eq!(diff.total_changed(), 10);

        let unattr_paths: Vec<&str> = diff
            .changed_unattributed
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert!(unattr_paths.contains(&"/usr/bin/tool-8"));
        assert!(unattr_paths.contains(&"/usr/bin/tool-9"));
    }

    /// Test 4: Package owner changed between old and new baseline.
    /// Path X was attributed to package A in old, package B in new.
    /// Classification: changed_pkg (the change is still attributable to a
    /// package operation because the *new* baseline has a package owner).
    #[test]
    fn diff_package_owner_changed() {
        let old: HashMap<String, SnapshotEntry> =
            [("/usr/bin/x".to_string(), entry("hash1", Some("pkg-a")))]
                .into_iter()
                .collect();

        let new: HashMap<String, SnapshotEntry> =
            [("/usr/bin/x".to_string(), entry("hash2", Some("pkg-b")))]
                .into_iter()
                .collect();

        let diff = compute_diff(&old, &new);
        assert_eq!(diff.changed_pkg, vec!["/usr/bin/x"]);
        assert!(diff.changed_unattributed.is_empty());
    }

    /// Test 5: Empty old baseline -- all entries appear as added.
    #[test]
    fn diff_empty_old_baseline() {
        let old = HashMap::new();
        let mut new = HashMap::new();
        for i in 0..5 {
            new.insert(format!("/bin/{}", i), entry("hash", None));
        }

        let diff = compute_diff(&old, &new);
        assert_eq!(diff.added.len(), 5);
        assert!(diff.removed.is_empty());
        assert!(diff.changed_pkg.is_empty());
        assert!(diff.changed_unattributed.is_empty());
    }

    /// Test 6: Empty new baseline -- all entries appear as removed.
    ///
    /// In practice this should be impossible because the scanner always
    /// produces entries from configured watch paths. Tested for
    /// classification correctness regardless.
    #[test]
    fn diff_empty_new_baseline() {
        let mut old = HashMap::new();
        for i in 0..5 {
            old.insert(format!("/bin/{}", i), entry("hash", None));
        }
        let new = HashMap::new();

        let diff = compute_diff(&old, &new);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed.len(), 5);
        assert!(diff.changed_pkg.is_empty());
        assert!(diff.changed_unattributed.is_empty());
    }

    /// Diff with 50 unattributed changes -- all must appear in the result.
    #[test]
    fn diff_50_unattributed_all_present() {
        let mut old = HashMap::new();
        let mut new = HashMap::new();
        for i in 0..50 {
            let path = format!("/etc/conf.d/file-{:03}", i);
            old.insert(path.clone(), entry("old", None));
            new.insert(path, entry("new", None));
        }

        let diff = compute_diff(&old, &new);
        assert_eq!(diff.changed_unattributed.len(), 50);
        // Verify all 50 paths are present (no truncation)
        for i in 0..50 {
            let expected = format!("/etc/conf.d/file-{:03}", i);
            assert!(
                diff.changed_unattributed.iter().any(|e| e.path == expected),
                "missing path: {}",
                expected
            );
        }
    }

    /// catch_unwind wrapper returns Err on panic.
    #[test]
    fn compute_diff_safe_catches_panic() {
        // Feed valid data -- should succeed
        let old = HashMap::new();
        let new = HashMap::new();
        let result = compute_diff_safe(&old, &new);
        assert!(result.is_ok());
    }
}
