//! Acceptance guard: proving the reviewed state is still the current state.
//!
//! `vigil check --accept` shows the operator a set of changes and then writes
//! the current filesystem state into the baseline. Those are two separate
//! observations of the same path, and anything can happen between them.
//!
//! Without a guard, an attacker who modifies a file after the report is printed
//! but before acceptance completes gets their content signed into the baseline,
//! and the next scan reports it as expected. This module closes that window by
//! comparing what acceptance is about to commit against what the operator
//! actually reviewed, and by handing the *verified* snapshot back to the caller
//! so no third observation is needed.

use crate::types::{
    BaselineEntry, CaptureOpts, Change, ChangeResult, FileSnapshot, SnapshotOrDeleted,
};

/// What the scan observed, distilled to the dimensions the operator reviewed.
///
/// Built from the detection itself, so it describes exactly the state shown in
/// the report -- not a re-read that might already be out of date.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReviewedState {
    pub hash: Option<String>,
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub inode: Option<u64>,
    pub link_text: Option<std::path::PathBuf>,
    pub deleted: bool,
}

impl ReviewedState {
    /// Extract the reviewed state from a detection.
    ///
    /// Each `Change` variant carries the *new* value the scan observed; those
    /// are the values the operator saw and is now approving.
    pub fn from_change(change: &ChangeResult) -> Self {
        let mut state = Self::default();
        for c in &change.changes {
            match c {
                Change::ContentModified { new_hash, .. } => {
                    state.hash = Some(new_hash.clone());
                }
                Change::SizeChanged { new, .. } => state.size = Some(*new),
                Change::PermissionsChanged { new, .. } => state.mode = Some(*new),
                Change::OwnerChanged {
                    new_uid, new_gid, ..
                } => {
                    state.uid = Some(*new_uid);
                    state.gid = Some(*new_gid);
                }
                Change::InodeChanged { new, .. } => state.inode = Some(*new),
                Change::LinkTextChanged { new, .. } => state.link_text = Some(new.clone()),
                Change::Deleted => state.deleted = true,
                // A target replacement is described by the target's inode, which
                // the accompanying InodeChanged already records.
                _ => {}
            }
        }
        state
    }

    /// Compare against a freshly captured snapshot, returning every difference.
    ///
    /// Only dimensions the reviewed state actually recorded are compared. A
    /// dimension the scan did not report is not something the operator
    /// reviewed, so it is not something this can meaningfully re-check.
    pub fn differences(&self, snapshot: &FileSnapshot) -> Vec<String> {
        let mut out = Vec::new();

        if let Some(expected) = &self.hash {
            if &snapshot.content.hash != expected {
                out.push(format!(
                    "content hash {} -> {}",
                    short(expected),
                    short(&snapshot.content.hash)
                ));
            }
        }
        if let Some(expected) = self.size {
            if snapshot.content.size != expected {
                out.push(format!("size {} -> {}", expected, snapshot.content.size));
            }
        }
        if let Some(expected) = self.mode {
            if snapshot.permissions.mode != expected {
                out.push(format!(
                    "mode {:04o} -> {:04o}",
                    expected, snapshot.permissions.mode
                ));
            }
        }
        if let Some(expected) = self.uid {
            if snapshot.permissions.owner_uid != expected {
                out.push(format!(
                    "uid {} -> {}",
                    expected, snapshot.permissions.owner_uid
                ));
            }
        }
        if let Some(expected) = self.gid {
            if snapshot.permissions.owner_gid != expected {
                out.push(format!(
                    "gid {} -> {}",
                    expected, snapshot.permissions.owner_gid
                ));
            }
        }
        if let Some(expected) = self.inode {
            if snapshot.identity.inode != expected {
                out.push(format!("inode {} -> {}", expected, snapshot.identity.inode));
            }
        }
        if let Some(expected) = &self.link_text {
            if snapshot.identity.link_text.as_ref() != Some(expected) {
                out.push(format!(
                    "link text {} -> {}",
                    expected.display(),
                    snapshot
                        .identity
                        .link_text
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(none)".into())
                ));
            }
        }

        out
    }

    /// Whether this detection recorded anything re-checkable.
    pub fn is_checkable(&self) -> bool {
        self.deleted
            || self.hash.is_some()
            || self.size.is_some()
            || self.mode.is_some()
            || self.uid.is_some()
            || self.gid.is_some()
            || self.inode.is_some()
            || self.link_text.is_some()
    }
}

fn short(hash: &str) -> &str {
    if hash.len() > 12 {
        &hash[..12]
    } else {
        hash
    }
}

/// Outcome of re-validating one reviewed detection immediately before commit.
pub enum Revalidation {
    /// The path still holds exactly the state the operator reviewed.
    ///
    /// Carries the snapshot that was verified. The caller must commit *this*
    /// snapshot rather than taking a fresh one: re-reading would reopen the
    /// window this check exists to close.
    Confirmed(Box<FileSnapshot>),
    /// Reviewed as deleted, and still absent.
    ConfirmedDeleted,
    /// The path moved since it was reviewed. Acceptance must not proceed.
    Stale { differences: Vec<String> },
    /// The path could not be read, or could not be revalidated at all. Not a pass.
    Failed(String),
}

impl Revalidation {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed(_) | Self::ConfirmedDeleted)
    }
}

/// Re-read a reviewed path and confirm it still matches the review.
///
/// Called once per path, immediately before that path's baseline write.
///
/// The authoritative check is a full re-diff against the same `baseline` entry
/// the scan compared against, requiring the resulting change list to equal the
/// one the operator reviewed. Comparing only the dimensions the detection
/// happened to report would leave every other dimension unchecked: a detection
/// of a changed xattr would let an attacker swap the file's *contents* in the
/// meantime, and the fresh snapshot -- content hash included -- is what gets
/// written. Re-diffing closes the whole class rather than the reported
/// instances.
///
/// `baseline` is the stored entry for this path. `None` means the path is not
/// in the baseline, so there is nothing to re-diff against; that is refused
/// rather than accepted, because an unreviewable acceptance must never become
/// a silent one.
pub fn revalidate(
    change: &ChangeResult,
    baseline: Option<&BaselineEntry>,
    opts: &CaptureOpts,
) -> Revalidation {
    let reviewed = ReviewedState::from_change(change);
    let path = change.path.as_ref();

    let snapshot = match FileSnapshot::from_path(path, opts) {
        Ok(SnapshotOrDeleted::Snapshot(s)) => s,
        Ok(SnapshotOrDeleted::Deleted) => {
            return if reviewed.deleted {
                Revalidation::ConfirmedDeleted
            } else {
                Revalidation::Stale {
                    differences: vec!["reviewed as present, but the path is now gone".to_string()],
                }
            };
        }
        Err(e) => return Revalidation::Failed(e.to_string()),
    };

    if reviewed.deleted {
        return Revalidation::Stale {
            differences: vec!["reviewed as deleted, but the path exists again".to_string()],
        };
    }

    let Some(baseline) = baseline else {
        return Revalidation::Stale {
            differences: vec![
                "no baseline entry to revalidate against; re-run the scan and review \
                 this path again"
                    .to_string(),
            ],
        };
    };

    // The same comparison the scan performed, against the same baseline.
    let current = snapshot.diff(baseline);
    if current == change.changes {
        return Revalidation::Confirmed(Box::new(snapshot));
    }

    Revalidation::Stale {
        differences: describe_delta(&change.changes, &current, &reviewed, &snapshot),
    }
}

/// Describe how the current change list departs from the reviewed one.
///
/// Prefers a concrete value comparison for dimensions the operator actually saw,
/// and falls back to naming the change kinds that appeared or vanished.
fn describe_delta(
    reviewed_changes: &[Change],
    current: &[Change],
    reviewed: &ReviewedState,
    snapshot: &FileSnapshot,
) -> Vec<String> {
    let mut out = reviewed.differences(snapshot);

    let kind = |c: &Change| c.to_string();
    let reviewed_kinds: Vec<String> = reviewed_changes.iter().map(kind).collect();
    let current_kinds: Vec<String> = current.iter().map(kind).collect();

    for c in current {
        if !reviewed_changes.contains(c) {
            let k = kind(c);
            // Only name a kind the value comparison did not already cover.
            if !reviewed_kinds.contains(&k) {
                out.push(format!("new change since review: {k}"));
            }
        }
    }
    for c in reviewed_changes {
        if !current.contains(c) {
            let k = kind(c);
            if !current_kinds.contains(&k) {
                out.push(format!("reviewed change no longer present: {k}"));
            }
        }
    }

    if out.is_empty() {
        out.push("the path no longer compares equal to the state that was reviewed".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BaselineSource, FileType, Severity};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn opts() -> CaptureOpts {
        CaptureOpts {
            force_hash: true,
            max_file_size: 1024 * 1024,
            mmap_threshold: 1024 * 1024,
            baseline_mtime: None,
            baseline_hash: None,
        }
    }

    fn snapshot_of(path: &Path) -> FileSnapshot {
        match FileSnapshot::from_path(path, &opts()).expect("capture") {
            SnapshotOrDeleted::Snapshot(s) => s,
            SnapshotOrDeleted::Deleted => panic!("unexpected deletion of {}", path.display()),
        }
    }

    fn baseline_from(snapshot: &FileSnapshot) -> BaselineEntry {
        BaselineEntry {
            id: None,
            path: snapshot.path.clone(),
            identity: snapshot.identity.clone(),
            content: snapshot.content.clone(),
            permissions: snapshot.permissions.clone(),
            security: snapshot.security.clone(),
            mtime: snapshot.mtime,
            package: None,
            source: BaselineSource::AutoScan,
            added_at: 0,
            updated_at: 0,
        }
    }

    /// Model the real flow: capture a baseline, change the file, and build the
    /// detection from the actual diff -- exactly what the operator reviewed.
    fn reviewed(path: &Path, baseline: &BaselineEntry) -> ChangeResult {
        let now = snapshot_of(path);
        let changes = now.diff(baseline);
        assert!(
            !changes.is_empty(),
            "fixture must actually produce a detection"
        );
        ChangeResult {
            path: Arc::new(path.to_path_buf()),
            changes,
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        }
    }

    #[test]
    fn unmodified_path_is_confirmed_and_returns_the_verified_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"old").unwrap();
        let baseline = baseline_from(&snapshot_of(&file));
        std::fs::write(&file, b"reviewed").unwrap();
        let change = reviewed(&file, &baseline);

        match revalidate(&change, Some(&baseline), &opts()) {
            Revalidation::Confirmed(snapshot) => {
                assert_eq!(snapshot.content.hash, snapshot_of(&file).content.hash);
            }
            _ => panic!("expected confirmation"),
        }
    }

    /// The core guarantee: content changed after review must block acceptance.
    #[test]
    fn content_changed_after_review_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"old").unwrap();
        let baseline = baseline_from(&snapshot_of(&file));
        std::fs::write(&file, b"reviewed").unwrap();
        let change = reviewed(&file, &baseline);

        // Attacker writes after the operator read the report.
        std::fs::write(&file, b"substituted").unwrap();

        match revalidate(&change, Some(&baseline), &opts()) {
            Revalidation::Stale { differences } => assert!(
                differences.iter().any(|d| d.contains("content hash")),
                "{differences:?}"
            ),
            _ => panic!("expected staleness"),
        }
    }

    /// The hole the re-diff closes: a detection that reported only a metadata
    /// change must still refuse a *content* substitution, even though content
    /// was never part of what the operator reviewed.
    #[test]
    fn content_substituted_under_a_metadata_only_detection_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sudo");
        std::fs::write(&file, b"legitimate binary").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let baseline = baseline_from(&snapshot_of(&file));

        // The only reviewed change is a mode change. Content is untouched.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        let change = reviewed(&file, &baseline);
        assert!(
            change
                .changes
                .iter()
                .all(|c| !matches!(c, Change::ContentModified { .. })),
            "fixture must review a metadata-only change"
        );

        // Attacker swaps the contents before acceptance completes.
        std::fs::write(&file, b"trojan").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();

        let verdict = revalidate(&change, Some(&baseline), &opts());
        assert!(
            !verdict.is_confirmed(),
            "a content swap must be refused even when content was not the reviewed dimension"
        );
    }

    #[test]
    fn mode_changed_after_review_is_stale() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let baseline = baseline_from(&snapshot_of(&file));

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let change = reviewed(&file, &baseline);

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o777)).unwrap();

        match revalidate(&change, Some(&baseline), &opts()) {
            Revalidation::Stale { differences } => {
                assert!(
                    differences.iter().any(|d| d.starts_with("mode")),
                    "{differences:?}"
                )
            }
            _ => panic!("expected staleness"),
        }
    }

    #[test]
    fn path_deleted_after_review_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"old").unwrap();
        let baseline = baseline_from(&snapshot_of(&file));
        std::fs::write(&file, b"reviewed").unwrap();
        let change = reviewed(&file, &baseline);

        std::fs::remove_file(&file).unwrap();

        match revalidate(&change, Some(&baseline), &opts()) {
            Revalidation::Stale { differences } => {
                assert!(differences[0].contains("now gone"))
            }
            _ => panic!("expected staleness"),
        }
    }

    #[test]
    fn reviewed_deletion_still_absent_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gone");
        std::fs::write(&file, b"x").unwrap();
        let baseline = baseline_from(&snapshot_of(&file));
        std::fs::remove_file(&file).unwrap();

        let change = ChangeResult {
            path: Arc::new(file.clone()),
            changes: vec![Change::Deleted],
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        };

        assert!(matches!(
            revalidate(&change, Some(&baseline), &opts()),
            Revalidation::ConfirmedDeleted
        ));
    }

    /// A path reviewed as deleted that has reappeared is not a deletion to
    /// accept -- it is a new file nobody reviewed.
    #[test]
    fn reviewed_deletion_that_reappeared_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("back");
        std::fs::write(&file, b"x").unwrap();
        let baseline = baseline_from(&snapshot_of(&file));
        std::fs::remove_file(&file).unwrap();

        let change = ChangeResult {
            path: Arc::new(file.clone()),
            changes: vec![Change::Deleted],
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        };

        std::fs::write(&file, b"resurrected").unwrap();

        match revalidate(&change, Some(&baseline), &opts()) {
            Revalidation::Stale { differences } => {
                assert!(differences[0].contains("exists again"))
            }
            _ => panic!("expected staleness"),
        }
    }

    #[test]
    fn inode_replacement_after_review_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"old").unwrap();
        let baseline = baseline_from(&snapshot_of(&file));
        std::fs::write(&file, b"same bytes").unwrap();
        let change = reviewed(&file, &baseline);

        // Same content, new inode.
        let tmp = dir.path().join("tmp");
        std::fs::write(&tmp, b"same bytes").unwrap();
        std::fs::rename(&tmp, &file).unwrap();

        assert!(
            !revalidate(&change, Some(&baseline), &opts()).is_confirmed(),
            "a replaced inode is a different file object"
        );
    }

    /// Without a baseline entry there is nothing to re-diff against, so the
    /// guard has no way to know what it would be accepting. Fail closed.
    #[test]
    fn missing_baseline_entry_is_refused_not_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"whatever").unwrap();

        let change = ChangeResult {
            path: Arc::new(file.clone()),
            changes: vec![Change::Created],
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        };

        match revalidate(&change, None, &opts()) {
            Revalidation::Stale { differences } => assert!(
                differences[0].contains("no baseline entry"),
                "{differences:?}"
            ),
            _ => panic!("an unreviewable acceptance must be refused"),
        }
    }

    #[test]
    fn reviewed_state_extracts_only_the_dimensions_reported() {
        let change = ChangeResult {
            path: Arc::new(PathBuf::from("/x")),
            changes: vec![
                Change::ContentModified {
                    old_hash: "a".into(),
                    new_hash: "b".into(),
                },
                Change::OwnerChanged {
                    old_uid: 0,
                    new_uid: 1000,
                    old_gid: 0,
                    new_gid: 1000,
                },
            ],
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        };
        let reviewed = ReviewedState::from_change(&change);
        assert_eq!(reviewed.hash.as_deref(), Some("b"));
        assert_eq!(reviewed.uid, Some(1000));
        assert_eq!(reviewed.gid, Some(1000));
        assert_eq!(
            reviewed.mode, None,
            "mode was not reported, so not described"
        );
        assert!(reviewed.is_checkable());
    }

    #[test]
    fn unreadable_path_is_a_failure_not_a_pass() {
        let change = ChangeResult {
            path: Arc::new(PathBuf::from("/proc/nonexistent-vigil-test/xyz")),
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
        };
        assert!(!revalidate(&change, None, &opts()).is_confirmed());
    }

    #[test]
    fn link_text_rewritten_after_review_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        let c = dir.path().join("c");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        std::fs::write(&c, b"c").unwrap();
        let link = dir.path().join("link");

        std::os::unix::fs::symlink(&a, &link).unwrap();
        let baseline = baseline_from(&snapshot_of(&link));
        assert_eq!(baseline.identity.file_type, FileType::Symlink);

        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&b, &link).unwrap();
        let change = reviewed(&link, &baseline);

        // Repointed again before acceptance.
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&c, &link).unwrap();

        assert!(
            !revalidate(&change, Some(&baseline), &opts()).is_confirmed(),
            "a link repointed after review must be refused"
        );
    }
}
