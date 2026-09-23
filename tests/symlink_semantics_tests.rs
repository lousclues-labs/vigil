//! Symlink object versus symlink target semantics.
//!
//! Vigil follows symlinks when hashing, so a symlink's content/inode fields
//! describe its *target*. These tests pin the rule that a target replacement is
//! attributed to the target, while anything done to the link object itself is
//! attributed to the link -- and that neither is ever suppressed.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use vigil::types::{
    BaselineEntry, BaselineSource, CaptureOpts, Change, FileSnapshot, FileType, SnapshotOrDeleted,
};

fn opts() -> CaptureOpts {
    CaptureOpts {
        force_hash: true,
        max_file_size: 10 * 1024 * 1024,
        mmap_threshold: 1024 * 1024,
        baseline_mtime: None,
        baseline_hash: None,
    }
}

fn capture(path: &Path) -> FileSnapshot {
    match FileSnapshot::from_path(path, &opts()).expect("capture should succeed") {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("unexpected deletion for {}", path.display()),
    }
}

fn to_baseline(snap: &FileSnapshot) -> BaselineEntry {
    BaselineEntry {
        id: None,
        path: snap.path.clone(),
        identity: snap.identity.clone(),
        content: snap.content.clone(),
        permissions: snap.permissions.clone(),
        security: snap.security.clone(),
        mtime: snap.mtime,
        package: None,
        source: BaselineSource::Manual,
        added_at: 0,
        updated_at: 0,
    }
}

/// Replace a file's contents by rename, which gives the path a new inode.
fn replace_with_new_inode(target: &Path, contents: &str) {
    let tmp = target.with_extension("new");
    fs::write(&tmp, contents).unwrap();
    fs::rename(&tmp, target).unwrap();
}

/// Replace a symlink so the new link object is guaranteed a different inode.
///
/// Removing the link and recreating it does not guarantee that: the
/// filesystem may hand back the inode it just freed, and ext4 does so every
/// time. An earlier version of this test removed-then-recreated and so
/// asserted an allocator behaviour rather than a property of the code --
/// passing on tmpfs, which never reuses, and failing on ext4, which always
/// does. Creating the replacement while the original still exists means its
/// inode is still allocated and cannot be reused. This is also how tools
/// swap a symlink atomically.
fn replace_symlink_with_new_inode(link: &Path, target: &Path) {
    let tmp = link.with_extension("new");
    std::os::unix::fs::symlink(target, &tmp).unwrap();
    fs::rename(&tmp, link).unwrap();
}

/// The headline case: dpkg replaces a unit file, and the `/etc/systemd`
/// symlink pointing at it must not look independently replaced.
#[test]
fn target_inode_change_is_reported_as_alias_not_symlink_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("rsyslog.service");
    let link = dir.path().join("multi-user.target.wants-rsyslog.service");
    fs::write(&target, "old unit\n").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let before = capture(&link);
    let baseline = to_baseline(&before);
    let link_inode_before = before.identity.link_inode.expect("link inode captured");

    replace_with_new_inode(&target, "new unit\n");

    let after = capture(&link);
    let changes = after.diff(&baseline);

    // The symlink object did not move.
    assert_eq!(after.identity.link_inode, Some(link_inode_before));
    assert_eq!(after.identity.link_text, before.identity.link_text);

    // It is attributed to the target, and that attribution leads the list.
    let alias = changes
        .iter()
        .find_map(|c| match c {
            Change::SymlinkTargetReplaced {
                target: t,
                old_target_inode,
                new_target_inode,
            } => Some((t.clone(), *old_target_inode, *new_target_inode)),
            _ => None,
        })
        .expect("target replacement should be attributed to the target");
    assert_eq!(alias.0, fs::canonicalize(&target).unwrap());
    assert_ne!(alias.1, alias.2, "target inode should have moved");
    assert!(matches!(
        changes.first(),
        Some(Change::SymlinkTargetReplaced { .. })
    ));

    // Forensic detail is preserved, not collapsed away.
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::ContentModified { .. })),
        "raw content change must still be recorded: {changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::InodeChanged { .. })),
        "raw inode change must still be recorded: {changes:?}"
    );

    // And it is NOT reported as the link being repointed.
    assert!(
        !changes
            .iter()
            .any(|c| matches!(c, Change::LinkTextChanged { .. })),
        "link text did not change: {changes:?}"
    );
}

/// Several aliases to one replaced target each carry the same attribution.
#[test]
fn multiple_aliases_to_one_target_all_attribute_to_that_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("rsyslog.service");
    fs::write(&target, "old unit\n").unwrap();

    let links: Vec<PathBuf> = ["a.service", "b.service", "c.service"]
        .iter()
        .map(|n| {
            let l = dir.path().join(n);
            std::os::unix::fs::symlink(&target, &l).unwrap();
            l
        })
        .collect();

    let baselines: Vec<BaselineEntry> = links.iter().map(|l| to_baseline(&capture(l))).collect();

    replace_with_new_inode(&target, "new unit\n");

    let canonical = fs::canonicalize(&target).unwrap();
    for (link, baseline) in links.iter().zip(&baselines) {
        let changes = capture(link).diff(baseline);
        let alias = changes
            .iter()
            .find_map(|c| match c {
                Change::SymlinkTargetReplaced { target, .. } => Some(target.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{} should attribute to its target", link.display()));
        assert_eq!(alias, canonical);
    }
}

/// Rewriting the link itself is the link's change, never the target's.
#[test]
fn link_text_change_is_reported_as_link_text_change() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    fs::write(&first, "one\n").unwrap();
    fs::write(&second, "two\n").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&first, &link).unwrap();

    let baseline = to_baseline(&capture(&link));

    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&second, &link).unwrap();

    let changes = capture(&link).diff(&baseline);

    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::LinkTextChanged { .. })),
        "repointed link must report a link text change: {changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::SymlinkTargetChanged { .. })),
        "canonical target also changed: {changes:?}"
    );
    assert!(
        !changes
            .iter()
            .any(|c| matches!(c, Change::SymlinkTargetReplaced { .. })),
        "a repointed link is not an alias of a target replacement: {changes:?}"
    );
}

/// A link-text rewrite that resolves to the same file is still a change to the
/// link. Before symlink object tracking this was invisible.
#[test]
fn link_text_change_with_identical_canonical_target_is_still_detected() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "same\n").unwrap();
    let link = dir.path().join("link");

    std::os::unix::fs::symlink(&target, &link).unwrap();
    let baseline = to_baseline(&capture(&link));

    // Relative link text, identical resolution.
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink("target", &link).unwrap();

    let changes = capture(&link).diff(&baseline);
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::LinkTextChanged { .. })),
        "absolute-to-relative rewrite must be visible: {changes:?}"
    );
}

#[test]
fn relative_symlink_resolves_and_records_raw_link_text() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    let target = sub.join("target");
    fs::write(&target, "data\n").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("sub/target", &link).unwrap();

    let snap = capture(&link);
    assert_eq!(snap.identity.file_type, FileType::Symlink);
    assert_eq!(snap.identity.link_text, Some(PathBuf::from("sub/target")));
    assert_eq!(
        snap.identity.symlink_target,
        Some(fs::canonicalize(&target).unwrap()),
        "canonical target is resolved even for a relative link"
    );
}

/// A broken symlink still exists. Reporting it as deleted would be wrong.
#[test]
fn broken_symlink_is_captured_not_reported_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("gone");
    let link = dir.path().join("link");
    fs::write(&target, "x\n").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let baseline = to_baseline(&capture(&link));

    fs::remove_file(&target).unwrap();

    let snap = match FileSnapshot::from_path(&link, &opts()).expect("broken link should capture") {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("a broken symlink is not a deleted path"),
    };

    assert_eq!(snap.identity.file_type, FileType::Symlink);
    assert_eq!(
        snap.identity.symlink_target, None,
        "an unresolvable link has no canonical target"
    );
    assert_eq!(snap.identity.link_text, Some(target.clone()));

    // The target disappearing is a visible change, not silence.
    let changes = snap.diff(&baseline);
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::SymlinkTargetChanged { .. })),
        "target loss must surface: {changes:?}"
    );
    assert!(
        !changes.iter().any(|c| matches!(c, Change::Deleted)),
        "the link itself was not deleted: {changes:?}"
    );
}

/// Deleting the link itself is a deletion.
#[test]
fn deleted_symlink_is_reported_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "x\n").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let _ = capture(&link);

    fs::remove_file(&link).unwrap();

    assert!(matches!(
        FileSnapshot::from_path(&link, &opts()).expect("lookup should succeed"),
        SnapshotOrDeleted::Deleted
    ));
}

/// A symlink loop is unresolvable but present. It must not be a deletion and
/// must not hang or panic.
#[test]
fn symlink_loop_is_captured_not_reported_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::os::unix::fs::symlink(&b, &a).unwrap();
    std::os::unix::fs::symlink(&a, &b).unwrap();

    let snap = match FileSnapshot::from_path(&a, &opts()).expect("loop should capture") {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("a looping symlink is not a deleted path"),
    };

    assert_eq!(snap.identity.file_type, FileType::Symlink);
    assert_eq!(snap.identity.symlink_target, None);
    assert_eq!(snap.identity.link_text, Some(b.clone()));
}

/// An entry carried over from a pre-v3 baseline has no link fields. The alias
/// attribution must not fire on it: absence of evidence is not evidence.
#[test]
fn legacy_baseline_without_link_data_is_not_attributed_as_alias() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "old\n").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let mut baseline = to_baseline(&capture(&link));
    // Simulate an entry written before schema v3.
    baseline.identity.link_text = None;
    baseline.identity.link_inode = None;
    baseline.identity.link_device = None;

    replace_with_new_inode(&target, "new\n");

    let changes = capture(&link).diff(&baseline);
    assert!(
        !changes
            .iter()
            .any(|c| matches!(c, Change::SymlinkTargetReplaced { .. })),
        "without baseline link data the alias claim is unprovable: {changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::InodeChanged { .. })),
        "the raw change is still reported: {changes:?}"
    );
}

/// Replacing the symlink object itself while keeping the same text is a change
/// to the link, not an alias of a target change.
#[test]
fn symlink_object_replacement_is_not_treated_as_alias() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "x\n").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let before = capture(&link);
    let baseline = to_baseline(&before);

    // Recreate the link with identical text: new inode, same meaning.
    replace_symlink_with_new_inode(&link, &target);
    replace_with_new_inode(&target, "y\n");

    let after = capture(&link);
    assert_ne!(
        after.identity.link_inode, before.identity.link_inode,
        "link object should have a new inode"
    );

    let changes = after.diff(&baseline);
    assert!(
        !changes
            .iter()
            .any(|c| matches!(c, Change::SymlinkTargetReplaced { .. })),
        "the link object moved, so this is not a pure alias: {changes:?}"
    );
}

/// Regular files must be unaffected by any of the symlink handling.
#[test]
fn regular_file_carries_no_link_fields() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("plain");
    fs::write(&file, "data\n").unwrap();

    let snap = capture(&file);
    assert_eq!(snap.identity.file_type, FileType::Regular);
    assert_eq!(snap.identity.link_text, None);
    assert_eq!(snap.identity.link_inode, None);
    assert_eq!(snap.identity.link_device, None);
    assert!(!snap.identity.has_link_object_data());

    let meta = fs::symlink_metadata(&file).unwrap();
    assert_eq!(snap.identity.inode, meta.ino());
}

/// Concurrent replacement of the target between scans still produces a
/// coherent, attributable result rather than a blended snapshot.
#[test]
fn concurrent_target_replacement_still_attributes_to_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, "gen0\n").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let baseline = to_baseline(&capture(&link));

    for gen in 1..=5 {
        replace_with_new_inode(&target, &format!("gen{gen}\n"));
    }

    let changes = capture(&link).diff(&baseline);
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::SymlinkTargetReplaced { .. })),
        "repeated target replacement is still a target replacement: {changes:?}"
    );
}
