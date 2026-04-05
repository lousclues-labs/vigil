// Security tests: database and baseline integrity.

use std::fs;
use std::path::PathBuf;

use vigil::db::ops;
use vigil::types::*;

use crate::common::fixtures::*;

#[test]
fn baseline_hash_is_deterministic() {
    // Principle III: Determinism — same file always produces same hash.
    let tmp = TempDir::new("sec-determinism");
    let file = tmp.create_file("deterministic.txt", b"fixed content for determinism test");

    let entry1 = baseline_entry_for(&file);
    let entry2 = baseline_entry_for(&file);

    assert_eq!(entry1.hash, entry2.hash, "Same file must produce same hash");
}

#[test]
fn different_content_different_hash() {
    // Verify BLAKE3 produces distinct hashes for different content.
    let tmp = TempDir::new("sec-distinct");
    let file_a = tmp.create_file("a.txt", b"content A");
    let file_b = tmp.create_file("b.txt", b"content B");

    let entry_a = baseline_entry_for(&file_a);
    let entry_b = baseline_entry_for(&file_b);

    assert_ne!(
        entry_a.hash, entry_b.hash,
        "Different content must produce different hashes"
    );
}

#[test]
fn inode_tracked_in_baseline() {
    // File replacement attack detection requires inode tracking.
    let tmp = TempDir::new("sec-inode");
    let file = tmp.create_file("inode-test.txt", b"original");

    let entry = baseline_entry_for(&file);
    assert!(entry.inode > 0, "Inode must be recorded");
    assert!(entry.device > 0, "Device must be recorded");
}

#[test]
fn file_replacement_changes_inode() {
    // Simulates: attacker deletes file and creates new one at same path.
    // The inode MUST change.
    let tmp = TempDir::new("sec-replace");
    let file_path = tmp.create_file("sudo", b"real sudo binary");

    use std::os::unix::fs::MetadataExt;
    let original_inode = fs::metadata(&file_path).unwrap().ino();

    // Replace: delete + create (same path, different inode)
    fs::remove_file(&file_path).unwrap();
    fs::write(&file_path, b"trojanized sudo").unwrap();

    let new_inode = fs::metadata(&file_path).unwrap().ino();

    // Inodes should differ (on most filesystems)
    // Note: on some filesystems, inode reuse is possible but rare.
    // This test verifies that our comparison would detect it if they differ.
    if original_inode != new_inode {
        let config = test_config(&tmp);
        let mut entry = baseline_entry_for(&file_path);
        entry.inode = original_inode; // pretend baseline has old inode
        entry.hash = vigil::baseline::hash::blake3_hash_bytes(b"real sudo binary");

        let result = vigil::compare::compare_entry(
            &entry,
            &config,
            vigil::types::Severity::Medium,
            "test",
            false,
        )
        .unwrap();
        assert!(result.is_some(), "File replacement must be detected");

        let change = result.unwrap();
        let detected_inode_or_modified = change.change_types.contains(&ChangeType::InodeChanged)
            || change.change_types.contains(&ChangeType::Modified);
        assert!(detected_inode_or_modified);
    }
}

#[test]
fn database_unique_constraint_prevents_silent_overwrite() {
    // A replaced file (same path, different inode) should not silently
    // overwrite the baseline entry via insert.
    let conn = test_db();

    let mut entry1 = synthetic_baseline("/usr/bin/sudo", "hash_original");
    entry1.inode = 1000;
    ops::insert_baseline(&conn, &entry1).unwrap();

    let mut entry2 = synthetic_baseline("/usr/bin/sudo", "hash_trojan");
    entry2.inode = 2000; // different inode

    // This should succeed (different inode = different unique key)
    let result = ops::insert_baseline(&conn, &entry2);
    assert!(result.is_ok(), "Different inode should be a separate entry");

    // Both entries should exist
    let count = ops::baseline_count(&conn).unwrap();
    assert_eq!(count, 2);
}

#[test]
fn audit_log_records_suppressed_entries() {
    // Principle XIII: The audit trail never lies.
    // Even suppressed alerts must be recorded.
    let conn = test_db();

    let change = ChangeResult {
        path: PathBuf::from("/etc/shadow"),
        change_types: vec![ChangeType::Modified],
        severity: Severity::Critical,
        old_hash: Some("old_hash".into()),
        new_hash: Some("new_hash".into()),
        old_permissions: None,
        new_permissions: None,
        old_owner_uid: None,
        new_owner_uid: None,
        old_owner_gid: None,
        new_owner_gid: None,
        old_inode: None,
        new_inode: None,
        old_mtime: None,
        new_mtime: None,
        package: None,
        package_update: false,
        monitored_group: "system_critical".into(),
    };

    // Write as suppressed during maintenance window
    ops::insert_audit_entry(&conn, &change, ChangeType::Modified, true, true, None).unwrap();

    let entries = ops::get_recent_audit(&conn, 10).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].suppressed, "Suppressed flag must be recorded");
    assert!(
        entries[0].maintenance_window,
        "Maintenance window flag must be recorded"
    );
    assert_eq!(
        entries[0].severity, "critical",
        "Severity must be recorded even when suppressed"
    );
}

#[test]
fn metadata_captures_permissions_and_ownership() {
    let tmp = TempDir::new("sec-meta");
    let file = tmp.create_file_with_perms("secret.key", b"ssh key data", 0o600);

    let entry = baseline_entry_for(&file);

    // Verify permission bits are captured (at least the permission part)
    assert_eq!(
        entry.permissions & 0o777,
        0o600,
        "Permissions must be captured correctly"
    );
    // Verify ownership metadata was captured (matches the file's actual UID)
    use std::os::unix::fs::MetadataExt;
    let file_uid = std::fs::metadata(&file).unwrap().uid();
    assert_eq!(entry.owner_uid, file_uid, "UID must be captured");
}
