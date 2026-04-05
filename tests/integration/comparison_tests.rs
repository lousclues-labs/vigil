// Integration tests: comparison engine — TOCTOU-hardened file comparison.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use vigil::compare;
use vigil::types::*;

use crate::common::assertions::*;
use crate::common::fixtures::*;

#[test]
fn compare_unchanged_file_returns_none() {
    let tmp = TempDir::new("cmp-unchanged");
    let file_path = tmp.create_file("stable.txt", b"stable content");

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file_path);

    let result = compare::compare_entry(
        &entry,
        &config,
        vigil::types::Severity::Medium,
        "test",
        false,
    )
    .unwrap();
    assert!(result.is_none(), "Unchanged file should return None");
}

#[test]
fn compare_detects_content_modification() {
    let tmp = TempDir::new("cmp-modified");
    let file_path = tmp.create_file("target.txt", b"original");

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file_path);

    // Modify the file (use different length to ensure size change triggers hash comparison)
    fs::write(&file_path, b"tampered content that is longer").unwrap();

    let result = compare::compare_entry(
        &entry,
        &config,
        vigil::types::Severity::Medium,
        "test",
        false,
    )
    .unwrap();
    assert!(result.is_some());
    let change = result.unwrap();
    assert_has_change_type(&change, ChangeType::Modified);
    assert!(change.old_hash.is_some());
    assert!(change.new_hash.is_some());
    assert_ne!(change.old_hash, change.new_hash);
}

#[test]
fn compare_detects_deletion() {
    let tmp = TempDir::new("cmp-deleted");
    let file_path = tmp.create_file("victim.txt", b"doomed");

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file_path);

    fs::remove_file(&file_path).unwrap();

    let result = compare::compare_entry(
        &entry,
        &config,
        vigil::types::Severity::Medium,
        "test",
        false,
    )
    .unwrap();
    assert!(result.is_some());
    assert_has_change_type(&result.unwrap(), ChangeType::Deleted);
}

#[test]
fn compare_detects_permission_change() {
    let tmp = TempDir::new("cmp-perms");
    let file_path = tmp.create_file_with_perms("secret.txt", b"data", 0o644);

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file_path);

    // Change permissions
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

    let result = compare::compare_entry(
        &entry,
        &config,
        vigil::types::Severity::Medium,
        "test",
        false,
    )
    .unwrap();
    assert!(result.is_some());
    assert_has_change_type(&result.unwrap(), ChangeType::PermissionsChanged);
}

#[test]
fn compare_detects_file_replacement_via_inode() {
    let tmp = TempDir::new("cmp-inode");
    let file_path = tmp.create_file("replaced.txt", b"original");

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file_path);

    // Replace the file (delete + create = different inode)
    fs::remove_file(&file_path).unwrap();
    fs::write(&file_path, b"replacement").unwrap();

    let result = compare::compare_entry(
        &entry,
        &config,
        vigil::types::Severity::Medium,
        "test",
        false,
    )
    .unwrap();
    assert!(result.is_some());
    let change = result.unwrap();
    // Should detect inode change and/or content modification
    let has_inode_or_modified = change.change_types.contains(&ChangeType::InodeChanged)
        || change.change_types.contains(&ChangeType::Modified);
    assert!(has_inode_or_modified, "Should detect file replacement");
}

#[test]
fn compare_event_with_group_severity() {
    let tmp = TempDir::new("cmp-event");
    let file_path = tmp.create_file("watched.txt", b"content");

    let entry = baseline_entry_for(&file_path);

    // Modify
    fs::write(&file_path, b"changed content that is longer").unwrap();

    let result = compare::compare_event(
        &file_path,
        &entry,
        "system_critical",
        Severity::Critical,
        2_147_483_648,
    )
    .unwrap();

    assert!(result.is_some());
    let change = result.unwrap();
    assert_eq!(change.severity, Severity::Critical);
    assert_eq!(change.monitored_group, "system_critical");
}

#[test]
fn compare_provides_old_and_new_hashes() {
    let tmp = TempDir::new("cmp-hashes");
    let file_path = tmp.create_file("hashtest.txt", b"before");

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file_path);
    let original_hash = entry.hash.clone();

    fs::write(&file_path, b"after").unwrap();

    let result = compare::compare_entry(
        &entry,
        &config,
        vigil::types::Severity::Medium,
        "test",
        false,
    )
    .unwrap()
    .unwrap();
    assert_eq!(result.old_hash, Some(original_hash));
    assert!(result.new_hash.is_some());
    assert_ne!(result.old_hash, result.new_hash);
}
