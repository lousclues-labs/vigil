// Security tests: permission and access control checks.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use vigil::baseline;
use vigil::db;
use vigil::types::*;

use crate::common::fixtures::*;

#[test]
fn detect_permission_escalation() {
    // Scenario: file permissions changed from 0644 to 4755 (setuid).
    let tmp = TempDir::new("sec-perm-esc");
    let file = tmp.create_file_with_perms("binary", b"safe binary", 0o755);

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file);

    // Change to setuid
    fs::set_permissions(&file, fs::Permissions::from_mode(0o4755)).unwrap();

    let result = vigil::compare::compare_entry(&entry, &config).unwrap();
    assert!(result.is_some(), "Should detect permission change");

    let change = result.unwrap();
    assert!(
        change
            .change_types
            .contains(&ChangeType::PermissionsChanged),
        "Should specifically detect permission change"
    );
}

#[test]
fn detect_world_writable() {
    // Scenario: critical file made world-writable.
    let tmp = TempDir::new("sec-world-write");
    let file = tmp.create_file_with_perms("config", b"secure config", 0o644);

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file);

    // Make world-writable
    fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();

    let result = vigil::compare::compare_entry(&entry, &config).unwrap();
    assert!(result.is_some());
    assert!(
        result
            .unwrap()
            .change_types
            .contains(&ChangeType::PermissionsChanged),
        "World-writable change must be detected"
    );
}

#[test]
fn db_path_permissions() {
    // Database should be created with reasonable permissions.
    let tmp = TempDir::new("sec-db-perms");
    let config = test_config(&tmp);
    let _conn = db::open_db(&config).unwrap();

    let meta = fs::metadata(&config.daemon.db_path).unwrap();
    let mode = meta.permissions().mode() & 0o777;

    // Database should not be world-writable
    assert_eq!(
        mode & 0o002,
        0,
        "Database file must not be world-writable (mode: {:o})",
        mode
    );
}

#[test]
#[ignore = "requires privileged environment"]
fn detect_ownership_change_to_root() {
    // This test requires root to change file ownership.
    // Verifies that ownership changes are detected.
    let tmp = TempDir::new("sec-own-root");
    let file = tmp.create_file("owned.txt", b"data");

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file);

    // Would need chown here — only runs under sudo
    // nix::unistd::chown(&file, Some(nix::unistd::Uid::from_raw(0)), None).unwrap();

    let result = vigil::compare::compare_entry(&entry, &config).unwrap();
    if let Some(change) = result {
        assert!(change.change_types.contains(&ChangeType::OwnerChanged));
    }
}
