// Integration tests for audit chain verification (Item 16).

use crate::common::fixtures;
use std::path::PathBuf;
use vigil::db::ops;
use vigil::types::{ChangeResult, ChangeType, Severity};

fn make_test_change(path: &str, severity: Severity) -> ChangeResult {
    ChangeResult {
        path: PathBuf::from(path),
        change_types: vec![ChangeType::Modified],
        severity,
        old_hash: Some("oldhash".into()),
        new_hash: Some("newhash".into()),
        old_permissions: Some(0o644),
        new_permissions: Some(0o644),
        old_owner_uid: Some(0),
        new_owner_uid: Some(0),
        old_owner_gid: Some(0),
        new_owner_gid: Some(0),
        old_inode: Some(100),
        new_inode: Some(100),
        old_mtime: None,
        new_mtime: None,
        package: None,
        package_update: false,
        monitored_group: "test".into(),
        responsible_pid: None,
        responsible_exe: None,
    }
}

#[test]
fn audit_chain_valid_after_inserts() {
    let conn = fixtures::test_db();

    // Insert 5 audit entries
    for i in 0..5 {
        let change = make_test_change(&format!("/etc/file{}", i), Severity::Medium);
        ops::insert_audit_entry(&conn, &change, ChangeType::Modified, false, false, None).unwrap();
    }

    let (total, valid, broken, missing) = ops::verify_audit_chain(&conn).unwrap();
    assert_eq!(total, 5);
    assert_eq!(valid, 5);
    assert!(broken.is_empty());
    assert_eq!(missing, 0);
}

#[test]
fn audit_chain_detects_deleted_entry() {
    let conn = fixtures::test_db();

    // Insert 5 entries
    let mut ids = Vec::new();
    for i in 0..5 {
        let change = make_test_change(&format!("/etc/file{}", i), Severity::Medium);
        let id = ops::insert_audit_entry(&conn, &change, ChangeType::Modified, false, false, None)
            .unwrap();
        ids.push(id);
    }

    // Delete the middle entry (id 3)
    conn.execute(
        "DELETE FROM audit_log WHERE id = ?1",
        rusqlite::params![ids[2]],
    )
    .unwrap();

    let (total, _valid, broken, _missing) = ops::verify_audit_chain(&conn).unwrap();
    assert_eq!(total, 4);
    // The entry after the deleted one should have a broken chain link
    assert!(
        !broken.is_empty(),
        "chain should detect break after deletion"
    );
}

#[test]
fn audit_chain_detects_tampered_entry() {
    let conn = fixtures::test_db();

    // Insert 5 entries
    for i in 0..5 {
        let change = make_test_change(&format!("/etc/file{}", i), Severity::Medium);
        ops::insert_audit_entry(&conn, &change, ChangeType::Modified, false, false, None).unwrap();
    }

    // Tamper with the middle entry's path
    conn.execute(
        "UPDATE audit_log SET path = '/etc/TAMPERED' WHERE id = 3",
        [],
    )
    .unwrap();

    let (total, _valid, broken, missing) = ops::verify_audit_chain(&conn).unwrap();
    assert_eq!(total, 5);
    assert_eq!(missing, 0);
    assert!(!broken.is_empty(), "chain should detect tampering");
}
