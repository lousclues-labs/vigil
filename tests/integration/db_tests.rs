// Integration tests: database operations.

use vigil::db;
use vigil::db::ops;
use vigil::types::*;

use crate::common::fixtures::*;

#[test]
fn database_create_and_schema() {
    let tmp = TempDir::new("db-schema");
    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();

    // Schema should exist
    let count = ops::baseline_count(&conn).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn database_integrity_check_passes() {
    let tmp = TempDir::new("db-integrity");
    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();

    assert!(db::integrity_check(&conn).is_ok());
}

#[test]
fn database_wal_checkpoint() {
    let tmp = TempDir::new("db-wal");
    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();

    // Insert some data
    let entry = synthetic_baseline("/test/file", "hash123");
    ops::upsert_baseline(&conn, &entry).unwrap();

    // Checkpoint should succeed
    assert!(db::wal_checkpoint(&conn).is_ok());
}

#[test]
fn maintenance_window_state() {
    let conn = test_db();

    // Not active by default
    let val = ops::get_config_state(&conn, "maintenance_window_active").unwrap();
    assert!(val.is_none());

    // Enter maintenance window
    ops::set_config_state(&conn, "maintenance_window_active", "1").unwrap();
    let val = ops::get_config_state(&conn, "maintenance_window_active").unwrap();
    assert_eq!(val, Some("1".into()));

    // Exit maintenance window
    ops::set_config_state(&conn, "maintenance_window_active", "0").unwrap();
    let val = ops::get_config_state(&conn, "maintenance_window_active").unwrap();
    assert_eq!(val, Some("0".into()));
}

#[test]
fn audit_trail_never_suppressed() {
    let conn = test_db();

    // Even when suppressed=true, the audit entry is written
    let change = ChangeResult {
        path: std::path::PathBuf::from("/etc/shadow"),
        change_types: vec![ChangeType::Modified],
        severity: Severity::Critical,
        old_hash: Some("aaa".into()),
        new_hash: Some("bbb".into()),
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

    // Suppressed entry
    ops::insert_audit_entry(&conn, &change, ChangeType::Modified, true, true, None).unwrap();

    // Non-suppressed entry
    ops::insert_audit_entry(&conn, &change, ChangeType::Modified, false, false, None).unwrap();

    let entries = ops::get_recent_audit(&conn, 100).unwrap();
    assert_eq!(
        entries.len(),
        2,
        "Both suppressed and non-suppressed entries must be written"
    );
}

#[test]
fn unique_constraint_on_path_device_inode() {
    let conn = test_db();
    let entry = synthetic_baseline("/etc/passwd", "hash1");

    ops::insert_baseline(&conn, &entry).unwrap();

    // Inserting same (path, device, inode) should fail
    let result = ops::insert_baseline(&conn, &entry);
    assert!(result.is_err());
}
