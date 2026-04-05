// Snapshot tests for regression safety using insta.

use insta::assert_json_snapshot;
use std::path::PathBuf;

use vigil::types::*;

#[test]
fn snapshot_baseline_export() {
    let conn = crate::common::fixtures::test_db();

    let entry = BaselineEntry {
        id: None,
        path: PathBuf::from("/etc/passwd"),
        hash: "abc123def456789012345678901234567890123456789012345678901234".into(),
        size: 2048,
        permissions: 0o100644,
        owner_uid: 0,
        owner_gid: 0,
        mtime: 1700000000,
        inode: 12345,
        device: 1,
        xattrs: "{}".into(),
        security_context: String::new(),
        package: Some("base".into()),
        source: BaselineSource::PackageManager,
        added_at: 1700000000,
        updated_at: 1700000000,
    };
    vigil::db::ops::upsert_baseline(&conn, &entry).unwrap();

    let entries = vigil::db::ops::get_all_baselines(&conn).unwrap();
    assert_json_snapshot!("baseline_export", entries);
}

#[test]
fn snapshot_diff_output() {
    let change = ChangeResult {
        path: PathBuf::from("/etc/passwd"),
        change_types: vec![ChangeType::Modified],
        severity: Severity::Critical,
        old_hash: Some("aaa111".into()),
        new_hash: Some("bbb222".into()),
        old_permissions: Some(0o100644),
        new_permissions: Some(0o100644),
        old_owner_uid: Some(0),
        new_owner_uid: Some(0),
        old_owner_gid: Some(0),
        new_owner_gid: Some(0),
        old_inode: Some(12345),
        new_inode: Some(12345),
        old_mtime: Some(1700000000),
        new_mtime: Some(1700001000),
        package: Some("base".into()),
        package_update: false,
        monitored_group: "system_critical".into(),
    };

    assert_json_snapshot!("diff_output", vec![change]);
}

#[test]
fn snapshot_alert_json() {
    let alert = Alert {
        version: 1,
        timestamp: chrono::DateTime::parse_from_rfc3339("2026-04-02T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        event_id: "vigil_test12345678".into(),
        severity: Severity::Critical,
        change_type: ChangeType::Modified,
        file: AlertFileInfo {
            path: PathBuf::from("/etc/passwd"),
            baseline_hash: Some("aaa111".into()),
            current_hash: Some("bbb222".into()),
            baseline_size: Some(2048),
            current_size: Some(2100),
            baseline_permissions: Some("0644".into()),
            current_permissions: Some("0644".into()),
            baseline_owner: Some("0".into()),
            current_owner: Some("0".into()),
            inode_changed: false,
            mtime_changed: true,
            package: Some("base".into()),
            package_update: false,
        },
        context: AlertContext {
            hostname: "test-host".into(),
            monitored_group: "system_critical".into(),
            maintenance_window: false,
        },
    };

    assert_json_snapshot!("alert_json", alert);
}
