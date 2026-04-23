use std::sync::Arc;
use vigil::baseline_diff::{record_unattributed_to_wal, ChangedEntry};
use vigil::types::Severity;
use vigil::wal::{DetectionSource, DetectionWal};

/// Build a WAL for testing (no HMAC).
fn open_test_wal(dir: &std::path::Path) -> Arc<DetectionWal> {
    Arc::new(DetectionWal::open(&dir.join("detections.wal"), None, 64 * 1024 * 1024).unwrap())
}

/// After a baseline refresh, unattributed changes must be recorded in the WAL
/// with DetectionSource::BaselineRefresh and Severity::High.
#[test]
fn baseline_refresh_records_unattributed_to_wal() {
    let dir = tempfile::tempdir().unwrap();
    let wal = open_test_wal(dir.path());

    let entries = vec![
        ChangedEntry {
            path: "/etc/resolv.conf".into(),
            old_hash: "aabbccdd".into(),
            new_hash: "11223344".into(),
        },
        ChangedEntry {
            path: "/etc/hosts".into(),
            old_hash: "eeff0011".into(),
            new_hash: "55667788".into(),
        },
    ];

    let appended = record_unattributed_to_wal(&wal, &entries, false);
    assert_eq!(appended, 2, "both entries should be appended");

    let wal_entries = wal.iter_unconsumed().unwrap();
    assert_eq!(wal_entries.len(), 2, "WAL should contain exactly 2 entries");

    // Verify first entry
    let e0 = &wal_entries[0];
    assert_eq!(e0.record.path, "/etc/resolv.conf");
    assert_eq!(e0.record.source, DetectionSource::BaselineRefresh);
    assert_eq!(e0.record.severity, Severity::High);
    assert!(!e0.record.maintenance_window);
    assert!(e0.record.package.is_none());
    assert!(!e0.record.package_update);
    assert_eq!(e0.record.monitored_group, "baseline_refresh");

    // Verify the change captures old and new hash
    assert_eq!(e0.record.changes.len(), 1);
    match &e0.record.changes[0] {
        vigil::types::Change::ContentModified { old_hash, new_hash } => {
            assert_eq!(old_hash, "aabbccdd");
            assert_eq!(new_hash, "11223344");
        }
        other => panic!("expected ContentModified, got {:?}", other),
    }

    // Verify second entry
    let e1 = &wal_entries[1];
    assert_eq!(e1.record.path, "/etc/hosts");
    assert_eq!(e1.record.source, DetectionSource::BaselineRefresh);
    assert_eq!(e1.record.severity, Severity::High);
}

/// During a maintenance window, the maintenance_window flag must propagate.
#[test]
fn baseline_refresh_wal_records_maintenance_window() {
    let dir = tempfile::tempdir().unwrap();
    let wal = open_test_wal(dir.path());

    let entries = vec![ChangedEntry {
        path: "/etc/machine-id".into(),
        old_hash: "old".into(),
        new_hash: "new".into(),
    }];

    let appended = record_unattributed_to_wal(&wal, &entries, true);
    assert_eq!(appended, 1);

    let wal_entries = wal.iter_unconsumed().unwrap();
    assert!(
        wal_entries[0].record.maintenance_window,
        "maintenance_window should be true"
    );
}

/// WAL append failure for one entry must not block others (Principle X).
/// Test by filling the WAL to its limit, then verifying partial success.
#[test]
fn baseline_refresh_wal_failure_does_not_block_others() {
    let dir = tempfile::tempdir().unwrap();
    // Tiny WAL -- just enough for a few entries
    let wal = Arc::new(DetectionWal::open(&dir.path().join("detections.wal"), None, 512).unwrap());

    // Create many entries that will exceed the WAL capacity
    let entries: Vec<ChangedEntry> = (0..100)
        .map(|i| ChangedEntry {
            path: format!("/etc/file-{:04}", i),
            old_hash: "old".into(),
            new_hash: "new".into(),
        })
        .collect();

    let appended = record_unattributed_to_wal(&wal, &entries, false);
    // Some should succeed, some should fail (WAL full), but it must not panic
    assert!(appended > 0, "at least some entries should be appended");
    assert!(appended < 100, "not all entries should fit in tiny WAL");
}

/// Diff computation correctly classifies changes by package attribution.
/// This is the end-to-end flow test for the diff module.
#[test]
fn baseline_diff_compute_roundtrip() {
    use std::collections::HashMap;
    use vigil::baseline_diff::{compute_diff, SnapshotEntry};

    let mut old = HashMap::new();
    old.insert(
        "/usr/bin/ls".to_string(),
        SnapshotEntry {
            hash: "h1".into(),
            package: Some("coreutils".into()),
        },
    );
    old.insert(
        "/etc/resolv.conf".to_string(),
        SnapshotEntry {
            hash: "h2".into(),
            package: None,
        },
    );
    old.insert(
        "/usr/bin/removed".to_string(),
        SnapshotEntry {
            hash: "h3".into(),
            package: Some("gone-pkg".into()),
        },
    );

    let mut new = HashMap::new();
    new.insert(
        "/usr/bin/ls".to_string(),
        SnapshotEntry {
            hash: "h1_new".into(),
            package: Some("coreutils".into()),
        },
    );
    new.insert(
        "/etc/resolv.conf".to_string(),
        SnapshotEntry {
            hash: "h2_new".into(),
            package: None,
        },
    );
    new.insert(
        "/usr/bin/newfile".to_string(),
        SnapshotEntry {
            hash: "h4".into(),
            package: Some("new-pkg".into()),
        },
    );

    let diff = compute_diff(&old, &new);

    // /usr/bin/ls changed with package -> changed_pkg
    assert!(diff.changed_pkg.contains(&"/usr/bin/ls".to_string()));
    // /etc/resolv.conf changed without package -> unattributed
    assert_eq!(diff.changed_unattributed.len(), 1);
    assert_eq!(diff.changed_unattributed[0].path, "/etc/resolv.conf");
    assert_eq!(diff.changed_unattributed[0].old_hash, "h2");
    assert_eq!(diff.changed_unattributed[0].new_hash, "h2_new");
    // /usr/bin/newfile is new
    assert!(diff.added.contains(&"/usr/bin/newfile".to_string()));
    // /usr/bin/removed is gone
    assert!(diff.removed.contains(&"/usr/bin/removed".to_string()));
}

/// Audit trail integration: WAL entries appended by baseline refresh
/// use the correct HMAC chain when HMAC is enabled.
#[test]
fn baseline_refresh_wal_with_hmac() {
    use zeroize::Zeroizing;

    let dir = tempfile::tempdir().unwrap();
    let key = Zeroizing::new(b"test-hmac-key-for-wal".to_vec());
    let wal = Arc::new(
        DetectionWal::open(
            &dir.path().join("detections.wal"),
            Some(&key),
            64 * 1024 * 1024,
        )
        .unwrap(),
    );

    let entries = vec![ChangedEntry {
        path: "/etc/shadow".into(),
        old_hash: "before".into(),
        new_hash: "after".into(),
    }];

    let appended = record_unattributed_to_wal(&wal, &entries, false);
    assert_eq!(appended, 1);

    // Read back and verify entry is valid (HMAC-signed)
    let wal_entries = wal.iter_unconsumed().unwrap();
    assert_eq!(wal_entries.len(), 1);
    assert_eq!(wal_entries[0].record.path, "/etc/shadow");
    assert_eq!(
        wal_entries[0].record.source,
        DetectionSource::BaselineRefresh
    );
}
