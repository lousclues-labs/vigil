//! Tests for v0.23.0 security hardening (Round 3).

use std::path::PathBuf;
use vigil::db::{baseline_ops, schema, DbFileIdentity};

// === VULN-025: TOCTOU inode check ===

#[test]
fn db_file_identity_from_path_returns_valid_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    std::fs::write(&path, b"test data").unwrap();

    let identity = DbFileIdentity::from_path(&path).unwrap();
    assert!(identity.inode > 0);
    assert!(identity.device > 0);
}

#[test]
fn db_file_identity_detects_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    std::fs::write(&path, b"original data").unwrap();

    let identity = DbFileIdentity::from_path(&path).unwrap();

    // File not replaced yet
    assert!(!identity.is_replaced(&path).unwrap());

    // Replace file atomically (new inode)
    let tmp = dir.path().join("test.db.tmp");
    std::fs::write(&tmp, b"replacement data").unwrap();
    std::fs::rename(&tmp, &path).unwrap();

    // Should detect replacement
    assert!(identity.is_replaced(&path).unwrap());
}

#[test]
fn db_file_identity_same_file_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    std::fs::write(&path, b"original data").unwrap();

    let identity = DbFileIdentity::from_path(&path).unwrap();

    // Modify contents in-place (same inode)
    std::fs::write(&path, b"modified data").unwrap();

    // Same inode, should NOT detect as replaced
    assert!(!identity.is_replaced(&path).unwrap());
}

// === VULN-026: WAL/SHM permissions ===
// (Tested indirectly through open_db; WAL/SHM files are created by SQLite)

// === VULN-032: Full HMAC coverage ===

#[test]
fn baseline_hmac_covers_all_security_fields() {
    let conn1 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn1).unwrap();
    let conn2 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn2).unwrap();

    let key = b"test-hmac-key-for-hmac-coverage";

    let entry = vigil::types::BaselineEntry {
        id: None,
        path: "/etc/passwd".into(),
        identity: vigil::types::FileIdentity {
            inode: 12345,
            device: 1,
            file_type: vigil::types::FileType::Regular,
            symlink_target: None,
        },
        content: vigil::types::ContentFingerprint {
            hash: "abc123".into(),
            size: 100,
        },
        permissions: vigil::types::PermissionState {
            mode: 0o644,
            owner_uid: 0,
            owner_gid: 0,
            capabilities: None,
        },
        security: vigil::types::SecurityState::default(),
        mtime: 1700000000,
        package: None,
        source: vigil::types::BaselineSource::AutoScan,
        added_at: 1700000000,
        updated_at: 1700000000,
    };

    // Same entry in both
    baseline_ops::upsert(&conn1, &entry).unwrap();
    baseline_ops::upsert(&conn2, &entry).unwrap();

    let hmac1 = baseline_ops::compute_baseline_hmac(&conn1, key).unwrap();
    let hmac2 = baseline_ops::compute_baseline_hmac(&conn2, key).unwrap();
    assert_eq!(hmac1, hmac2, "identical entries must produce identical HMACs");

    // Change inode — previously not covered, now should change HMAC
    let mut entry_diff_inode = entry.clone();
    entry_diff_inode.identity.inode = 99999;
    let conn3 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn3).unwrap();
    baseline_ops::upsert(&conn3, &entry_diff_inode).unwrap();
    let hmac3 = baseline_ops::compute_baseline_hmac(&conn3, key).unwrap();
    assert_ne!(hmac1, hmac3, "inode change must produce different HMAC");

    // Change device — previously not covered
    let mut entry_diff_device = entry.clone();
    entry_diff_device.identity.device = 42;
    let conn4 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn4).unwrap();
    baseline_ops::upsert(&conn4, &entry_diff_device).unwrap();
    let hmac4 = baseline_ops::compute_baseline_hmac(&conn4, key).unwrap();
    assert_ne!(hmac1, hmac4, "device change must produce different HMAC");

    // Change size — previously not covered
    let mut entry_diff_size = entry.clone();
    entry_diff_size.content.size = 9999;
    let conn5 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn5).unwrap();
    baseline_ops::upsert(&conn5, &entry_diff_size).unwrap();
    let hmac5 = baseline_ops::compute_baseline_hmac(&conn5, key).unwrap();
    assert_ne!(hmac1, hmac5, "size change must produce different HMAC");

    // Change capabilities — previously not covered
    let mut entry_diff_caps = entry.clone();
    entry_diff_caps.permissions.capabilities = Some("cap_net_admin".into());
    let conn6 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn6).unwrap();
    baseline_ops::upsert(&conn6, &entry_diff_caps).unwrap();
    let hmac6 = baseline_ops::compute_baseline_hmac(&conn6, key).unwrap();
    assert_ne!(hmac1, hmac6, "capabilities change must produce different HMAC");

    // Change security_context — previously not covered
    let mut entry_diff_ctx = entry.clone();
    entry_diff_ctx.security.security_context = "system_u:object_r:etc_t:s0".into();
    let conn7 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn7).unwrap();
    baseline_ops::upsert(&conn7, &entry_diff_ctx).unwrap();
    let hmac7 = baseline_ops::compute_baseline_hmac(&conn7, key).unwrap();
    assert_ne!(
        hmac1, hmac7,
        "security_context change must produce different HMAC"
    );
}

// === VULN-030: Mount change detection ===

#[test]
fn parse_mountinfo_returns_some() {
    // This should work on any Linux system with /proc
    let mounts = vigil::monitor::fanotify::parse_mountinfo();
    assert!(
        mounts.is_some(),
        "parse_mountinfo should succeed on Linux with /proc"
    );
    let mounts = mounts.unwrap();
    assert!(
        !mounts.is_empty(),
        "there should be at least one mount point"
    );
    // Root mount should always be present
    assert!(
        mounts.contains(&PathBuf::from("/")),
        "root mount / should always be present"
    );
}

// === VULN-031: kernel_queue_overflows metric ===

#[test]
fn metrics_kernel_queue_overflows_counter_exists() {
    use std::sync::atomic::Ordering;
    let m = vigil::metrics::Metrics::new();
    assert_eq!(m.kernel_queue_overflows.load(Ordering::Relaxed), 0);

    m.kernel_queue_overflows.fetch_add(3, Ordering::Relaxed);
    let snap = m.snapshot();
    assert_eq!(snap.kernel_queue_overflows, 3);
}

// === VULN-033: Self-binary in vigil_self watch group ===

#[test]
fn default_config_includes_self_binary_in_watch() {
    let config = vigil::config::default_config();
    let vigil_self = config.watch.get("vigil_self").expect("vigil_self group must exist");
    assert!(
        vigil_self.paths.contains(&"/usr/bin/vigil".to_string()),
        "vigil_self should include /usr/bin/vigil"
    );
    assert!(
        vigil_self.paths.contains(&"/usr/bin/vigild".to_string()),
        "vigil_self should include /usr/bin/vigild"
    );
}

// === VULN-037: Symlink target resolution ===

#[test]
fn symlink_target_uses_canonical_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real_file");
    std::fs::write(&target, b"hello").unwrap();

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let opts = vigil::types::CaptureOpts {
        force_hash: true,
        max_file_size: 1_000_000,
        mmap_threshold: 1_000_000,
        baseline_mtime: None,
        baseline_hash: None,
    };

    match vigil::types::FileSnapshot::from_path(&link, &opts).unwrap() {
        vigil::types::SnapshotOrDeleted::Snapshot(snap) => {
            assert_eq!(snap.identity.file_type, vigil::types::FileType::Symlink);
            assert!(
                snap.identity.symlink_target.is_some(),
                "symlink target should be recorded"
            );
            let resolved = snap.identity.symlink_target.unwrap();
            // Canonical path should be absolute and resolved
            assert!(resolved.is_absolute(), "canonical target should be absolute");
        }
        vigil::types::SnapshotOrDeleted::Deleted => panic!("file should exist"),
    }
}
