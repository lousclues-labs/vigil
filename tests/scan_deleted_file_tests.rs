use std::collections::BTreeMap;

use vigil::types::{
    BaselineEntry, BaselineSource, Change, ContentFingerprint, FileIdentity, FileType,
    PermissionState, ScanMode, SecurityState,
};

#[test]
fn test_scan_handles_deleted_file_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("baseline.db");

    // Create a temporary file to baseline
    let watched_file = dir.path().join("test_file.txt");
    std::fs::write(&watched_file, b"test content").unwrap();

    // Open a database and insert a baseline entry for the file
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    vigil::db::schema::create_baseline_tables(&conn).unwrap();

    let meta = std::fs::metadata(&watched_file).unwrap();
    use std::os::unix::fs::MetadataExt;

    let entry = BaselineEntry {
        id: None,
        path: watched_file.clone(),
        identity: FileIdentity {
            inode: meta.ino(),
            device: meta.dev(),
            file_type: FileType::Regular,
            symlink_target: None,
            ..Default::default()
        },
        content: ContentFingerprint {
            hash: blake3::hash(b"test content").to_hex().to_string(),
            size: meta.len(),
        },
        permissions: PermissionState {
            mode: meta.mode(),
            owner_uid: meta.uid(),
            owner_gid: meta.gid(),
            capabilities: None,
        },
        security: SecurityState {
            xattrs: BTreeMap::new(),
            security_context: String::new(),
        },
        mtime: meta.mtime(),
        package: None,
        source: BaselineSource::AutoScan,
        added_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    };

    vigil::db::baseline_ops::upsert(&conn, &entry).unwrap();

    // Now delete the file
    std::fs::remove_file(&watched_file).unwrap();

    // Run a scan — it should detect the deletion
    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = db_path;

    let result = vigil::scanner::run_scan(&conn, &cfg, ScanMode::Full).unwrap();

    assert!(
        result.changes_found >= 1,
        "should detect at least one change"
    );

    // Verify a Deleted change was produced
    let has_deletion = result.changes.iter().any(|cr| {
        cr.path.as_ref() == &watched_file && cr.changes.iter().any(|c| matches!(c, Change::Deleted))
    });
    assert!(has_deletion, "should produce a deletion ChangeResult");
}

/// An unreadable directory must be counted as an error, not silently pruned.
///
/// `walk_files` discarded its own failures at `debug` level and never touched
/// the operator-facing error count. A `read_dir` failure prunes the entire
/// subtree — nothing beneath it is visited, counted as a file, *or* counted as
/// an error — so `vigil init` reported "N files baselined" with no capture
/// errors while a whole watched subtree went unmonitored.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_reported_as_a_capture_error() {
    use std::os::unix::fs::PermissionsExt;

    // Root can read anything, so this cannot be exercised as root.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: running as root, permissions do not apply");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let watched = dir.path().join("watched");
    let secret = watched.join("secret");
    std::fs::create_dir_all(&secret).unwrap();
    std::fs::write(secret.join("key.pem"), b"private").unwrap();
    std::fs::write(watched.join("visible.conf"), b"ok").unwrap();

    // Make the subtree unreadable.
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();

    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = dir.path().join("baseline.db");
    // The tempdir lives under /tmp/, which the shipped defaults exclude.
    cfg.exclusions.system_exclusions.clear();
    cfg.exclusions.patterns.clear();
    cfg.watch.clear();
    cfg.watch.insert(
        "test".to_string(),
        vigil::config::WatchGroup {
            severity: vigil::types::Severity::High,
            paths: vec![watched.to_string_lossy().into_owned()],
            mode: Default::default(),
            expect_present: false,
        },
    );

    let conn = vigil::db::open_db_at(&cfg.daemon.db_path, false).unwrap();
    let result = vigil::scanner::build_initial_baseline(&conn, &cfg).unwrap();

    // Restore so tempdir cleanup can proceed.
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o755)).unwrap();

    let group = result
        .groups
        .iter()
        .find(|g| g.name == "test")
        .expect("group present");
    assert!(
        group.errors > 0,
        "an unreadable subtree must be counted as a capture error, got {} errors \
         for {} files. Reporting zero errors states the files were fine when they \
         were never examined.",
        group.errors,
        group.file_count
    );
}
