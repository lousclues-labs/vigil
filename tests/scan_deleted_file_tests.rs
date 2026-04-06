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
