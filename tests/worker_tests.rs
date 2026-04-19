use chrono::Utc;
use rusqlite::Connection;
use vigil::db::{baseline_ops, schema};
use vigil::types::{BaselineEntry, BaselineSource, CaptureOpts, FsEvent, FsEventType};

#[test]
fn process_event_detects_content_change() {
    let conn = Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.txt");
    std::fs::write(&path, b"old content").unwrap();

    let cfg = vigil::config::default_config();
    let opts = CaptureOpts {
        force_hash: true,
        max_file_size: cfg.scanner.max_file_size,
        mmap_threshold: cfg.scanner.mmap_threshold,
        baseline_mtime: None,
        baseline_hash: None,
    };

    let file = std::fs::File::open(&path).unwrap();
    let snapshot = vigil::types::FileSnapshot::from_fd(&file, &path, &opts).unwrap();

    let entry = BaselineEntry {
        id: None,
        path: path.clone(),
        identity: snapshot.identity.clone(),
        content: snapshot.content.clone(),
        permissions: snapshot.permissions.clone(),
        security: snapshot.security.clone(),
        mtime: snapshot.mtime,
        package: None,
        source: BaselineSource::AutoScan,
        added_at: 1,
        updated_at: 1,
    };
    baseline_ops::upsert(&conn, &entry).unwrap();

    std::fs::write(&path, b"new content").unwrap();

    let mut cfg2 = vigil::config::default_config();
    cfg2.watch.clear();
    cfg2.watch.insert(
        "test".into(),
        vigil::config::WatchGroup {
            severity: vigil::types::Severity::High,
            paths: vec![dir.path().to_string_lossy().to_string()],
            mode: vigil::config::WatchMode::PerFile,
            expect_present: false,
        },
    );

    // Re-open in-memory conn with baseline data for the worker context.
    // We need a fresh connection since WorkerContext takes ownership.
    let conn2 = Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn2).unwrap();
    baseline_ops::upsert(&conn2, &entry).unwrap();

    let event = FsEvent {
        path: std::sync::Arc::new(path.clone()),
        event_type: FsEventType::Modify,
        timestamp: Utc::now(),
        event_fd: None,
        process: None,
        bloom_generation: 0,
    };

    let mut ctx = vigil::worker::WorkerContext::for_test(conn2, &cfg2);
    let out = ctx.evaluate(&event).unwrap();

    let result = out.expect("expected change");
    assert!(result
        .changes
        .iter()
        .any(|c| matches!(c, vigil::types::Change::ContentModified { .. })));
}
