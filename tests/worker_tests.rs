use std::sync::Arc;

use arc_swap::ArcSwap;
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
        },
    );

    let event = FsEvent {
        path: path.clone(),
        event_type: FsEventType::Modify,
        timestamp: Utc::now(),
        event_fd: None,
        process: None,
    };

    let out = vigil::worker::process_event(
        &conn,
        &event,
        &Arc::new(ArcSwap::from_pointee(cfg2.clone())),
        &Arc::new(ArcSwap::from_pointee(
            vigil::watch_index::WatchGroupIndex::from_config(&cfg2),
        )),
        &vigil::metrics::Metrics::new(),
    )
    .unwrap();

    let result = out.expect("expected change");
    assert!(result
        .changes
        .iter()
        .any(|c| matches!(c, vigil::types::Change::ContentModified { .. })));
}
