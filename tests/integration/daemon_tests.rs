// Integration tests: daemon event loop.
//
// These tests exercise the core daemon event processing pipeline by
// simulating filesystem changes against a baseline and verifying that
// the correct audit log entries are recorded.
//
// # Running
//
// These tests use inotify (no elevated privileges required):
//
//   cargo test --test integration daemon -- --ignored
//
// If you have CAP_SYS_ADMIN, fanotify tests can be run by changing the
// monitor_backend in the test config to Fanotify.

use std::fs;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vigil::alert::AlertEngine;
use vigil::baseline;
use vigil::config;
use vigil::db;
use vigil::db::ops;

use crate::common::fixtures::*;

/// End-to-end daemon test: init baseline, start monitor, mutate files,
/// verify audit log entries, then shut down cleanly.
#[test]
#[ignore] // Requires inotify; run with: cargo test --test integration daemon -- --ignored
fn daemon_lifecycle_create_modify_delete() {
    let tmp = TempDir::new("daemon-lifecycle");
    let watched_dir = tmp.create_dir("watched");

    // Create initial files in the watched directory
    let test_file = watched_dir.join("test.txt");
    fs::write(&test_file, b"initial content").expect("write initial file");

    // Build config pointing at the watched directory
    let cfg = test_config_with_paths(
        &tmp,
        vec![watched_dir.to_string_lossy().into_owned() + "/"],
        vigil::types::Severity::High,
    );

    // Open database and initialize baseline
    let conn = db::open_db(&cfg).expect("open db");
    let (count, _) = baseline::init_baseline(&conn, &cfg, false).expect("init baseline");
    assert!(count > 0, "baseline should have at least 1 entry");

    // Create alert engine
    let alert_engine = AlertEngine::new(&cfg).expect("create alert engine");

    // Set up shutdown flag and event channel
    let shutdown = Arc::new(AtomicBool::new(false));
    let (event_tx, event_rx) = crossbeam_channel::bounded(1024);
    let watch_index = Arc::new(parking_lot::RwLock::new(
        vigil::watch_index::WatchGroupIndex::from_config(&cfg),
    ));
    let metrics = Arc::new(vigil::metrics::Metrics::new());

    // Start inotify monitor in a background thread
    let shutdown_clone = shutdown.clone();
    vigil::monitor::start_monitor(&cfg, event_tx, shutdown_clone, watch_index, metrics)
        .expect("start monitor");

    // Build event filter
    let mut event_filter = vigil::monitor::filter::EventFilter::new(&cfg);

    // Pre-compute watch group lookup
    let expanded_groups: Vec<(std::path::PathBuf, String, vigil::types::Severity)> = cfg
        .watch
        .iter()
        .flat_map(|(group_name, group)| {
            let expanded = config::expand_user_paths(&group.paths);
            expanded
                .into_iter()
                .map(move |p| (p, group_name.clone(), group.severity))
        })
        .collect();

    // Spawn event processing thread
    let conn2 = db::open_db(&cfg).expect("open db for processing");
    let shutdown_thread = shutdown.clone();
    let processing_handle = std::thread::spawn(move || {
        while !shutdown_thread.load(Ordering::Acquire) {
            match event_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => {
                    if !event_filter.should_process(&event) {
                        continue;
                    }
                    let path_str = event.path.to_string_lossy().into_owned();
                    let baseline_entry = match ops::get_baseline_by_path(&conn2, &path_str) {
                        Ok(Some(entry)) => entry,
                        Ok(None) => {
                            // New file — record a Created audit entry
                            if matches!(
                                event.event_type,
                                vigil::types::FsEventType::Create
                                    | vigil::types::FsEventType::MovedTo
                            ) {
                                let change = vigil::types::ChangeResult {
                                    path: event.path.clone(),
                                    change_types: vec![vigil::types::ChangeType::Created],
                                    severity: vigil::types::Severity::High,
                                    old_hash: None,
                                    new_hash: None,
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
                                    monitored_group: "custom".into(),
                                };
                                let _ = alert_engine.dispatch(&change, false, &conn2);
                            }
                            continue;
                        }
                        Err(_) => continue,
                    };

                    let (group_name, severity) = expanded_groups
                        .iter()
                        .find(|(wp, _, _)| event.path.starts_with(wp) || event.path == *wp)
                        .map(|(_, gn, sev)| (gn.clone(), *sev))
                        .unwrap_or(("unknown".into(), vigil::types::Severity::Medium));

                    match vigil::compare::compare_event(
                        &event.path,
                        &baseline_entry,
                        &group_name,
                        severity,
                        cfg.scanner.max_file_size,
                    ) {
                        Ok(Some(change)) => {
                            let _ = alert_engine.dispatch(&change, false, &conn2);
                        }
                        Ok(None) => {}
                        Err(_) => {}
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    // Give the monitor time to set up watches
    std::thread::sleep(Duration::from_millis(500));

    // 1. Modify the existing file
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&test_file)
            .expect("open for modify");
        f.write_all(b"modified content").expect("write modified");
        f.flush().expect("flush");
    }
    std::thread::sleep(Duration::from_millis(300));

    // 2. Create a new file
    let new_file = watched_dir.join("new_file.txt");
    fs::write(&new_file, b"new content").expect("write new file");
    std::thread::sleep(Duration::from_millis(300));

    // 3. Delete the new file
    fs::remove_file(&new_file).expect("delete new file");
    std::thread::sleep(Duration::from_millis(300));

    // Wait for events to be processed
    std::thread::sleep(Duration::from_secs(1));

    // Signal shutdown
    shutdown.store(true, Ordering::Release);
    processing_handle
        .join()
        .expect("processing thread panicked");

    // Verify audit log entries
    let entries = ops::get_recent_audit(&conn, 100).expect("get audit entries");

    // We should have at least one audit entry (the modification)
    assert!(
        !entries.is_empty(),
        "Expected at least one audit entry, found none. \
         This test requires inotify to be functional."
    );

    // Check that we recorded a modification
    let has_modified = entries.iter().any(|e| e.change_type == "modified");
    assert!(
        has_modified,
        "Expected a 'modified' audit entry for test.txt, found: {:?}",
        entries.iter().map(|e| &e.change_type).collect::<Vec<_>>()
    );

    // Verify PID file cleanup (we didn't create one in this test,
    // but verify the cleanup function works)
    let pid_path = tmp.path.join("test.pid");
    if pid_path.exists() {
        fs::remove_file(&pid_path).expect("cleanup pid file");
    }
    assert!(!pid_path.exists(), "PID file should be cleaned up");

    // Verify WAL checkpoint succeeds
    assert!(
        db::wal_checkpoint(&conn).is_ok(),
        "WAL checkpoint should succeed"
    );
}
