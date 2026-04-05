use std::sync::atomic::Ordering;
use std::time::Duration;

#[test]
#[cfg_attr(tarpaulin, ignore)]
fn daemon_start_and_shutdown_smoke_test() {
    let dir = tempfile::tempdir().unwrap();
    let watch_dir = dir.path().join("watch");
    std::fs::create_dir_all(&watch_dir).unwrap();
    let watched_file = watch_dir.join("file.txt");
    std::fs::write(&watched_file, b"hello").unwrap();

    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = dir.path().join("baseline.db");
    cfg.daemon.pid_file = dir.path().join("vigild.pid");
    cfg.daemon.runtime_dir = dir.path().join("run");
    cfg.daemon.monitor_backend = vigil::types::MonitorBackend::Inotify;
    cfg.alerts.log_file = dir.path().join("alerts.json");
    cfg.alerts.desktop_notifications = false;
    cfg.alerts.syslog = false;
    cfg.hooks.signal_socket.clear();
    cfg.watch.clear();
    cfg.watch.insert(
        "test".into(),
        vigil::config::WatchGroup {
            severity: vigil::types::Severity::Medium,
            paths: vec![watch_dir.to_string_lossy().to_string()],
        },
    );

    let daemon = vigil::Daemon::from_config(cfg).unwrap();
    let shutdown = daemon.shutdown.clone();

    let handle = std::thread::spawn(move || daemon.run());

    std::thread::sleep(Duration::from_millis(600));
    std::fs::write(&watched_file, b"world").unwrap();
    std::thread::sleep(Duration::from_millis(600));

    shutdown.store(true, Ordering::Release);

    let run_result = handle.join().unwrap();
    assert!(run_result.is_ok());

    let baseline_conn = vigil::db::open_db_at(&dir.path().join("baseline.db"), true).unwrap();
    let baseline_count = vigil::db::baseline_ops::count(&baseline_conn).unwrap();
    assert!(
        baseline_count > 0,
        "expected daemon startup to auto-initialize baseline"
    );
}
