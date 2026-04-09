use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::bounded;
use vigil::alert::{AlertDispatcher, AlertPayload};
use vigil::types::{Change, ChangeResult, Severity};

#[test]
fn dispatcher_writes_and_verifies_audit_chain() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.db");

    let mut cfg = vigil::config::default_config();
    cfg.alerts.syslog = false;
    cfg.alerts.desktop_notifications = false;
    cfg.alerts.log_file = dir.path().join("alerts.json");
    cfg.hooks.signal_socket.clear();
    cfg.alerts.remote_syslog.enabled = false;

    let metrics = Arc::new(vigil::metrics::Metrics::new());
    let dispatcher = AlertDispatcher::new(&cfg, &audit_path, metrics.clone(), None).unwrap();

    let (tx, rx) = bounded::<AlertPayload>(4);
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let handle = std::thread::spawn(move || {
        dispatcher.run(rx, shutdown_clone);
    });

    tx.send(AlertPayload {
        change: ChangeResult {
            path: Arc::new("/tmp/test-alert".into()),
            changes: vec![Change::Created],
            severity: Severity::High,
            monitored_group: "test".into(),
            process: None,
            package: None,
            package_update: false,
        },
        maintenance_window: false,
    })
    .unwrap();

    std::thread::sleep(Duration::from_millis(300));
    shutdown.store(true, Ordering::Release);
    drop(tx);
    handle.join().unwrap();

    let conn = rusqlite::Connection::open(&audit_path).unwrap();
    let entries = vigil::db::audit_ops::get_recent(&conn, 10).unwrap();
    assert_eq!(entries.len(), 1);

    let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn).unwrap();
    assert_eq!(total, 1);
    assert_eq!(valid, 1);
    assert!(breaks.is_empty());
    assert_eq!(missing, 0);
}
