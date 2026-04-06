use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::RwLock;

use crate::db::baseline_ops;
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::DaemonState;

/// Spawn the control socket listener thread.
pub fn spawn(
    socket_path: PathBuf,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<DaemonState>>,
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
    baseline_db_path: &Path,
) -> Result<JoinHandle<()>> {
    let db_path = baseline_db_path.to_path_buf();

    // Remove stale socket
    let _ = std::fs::remove_file(&socket_path);

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path).map_err(|e| {
        VigilError::Control(format!(
            "cannot bind control socket {}: {}",
            socket_path.display(),
            e
        ))
    })?;

    // Set socket permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }

    // Set non-blocking so we can check shutdown
    listener
        .set_nonblocking(true)
        .map_err(|e| VigilError::Control(format!("cannot set non-blocking: {}", e)))?;

    let socket_path_clone = socket_path.clone();

    std::thread::Builder::new()
        .name("vigil-control".into())
        .spawn(move || {
            tracing::info!(path = %socket_path_clone.display(), "control socket listening");

            while !shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

                        if let Err(e) =
                            handle_connection(stream, &metrics, &state, &reload_flag, &db_path)
                        {
                            tracing::debug!(error = %e, "control socket connection error");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "control socket accept error");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }

            // Cleanup socket file on shutdown
            let _ = std::fs::remove_file(&socket_path_clone);
            tracing::info!("control socket stopped");
        })
        .map_err(|e| VigilError::Control(format!("cannot spawn control thread: {}", e)))
}

fn handle_connection(
    stream: std::os::unix::net::UnixStream,
    metrics: &Metrics,
    state: &RwLock<DaemonState>,
    reload_flag: &AtomicBool,
    baseline_db_path: &Path,
) -> Result<()> {
    let reader = BufReader::new(&stream);
    let mut writer = &stream;

    // Read one JSON line
    let mut line = String::new();
    let mut reader = reader;
    if reader.read_line(&mut line).is_err() {
        return Ok(());
    }

    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }

    let request: serde_json::Value = serde_json::from_str(line)
        .map_err(|e| VigilError::Control(format!("invalid JSON: {}", e)))?;

    let method = request["method"].as_str().unwrap_or("");

    let response = match method {
        "status" => {
            let snap = metrics.snapshot();
            let state_val = match &*state.read() {
                DaemonState::Healthy => serde_json::json!("healthy"),
                DaemonState::Degraded { reason, since } => serde_json::json!({
                    "degraded": { "reason": reason, "since": since.to_rfc3339() }
                }),
            };
            serde_json::json!({
                "ok": true,
                "metrics": snap,
                "state": state_val,
                "uptime_secs": chrono::Utc::now().timestamp() - snap.uptime_start,
            })
        }
        "baseline_count" => match crate::db::open_baseline_db_readonly(baseline_db_path) {
            Ok(conn) => match baseline_ops::count(&conn) {
                Ok(count) => serde_json::json!({"ok": true, "count": count}),
                Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
            },
            Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
        },
        "reload" => {
            reload_flag.store(true, Ordering::Release);
            serde_json::json!({"ok": true, "message": "reload requested"})
        }
        _ => {
            serde_json::json!({"ok": false, "error": format!("unknown method: {}", method)})
        }
    };

    let mut response_str = serde_json::to_string(&response).unwrap_or_else(|_| "{}".into());
    response_str.push('\n');
    let _ = writer.write_all(response_str.as_bytes());
    let _ = writer.flush();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn control_socket_status_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("test-control.sock");
        let db_path = dir.path().join("baseline.db");

        // Create a minimal baseline DB
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();
        drop(conn);

        let metrics = Arc::new(Metrics::new());
        let state = Arc::new(RwLock::new(DaemonState::Healthy));
        let shutdown = Arc::new(AtomicBool::new(false));
        let reload_flag = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            socket_path.clone(),
            metrics,
            state,
            shutdown.clone(),
            reload_flag,
            &db_path,
        )
        .unwrap();

        // Give the thread time to bind
        std::thread::sleep(Duration::from_millis(200));

        // Connect and send status command
        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(stream, r#"{{"method":"status"}}"#).unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        assert!(parsed["metrics"].is_object());

        // Test baseline_count
        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(stream, r#"{{"method":"baseline_count"}}"#).unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["count"], 0);

        // Shutdown
        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }
}
