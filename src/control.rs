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
use crate::types::{DaemonState, ScanMode};

/// Request sent through the scan trigger channel.
#[derive(Debug)]
pub struct ScanRequest {
    pub mode: ScanMode,
    pub response_tx: crossbeam_channel::Sender<ScanResponse>,
}

/// Response returned after a triggered scan completes.
#[derive(Debug, serde::Serialize)]
pub struct ScanResponse {
    pub ok: bool,
    pub total_checked: u64,
    pub changes_found: u64,
    pub errors: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Spawn the control socket listener thread.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    socket_path: PathBuf,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<DaemonState>>,
    shutdown: Arc<AtomicBool>,
    reload_flag: Arc<AtomicBool>,
    scan_trigger_tx: crossbeam_channel::Sender<ScanRequest>,
    baseline_db_path: &Path,
    startup_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
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
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }

    // Set non-blocking so we can check shutdown
    listener
        .set_nonblocking(true)
        .map_err(|e| VigilError::Control(format!("cannot set non-blocking: {}", e)))?;

    let socket_path_clone = socket_path.clone();

    // Use the HMAC key loaded at startup — never re-read from disk
    let hmac_key: Option<Vec<u8>> = startup_hmac_key.map(|k| (*k).clone());
    let auth_enabled = hmac_key.is_some();

    std::thread::Builder::new()
        .name("vigil-control".into())
        .spawn(move || {
            tracing::info!(path = %socket_path_clone.display(), "control socket listening");

            while !shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

                        if let Err(e) = handle_connection(
                            stream,
                            &metrics,
                            &state,
                            &reload_flag,
                            &scan_trigger_tx,
                            &db_path,
                            hmac_key.as_deref(),
                            auth_enabled,
                        ) {
                            tracing::debug!(error = %e, "control socket connection error");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "control socket accept error");
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }

            // Cleanup socket file on shutdown
            let _ = std::fs::remove_file(&socket_path_clone);
            tracing::info!("control socket stopped");
        })
        .map_err(|e| VigilError::Control(format!("cannot spawn control thread: {}", e)))
}

#[allow(clippy::too_many_arguments)]
fn handle_connection(
    stream: std::os::unix::net::UnixStream,
    metrics: &Metrics,
    state: &RwLock<DaemonState>,
    reload_flag: &AtomicBool,
    scan_trigger_tx: &crossbeam_channel::Sender<ScanRequest>,
    baseline_db_path: &Path,
    hmac_key: Option<&[u8]>,
    auth_enabled: bool,
) -> Result<()> {
    // Log peer credentials when available
    log_peer_credentials(&stream);

    if auth_enabled {
        if let Some(key) = hmac_key {
            // Challenge-response authentication
            let nonce = match generate_nonce() {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "nonce generation failed — rejecting connection");
                    let fail_resp = r#"{"ok":false,"error":"internal security error"}"#;
                    let mut writer = &stream;
                    let _ = writer.write_all(fail_resp.as_bytes());
                    let _ = writer.write_all(b"\n");
                    let _ = writer.flush();
                    return Ok(());
                }
            };
            let challenge = serde_json::json!({"challenge": nonce});
            let mut writer = &stream;
            let mut challenge_str =
                serde_json::to_string(&challenge).unwrap_or_else(|_| r#"{"challenge":""}"#.into());
            challenge_str.push('\n');
            writer
                .write_all(challenge_str.as_bytes())
                .map_err(|e| VigilError::Control(format!("failed to send challenge: {}", e)))?;
            writer
                .flush()
                .map_err(|e| VigilError::Control(format!("failed to flush challenge: {}", e)))?;

            // Read authenticated request
            let mut line = String::new();
            let mut reader = BufReader::new(&stream);
            if reader.read_line(&mut line).is_err() {
                return Ok(());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return Ok(());
            }

            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(request) => {
                    let client_response = request["response"].as_str().unwrap_or("");
                    let expected_hmac =
                        crate::hmac::compute_hmac(key, nonce.as_bytes()).unwrap_or_default();
                    if client_response != expected_hmac {
                        let fail_resp = r#"{"ok":false,"error":"authentication failed"}"#;
                        let mut writer = &stream;
                        let _ = writer.write_all(fail_resp.as_bytes());
                        let _ = writer.write_all(b"\n");
                        let _ = writer.flush();
                        tracing::warn!("control socket authentication failed");
                        return Ok(());
                    }

                    let method = request["method"].as_str().unwrap_or("");
                    let response = dispatch(
                        method,
                        &request,
                        metrics,
                        state,
                        reload_flag,
                        scan_trigger_tx,
                        baseline_db_path,
                    );

                    let mut writer = &stream;
                    let mut response_str = serde_json::to_string(&response)
                        .unwrap_or_else(|_| r#"{"ok":false,"error":"serialization error"}"#.into());
                    response_str.push('\n');
                    let _ = writer.write_all(response_str.as_bytes());
                    let _ = writer.flush();
                }
                Err(_) => {
                    let fail_resp = r#"{"ok":false,"error":"invalid JSON"}"#;
                    let mut writer = &stream;
                    let _ = writer.write_all(fail_resp.as_bytes());
                    let _ = writer.write_all(b"\n");
                    let _ = writer.flush();
                }
            }
            return Ok(());
        }
    } else {
        tracing::warn!("control socket connection without authentication (hmac_signing disabled)");
    }

    // Unauthenticated fallback path
    let mut line = String::new();
    let mut reader = BufReader::new(&stream);
    if reader.read_line(&mut line).is_err() {
        return Ok(());
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(request) => {
            let method = request["method"].as_str().unwrap_or("");
            dispatch(
                method,
                &request,
                metrics,
                state,
                reload_flag,
                scan_trigger_tx,
                baseline_db_path,
            )
        }
        Err(_) => serde_json::json!({"ok": false, "error": "invalid JSON"}),
    };

    let mut writer = &stream;
    let mut response_str = serde_json::to_string(&response)
        .unwrap_or_else(|_| r#"{"ok":false,"error":"serialization error"}"#.into());
    response_str.push('\n');
    let _ = writer.write_all(response_str.as_bytes());
    let _ = writer.flush();

    Ok(())
}

fn dispatch(
    method: &str,
    request: &serde_json::Value,
    metrics: &Metrics,
    state: &RwLock<DaemonState>,
    reload_flag: &AtomicBool,
    scan_trigger_tx: &crossbeam_channel::Sender<ScanRequest>,
    baseline_db_path: &Path,
) -> serde_json::Value {
    // Log and count security-relevant control socket commands
    if matches!(method, "reload" | "scan") {
        log_control_action(method, metrics);
    }

    match method {
        "status" => handle_status(metrics, state),
        "baseline_count" => handle_baseline_count(baseline_db_path),
        "reload" => handle_reload(reload_flag),
        "scan" => handle_scan(request, scan_trigger_tx),
        "metrics_prometheus" => handle_metrics_prometheus(metrics),
        _ => serde_json::json!({"ok": false, "error": format!("unknown method: {}", method)}),
    }
}

fn handle_status(metrics: &Metrics, state: &RwLock<DaemonState>) -> serde_json::Value {
    let snap = metrics.snapshot();
    let state_str = match &*state.read() {
        DaemonState::Healthy => "healthy".to_string(),
        DaemonState::Degraded { reason, .. } => format!("degraded: {}", reason),
    };
    let uptime_seconds = chrono::Utc::now().timestamp() - snap.uptime_start;
    serde_json::json!({
        "ok": true,
        "daemon": {
            "state": state_str,
            "uptime_seconds": uptime_seconds,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "metrics": {
            "events_received": snap.events_received,
            "events_processed": snap.events_processed,
            "events_dropped": snap.events_dropped,
            "events_debounced": snap.events_debounced,
            "events_filtered": snap.events_filtered,
            "hashes_computed": snap.hashes_computed,
            "changes_detected": snap.changes_detected,
            "alerts_dispatched": snap.alerts_dispatched,
            "alerts_suppressed": snap.alerts_suppressed,
            "db_writes": snap.db_writes,
            "db_errors": snap.db_errors,
            "panics_caught": snap.panics_caught,
            "scan_duration_ms": snap.scan_duration_ms,
            "last_scan_total": snap.last_scan_total,
        },
    })
}

fn handle_baseline_count(baseline_db_path: &Path) -> serde_json::Value {
    match crate::db::open_baseline_db_readonly(baseline_db_path) {
        Ok(conn) => match baseline_ops::count(&conn) {
            Ok(count) => serde_json::json!({"ok": true, "count": count}),
            Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
        },
        Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
    }
}

fn handle_reload(reload_flag: &AtomicBool) -> serde_json::Value {
    reload_flag.store(true, Ordering::Release);
    serde_json::json!({"ok": true, "message": "reload signal sent"})
}

fn handle_scan(
    request: &serde_json::Value,
    scan_trigger_tx: &crossbeam_channel::Sender<ScanRequest>,
) -> serde_json::Value {
    let mode = request
        .get("params")
        .and_then(|p| p.get("mode"))
        .and_then(|m| m.as_str())
        .map(|s| match s {
            "full" => ScanMode::Full,
            _ => ScanMode::Incremental,
        })
        .unwrap_or(ScanMode::Incremental);

    let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);

    if scan_trigger_tx
        .send(ScanRequest {
            mode,
            response_tx: resp_tx,
        })
        .is_err()
    {
        return serde_json::json!({"ok": false, "error": "scan channel unavailable"});
    }

    match resp_rx.recv_timeout(Duration::from_secs(600)) {
        Ok(resp) => serde_json::to_value(&resp)
            .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "serialization error"})),
        Err(_) => serde_json::json!({"ok": false, "error": "scan timed out"}),
    }
}

fn handle_metrics_prometheus(metrics: &Metrics) -> serde_json::Value {
    let snap = metrics.snapshot();
    serde_json::json!({
        "ok": true,
        "text": snap.to_prometheus(),
    })
}

/// Log control socket command execution for audit trail.
fn log_control_action(method: &str, metrics: &Metrics) {
    tracing::warn!(method = method, "control socket command executed");
    metrics.control_commands.fetch_add(1, Ordering::Relaxed);
}

/// Generate a random 32-byte hex nonce for challenge-response auth.
/// Returns Err if randomness cannot be obtained, to prevent predictable nonces.
fn generate_nonce() -> std::result::Result<String, std::io::Error> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| std::io::Error::new(e.kind(), format!("cannot open /dev/urandom: {}", e)))?;
    f.read_exact(&mut buf)
        .map_err(|e| std::io::Error::new(e.kind(), format!("/dev/urandom read failed: {}", e)))?;
    // Verify buffer is not all-zero (catastrophic RNG failure)
    if buf.iter().all(|&b| b == 0) {
        return Err(std::io::Error::other(
            "urandom returned all zeros — refusing to generate nonce",
        ));
    }
    Ok(hex::encode(buf))
}

/// Log peer credentials of the connecting process using SO_PEERCRED.
fn log_peer_credentials(stream: &std::os::unix::net::UnixStream) {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: getsockopt with SO_PEERCRED is safe on a valid Unix socket fd.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 {
        tracing::info!(
            peer_pid = cred.pid,
            peer_uid = cred.uid,
            peer_gid = cred.gid,
            "control socket connection"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn control_socket_roundtrip() {
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
        let (scan_tx, _scan_rx) = crossbeam_channel::bounded::<ScanRequest>(1);

        let handle = spawn(
            socket_path.clone(),
            metrics,
            state,
            shutdown.clone(),
            reload_flag,
            scan_tx,
            &db_path,
            None,
        )
        .unwrap();

        // Give the thread time to bind
        std::thread::sleep(Duration::from_millis(200));

        // Test status
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
        assert!(parsed["daemon"]["version"].is_string());
        assert!(parsed["metrics"]["events_received"].is_number());

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

        // Test reload
        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(stream, r#"{{"method":"reload"}}"#).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);

        // Test metrics_prometheus
        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(stream, r#"{{"method":"metrics_prometheus"}}"#).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        let text = parsed["text"].as_str().unwrap();
        assert!(text.contains("vigil_events_received_total"));

        // Test unknown method
        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(stream, r#"{{"method":"bogus"}}"#).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], false);
        assert!(parsed["error"].as_str().unwrap().contains("unknown method"));

        // Test malformed JSON
        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(stream, "not json").unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], false);

        // Shutdown
        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn dispatch_status_fields() {
        let metrics = Metrics::new();
        metrics.events_received.fetch_add(10, Ordering::Relaxed);
        let state = RwLock::new(DaemonState::Healthy);
        let reload_flag = AtomicBool::new(false);
        let (scan_tx, _scan_rx) = crossbeam_channel::bounded::<ScanRequest>(1);

        let result = dispatch(
            "status",
            &serde_json::json!({"method": "status"}),
            &metrics,
            &state,
            &reload_flag,
            &scan_tx,
            Path::new("/dev/null"),
        );

        assert_eq!(result["ok"], true);
        assert_eq!(result["daemon"]["state"], "healthy");
        assert_eq!(result["metrics"]["events_received"], 10);
    }

    #[test]
    fn control_commands_metric_increments_on_reload() {
        let metrics = Metrics::new();
        let state = RwLock::new(DaemonState::Healthy);
        let reload_flag = AtomicBool::new(false);
        let (scan_tx, _scan_rx) = crossbeam_channel::bounded::<ScanRequest>(1);

        assert_eq!(metrics.control_commands.load(Ordering::Relaxed), 0);

        dispatch(
            "reload",
            &serde_json::json!({"method": "reload"}),
            &metrics,
            &state,
            &reload_flag,
            &scan_tx,
            Path::new("/dev/null"),
        );

        assert_eq!(
            metrics.control_commands.load(Ordering::Relaxed),
            1,
            "control_commands metric should increment on reload"
        );
    }
}
