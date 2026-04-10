use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
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

/// Shared state for the control socket handler.
pub struct ControlHandler {
    pub metrics: Arc<Metrics>,
    pub state: Arc<RwLock<DaemonState>>,
    pub reload_flag: Arc<AtomicBool>,
    pub scan_trigger_tx: crossbeam_channel::Sender<ScanRequest>,
    pub baseline_db_path: PathBuf,
    pub hmac_key: Option<Vec<u8>>,
    pub auth_enabled: bool,
}

pub fn spawn(
    socket_path: PathBuf,
    handler: ControlHandler,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
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

    std::thread::Builder::new()
        .name("vigil-control".into())
        .spawn(move || {
            tracing::info!(path = %socket_path_clone.display(), "control socket listening");

            while !shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

                        if let Err(e) = handler.handle_connection(stream) {
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

impl ControlHandler {
    fn handle_connection(&self, stream: std::os::unix::net::UnixStream) -> Result<()> {
        log_peer_credentials(&stream);
        let request = if self.auth_enabled {
            self.authenticate_and_read(&stream)?
        } else {
            tracing::warn!(
                "control socket connection without authentication (hmac_signing disabled)"
            );
            match self.read_request(&stream) {
                Ok(r) => r,
                Err(_) => {
                    let _ = self.write_response(
                        &stream,
                        &serde_json::json!({"ok": false, "error": "invalid JSON"}),
                    );
                    return Ok(());
                }
            }
        };
        let method = request["method"].as_str().unwrap_or("");
        let response = self.dispatch(method, &request);
        self.write_response(&stream, &response)
    }

    fn authenticate_and_read(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<serde_json::Value> {
        let key = self
            .hmac_key
            .as_deref()
            .ok_or_else(|| VigilError::Control("auth enabled but no HMAC key".into()))?;

        // Generate and send challenge
        let nonce = match generate_nonce() {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e, "nonce generation failed — rejecting connection");
                let fail_resp = r#"{"ok":false,"error":"internal security error"}"#;
                let mut writer = stream;
                let _ = writer.write_all(fail_resp.as_bytes());
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
                return Err(VigilError::Control("nonce generation failed".into()));
            }
        };
        let challenge = serde_json::json!({"challenge": nonce});
        let mut writer = stream;
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
        let mut reader = BufReader::new(stream);
        if reader.read_line(&mut line).is_err() {
            return Err(VigilError::Control("failed to read request".into()));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(VigilError::Control("empty request".into()));
        }

        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(request) => {
                let client_response = request["response"].as_str().unwrap_or("");
                let expected_hmac =
                    crate::hmac::compute_hmac(key, nonce.as_bytes()).unwrap_or_default();
                if client_response != expected_hmac {
                    let fail_resp = r#"{"ok":false,"error":"authentication failed"}"#;
                    let mut writer = stream;
                    let _ = writer.write_all(fail_resp.as_bytes());
                    let _ = writer.write_all(b"\n");
                    let _ = writer.flush();
                    tracing::warn!("control socket authentication failed");
                    return Err(VigilError::Control("authentication failed".into()));
                }
                Ok(request)
            }
            Err(_) => {
                let fail_resp = r#"{"ok":false,"error":"invalid JSON"}"#;
                let mut writer = stream;
                let _ = writer.write_all(fail_resp.as_bytes());
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
                Err(VigilError::Control("invalid JSON".into()))
            }
        }
    }

    fn read_request(&self, stream: &std::os::unix::net::UnixStream) -> Result<serde_json::Value> {
        let mut line = String::new();
        let mut reader = BufReader::new(stream);
        if reader.read_line(&mut line).is_err() {
            return Err(VigilError::Control("failed to read request".into()));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(VigilError::Control("empty request".into()));
        }
        serde_json::from_str::<serde_json::Value>(trimmed)
            .map_err(|_| VigilError::Control("invalid JSON".into()))
    }

    fn write_response(
        &self,
        stream: &std::os::unix::net::UnixStream,
        response: &serde_json::Value,
    ) -> Result<()> {
        let mut writer = stream;
        let mut response_str = serde_json::to_string(response)
            .unwrap_or_else(|_| r#"{"ok":false,"error":"serialization error"}"#.into());
        response_str.push('\n');
        let _ = writer.write_all(response_str.as_bytes());
        let _ = writer.flush();
        Ok(())
    }

    fn dispatch(&self, method: &str, request: &serde_json::Value) -> serde_json::Value {
        // Log and count security-relevant control socket commands
        if matches!(method, "reload" | "scan") {
            log_control_action(method, &self.metrics);
        }

        match method {
            "status" => self.handle_status(),
            "baseline_count" => self.handle_baseline_count(),
            "reload" => self.handle_reload(),
            "scan" => self.handle_scan(request),
            "metrics_prometheus" => self.handle_metrics_prometheus(),
            _ => serde_json::json!({"ok": false, "error": format!("unknown method: {}", method)}),
        }
    }

    fn handle_status(&self) -> serde_json::Value {
        let snap = self.metrics.snapshot();
        let state_str = match &*self.state.read() {
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

    fn handle_baseline_count(&self) -> serde_json::Value {
        match crate::db::open_baseline_db_readonly(&self.baseline_db_path) {
            Ok(conn) => match baseline_ops::count(&conn) {
                Ok(count) => serde_json::json!({"ok": true, "count": count}),
                Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
            },
            Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
        }
    }

    fn handle_reload(&self) -> serde_json::Value {
        self.reload_flag.store(true, Ordering::Release);
        serde_json::json!({"ok": true, "message": "reload signal sent"})
    }

    fn handle_scan(&self, request: &serde_json::Value) -> serde_json::Value {
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

        if self
            .scan_trigger_tx
            .send(ScanRequest {
                mode,
                response_tx: resp_tx,
            })
            .is_err()
        {
            return serde_json::json!({"ok": false, "error": "scan channel unavailable"});
        }

        match resp_rx.recv_timeout(Duration::from_secs(600)) {
            Ok(resp) => serde_json::to_value(&resp).unwrap_or_else(
                |_| serde_json::json!({"ok": false, "error": "serialization error"}),
            ),
            Err(_) => serde_json::json!({"ok": false, "error": "scan timed out"}),
        }
    }

    fn handle_metrics_prometheus(&self) -> serde_json::Value {
        let snap = self.metrics.snapshot();
        serde_json::json!({
            "ok": true,
            "text": snap.to_prometheus(),
        })
    }
}

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
#[allow(unsafe_code)]
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

        let handler = ControlHandler {
            metrics,
            state,
            reload_flag,
            scan_trigger_tx: scan_tx,
            baseline_db_path: db_path.clone(),
            hmac_key: None,
            auth_enabled: false,
        };
        let handle = spawn(socket_path.clone(), handler, shutdown.clone()).unwrap();

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
        let metrics = Arc::new(Metrics::new());
        metrics.events_received.fetch_add(10, Ordering::Relaxed);
        let state = Arc::new(RwLock::new(DaemonState::Healthy));
        let reload_flag = Arc::new(AtomicBool::new(false));
        let (scan_tx, _scan_rx) = crossbeam_channel::bounded::<ScanRequest>(1);

        let handler = ControlHandler {
            metrics: metrics.clone(),
            state,
            reload_flag,
            scan_trigger_tx: scan_tx,
            baseline_db_path: PathBuf::from("/dev/null"),
            hmac_key: None,
            auth_enabled: false,
        };

        let result = handler.dispatch("status", &serde_json::json!({"method": "status"}));

        assert_eq!(result["ok"], true);
        assert_eq!(result["daemon"]["state"], "healthy");
        assert_eq!(result["metrics"]["events_received"], 10);
    }

    #[test]
    fn control_commands_metric_increments_on_reload() {
        let metrics = Arc::new(Metrics::new());
        let state = Arc::new(RwLock::new(DaemonState::Healthy));
        let reload_flag = Arc::new(AtomicBool::new(false));
        let (scan_tx, _scan_rx) = crossbeam_channel::bounded::<ScanRequest>(1);

        assert_eq!(metrics.control_commands.load(Ordering::Relaxed), 0);

        let handler = ControlHandler {
            metrics: metrics.clone(),
            state,
            reload_flag,
            scan_trigger_tx: scan_tx,
            baseline_db_path: PathBuf::from("/dev/null"),
            hmac_key: None,
            auth_enabled: false,
        };

        handler.dispatch("reload", &serde_json::json!({"method": "reload"}));

        assert_eq!(
            metrics.control_commands.load(Ordering::Relaxed),
            1,
            "control_commands metric should increment on reload"
        );
    }
}
