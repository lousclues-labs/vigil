use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};

use crate::db::baseline_ops;
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::{DaemonState, ScanMode};
use zeroize::Zeroizing;

/// Maximum size of a single control socket request line.
/// Legitimate requests are small JSON objects (< 1KB typically).
/// 64KB provides generous headroom while preventing OOM attacks.
const MAX_REQUEST_LINE_BYTES: u64 = 65_536;

/// Maximum number of concurrent in-flight control socket connections.
/// Bounds resource usage from a slow/malicious peer holding multiple sockets.
/// Excess connections receive a 503-style JSON refusal and close immediately.
const MAX_CONCURRENT_CONNECTIONS: usize = 8;

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
    pub baseline_conn: Arc<Mutex<rusqlite::Connection>>,
    pub config: Arc<arc_swap::ArcSwap<crate::config::Config>>,
    pub hmac_key: Option<Zeroizing<Vec<u8>>>,
    pub auth_enabled: bool,
    pub maintenance_active: Arc<AtomicBool>,
    pub maintenance_entered_at: Arc<AtomicI64>,
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
            let handler = Arc::new(handler);
            let in_flight = Arc::new(AtomicUsize::new(0));

            while !shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

                        // Bound concurrent connections so a slow/hung peer
                        // cannot starve health-check traffic from `vigil
                        // update`. Atomic-CAS reservation slot.
                        let current = in_flight.load(Ordering::Acquire);
                        if current >= MAX_CONCURRENT_CONNECTIONS {
                            let _ = handler.write_response(
                                &stream,
                                &serde_json::json!({
                                    "ok": false,
                                    "error": "control socket busy: too many concurrent connections"
                                }),
                            );
                            tracing::warn!(
                                in_flight = current,
                                max = MAX_CONCURRENT_CONNECTIONS,
                                "rejecting control socket connection: at concurrency limit"
                            );
                            continue;
                        }
                        in_flight.fetch_add(1, Ordering::AcqRel);

                        let handler_clone = Arc::clone(&handler);
                        let in_flight_clone = Arc::clone(&in_flight);
                        match std::thread::Builder::new()
                            .name("vigil-control-conn".into())
                            .spawn(move || {
                                if let Err(e) = handler_clone.handle_connection(stream) {
                                    tracing::debug!(error = %e, "control socket connection error");
                                }
                                in_flight_clone.fetch_sub(1, Ordering::AcqRel);
                            }) {
                            Ok(_) => {}
                            Err(e) => {
                                // VIGIL-VULN-073: spawn failed — release
                                // the in-flight slot immediately to prevent
                                // permanent slot leak that would wedge the socket.
                                in_flight.fetch_sub(1, Ordering::AcqRel);
                                tracing::error!(
                                    error = %e,
                                    "failed to spawn control connection handler thread"
                                );
                            }
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
        let peer = peer_credentials(&stream);
        match &peer {
            Some(p) => {
                tracing::info!(
                    peer_pid = p.pid,
                    peer_uid = p.uid,
                    peer_gid = p.gid,
                    "control socket connection"
                );
            }
            None => {
                // Without SO_PEERCRED we cannot tell who is on the other end.
                // Fail closed rather than silently allow.
                let _ = self.write_response(
                    &stream,
                    &serde_json::json!({
                        "ok": false,
                        "error": "unauthorized: peer credentials unavailable"
                    }),
                );
                tracing::warn!("rejecting control socket connection: SO_PEERCRED unavailable");
                return Ok(());
            }
        }

        // Enforce peer UID even when HMAC auth is disabled. The socket file is
        // mode 0600 so the kernel typically blocks non-root access, but defense
        // in depth: explicitly reject any connection whose peer UID is neither
        // root (0) nor the daemon's own effective UID.
        if let Some(p) = &peer {
            let our_uid = current_euid();
            if p.uid != 0 && p.uid != our_uid {
                let _ = self.write_response(
                    &stream,
                    &serde_json::json!({
                        "ok": false,
                        "error": "unauthorized: peer UID is not root or daemon UID"
                    }),
                );
                tracing::warn!(
                    peer_pid = p.pid,
                    peer_uid = p.uid,
                    "rejecting control socket connection: unauthorized peer UID"
                );
                return Ok(());
            }
        }

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
            .as_ref()
            .map(|k| k.as_slice())
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

        // Read authenticated request (bounded)
        let line = read_bounded_line(stream)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(VigilError::Control("empty request".into()));
        }

        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(request) => {
                let client_response = request["response"].as_str().unwrap_or("");
                // Use constant-time HMAC verification (Mac::verify_slice). The
                // previous string `!=` comparison was both timing-leaky and
                // could be bypassed when compute_hmac() returned an empty
                // String via unwrap_or_default().
                if !crate::hmac::verify_hmac(key, nonce.as_bytes(), client_response) {
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
        let line = read_bounded_line(stream)?;
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
        let response_str = serde_json::to_string(response)
            .map_err(|e| VigilError::Control(format!("response serialize failed: {}", e)))?;
        writer
            .write_all(response_str.as_bytes())
            .map_err(|e| VigilError::Control(format!("response write failed: {}", e)))?;
        writer
            .write_all(b"\n")
            .map_err(|e| VigilError::Control(format!("response newline write failed: {}", e)))?;
        writer
            .flush()
            .map_err(|e| VigilError::Control(format!("response flush failed: {}", e)))?;
        Ok(())
    }

    fn dispatch(&self, method: &str, request: &serde_json::Value) -> serde_json::Value {
        // Log and count security-relevant control socket commands
        if matches!(
            method,
            "reload" | "scan" | "maintenance_enter" | "maintenance_exit" | "baseline_refresh"
        ) {
            log_control_action(method, &self.metrics);
        }

        match method {
            "status" => self.handle_status(),
            "baseline_count" => self.handle_baseline_count(),
            "reload" => self.handle_reload(),
            "scan" => self.handle_scan(request),
            "metrics_prometheus" => self.handle_metrics_prometheus(),
            "maintenance_enter" => self.handle_maintenance_enter(),
            "maintenance_exit" => self.handle_maintenance_exit(),
            "baseline_refresh" => self.handle_baseline_refresh(),
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
                "maintenance_window": self.maintenance_active.load(Ordering::Acquire),
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
        let conn = self.baseline_conn.lock();
        match baseline_ops::count(&conn) {
            Ok(count) => serde_json::json!({"ok": true, "count": count}),
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

    fn handle_maintenance_enter(&self) -> serde_json::Value {
        self.maintenance_active.store(true, Ordering::Release);
        self.maintenance_entered_at
            .store(chrono::Utc::now().timestamp(), Ordering::Release);
        serde_json::json!({"ok": true, "message": "maintenance window entered"})
    }

    fn handle_maintenance_exit(&self) -> serde_json::Value {
        self.maintenance_active.store(false, Ordering::Release);
        self.maintenance_entered_at.store(0, Ordering::Release);
        serde_json::json!({"ok": true, "message": "maintenance window exited"})
    }

    fn handle_baseline_refresh(&self) -> serde_json::Value {
        // Refuse baseline refresh while in degraded state to prevent
        // cementing compromised filesystem state as the new baseline
        {
            let state = self.state.read();
            if let DaemonState::Degraded { reason, .. } = &*state {
                return serde_json::json!({
                    "ok": false,
                    "error": format!("baseline refresh refused: daemon is degraded ({})", reason)
                });
            }
        }
        let cfg = self.config.load();
        let conn = self.baseline_conn.lock();
        match crate::scanner::build_initial_baseline(&conn, &cfg) {
            Ok(result) => {
                serde_json::json!({
                    "ok": true,
                    "message": "baseline refreshed",
                    "total_count": result.total_count,
                    "duration_ms": result.duration.as_millis() as u64,
                })
            }
            Err(e) => {
                serde_json::json!({"ok": false, "error": format!("baseline refresh failed: {}", e)})
            }
        }
    }
}

/// Read a single line from the stream, bounded to MAX_REQUEST_LINE_BYTES.
/// Returns Err if the line exceeds the limit or if an I/O error occurs.
fn read_bounded_line(stream: &std::os::unix::net::UnixStream) -> Result<String> {
    let mut line = String::new();
    let limited = Read::take(stream, MAX_REQUEST_LINE_BYTES);
    let mut reader = BufReader::new(limited);
    match reader.read_line(&mut line) {
        Ok(0) => Err(VigilError::Control(
            "empty request (connection closed)".into(),
        )),
        Ok(_) => {
            if !line.ends_with('\n') && line.len() as u64 >= MAX_REQUEST_LINE_BYTES {
                Err(VigilError::Control(format!(
                    "request exceeds maximum size of {} bytes",
                    MAX_REQUEST_LINE_BYTES
                )))
            } else {
                Ok(line)
            }
        }
        Err(e) => Err(VigilError::Control(format!("read error: {}", e))),
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

/// Read peer credentials of the connecting process via SO_PEERCRED.
/// Returns `None` if the syscall fails (in which case callers should reject
/// the connection).
#[allow(unsafe_code)]
fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> Option<libc::ucred> {
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
        Some(cred)
    } else {
        None
    }
}

/// Return the daemon's effective UID. Cached in a OnceLock to avoid
/// repeated syscalls on every connection (VIGIL-VULN-073).
#[allow(unsafe_code)]
fn current_euid() -> u32 {
    static EUID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *EUID.get_or_init(|| {
        // SAFETY: geteuid is always safe to call.
        unsafe { libc::geteuid() }
    })
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
            baseline_conn: Arc::new(Mutex::new(
                crate::db::open_baseline_db_readonly(&db_path).unwrap(),
            )),
            config: Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::config::default_config(),
            )),
            hmac_key: None,
            auth_enabled: false,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            maintenance_entered_at: Arc::new(AtomicI64::new(0)),
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
            baseline_conn: Arc::new(Mutex::new({
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                crate::db::schema::create_baseline_tables(&conn).unwrap();
                conn
            })),
            config: Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::config::default_config(),
            )),
            hmac_key: None,
            auth_enabled: false,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            maintenance_entered_at: Arc::new(AtomicI64::new(0)),
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
            baseline_conn: Arc::new(Mutex::new({
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                crate::db::schema::create_baseline_tables(&conn).unwrap();
                conn
            })),
            config: Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::config::default_config(),
            )),
            hmac_key: None,
            auth_enabled: false,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            maintenance_entered_at: Arc::new(AtomicI64::new(0)),
        };

        handler.dispatch("reload", &serde_json::json!({"method": "reload"}));

        assert_eq!(
            metrics.control_commands.load(Ordering::Relaxed),
            1,
            "control_commands metric should increment on reload"
        );
    }

    #[test]
    fn read_bounded_line_rejects_oversized_request() {
        use std::os::unix::net::UnixStream;

        let (mut client, server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send data larger than MAX_REQUEST_LINE_BYTES without a newline
        let oversized = vec![b'a'; (MAX_REQUEST_LINE_BYTES as usize) + 100];
        // Write in a separate thread to avoid blocking
        let write_handle = std::thread::spawn(move || {
            let _ = client.write_all(&oversized);
            let _ = client.flush();
        });

        let result = read_bounded_line(&server);
        assert!(result.is_err(), "should reject oversized request");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeds maximum size"),
            "error should mention size limit: {}",
            err_msg
        );

        let _ = write_handle.join();
    }

    #[test]
    fn baseline_refresh_refused_when_degraded() {
        let metrics = Arc::new(Metrics::new());
        let state = Arc::new(RwLock::new(DaemonState::Degraded {
            reason: "baseline_db_replaced".into(),
            since: chrono::Utc::now(),
        }));
        let (scan_tx, _scan_rx) = crossbeam_channel::bounded::<ScanRequest>(1);

        let handler = ControlHandler {
            metrics,
            state,
            reload_flag: Arc::new(AtomicBool::new(false)),
            scan_trigger_tx: scan_tx,
            baseline_db_path: PathBuf::from("/dev/null"),
            baseline_conn: Arc::new(Mutex::new({
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                crate::db::schema::create_baseline_tables(&conn).unwrap();
                conn
            })),
            config: Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::config::default_config(),
            )),
            hmac_key: None,
            auth_enabled: false,
            maintenance_active: Arc::new(AtomicBool::new(false)),
            maintenance_entered_at: Arc::new(AtomicI64::new(0)),
        };

        let result = handler.handle_baseline_refresh();
        assert_eq!(result["ok"], false);
        assert!(
            result["error"].as_str().unwrap().contains("degraded"),
            "should mention degraded state"
        );
    }

    /// Regression test for CRITICAL audit finding: HMAC verification must use
    /// constant-time comparison and fail closed. Previously authentication
    /// could be bypassed when compute_hmac() returned an empty string via
    /// unwrap_or_default(); a client sending {"response":""} would
    /// incorrectly authenticate.
    #[test]
    fn verify_hmac_rejects_empty_response() {
        let key = b"super_secret_test_key";
        let nonce = b"deadbeefcafebabe";
        // Empty client response must NEVER authenticate against any nonzero key.
        assert!(
            !crate::hmac::verify_hmac(key, nonce, ""),
            "empty client response must not authenticate"
        );
        // Wrong response must not authenticate.
        assert!(
            !crate::hmac::verify_hmac(key, nonce, "not_the_real_hmac"),
            "wrong response must not authenticate"
        );
        // Correct response must authenticate.
        let expected = crate::hmac::compute_hmac(key, nonce).unwrap();
        assert!(
            crate::hmac::verify_hmac(key, nonce, &expected),
            "correct response must authenticate"
        );
    }
}
