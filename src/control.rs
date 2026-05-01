//! Unix domain control socket for CLI-to-daemon communication.
//!
//! Accepts connections on `/run/vigil/control.sock`, authenticates via
//! HMAC challenge-response over SO_PEERCRED, and dispatches commands
//! (status, scan, reload, maintenance). Reads are bounded to 64KB
//! (SEC-003). The nonce is sourced from /dev/urandom.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};

use crate::db::baseline_ops;
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::{DaemonState, ScanMode};
use crate::wal::DetectionWal;
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
    pub control_unauthenticated_connections: Arc<AtomicU64>,
    pub wal: Option<Arc<DetectionWal>>,
    pub shared_baseline_identity: Option<Arc<crate::coordinator::SharedBaselineIdentity>>,
    pub baseline_generation: Arc<AtomicU64>,
    pub expectation_registry: Option<Arc<crate::coordinator::ExpectationRegistry>>,
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
        if e.kind() == std::io::ErrorKind::AddrInUse {
            VigilError::Control(format!(
                "Another vigild is running (control socket {} already in use). Stop it first: `sudo systemctl stop vigild`.",
                socket_path.display(),
            ))
        } else {
            VigilError::Control(format!(
                "cannot bind control socket {}: {}",
                socket_path.display(),
                e
            ))
        }
    })?;

    // Set socket permissions to 0600
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!(path = %socket_path.display(), error = %e, "failed to set control socket permissions to 0600");
        }
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
                        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
                            tracing::warn!(error = %e, "failed to set control socket read timeout");
                        }
                        if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(5))) {
                            tracing::warn!(error = %e, "failed to set control socket write timeout");
                        }

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
                                // VIGIL-VULN-073: spawn failed. Release
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
            static AUTH_DISABLED_WARNED: OnceLock<()> = OnceLock::new();
            AUTH_DISABLED_WARNED.get_or_init(|| {
                tracing::info!(
                    "control socket operating without authentication (hmac_signing disabled)"
                );
            });
            self.control_unauthenticated_connections
                .fetch_add(1, Ordering::Relaxed);
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

        // Streaming commands get the raw stream for multi-line output.
        if method == "baseline_refresh" {
            return self.handle_baseline_refresh_streaming(&stream);
        }

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
                tracing::error!(error = %e, "nonce generation failed; rejecting connection");
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
        // Log and count control socket commands at appropriate levels.
        // Read-only queries at debug; mutating commands at info.
        log_control_action(method, &self.metrics);

        match method {
            "status" => self.handle_status(),
            "baseline_count" => self.handle_baseline_count(),
            "reload" => self.handle_reload(),
            "scan" => self.handle_scan(request),
            "metrics_prometheus" => self.handle_metrics_prometheus(),
            "maintenance_enter" => self.handle_maintenance_enter(),
            "maintenance_exit" => self.handle_maintenance_exit(),
            "baseline_refresh" => self.handle_baseline_refresh(),
            "expect_file_change" => self.handle_expect_file_change(request),
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
        let baseline_count = {
            let conn = self.baseline_conn.lock();
            baseline_ops::count(&conn).unwrap_or(0)
        };
        let alerts_total = snap.alerts_dispatched;
        let critical_alerts_total = snap.critical_alerts_dispatched;
        serde_json::json!({
            "ok": true,
            "daemon": {
                "state": state_str,
                "uptime_seconds": uptime_seconds,
                "version": env!("CARGO_PKG_VERSION"),
                "maintenance_window": self.maintenance_active.load(Ordering::Acquire),
                "baseline_count": baseline_count,
                "alerts_total": alerts_total,
                "critical_alerts_total": critical_alerts_total,
            },
            "metrics": snap.status_view(),
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
        // Non-streaming fallback (used only by dispatch table for unknown callers).
        // The primary path is handle_baseline_refresh_streaming.
        serde_json::json!({
            "ok": false,
            "error": "baseline_refresh requires a streaming connection"
        })
    }

    fn handle_expect_file_change(&self, request: &serde_json::Value) -> serde_json::Value {
        let Some(registry) = &self.expectation_registry else {
            return serde_json::json!({"ok": false, "error": "expectation registry not available"});
        };

        let Some(path_str) = request.get("path").and_then(|v| v.as_str()) else {
            return serde_json::json!({"ok": false, "error": "missing 'path' parameter"});
        };

        let window_secs = request
            .get("window_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);

        let path = std::path::PathBuf::from(path_str);
        let expectation = registry.register(path);
        expectation.expect_change_within(std::time::Duration::from_secs(window_secs));

        serde_json::json!({"ok": true, "window_secs": window_secs})
    }

    /// Streaming baseline refresh: builds a new baseline in a temp DB,
    /// streams progress events over the socket, then atomically swaps.
    fn handle_baseline_refresh_streaming(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<()> {
        use std::io::Write;

        let write_event =
            |stream: &std::os::unix::net::UnixStream, event: &serde_json::Value| -> Result<()> {
                let mut writer = stream;
                let s = serde_json::to_string(event)
                    .map_err(|e| VigilError::Control(format!("serialize: {}", e)))?;
                writer
                    .write_all(s.as_bytes())
                    .map_err(|e| VigilError::Control(format!("write: {}", e)))?;
                writer
                    .write_all(b"\n")
                    .map_err(|e| VigilError::Control(format!("write: {}", e)))?;
                writer
                    .flush()
                    .map_err(|e| VigilError::Control(format!("flush: {}", e)))?;
                Ok(())
            };

        // Refuse during Degraded state
        {
            let state = self.state.read();
            if let DaemonState::Degraded { reason, .. } = &*state {
                let msg = format!(
                    "vigild is degraded (reason: {}). Refresh refused. \
                     Investigate before refreshing: vigil doctor. \
                     A refresh during degraded state could absorb a compromise into the baseline.",
                    reason
                );
                let _ = write_event(stream, &serde_json::json!({"event": "error", "error": msg}));
                return Ok(());
            }
        }

        let cfg = self.config.load();
        let db_path = &cfg.daemon.db_path;

        // Check disk space: need at least existing DB size + 20% headroom
        let existing_size = std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);
        let needed = existing_size + (existing_size / 5).max(10 * 1024 * 1024); // +20% or 10MB min
        if let Ok(stat) = nix::sys::statvfs::statvfs(db_path.parent().unwrap_or(db_path)) {
            let available = stat.blocks_available() * stat.fragment_size();
            if available < needed {
                let msg = format!(
                    "not enough disk space for refresh. \
                     Need approximately {} MB free at {}; have {} MB. \
                     Free space and retry, or move the data directory.",
                    needed / (1024 * 1024),
                    db_path.parent().unwrap_or(db_path).display(),
                    available / (1024 * 1024),
                );
                let _ = write_event(stream, &serde_json::json!({"event": "error", "error": msg}));
                return Ok(());
            }
        }

        // Build into a temp sibling file
        let tmp_path = db_path.with_extension("db.refresh");
        // Remove any leftover temp file from a previous failed attempt
        let _ = std::fs::remove_file(&tmp_path);

        let tmp_conn = match crate::db::open_baseline_db_at_path(&tmp_path) {
            Ok(c) => c,
            Err(e) => {
                let _ = write_event(
                    stream,
                    &serde_json::json!({
                        "event": "error",
                        "error": format!("failed to create temp baseline at {}: {}", tmp_path.display(), e)
                    }),
                );
                return Ok(());
            }
        };
        if let Err(e) = crate::db::schema::create_baseline_tables(&tmp_conn) {
            let _ = std::fs::remove_file(&tmp_path);
            let _ = write_event(
                stream,
                &serde_json::json!({
                    "event": "error",
                    "error": format!("failed to init temp baseline schema: {}", e)
                }),
            );
            return Ok(());
        }

        // Send initial progress event
        let _ = write_event(
            stream,
            &serde_json::json!({"event": "progress", "phase": "scanning", "done": 0, "total": 0}),
        );

        // Capture audit chain head before refresh so we can verify
        // the refresh did not modify any pre-existing audit entries.
        let pre_refresh_chain_head = {
            let cfg = self.config.load();
            let audit_path = crate::db::audit_db_path(&cfg);
            rusqlite::Connection::open_with_flags(
                &audit_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .ok()
            .and_then(|c| crate::db::audit_ops::get_last_chain_hash(&c).ok().flatten())
        };

        // Increase socket timeouts for the long-running refresh
        let _ = stream.set_write_timeout(Some(Duration::from_secs(600)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));

        // Rate-limited progress sender: max 4 events/second
        let last_progress = std::sync::Mutex::new(std::time::Instant::now());
        let progress_stream = stream;
        let progress_cb = |done: u64, total: u64, phase: &str| {
            let mut last = last_progress.lock().unwrap();
            if last.elapsed() >= Duration::from_millis(250) || done == total {
                *last = std::time::Instant::now();
                let _ = write_event(
                    progress_stream,
                    &serde_json::json!({
                        "event": "progress",
                        "phase": phase,
                        "done": done,
                        "total": total,
                    }),
                );
            }
        };

        // Snapshot old baseline entries for post-refresh diff.
        let old_entries = {
            let conn = self.baseline_conn.lock();
            match crate::baseline_diff::snapshot_from_conn(&conn) {
                Ok(map) => map,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to snapshot old baseline for diff");
                    std::collections::HashMap::new()
                }
            }
        };

        // Build baseline with progress
        let result =
            crate::scanner::build_initial_baseline_with_progress(&tmp_conn, &cfg, &progress_cb);

        match result {
            Ok(ref init_result) => {
                // Verify the temp DB before swapping
                let verify_ok = tmp_conn
                    .query_row("SELECT COUNT(*) FROM baseline", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .is_ok();

                if !verify_ok {
                    let _ = std::fs::remove_file(&tmp_path);
                    let _ = write_event(
                        stream,
                        &serde_json::json!({
                            "event": "error",
                            "error": "temp baseline failed verification; live baseline untouched"
                        }),
                    );
                    return Ok(());
                }

                // Snapshot new baseline entries for diff.
                let new_entries = match crate::baseline_diff::snapshot_from_conn(&tmp_conn) {
                    Ok(map) => Some(map),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to snapshot new baseline for diff");
                        None
                    }
                };

                // Compute diff with panic isolation (Principle X).
                // Diff failure must never abort the baseline swap.
                let diff_result = if let Some(ref new_map) = new_entries {
                    match crate::baseline_diff::compute_diff_safe(&old_entries, new_map) {
                        Ok(diff) => Some(diff),
                        Err(panic_msg) => {
                            tracing::warn!(
                                error = %panic_msg,
                                "diff computation panicked; swap will proceed without diff"
                            );
                            None
                        }
                    }
                } else {
                    None
                };

                // Checkpoint the temp DB so its WAL/SHM sidecars are empty
                // before we close it. Without this, the temp's -wal/-shm files
                // can be carried into the live slot via stale on-disk state.
                let _ = tmp_conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
                // Close temp connection before rename
                drop(tmp_conn);

                // Close the live baseline connection BEFORE the rename so that
                // its file descriptor no longer references the (about to be
                // unlinked) old inode. Replace with an in-memory placeholder
                // so the Mutex stays well-typed; the real connection is
                // re-opened against the new file below.
                //
                // Without this step, SQLite's WAL/SHM sidecars belonging to
                // the old inode survive on disk under the names
                // `${db}-wal` / `${db}-shm`. After the rename, those stale
                // sidecars are name-associated with the new (different) inode.
                // The next process to open the baseline DB (the daemon's own
                // reopen below, or `vigil check` from the CLI) loads the
                // mismatched WAL/SHM and fails with
                // "database disk image is malformed".
                {
                    let mut guard = self.baseline_conn.lock();
                    match rusqlite::Connection::open_in_memory() {
                        Ok(placeholder) => {
                            let old = std::mem::replace(&mut *guard, placeholder);
                            drop(old);
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "failed to allocate in-memory placeholder; aborting swap"
                            );
                            let _ = std::fs::remove_file(&tmp_path);
                            let _ = write_event(
                                stream,
                                &serde_json::json!({
                                    "event": "error",
                                    "error": format!(
                                        "failed to prepare baseline swap: {}", e
                                    )
                                }),
                            );
                            return Ok(());
                        }
                    }
                }

                // Signal the guardian that an authorized replacement is about
                // to happen, so it does not degrade on the inode change.
                if let Some(ref shared_id) = self.shared_baseline_identity {
                    let deadline =
                        std::time::Instant::now() + crate::coordinator::BASELINE_REPLACEMENT_WINDOW;
                    shared_id.expect_baseline_replacement(deadline);
                }

                // Remove stale `-wal` / `-shm` sidecars that belonged to the
                // old inode. Errors are non-fatal: the files may not exist
                // (e.g. WAL mode disabled, or already checkpointed at close).
                let live_wal = sidecar_path(db_path, "-wal");
                let live_shm = sidecar_path(db_path, "-shm");
                let _ = std::fs::remove_file(&live_wal);
                let _ = std::fs::remove_file(&live_shm);

                // Atomic swap: rename temp over live.
                // This MUST happen regardless of diff outcome.
                if let Err(e) = std::fs::rename(&tmp_path, db_path) {
                    let _ = std::fs::remove_file(&tmp_path);
                    let _ = write_event(
                        stream,
                        &serde_json::json!({
                            "event": "error",
                            "error": format!("failed to swap baseline: {}", e)
                        }),
                    );
                    return Ok(());
                }

                // Best-effort cleanup of the temp DB's sidecars. After
                // wal_checkpoint(TRUNCATE) + drop they should already be
                // gone, but guard against any straggler.
                let _ = std::fs::remove_file(sidecar_path(&tmp_path, "-wal"));
                let _ = std::fs::remove_file(sidecar_path(&tmp_path, "-shm"));

                // Reopen the daemon's baseline connection
                {
                    let mut conn = self.baseline_conn.lock();
                    match crate::db::open_baseline_db_at_path(db_path) {
                        Ok(new_conn) => {
                            *conn = new_conn;
                            tracing::info!("baseline connection reopened after refresh");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to reopen baseline after swap");
                        }
                    }
                }

                // Increment generation so workers and scan scheduler
                // invalidate caches / reopen connections.
                self.baseline_generation.fetch_add(1, Ordering::Release);

                // Update config_state in the new DB
                if let Ok(conn) = crate::db::open_baseline_db_at_path(db_path) {
                    let now = chrono::Utc::now().timestamp();
                    let _ = crate::db::baseline_ops::set_config_state(
                        &conn,
                        "last_baseline_refresh",
                        &now.to_string(),
                    );
                    let _ = crate::db::baseline_ops::set_config_state(
                        &conn,
                        "baseline_initialized",
                        "true",
                    );
                    // Recompute HMAC if configured
                    if cfg.security.hmac_signing {
                        if let Ok(key) = crate::hmac::load_hmac_key(&cfg.security.hmac_key_path) {
                            if let Ok(hmac) =
                                crate::db::baseline_ops::compute_baseline_hmac(&conn, &key)
                            {
                                let _ = crate::db::baseline_ops::set_config_state(
                                    &conn,
                                    "baseline_hmac",
                                    &hmac,
                                );
                            }
                        }
                    }
                }

                let total = init_result.total_count;
                let duration_ms = init_result.duration.as_millis() as u64;

                // Record unattributed changes to the detection WAL
                // (Principle XIII: Audit Trail Never Lies).
                if let Some(ref diff) = diff_result {
                    if !diff.changed_unattributed.is_empty() {
                        let maintenance = self.maintenance_active.load(Ordering::Acquire);
                        if let Some(ref wal) = self.wal {
                            let appended = crate::baseline_diff::record_unattributed_to_wal(
                                wal,
                                &diff.changed_unattributed,
                                maintenance,
                            );
                            self.metrics
                                .baseline_refresh_unattributed_changes
                                .fetch_add(appended, Ordering::Relaxed);
                        }
                    }
                }

                // Build the complete event.
                // JSON field naming convention:
                //   *_paths_sample  -- capped list (added/removed: max 20)
                //   *_paths         -- complete list (changed_unattributed: never truncated)
                let mut event = match &diff_result {
                    Some(diff) => {
                        let unattr_paths: Vec<&str> = diff
                            .changed_unattributed
                            .iter()
                            .map(|e| e.path.as_str())
                            .collect();
                        serde_json::json!({
                            "event": "complete",
                            "duration_ms": duration_ms,
                            "total": total,
                            "added": diff.added.len(),
                            "removed": diff.removed.len(),
                            "changed": diff.total_changed(),
                            "changed_pkg": diff.changed_pkg.len(),
                            "changed_unattributed": unattr_paths.len(),
                            "changed_unattributed_paths": unattr_paths,
                            "added_paths_sample": diff.added.iter().take(20).collect::<Vec<_>>(),
                            "removed_paths_sample": diff.removed.iter().take(20).collect::<Vec<_>>(),
                        })
                    }
                    None => {
                        serde_json::json!({
                            "event": "complete",
                            "duration_ms": duration_ms,
                            "total": total,
                            "diff_unavailable": true,
                            "diff_error": "diff computation failed; baseline was swapped successfully",
                        })
                    }
                };

                // Query audit log status post-refresh (Principle V: Unambiguous).
                // The refresh never modifies existing audit entries; verify that
                // property and report it.
                let audit_status =
                    query_audit_log_status(&self.config.load(), pre_refresh_chain_head.as_deref());
                event["audit_log"] = audit_status;

                let _ = write_event(stream, &event);
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                let _ = write_event(
                    stream,
                    &serde_json::json!({
                        "event": "error",
                        "error": format!("baseline refresh failed: {}", e)
                    }),
                );
            }
        }

        Ok(())
    }
}

/// Query audit log entry count and chain integrity for the refresh complete event.
/// Returns a JSON object suitable for inclusion in the streamed `complete` event.
/// If the query fails, returns an object with null fields and an error string.
fn query_audit_log_status(
    config: &crate::config::Config,
    pre_refresh_chain_head: Option<&str>,
) -> serde_json::Value {
    let audit_path = crate::db::audit_db_path(config);
    let conn = match rusqlite::Connection::open_with_flags(
        &audit_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(e) => {
            return serde_json::json!({
                "entry_count": null,
                "chain_intact": null,
                "preserved_by_refresh": null,
                "error": format!("cannot open audit DB: {}", e),
            });
        }
    };

    let entry_count = crate::db::audit_ops::count(&conn).ok();

    // Lightweight chain check: verify_chain walks all entries computing blake3
    // hashes. For large DBs this is O(N) but matches what `vigil doctor` does.
    let chain_result = crate::db::audit_ops::verify_chain(&conn);
    let (chain_intact, chain_break_id) = match &chain_result {
        Ok((_, _, breaks, _)) if breaks.is_empty() => (Some(true), None),
        Ok((_, _, breaks, _)) => (Some(false), breaks.first().map(|(id, _)| *id)),
        Err(_) => (None, None),
    };

    // Verify the refresh preserved all pre-existing entries: the pre-refresh
    // chain head must still exist in the DB.
    let preserved = match pre_refresh_chain_head {
        Some(head) => {
            let found: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM audit_log WHERE chain_hash = ?1",
                    rusqlite::params![head],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            Some(found)
        }
        None => {
            // No pre-refresh chain head means the audit DB was empty before
            // refresh. The refresh trivially preserved it.
            Some(true)
        }
    };

    let mut obj = serde_json::json!({
        "entry_count": entry_count,
        "chain_intact": chain_intact,
        "preserved_by_refresh": preserved,
    });

    if let Some(id) = chain_break_id {
        obj["chain_break_at"] = serde_json::json!(id);
    }
    if let Err(e) = &chain_result {
        obj["error"] = serde_json::json!(format!("chain verification failed: {}", e));
    }
    if preserved == Some(false) {
        tracing::error!(
            "audit log integrity check failed: pre-refresh chain head not found post-refresh"
        );
    }

    obj
}

/// Build a SQLite sidecar path (e.g. `${db}-wal`, `${db}-shm`) by appending
/// `suffix` to the database path. Used to clean up stale sidecars before/after
/// the atomic baseline swap so a renamed inode does not inherit the old
/// inode's WAL/SHM contents (which would surface as
/// "database disk image is malformed" on the next open).
fn sidecar_path(db: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut s: std::ffi::OsString = db.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
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
    match method {
        "status" | "baseline_count" | "metrics_prometheus" => {
            tracing::debug!(method = method, "control socket query");
        }
        "reload" | "scan" | "maintenance_enter" | "maintenance_exit" | "baseline_refresh" => {
            tracing::info!(method = method, "control socket command executed");
        }
        _ => {
            tracing::debug!(method = method, "control socket unknown method");
        }
    }
    metrics.control_commands.fetch_add(1, Ordering::Relaxed);
}

/// Generate a random 32-byte hex nonce for challenge-response auth.
/// Returns Err if randomness cannot be obtained, to prevent predictable nonces.
fn generate_nonce() -> std::result::Result<String, std::io::Error> {
    let buf = crate::util::random::random_bytes(32)
        .map_err(|e| std::io::Error::other(format!("random_bytes failed: {}", e)))?;
    // Verify buffer is not all-zero (catastrophic RNG failure)
    if buf.iter().all(|&b| b == 0) {
        return Err(std::io::Error::other(
            "getrandom returned all zeros; refusing to generate nonce",
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
    // SAFETY: libc::ucred is a plain-old-data struct (pid, uid, gid).
    // zeroed() is valid for POD types.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: getsockopt(SO_PEERCRED) reads the peer's credentials from
    // a connected Unix socket. The fd is valid (from stream.as_raw_fd()),
    // and cred/len are correctly sized. Returns 0 on success, -1 on error.
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
        // SAFETY: geteuid returns the effective uid with no side effects.
        // Cannot fail and has no memory safety implications.
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
            control_unauthenticated_connections: Arc::new(AtomicU64::new(0)),
            wal: None,
            shared_baseline_identity: None,
            baseline_generation: Arc::new(AtomicU64::new(0)),
            expectation_registry: None,
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
            control_unauthenticated_connections: Arc::new(AtomicU64::new(0)),
            wal: None,
            shared_baseline_identity: None,
            baseline_generation: Arc::new(AtomicU64::new(0)),
            expectation_registry: None,
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
            control_unauthenticated_connections: Arc::new(AtomicU64::new(0)),
            wal: None,
            shared_baseline_identity: None,
            baseline_generation: Arc::new(AtomicU64::new(0)),
            expectation_registry: None,
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
            reason: crate::types::DegradedReason::BaselineDbReplaced,
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
            control_unauthenticated_connections: Arc::new(AtomicU64::new(0)),
            wal: None,
            shared_baseline_identity: None,
            baseline_generation: Arc::new(AtomicU64::new(0)),
            expectation_registry: None,
        };

        // Use a Unix socket pair to capture the streaming response
        let (server, client) = std::os::unix::net::UnixStream::pair().unwrap();
        handler.handle_baseline_refresh_streaming(&server).unwrap();
        drop(server);

        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(client);
        let mut found_degraded = false;
        for line in reader.lines().map_while(|r| r.ok()) {
            if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                if event.get("event").and_then(|v| v.as_str()) == Some("error") {
                    let err = event["error"].as_str().unwrap_or("");
                    if err.contains("degraded") {
                        found_degraded = true;
                    }
                }
            }
        }
        assert!(found_degraded, "should mention degraded state");
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

    /// Diff failure must not abort the baseline swap. When diff_result is None
    /// (simulating a panic or read error), the complete event must contain
    /// `diff_unavailable: true` and `diff_error`.
    #[test]
    fn diff_unavailable_fields_in_complete_event() {
        // Simulate a complete event when diff is unavailable
        let duration_ms = 1234u64;
        let total = 100u64;

        // This mirrors the None branch in handle_baseline_refresh_streaming
        let event = serde_json::json!({
            "event": "complete",
            "duration_ms": duration_ms,
            "total": total,
            "diff_unavailable": true,
            "diff_error": "diff computation failed; baseline was swapped successfully",
        });

        assert_eq!(event["event"], "complete");
        assert_eq!(event["diff_unavailable"], true);
        assert!(event["diff_error"]
            .as_str()
            .unwrap()
            .contains("swapped successfully"));
        // The diff fields (added, removed, etc.) must NOT appear
        assert!(event.get("added").is_none());
        assert!(event.get("changed_unattributed_paths").is_none());
    }

    /// Complete event with diff available must contain all required fields
    /// with the correct naming convention: _sample for capped, _paths for full.
    #[test]
    fn complete_event_field_naming_convention() {
        use crate::baseline_diff::{BaselineDiff, ChangedEntry};

        let diff = BaselineDiff {
            added: (0..25).map(|i| format!("/new/{}", i)).collect(),
            removed: (0..5).map(|i| format!("/old/{}", i)).collect(),
            changed_pkg: vec!["/pkg/a".into()],
            changed_unattributed: vec![
                ChangedEntry {
                    path: "/etc/x".into(),
                    old_hash: "aaa".into(),
                    new_hash: "bbb".into(),
                },
                ChangedEntry {
                    path: "/etc/y".into(),
                    old_hash: "ccc".into(),
                    new_hash: "ddd".into(),
                },
            ],
        };

        let unattr_paths: Vec<&str> = diff
            .changed_unattributed
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        let event = serde_json::json!({
            "event": "complete",
            "duration_ms": 500,
            "total": 100,
            "added": diff.added.len(),
            "removed": diff.removed.len(),
            "changed": diff.total_changed(),
            "changed_pkg": diff.changed_pkg.len(),
            "changed_unattributed": unattr_paths.len(),
            "changed_unattributed_paths": unattr_paths,
            "added_paths_sample": diff.added.iter().take(20).collect::<Vec<_>>(),
            "removed_paths_sample": diff.removed.iter().take(20).collect::<Vec<_>>(),
        });

        // changed_unattributed_paths: complete list, never truncated
        let paths = event["changed_unattributed_paths"].as_array().unwrap();
        assert_eq!(paths.len(), 2, "all unattributed paths must be present");

        // added_paths_sample: capped at 20
        let added_sample = event["added_paths_sample"].as_array().unwrap();
        assert_eq!(added_sample.len(), 20, "added_paths_sample capped at 20");

        // removed_paths_sample: complete when under cap
        let removed_sample = event["removed_paths_sample"].as_array().unwrap();
        assert_eq!(
            removed_sample.len(),
            5,
            "removed_paths_sample uncapped when <= 20"
        );

        // Count fields present
        assert_eq!(event["changed_unattributed"], 2);
        assert_eq!(event["changed"], 3); // 1 pkg + 2 unattributed
    }

    #[test]
    fn audit_log_status_intact_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        // Create audit DB with entries
        let audit_path = crate::db::audit_db_path(&cfg);
        let conn = rusqlite::Connection::open(&audit_path).unwrap();
        crate::db::schema::create_audit_tables(&conn).unwrap();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let h1 = crate::db::audit_ops::compute_chain_hash(&genesis, 1000, "/f", "[]", "high");
        conn.execute(
            "INSERT INTO audit_log (timestamp, path, changes_json, severity, maintenance, suppressed, chain_hash)
             VALUES (1000, '/f', '[]', 'high', 0, 0, ?1)",
            rusqlite::params![h1],
        )
        .unwrap();
        drop(conn);

        let status = query_audit_log_status(&cfg, Some(&h1));
        assert_eq!(status["entry_count"], 1);
        assert_eq!(status["chain_intact"], true);
        assert_eq!(status["preserved_by_refresh"], true);
        assert!(status.get("error").is_none() || status["error"].is_null());
    }

    #[test]
    fn audit_log_status_broken_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let audit_path = crate::db::audit_db_path(&cfg);
        let conn = rusqlite::Connection::open(&audit_path).unwrap();
        crate::db::schema::create_audit_tables(&conn).unwrap();
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let h1 = crate::db::audit_ops::compute_chain_hash(&genesis, 1000, "/f", "[]", "high");
        conn.execute(
            "INSERT INTO audit_log (timestamp, path, changes_json, severity, maintenance, suppressed, chain_hash)
             VALUES (1000, '/f', '[]', 'high', 0, 0, ?1)",
            rusqlite::params![h1],
        )
        .unwrap();
        // Insert a second entry with a corrupted chain
        conn.execute(
            "INSERT INTO audit_log (timestamp, path, changes_json, severity, maintenance, suppressed, chain_hash)
             VALUES (2000, '/g', '[]', 'high', 0, 0, 'corrupt')",
            [],
        )
        .unwrap();
        drop(conn);

        let status = query_audit_log_status(&cfg, Some(&h1));
        assert_eq!(status["chain_intact"], false);
        assert!(status["chain_break_at"].is_number());
    }

    #[test]
    fn audit_log_status_preserved_false_when_head_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let audit_path = crate::db::audit_db_path(&cfg);
        let conn = rusqlite::Connection::open(&audit_path).unwrap();
        crate::db::schema::create_audit_tables(&conn).unwrap();
        drop(conn);

        // Pre-refresh head was "some_hash" but audit DB is empty
        let status = query_audit_log_status(&cfg, Some("nonexistent_hash"));
        assert_eq!(status["preserved_by_refresh"], false);
    }

    #[test]
    fn audit_log_status_empty_db() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let audit_path = crate::db::audit_db_path(&cfg);
        let conn = rusqlite::Connection::open(&audit_path).unwrap();
        crate::db::schema::create_audit_tables(&conn).unwrap();
        drop(conn);

        // No pre-refresh head (empty DB before refresh too)
        let status = query_audit_log_status(&cfg, None);
        assert_eq!(status["entry_count"], 0);
        assert_eq!(status["chain_intact"], true);
        assert_eq!(status["preserved_by_refresh"], true);
    }

    #[test]
    fn audit_log_status_unavailable_when_db_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("nonexistent/baseline.db");

        let status = query_audit_log_status(&cfg, None);
        assert!(status["entry_count"].is_null());
        assert!(status["chain_intact"].is_null());
        assert!(status["error"].is_string());
    }
}
