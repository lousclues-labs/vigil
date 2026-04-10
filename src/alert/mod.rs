pub mod dbus;
pub mod journal;
pub mod json_log;
pub mod remote_syslog;
pub mod socket;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError};
use parking_lot::Mutex;

use crate::config::Config;
use crate::db::audit_ops;
use crate::error::Result;
use crate::metrics::Metrics;
use crate::types::{Alert, AlertContext, AlertFileInfo, Change, ChangeResult, Severity};

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use zeroize::Zeroizing;

/// Message passed from workers/scanners to the alert dispatcher.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    pub change: ChangeResult,
    pub maintenance_window: bool,
}

pub trait AlertSink: Send + Sync {
    fn name(&self) -> &str;
    fn dispatch(&self, alert: &Alert) -> Result<()>;
    fn min_severity(&self) -> Severity {
        Severity::Low
    }
}

struct RateLimiter {
    count: u32,
    window_start: Instant,
}

pub struct AlertDispatcher {
    sinks: Vec<Box<dyn AlertSink>>,
    audit_conn: rusqlite::Connection,
    audit_db_path: std::path::PathBuf,
    rate_limiter: Mutex<RateLimiter>,
    cooldowns: Mutex<HashMap<String, Instant>>,
    cooldown_secs: u64,
    hmac_key: Option<Zeroizing<Vec<u8>>>,
    last_chain_hash: Mutex<String>,
    max_alerts_per_minute: u32,
    metrics: Arc<Metrics>,
    hostname: String,
    consecutive_audit_failures: AtomicU32,
    /// Bounded buffer for audit entries that failed to write; retried after DB reopen.
    audit_retry_buffer: Mutex<Vec<PendingAuditEntry>>,
}

/// An audit entry pending retry after a DB write failure.
struct PendingAuditEntry {
    payload: AlertPayload,
    suppressed: bool,
}

impl AlertDispatcher {
    pub fn new(
        config: &Config,
        audit_db_path: &Path,
        metrics: Arc<Metrics>,
        startup_hmac_key: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Self> {
        if let Some(parent) = audit_db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let audit_conn = rusqlite::Connection::open(audit_db_path)?;
        let audit_path = audit_db_path.to_path_buf();
        crate::db::apply_pragmas(
            &audit_conn,
            &crate::db::PragmaOpts {
                sync_mode: "FULL",
                wal_mode: true,
                ..crate::db::PragmaOpts::default()
            },
        )?;
        crate::db::schema::create_audit_tables(&audit_conn)?;

        let mut sinks: Vec<Box<dyn AlertSink>> = Vec::new();

        if config.alerts.syslog {
            sinks.push(Box::new(journal::JournalSink));
        }

        if !config.alerts.log_file.as_os_str().is_empty() {
            if let Ok(sink) = json_log::JsonFileSink::new(&config.alerts.log_file) {
                sinks.push(Box::new(sink));
            } else {
                tracing::warn!(path = %config.alerts.log_file.display(), "failed to initialize JSON log sink");
            }
        }

        if config.alerts.desktop_notifications {
            sinks.push(Box::new(dbus::DbusSink::new(
                config.alerts.notification_rate_limit,
                config.alerts.notification_rate_window_secs,
            )));
        }

        if !config.hooks.signal_socket.is_empty() {
            sinks.push(Box::new(socket::SocketSink::new(
                &config.hooks.signal_socket,
            )));
        }

        if config.alerts.remote_syslog.enabled {
            if let Ok(sink) = remote_syslog::RemoteSyslogSink::new(&config.alerts.remote_syslog) {
                sinks.push(Box::new(sink));
            } else {
                tracing::warn!("failed to initialize remote syslog sink");
            }
        }

        let last_hash = audit_ops::get_last_chain_hash(&audit_conn)?.unwrap_or_else(|| {
            blake3::hash(b"vigil-audit-chain-genesis")
                .to_hex()
                .to_string()
        });

        let hmac_key = startup_hmac_key;

        let hostname = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "localhost".to_string());

        Ok(Self {
            sinks,
            audit_conn,
            audit_db_path: audit_path,
            rate_limiter: Mutex::new(RateLimiter {
                count: 0,
                window_start: Instant::now(),
            }),
            cooldowns: Mutex::new(HashMap::new()),
            cooldown_secs: config.alerts.cooldown_seconds,
            hmac_key,
            last_chain_hash: Mutex::new(last_hash),
            max_alerts_per_minute: config.alerts.max_alerts_per_minute,
            metrics,
            hostname,
            consecutive_audit_failures: AtomicU32::new(0),
            audit_retry_buffer: Mutex::new(Vec::new()),
        })
    }

    pub fn run(mut self, alert_rx: Receiver<AlertPayload>, shutdown: Arc<AtomicBool>) {
        while !shutdown.load(Ordering::Acquire) {
            match alert_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(payload) => {
                    let suppressed =
                        self.is_suppressed(&payload.change, payload.maintenance_window);
                    self.record_audit(&payload, suppressed);
                    if suppressed {
                        self.metrics
                            .alerts_suppressed
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let alert = self.build_alert(&payload);
                    self.dispatch_to_sinks(&alert);
                    self.metrics
                        .alerts_dispatched
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn record_audit(&mut self, payload: &AlertPayload, suppressed: bool) {
        if let Err(e) = self.write_audit_entry(payload, suppressed) {
            tracing::error!(error = %e, "audit write failed");
            self.metrics.db_errors.fetch_add(1, Ordering::Relaxed);

            // Buffer the failed entry for retry (bounded to 1000)
            {
                let mut buffer = self.audit_retry_buffer.lock();
                if buffer.len() < 1000 {
                    buffer.push(PendingAuditEntry {
                        payload: payload.clone(),
                        suppressed,
                    });
                } else {
                    tracing::error!("audit retry buffer full — audit entry permanently lost");
                    self.metrics
                        .audit_entries_lost
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            let failures = self
                .consecutive_audit_failures
                .fetch_add(1, Ordering::Relaxed)
                + 1;

            if failures >= 3 {
                tracing::warn!(
                    failures = failures,
                    "attempting to reopen audit DB after consecutive failures"
                );
                match rusqlite::Connection::open(&self.audit_db_path) {
                    Ok(new_conn) => {
                        if let Ok(()) = crate::db::apply_pragmas(
                            &new_conn,
                            &crate::db::PragmaOpts {
                                sync_mode: "FULL",
                                wal_mode: true,
                                ..crate::db::PragmaOpts::default()
                            },
                        ) {
                            self.audit_conn = new_conn;
                            self.consecutive_audit_failures.store(0, Ordering::Relaxed);
                            tracing::info!("audit DB connection reopened");

                            // Retry buffered entries
                            let pending: Vec<PendingAuditEntry> = {
                                let mut buffer = self.audit_retry_buffer.lock();
                                std::mem::take(&mut *buffer)
                            };
                            let retry_count = pending.len();
                            let mut retry_ok = 0u64;
                            for entry in pending {
                                if self
                                    .write_audit_entry(&entry.payload, entry.suppressed)
                                    .is_ok()
                                {
                                    retry_ok += 1;
                                }
                            }
                            if retry_count > 0 {
                                tracing::info!(
                                    retried = retry_count,
                                    succeeded = retry_ok,
                                    "retried buffered audit entries"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to reopen audit DB");
                    }
                }
            }
        } else {
            self.consecutive_audit_failures.store(0, Ordering::Relaxed);
            self.metrics.db_writes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dispatch_to_sinks(&self, alert: &Alert) {
        for sink in &self.sinks {
            if alert.severity >= sink.min_severity() {
                if let Err(e) = sink.dispatch(alert) {
                    tracing::warn!(sink = sink.name(), error = %e, "alert sink failed");
                }
            }
        }
    }

    fn is_suppressed(&self, change: &ChangeResult, maintenance_window: bool) -> bool {
        // Never fully suppress Critical/High changes, even during maintenance windows.
        // These still dispatch to sinks but will have maintenance_window=true in the alert.
        if maintenance_window && change.package.is_some() {
            if change.severity >= Severity::High {
                return false;
            }
            return true;
        }

        let now = Instant::now();
        let path = change.path.to_string_lossy().to_string();

        {
            let mut cooldowns = self.cooldowns.lock();
            if let Some(last) = cooldowns.get(&path) {
                if now.duration_since(*last) < Duration::from_secs(self.cooldown_secs) {
                    return true;
                }
            }
            // Only update timestamp when alert is NOT suppressed by cooldown
            cooldowns.insert(path, now);
        }

        {
            let mut rl = self.rate_limiter.lock();
            if rl.window_start.elapsed() > Duration::from_secs(60) {
                rl.count = 0;
                rl.window_start = Instant::now();
            }

            if rl.count >= self.max_alerts_per_minute {
                return true;
            }
            rl.count += 1;
        }

        false
    }

    fn write_audit_entry(&self, payload: &AlertPayload, suppressed: bool) -> Result<()> {
        let change = &payload.change;

        let previous = self.last_chain_hash.lock().clone();

        let hmac = match self.hmac_key.as_ref() {
            Some(key) => {
                let ts = chrono::Utc::now().timestamp();
                let primary = change
                    .changes
                    .first()
                    .map(change_to_name)
                    .unwrap_or("unknown");

                // Extract content hashes from the first ContentModified change, if any
                let (old_hash, new_hash) = change
                    .changes
                    .iter()
                    .find_map(|c| match c {
                        Change::ContentModified {
                            old_hash, new_hash, ..
                        } => Some((Some(old_hash.as_str()), Some(new_hash.as_str()))),
                        _ => None,
                    })
                    .unwrap_or((None, None));

                let data = crate::hmac::build_audit_hmac_data(
                    ts,
                    &change.path.to_string_lossy(),
                    primary,
                    &change.severity.to_string(),
                    old_hash,
                    new_hash,
                    &previous,
                );
                Some(crate::hmac::compute_hmac(key, &data)?)
            }
            None => None,
        };

        let new_hash = audit_ops::insert_audit_entry(
            &self.audit_conn,
            change,
            payload.maintenance_window,
            suppressed,
            hmac.as_deref(),
            &previous,
        )?;

        *self.last_chain_hash.lock() = new_hash;
        Ok(())
    }

    fn build_alert(&self, payload: &AlertPayload) -> Alert {
        let change = &payload.change;
        let change_type = change
            .changes
            .first()
            .map(change_to_name)
            .unwrap_or("unknown")
            .to_string();

        let event_id = format!(
            "{}-{}",
            chrono::Utc::now().timestamp_millis(),
            blake3::hash(change.path.to_string_lossy().as_bytes())
                .to_hex()
                .to_string()
                .chars()
                .take(8)
                .collect::<String>()
        );

        Alert {
            version: 2,
            timestamp: chrono::Utc::now(),
            event_id,
            severity: change.severity,
            change_type,
            file: AlertFileInfo {
                path: change.path.as_ref().clone(),
                changes_json: serde_json::to_string(&change.changes)
                    .unwrap_or_else(|_| "[]".to_string()),
                package: change.package.clone(),
                package_update: change.package_update,
                responsible_pid: change.process.as_ref().map(|p| p.pid),
                responsible_exe: change.process.as_ref().and_then(|p| p.exe.clone()),
            },
            context: AlertContext {
                hostname: self.hostname.clone(),
                monitored_group: change.monitored_group.clone(),
                maintenance_window: payload.maintenance_window,
            },
        }
    }
}

fn change_to_name(change: &Change) -> &'static str {
    match change {
        Change::ContentModified { .. } => "content_modified",
        Change::PermissionsChanged { .. } => "permissions_changed",
        Change::OwnerChanged { .. } => "owner_changed",
        Change::InodeChanged { .. } => "inode_changed",
        Change::TypeChanged { .. } => "type_changed",
        Change::SymlinkTargetChanged { .. } => "symlink_target_changed",
        Change::CapabilitiesChanged { .. } => "capabilities_changed",
        Change::XattrChanged { .. } => "xattr_changed",
        Change::SecurityContextChanged { .. } => "security_context_changed",
        Change::SizeChanged { .. } => "size_changed",
        Change::DeviceChanged { .. } => "device_changed",
        Change::Deleted => "deleted",
        Change::Created => "created",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChangeResult, Severity};

    #[test]
    fn dispatcher_writes_audit() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.db");

        let cfg = crate::config::default_config();
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let dispatcher = AlertDispatcher::new(&cfg, &audit_path, metrics, None).unwrap();

        let payload = AlertPayload {
            change: ChangeResult {
                path: std::sync::Arc::new(std::path::PathBuf::from("/tmp/test")),
                changes: vec![Change::Created],
                severity: Severity::High,
                monitored_group: "test".into(),
                process: None,
                package: None,
                package_update: false,
            },
            maintenance_window: false,
        };

        dispatcher.write_audit_entry(&payload, false).unwrap();
        let entries = audit_ops::get_recent(&dispatcher.audit_conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn cooldown_does_not_reset_on_suppressed_events() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.db");

        let mut cfg = crate::config::default_config();
        cfg.alerts.cooldown_seconds = 10; // 10 second cooldown

        let metrics = Arc::new(crate::metrics::Metrics::new());
        let dispatcher = AlertDispatcher::new(&cfg, &audit_path, metrics, None).unwrap();

        let change = ChangeResult {
            path: std::sync::Arc::new(std::path::PathBuf::from("/tmp/cooldown_test")),
            changes: vec![Change::Created],
            severity: Severity::High,
            monitored_group: "test".into(),
            process: None,
            package: None,
            package_update: false,
        };

        // First call should NOT be suppressed
        let suppressed = dispatcher.is_suppressed(&change, false);
        assert!(!suppressed, "first alert should not be suppressed");

        // Second call within cooldown should be suppressed
        let suppressed = dispatcher.is_suppressed(&change, false);
        assert!(
            suppressed,
            "second alert within cooldown should be suppressed"
        );

        // Third call should also still be suppressed (timer should NOT have reset)
        let suppressed = dispatcher.is_suppressed(&change, false);
        assert!(
            suppressed,
            "third alert should still be suppressed (timer not reset)"
        );
    }

    #[test]
    fn configurable_rate_limit_respected() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.db");

        let mut cfg = crate::config::default_config();
        cfg.alerts.max_alerts_per_minute = 3;
        cfg.alerts.cooldown_seconds = 0; // disable cooldown for this test

        let metrics = Arc::new(crate::metrics::Metrics::new());
        let dispatcher = AlertDispatcher::new(&cfg, &audit_path, metrics, None).unwrap();

        for i in 0..5 {
            let change = ChangeResult {
                path: std::sync::Arc::new(std::path::PathBuf::from(format!(
                    "/tmp/rate_test_{}",
                    i
                ))),
                changes: vec![Change::Created],
                severity: Severity::High,
                monitored_group: "test".into(),
                process: None,
                package: None,
                package_update: false,
            };
            let suppressed = dispatcher.is_suppressed(&change, false);
            if i < 3 {
                assert!(!suppressed, "alert {} should not be suppressed", i);
            } else {
                assert!(suppressed, "alert {} should be suppressed by rate limit", i);
            }
        }
    }

    #[test]
    fn hmac_includes_content_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.db");

        let mut cfg = crate::config::default_config();
        // Set up HMAC key inline for testing
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, "a".repeat(64)).unwrap();
        cfg.security.hmac_signing = true;
        cfg.security.hmac_key_path = key_path.clone();

        let hmac_key = crate::hmac::load_hmac_key(&key_path)
            .ok()
            .map(Zeroizing::new);
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let dispatcher = AlertDispatcher::new(&cfg, &audit_path, metrics, hmac_key).unwrap();

        let payload = AlertPayload {
            change: ChangeResult {
                path: std::sync::Arc::new(std::path::PathBuf::from("/tmp/hmac_test")),
                changes: vec![Change::ContentModified {
                    old_hash: "abc123".into(),
                    new_hash: "def456".into(),
                }],
                severity: Severity::High,
                monitored_group: "test".into(),
                process: None,
                package: None,
                package_update: false,
            },
            maintenance_window: false,
        };

        // Should succeed (HMAC computation includes content hashes)
        dispatcher.write_audit_entry(&payload, false).unwrap();
        let entries = audit_ops::get_recent(&dispatcher.audit_conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].hmac.is_some(), "HMAC should be present");
    }

    #[test]
    fn critical_severity_not_suppressed_during_maintenance() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.db");

        let cfg = crate::config::default_config();
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let dispatcher = AlertDispatcher::new(&cfg, &audit_path, metrics, None).unwrap();

        let critical_change = ChangeResult {
            path: std::sync::Arc::new(std::path::PathBuf::from("/usr/bin/sudo")),
            changes: vec![Change::ContentModified {
                old_hash: "aaa".into(),
                new_hash: "bbb".into(),
            }],
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: Some("sudo".into()),
            package_update: true,
        };

        // Critical + package during maintenance should NOT be suppressed
        assert!(
            !dispatcher.is_suppressed(&critical_change, true),
            "Critical severity changes must not be suppressed during maintenance"
        );

        let high_change = ChangeResult {
            path: std::sync::Arc::new(std::path::PathBuf::from("/usr/bin/passwd")),
            changes: vec![Change::ContentModified {
                old_hash: "ccc".into(),
                new_hash: "ddd".into(),
            }],
            severity: Severity::High,
            monitored_group: "system".into(),
            process: None,
            package: Some("shadow".into()),
            package_update: true,
        };

        // High + package during maintenance should NOT be suppressed
        assert!(
            !dispatcher.is_suppressed(&high_change, true),
            "High severity changes must not be suppressed during maintenance"
        );

        let low_change = ChangeResult {
            path: std::sync::Arc::new(std::path::PathBuf::from("/usr/share/doc/readme")),
            changes: vec![Change::ContentModified {
                old_hash: "eee".into(),
                new_hash: "fff".into(),
            }],
            severity: Severity::Low,
            monitored_group: "docs".into(),
            process: None,
            package: Some("man-pages".into()),
            package_update: true,
        };

        // Low + package during maintenance SHOULD be suppressed
        assert!(
            dispatcher.is_suppressed(&low_change, true),
            "Low severity changes with package should be suppressed during maintenance"
        );
    }
}
