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
    rate_limiter: Mutex<RateLimiter>,
    cooldowns: Mutex<HashMap<String, Instant>>,
    cooldown_secs: u64,
    hmac_key: Option<Vec<u8>>,
    last_chain_hash: Mutex<String>,
    metrics: Arc<Metrics>,
    hostname: String,
}

impl AlertDispatcher {
    pub fn new(config: &Config, audit_db_path: &Path, metrics: Arc<Metrics>) -> Result<Self> {
        if let Some(parent) = audit_db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let audit_conn = rusqlite::Connection::open(audit_db_path)?;
        audit_conn.pragma_update(None, "journal_mode", "WAL")?;
        audit_conn.pragma_update(None, "synchronous", "FULL")?;
        audit_conn.pragma_update(None, "foreign_keys", "ON")?;
        audit_conn.pragma_update(None, "busy_timeout", "5000")?;
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

        let hmac_key = if config.security.hmac_signing {
            match crate::hmac::load_hmac_key(&config.security.hmac_key_path) {
                Ok(key) => Some(key),
                Err(e) => {
                    tracing::warn!(error = %e, "HMAC key load failed; audit entries will be unsigned");
                    None
                }
            }
        } else {
            None
        };

        let hostname = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "localhost".to_string());

        Ok(Self {
            sinks,
            audit_conn,
            rate_limiter: Mutex::new(RateLimiter {
                count: 0,
                window_start: Instant::now(),
            }),
            cooldowns: Mutex::new(HashMap::new()),
            cooldown_secs: config.alerts.cooldown_seconds,
            hmac_key,
            last_chain_hash: Mutex::new(last_hash),
            metrics,
            hostname,
        })
    }

    pub fn run(
        self,
        alert_rx: Receiver<AlertPayload>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) {
        while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
            match alert_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(payload) => {
                    let suppressed =
                        self.is_suppressed(&payload.change, payload.maintenance_window);

                    if let Err(e) = self.write_audit_entry(&payload, suppressed) {
                        tracing::error!(error = %e, "audit write failed");
                        self.metrics
                            .db_errors
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        self.metrics
                            .db_writes
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }

                    if suppressed {
                        self.metrics
                            .alerts_suppressed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }

                    let alert = self.build_alert(&payload);
                    for sink in &self.sinks {
                        if alert.severity >= sink.min_severity() {
                            if let Err(e) = sink.dispatch(&alert) {
                                tracing::warn!(sink = sink.name(), error = %e, "alert sink failed");
                            }
                        }
                    }

                    self.metrics
                        .alerts_dispatched
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn is_suppressed(&self, change: &ChangeResult, maintenance_window: bool) -> bool {
        if maintenance_window && change.package.is_some() {
            return true;
        }

        let now = Instant::now();
        let path = change.path.to_string_lossy().to_string();

        {
            let mut cooldowns = self.cooldowns.lock();
            let previous = cooldowns.insert(path, now);
            if let Some(last) = previous {
                if now.duration_since(last) < Duration::from_secs(self.cooldown_secs) {
                    return true;
                }
            }
        }

        {
            let mut rl = self.rate_limiter.lock();
            if rl.window_start.elapsed() > Duration::from_secs(60) {
                rl.count = 0;
                rl.window_start = Instant::now();
            }

            if rl.count >= 10_000 {
                return true;
            }
            rl.count += 1;
        }

        false
    }

    fn write_audit_entry(&self, payload: &AlertPayload, suppressed: bool) -> Result<()> {
        let change = &payload.change;

        let hmac = self.hmac_key.as_ref().map(|key| {
            let ts = chrono::Utc::now().timestamp();
            let primary = change
                .changes
                .first()
                .map(change_to_name)
                .unwrap_or("unknown");
            let data = crate::hmac::build_audit_hmac_data(
                ts,
                &change.path.to_string_lossy(),
                primary,
                &change.severity.to_string(),
                None,
                None,
            );
            crate::hmac::compute_hmac(key, &data)
        });

        let previous = self.last_chain_hash.lock().clone();
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
                path: change.path.clone(),
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
        let dispatcher = AlertDispatcher::new(&cfg, &audit_path, metrics).unwrap();

        let payload = AlertPayload {
            change: ChangeResult {
                path: std::path::PathBuf::from("/tmp/test"),
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
}
