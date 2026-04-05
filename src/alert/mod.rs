pub mod dbus;
pub mod journal;
pub mod json_log;
pub mod socket;

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use parking_lot::Mutex;

use crate::config::Config;
use crate::error::Result;
use crate::types::{Alert, AlertContext, AlertFileInfo, ChangeResult, ChangeType, Severity};

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The alert engine: dispatches classified changes to output channels
/// with rate limiting, cooldown, and deduplication.
pub struct AlertEngine {
    syslog_enabled: bool,
    log_min_severity: Severity,
    dbus_min_severity: Severity,
    /// Per-path cooldown tracking (path → last alert time).
    cooldowns: Mutex<std::collections::HashMap<String, Instant>>,
    /// Alert count in the current minute window.
    rate_counter: Mutex<RateCounter>,
    /// D-Bus notifier (optional).
    dbus_notifier: Option<dbus::DbusNotifier>,
    /// JSON log writer (optional).
    json_logger: Option<json_log::JsonLogger>,
    /// Signal socket writer (optional).
    signal_socket: Option<socket::SignalSocket>,
    /// Cached hostname (read once at startup).
    hostname: String,
    /// Hot-reloadable rate limit (alerts per minute).
    rate_limit: AtomicU32,
    /// Hot-reloadable per-path cooldown (seconds).
    cooldown_secs: AtomicU64,
}

struct RateCounter {
    count: u32,
    window_start: Instant,
}

impl AlertEngine {
    pub fn new(config: &Config) -> Result<Self> {
        let dbus_notifier = if config.alerts.desktop_notifications {
            match dbus::DbusNotifier::new() {
                Ok(n) => Some(n),
                Err(e) => {
                    log::warn!("D-Bus notifications unavailable: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let json_logger = if !config.alerts.log_file.as_os_str().is_empty() {
            match json_log::JsonLogger::new(&config.alerts.log_file) {
                Ok(l) => Some(l),
                Err(e) => {
                    log::warn!("JSON log file unavailable: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let signal_socket = if !config.hooks.signal_socket.is_empty() {
            match socket::SignalSocket::new(&config.hooks.signal_socket) {
                Ok(s) => Some(s),
                Err(e) => {
                    log::warn!("Signal socket unavailable: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            syslog_enabled: config.alerts.syslog,
            log_min_severity: config.alerts.severity_filter.log_min_severity,
            dbus_min_severity: config.alerts.severity_filter.dbus_min_severity,
            cooldowns: Mutex::new(std::collections::HashMap::new()),
            rate_counter: Mutex::new(RateCounter {
                count: 0,
                window_start: Instant::now(),
            }),
            dbus_notifier,
            json_logger,
            signal_socket,
            hostname: hostname(),
            rate_limit: AtomicU32::new(config.alerts.rate_limit),
            cooldown_secs: AtomicU64::new(config.alerts.cooldown_seconds),
        })
    }

    /// Access the JSON logger for rotation.
    pub fn json_logger(&self) -> Option<&json_log::JsonLogger> {
        self.json_logger.as_ref()
    }

    /// Update the rate limiter and cooldown settings from a reloaded config.
    ///
    /// Called on SIGHUP after a successful config reload. Resets the rate
    /// counter window so the new limit takes effect immediately.
    pub fn update_rate_config(&self, rate_limit: u32, cooldown_seconds: u64) {
        {
            let mut rate = self.rate_counter.lock();
            rate.count = 0;
            rate.window_start = Instant::now();
        }
        self.rate_limit.store(rate_limit, Ordering::Release);
        self.cooldown_secs
            .store(cooldown_seconds, Ordering::Release);
        log::info!(
            "Alert engine updated: rate_limit={}, cooldown_seconds={}",
            rate_limit,
            cooldown_seconds
        );
    }

    /// Dispatch a change result to all configured output channels.
    /// Always writes to audit log regardless of suppression.
    pub fn dispatch(
        &self,
        change: &ChangeResult,
        maintenance_window: bool,
        conn: &rusqlite::Connection,
    ) -> Result<()> {
        let primary_change = change
            .change_types
            .first()
            .copied()
            .unwrap_or(ChangeType::Modified);

        // Always write to audit log (never suppress audit trail)
        let suppressed = self.is_suppressed(change, maintenance_window);
        crate::db::ops::insert_audit_entry(
            conn,
            change,
            primary_change,
            maintenance_window,
            suppressed,
            None,
        )?;

        if suppressed {
            log::debug!(
                "Alert suppressed for {}: cooldown/rate-limit/maintenance",
                change.path.display()
            );
            return Ok(());
        }

        let alert = self.build_alert(change, primary_change, maintenance_window);

        // journald/syslog (always, if enabled)
        if self.syslog_enabled {
            journal::log_alert(&alert);
        }

        // JSON log file
        if let Some(ref logger) = self.json_logger {
            if change.severity >= self.log_min_severity {
                logger.write(&alert);
            }
        }

        // D-Bus desktop notification
        if let Some(ref notifier) = self.dbus_notifier {
            if change.severity >= self.dbus_min_severity {
                notifier.notify(&alert);
            }
        }

        // Signal socket
        if let Some(ref sock) = self.signal_socket {
            sock.send_event(change);
        }

        // Update cooldown
        let path_str = change.path.to_string_lossy().into_owned();
        self.cooldowns.lock().insert(path_str, Instant::now());

        // Update rate counter
        self.rate_counter.lock().count += 1;

        Ok(())
    }

    fn is_suppressed(&self, change: &ChangeResult, maintenance_window: bool) -> bool {
        // During maintenance window, suppress notifications for package-managed paths
        // but HIGH/CRITICAL for non-package-managed paths still fire
        if maintenance_window && change.package.is_some() {
            return true;
        }

        // Per-path cooldown (uses hot-reloadable cooldown value)
        let cooldown_secs = self.cooldown_secs.load(Ordering::Acquire);
        let path_str = change.path.to_string_lossy();
        {
            let cooldowns = self.cooldowns.lock();
            if let Some(last) = cooldowns.get(path_str.as_ref()) {
                if last.elapsed() < Duration::from_secs(cooldown_secs) {
                    return true;
                }
            }
        }

        // Rate limiting (uses hot-reloadable rate limit)
        let rate_limit = self.rate_limit.load(Ordering::Acquire);
        {
            let mut rate = self.rate_counter.lock();
            // Reset window if it's been more than a minute
            if rate.window_start.elapsed() > Duration::from_secs(60) {
                rate.count = 0;
                rate.window_start = Instant::now();
            }
            if rate.count >= rate_limit {
                return true;
            }
        }

        false
    }

    fn build_alert(
        &self,
        change: &ChangeResult,
        primary_change: ChangeType,
        maintenance_window: bool,
    ) -> Alert {
        let alert_timestamp = Utc::now();
        let alert_timestamp_epoch = alert_timestamp.timestamp() as u64;
        Alert {
            version: 1,
            timestamp: alert_timestamp,
            event_id: {
                let seq = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
                format!("vigil_{:x}_{:06x}", alert_timestamp_epoch, seq)
            },
            severity: change.severity,
            change_type: primary_change,
            file: AlertFileInfo {
                path: change.path.clone(),
                baseline_hash: change.old_hash.clone(),
                current_hash: change.new_hash.clone(),
                baseline_size: None,
                current_size: None,
                baseline_permissions: change
                    .old_permissions
                    .map(|p| format!("{:04o}", p & 0o7777)),
                current_permissions: change
                    .new_permissions
                    .map(|p| format!("{:04o}", p & 0o7777)),
                baseline_owner: change.old_owner_uid.map(|u| format!("{}", u)),
                current_owner: change.new_owner_uid.map(|u| format!("{}", u)),
                inode_changed: change.change_types.contains(&ChangeType::InodeChanged),
                mtime_changed: change.old_mtime != change.new_mtime,
                package: change.package.clone(),
                package_update: change.package_update,
            },
            context: AlertContext {
                hostname: self.hostname.clone(),
                monitored_group: change.monitored_group.clone(),
                maintenance_window,
            },
        }
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
