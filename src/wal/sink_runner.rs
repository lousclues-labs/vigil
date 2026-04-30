//! WAL-to-alert-sink dispatch thread.
//!
//! Reads unconsumed detection records from the WAL, applies per-path cooldown
//! and per-minute rate limiting, dispatches unsuppressed alerts to all
//! configured sinks (journal, JSON log, D-Bus, socket, remote syslog), and
//! marks each entry sink-done. Suppressed entries are still marked consumed
//! so they do not retry forever.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::alert::{self, AlertSink};
use crate::config::Config;
use crate::error::{Result, VigilError};
use crate::metrics::Metrics;
use crate::types::{Alert, AlertContext, AlertFileInfo, Change, ChangeResult, Severity};

use super::{DetectionSource, DetectionWal, WalEntry};

struct RateLimiter {
    count: u32,
    window_start: Instant,
}

pub struct SinkRunner {
    wal: Arc<DetectionWal>,
    sinks: Vec<Box<dyn AlertSink>>,
    cooldowns: LruCache<String, Instant>,
    cooldown_secs: u64,
    rate_limiter: RateLimiter,
    max_alerts_per_minute: u32,
    metrics: Arc<Metrics>,
    hostname: String,
}

impl SinkRunner {
    pub fn new(
        wal: Arc<DetectionWal>,
        config: &Config,
        metrics: Arc<Metrics>,
        hostname: String,
    ) -> Result<Self> {
        let mut sinks: Vec<Box<dyn AlertSink>> = Vec::new();

        if config.alerts.syslog {
            sinks.push(Box::new(alert::journal::JournalSink));
        }

        if !config.alerts.log_file.as_os_str().is_empty() {
            if let Ok(sink) = alert::json_log::JsonFileSink::new(&config.alerts.log_file) {
                sinks.push(Box::new(sink));
            }
        }

        if config.alerts.desktop_notifications {
            sinks.push(Box::new(alert::dbus::DbusSink::new(
                config.alerts.notification_rate_limit,
                config.alerts.notification_rate_window_secs,
            )));
        }

        if !config.hooks.signal_socket.is_empty() {
            sinks.push(Box::new(alert::socket::SocketSink::new(
                &config.hooks.signal_socket,
            )));
        }

        if config.alerts.remote_syslog.enabled {
            if let Ok(sink) =
                alert::remote_syslog::RemoteSyslogSink::new(&config.alerts.remote_syslog)
            {
                sinks.push(Box::new(sink));
            }
        }

        Ok(Self {
            wal,
            sinks,
            cooldowns: LruCache::new(std::num::NonZeroUsize::new(10_000).unwrap()),
            cooldown_secs: config.alerts.cooldown_seconds,
            rate_limiter: RateLimiter {
                count: 0,
                window_start: Instant::now(),
            },
            max_alerts_per_minute: config.alerts.max_alerts_per_minute,
            metrics,
            hostname,
        })
    }

    pub fn spawn(mut self, shutdown: Arc<AtomicBool>) -> Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name("vigil-wal-sinks".into())
            .spawn(move || self.run(shutdown))
            .map_err(|e| VigilError::Daemon(format!("cannot spawn WAL sink runner: {}", e)))
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) {
        loop {
            let mut pending: Vec<_> = match self.wal.iter_unconsumed() {
                Ok(v) => v.into_iter().filter(|e| !e.sink_done()).collect(),
                Err(e) => {
                    tracing::error!(error = %e, "WAL sink iteration failed");
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };

            self.metrics
                .detections_wal_sink_lag
                .store(pending.len() as u64, Ordering::Relaxed);

            if pending.is_empty() {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }

            pending.sort_by_key(|e| e.sequence);

            let mut processed = 0usize;
            for entry in pending {
                if entry.record.source == DetectionSource::Sentinel {
                    if let Err(e) = self.wal.mark_sink_done(entry.offset) {
                        tracing::error!(offset = entry.offset, error = %e, "failed to mark sentinel WAL entry as sink-done");
                    }
                    continue;
                }

                let change = entry.record.to_change_result();
                let suppressed = self.is_suppressed(&change, entry.record.maintenance_window);
                if suppressed {
                    self.metrics
                        .alerts_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    let alert = self.build_alert(&entry, &change);
                    self.dispatch_to_sinks(&alert);
                    self.metrics
                        .alerts_dispatched
                        .fetch_add(1, Ordering::Relaxed);
                    if alert.severity == crate::types::Severity::Critical {
                        self.metrics
                            .critical_alerts_dispatched
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    self.metrics
                        .detections_wal_sink_dispatched
                        .fetch_add(1, Ordering::Relaxed);
                }

                if let Err(e) = self.wal.mark_sink_done(entry.offset) {
                    tracing::error!(offset = entry.offset, error = %e, "failed to mark WAL entry as sink-done");
                }
                processed += 1;
            }

            if processed == 0 {
                std::thread::sleep(Duration::from_millis(50));
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        tracing::info!(hostname = %self.hostname, "WAL sink runner stopped");
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

    fn is_suppressed(&mut self, change: &ChangeResult, maintenance_window: bool) -> bool {
        if maintenance_window && change.package.is_some() {
            if change.severity >= Severity::High {
                return false;
            }
            return true;
        }

        let now = Instant::now();
        let path = change.path.to_string_lossy().to_string();

        if let Some(last) = self.cooldowns.get(&path) {
            if now.duration_since(*last) < Duration::from_secs(self.cooldown_secs) {
                return true;
            }
        }
        self.cooldowns.put(path, now);

        if self.rate_limiter.window_start.elapsed() > Duration::from_secs(60) {
            self.rate_limiter.count = 0;
            self.rate_limiter.window_start = Instant::now();
        }

        if self.rate_limiter.count >= self.max_alerts_per_minute {
            return true;
        }
        self.rate_limiter.count += 1;

        false
    }

    fn build_alert(&self, entry: &WalEntry, change: &ChangeResult) -> Alert {
        let change_type = change
            .changes
            .first()
            .map(change_to_name)
            .unwrap_or("unknown")
            .to_string();

        let event_id = format!(
            "{}-{}",
            entry.record.timestamp * 1000,
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
                maintenance_window: entry.record.maintenance_window,
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
    use crate::types::{Change, Severity};

    fn mk_sink_record(idx: usize, severity: Severity, path: &str) -> super::super::DetectionRecord {
        super::super::DetectionRecord {
            timestamp: 1_700_000_000 + idx as i64,
            path: path.to_string(),
            changes: vec![Change::Created],
            severity,
            monitored_group: "test".into(),
            process: None,
            package: None,
            package_update: false,
            maintenance_window: false,
            source: super::super::DetectionSource::Realtime,
            disambiguation: None,
        }
    }

    #[test]
    fn bounded_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let wal = Arc::new(
            super::super::DetectionWal::open(
                &dir.path().join("detections.wal"),
                None,
                64 * 1024 * 1024,
            )
            .unwrap(),
        );

        let mut cfg = crate::config::default_config();
        cfg.alerts.cooldown_seconds = 10;
        let metrics = Arc::new(Metrics::new());

        let mut runner = SinkRunner::new(wal, &cfg, metrics, "test".to_string()).unwrap();
        for i in 0..20_000usize {
            let change = ChangeResult {
                path: Arc::new(std::path::PathBuf::from(format!("/tmp/sink-{}", i))),
                changes: vec![Change::Created],
                severity: Severity::Medium,
                monitored_group: "test".into(),
                process: None,
                package: None,
                package_update: false,
                disambiguation: None,
            };
            let _ = runner.is_suppressed(&change, false);
        }

        assert!(runner.cooldowns.len() <= 10_000);
    }

    #[test]
    fn sink_dispatch_independent() {
        let dir = tempfile::tempdir().unwrap();
        let wal = Arc::new(
            super::super::DetectionWal::open(
                &dir.path().join("detections.wal"),
                None,
                64 * 1024 * 1024,
            )
            .unwrap(),
        );

        // Append 5 entries
        for i in 0..5 {
            wal.append(&mk_sink_record(
                i,
                Severity::High,
                &format!("/tmp/sink-dispatch-{}", i),
            ))
            .unwrap();
        }

        // Mark all 5 entries as audit_done (but NOT sink_done)
        let entries = wal.iter_unconsumed().unwrap();
        assert_eq!(entries.len(), 5);
        for e in &entries {
            wal.mark_audit_done(e.offset).unwrap();
        }

        // Verify entries are still visible (not fully consumed)
        let still_visible = wal.iter_unconsumed().unwrap();
        assert_eq!(
            still_visible.len(),
            5,
            "entries with only audit_done should still be visible"
        );

        // Create SinkRunner and process entries
        let mut cfg = crate::config::default_config();
        cfg.alerts.syslog = false;
        cfg.alerts.desktop_notifications = false;
        cfg.alerts.log_file = std::path::PathBuf::new();
        cfg.alerts.cooldown_seconds = 0;
        cfg.alerts.max_alerts_per_minute = 100_000;
        let metrics = Arc::new(Metrics::new());

        let mut runner =
            SinkRunner::new(wal.clone(), &cfg, metrics.clone(), "test".to_string()).unwrap();

        // Simulate one iteration of run() loop
        let mut pending: Vec<_> = wal
            .iter_unconsumed()
            .unwrap()
            .into_iter()
            .filter(|e| !e.sink_done())
            .collect();
        pending.sort_by_key(|e| e.sequence);

        for entry in &pending {
            let change = entry.record.to_change_result();
            let suppressed = runner.is_suppressed(&change, entry.record.maintenance_window);
            if !suppressed {
                let alert = runner.build_alert(entry, &change);
                runner.dispatch_to_sinks(&alert);
                metrics
                    .detections_wal_sink_dispatched
                    .fetch_add(1, Ordering::Relaxed);
            }
            let _ = wal.mark_sink_done(entry.offset);
        }

        // Verify all 5 entries now have sink_done
        let remaining = wal.iter_unconsumed().unwrap();
        assert_eq!(
            remaining.len(),
            0,
            "all entries should be fully consumed now"
        );
        assert_eq!(
            metrics
                .detections_wal_sink_dispatched
                .load(Ordering::Relaxed),
            5,
            "all 5 entries should have been dispatched"
        );
    }

    #[test]
    fn suppressed_entries_marked_consumed() {
        let dir = tempfile::tempdir().unwrap();
        let wal = Arc::new(
            super::super::DetectionWal::open(
                &dir.path().join("detections.wal"),
                None,
                64 * 1024 * 1024,
            )
            .unwrap(),
        );

        // Append 10 entries all with the SAME path to trigger cooldown
        for i in 0..10 {
            wal.append(&mk_sink_record(i, Severity::Medium, "/tmp/same-path"))
                .unwrap();
        }

        // Create SinkRunner with 300s cooldown (all but first will be suppressed)
        let mut cfg = crate::config::default_config();
        cfg.alerts.syslog = false;
        cfg.alerts.desktop_notifications = false;
        cfg.alerts.log_file = std::path::PathBuf::new();
        cfg.alerts.cooldown_seconds = 300;
        cfg.alerts.max_alerts_per_minute = 100_000;
        let metrics = Arc::new(Metrics::new());

        let mut runner =
            SinkRunner::new(wal.clone(), &cfg, metrics.clone(), "test".to_string()).unwrap();

        // Simulate one iteration of run() loop
        let mut pending: Vec<_> = wal
            .iter_unconsumed()
            .unwrap()
            .into_iter()
            .filter(|e| !e.sink_done())
            .collect();
        pending.sort_by_key(|e| e.sequence);

        let mut dispatched = 0u32;
        for entry in &pending {
            let change = entry.record.to_change_result();
            let suppressed = runner.is_suppressed(&change, entry.record.maintenance_window);
            if !suppressed {
                dispatched += 1;
            }
            // Mark sink_done regardless of suppression (per spec:
            // suppressed entries are marked consumed, not retried forever)
            let _ = wal.mark_sink_done(entry.offset);
        }

        // Only the first entry should have been dispatched (rest suppressed by cooldown)
        assert_eq!(dispatched, 1, "only the first entry should be dispatched");

        // All 10 entries should have sink_done set
        let entries = wal.iter_unconsumed().unwrap();
        let sink_pending = entries.iter().filter(|e| !e.sink_done()).count();
        assert_eq!(
            sink_pending, 0,
            "all entries should have sink_done set (including suppressed)"
        );
    }
}
