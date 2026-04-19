//! Atomic counters for daemon-wide events, hashes, alerts, and performance.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// All counters use relaxed atomic ordering for approximate visibility.
pub struct Metrics {
    pub events_received: AtomicU64,
    pub events_processed: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_debounced: AtomicU64,
    pub events_filtered: AtomicU64,
    pub hashes_computed: AtomicU64,
    pub changes_detected: AtomicU64,
    pub alerts_dispatched: AtomicU64,
    pub alerts_suppressed: AtomicU64,
    pub db_writes: AtomicU64,
    pub db_errors: AtomicU64,
    pub panics_caught: AtomicU64,
    pub scan_duration_ms: AtomicU64,
    pub last_scan_total: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub baseline_updates: AtomicU64,
    pub backpressure_events: AtomicU64,
    /// Control socket commands executed.
    pub control_commands: AtomicU64,
    /// Fanotify kernel queue overflow events.
    pub kernel_queue_overflows: AtomicU64,
    /// Full scans triggered in response to fanotify queue overflow.
    pub fanotify_overflow_scans_triggered: AtomicU64,
    /// Fanotify mark add/remove failures (degrades coverage).
    pub fanotify_mark_failures: AtomicU64,
    /// Fanotify read() syscall failures (other than EAGAIN).
    pub fanotify_read_errors: AtomicU64,
    /// Package manager cache build failures or empty results when a package manager exists.
    pub package_cache_failures: AtomicU64,
    /// Audit entries permanently lost due to buffer overflow.
    pub audit_entries_lost: AtomicU64,
    pub detections_wal_appends: AtomicU64,
    pub detections_wal_audit_committed: AtomicU64,
    pub detections_wal_sink_dispatched: AtomicU64,
    pub detections_wal_replayed: AtomicU64,
    pub detections_wal_full: AtomicU64,
    pub detections_wal_tampered: AtomicU64,
    pub detections_wal_gaps: AtomicU64,
    pub detections_wal_bytes: AtomicU64,
    pub detections_wal_pending: AtomicU64,
    pub detections_wal_audit_lag: AtomicU64,
    pub detections_wal_sink_lag: AtomicU64,
    /// WAL entries rejected due to HMAC verification failure or zero-HMAC when HMAC required.
    pub wal_entries_rejected_hmac: AtomicU64,
    /// Inode changes where content verification succeeded and the new identity was accepted.
    pub inode_changes_recovered: AtomicU64,
    /// Inode changes where content verification failed and the daemon entered Degraded.
    pub inode_changes_rejected: AtomicU64,
    /// Fanotify thread supervised restarts after recoverable errors.
    pub fanotify_thread_restarts: AtomicU64,
    /// Worker DB reopen attempts after consecutive errors.
    pub worker_db_reopen_attempts: AtomicU64,
    /// Worker DB reopen failures (reopen itself failed).
    pub worker_db_reopen_failures: AtomicU64,
    /// Auto-rebaseline entries rejected due to empty hash or zero mtime.
    pub auto_rebaseline_rejected: AtomicU64,
    /// Unix timestamp set once at daemon startup.
    pub uptime_start: i64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            events_processed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            events_debounced: AtomicU64::new(0),
            events_filtered: AtomicU64::new(0),
            hashes_computed: AtomicU64::new(0),
            changes_detected: AtomicU64::new(0),
            alerts_dispatched: AtomicU64::new(0),
            alerts_suppressed: AtomicU64::new(0),
            db_writes: AtomicU64::new(0),
            db_errors: AtomicU64::new(0),
            panics_caught: AtomicU64::new(0),
            scan_duration_ms: AtomicU64::new(0),
            last_scan_total: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            baseline_updates: AtomicU64::new(0),
            backpressure_events: AtomicU64::new(0),
            control_commands: AtomicU64::new(0),
            kernel_queue_overflows: AtomicU64::new(0),
            fanotify_overflow_scans_triggered: AtomicU64::new(0),
            fanotify_mark_failures: AtomicU64::new(0),
            fanotify_read_errors: AtomicU64::new(0),
            package_cache_failures: AtomicU64::new(0),
            audit_entries_lost: AtomicU64::new(0),
            detections_wal_appends: AtomicU64::new(0),
            detections_wal_audit_committed: AtomicU64::new(0),
            detections_wal_sink_dispatched: AtomicU64::new(0),
            detections_wal_replayed: AtomicU64::new(0),
            detections_wal_full: AtomicU64::new(0),
            detections_wal_tampered: AtomicU64::new(0),
            detections_wal_gaps: AtomicU64::new(0),
            detections_wal_bytes: AtomicU64::new(0),
            detections_wal_pending: AtomicU64::new(0),
            detections_wal_audit_lag: AtomicU64::new(0),
            detections_wal_sink_lag: AtomicU64::new(0),
            wal_entries_rejected_hmac: AtomicU64::new(0),
            inode_changes_recovered: AtomicU64::new(0),
            inode_changes_rejected: AtomicU64::new(0),
            fanotify_thread_restarts: AtomicU64::new(0),
            worker_db_reopen_attempts: AtomicU64::new(0),
            worker_db_reopen_failures: AtomicU64::new(0),
            auto_rebaseline_rejected: AtomicU64::new(0),
            uptime_start: chrono::Utc::now().timestamp(),
        }
    }

    /// Record scan result metrics (changes, duration, total checked).
    pub fn record_scan(&self, changes_found: u64, duration_ms: u64, total_checked: u64) {
        self.changes_detected
            .fetch_add(changes_found, Ordering::Relaxed);
        self.scan_duration_ms.store(duration_ms, Ordering::Relaxed);
        self.last_scan_total.store(total_checked, Ordering::Relaxed);
    }

    /// Take a point-in-time snapshot of all counters for serialization.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            events_received: self.events_received.load(Ordering::Relaxed),
            events_processed: self.events_processed.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            events_debounced: self.events_debounced.load(Ordering::Relaxed),
            events_filtered: self.events_filtered.load(Ordering::Relaxed),
            hashes_computed: self.hashes_computed.load(Ordering::Relaxed),
            changes_detected: self.changes_detected.load(Ordering::Relaxed),
            alerts_dispatched: self.alerts_dispatched.load(Ordering::Relaxed),
            alerts_suppressed: self.alerts_suppressed.load(Ordering::Relaxed),
            db_writes: self.db_writes.load(Ordering::Relaxed),
            db_errors: self.db_errors.load(Ordering::Relaxed),
            panics_caught: self.panics_caught.load(Ordering::Relaxed),
            scan_duration_ms: self.scan_duration_ms.load(Ordering::Relaxed),
            last_scan_total: self.last_scan_total.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            baseline_updates: self.baseline_updates.load(Ordering::Relaxed),
            backpressure_events: self.backpressure_events.load(Ordering::Relaxed),
            control_commands: self.control_commands.load(Ordering::Relaxed),
            kernel_queue_overflows: self.kernel_queue_overflows.load(Ordering::Relaxed),
            fanotify_overflow_scans_triggered: self
                .fanotify_overflow_scans_triggered
                .load(Ordering::Relaxed),
            fanotify_mark_failures: self.fanotify_mark_failures.load(Ordering::Relaxed),
            fanotify_read_errors: self.fanotify_read_errors.load(Ordering::Relaxed),
            package_cache_failures: self.package_cache_failures.load(Ordering::Relaxed),
            audit_entries_lost: self.audit_entries_lost.load(Ordering::Relaxed),
            detections_wal_appends: self.detections_wal_appends.load(Ordering::Relaxed),
            detections_wal_audit_committed: self
                .detections_wal_audit_committed
                .load(Ordering::Relaxed),
            detections_wal_sink_dispatched: self
                .detections_wal_sink_dispatched
                .load(Ordering::Relaxed),
            detections_wal_replayed: self.detections_wal_replayed.load(Ordering::Relaxed),
            detections_wal_full: self.detections_wal_full.load(Ordering::Relaxed),
            detections_wal_tampered: self.detections_wal_tampered.load(Ordering::Relaxed),
            detections_wal_gaps: self.detections_wal_gaps.load(Ordering::Relaxed),
            detections_wal_bytes: self.detections_wal_bytes.load(Ordering::Relaxed),
            detections_wal_pending: self.detections_wal_pending.load(Ordering::Relaxed),
            detections_wal_audit_lag: self.detections_wal_audit_lag.load(Ordering::Relaxed),
            detections_wal_sink_lag: self.detections_wal_sink_lag.load(Ordering::Relaxed),
            wal_entries_rejected_hmac: self.wal_entries_rejected_hmac.load(Ordering::Relaxed),
            inode_changes_recovered: self.inode_changes_recovered.load(Ordering::Relaxed),
            inode_changes_rejected: self.inode_changes_rejected.load(Ordering::Relaxed),
            fanotify_thread_restarts: self.fanotify_thread_restarts.load(Ordering::Relaxed),
            worker_db_reopen_attempts: self.worker_db_reopen_attempts.load(Ordering::Relaxed),
            worker_db_reopen_failures: self.worker_db_reopen_failures.load(Ordering::Relaxed),
            auto_rebaseline_rejected: self.auto_rebaseline_rejected.load(Ordering::Relaxed),
            uptime_start: self.uptime_start,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable point-in-time snapshot of all metrics counters.
#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub events_received: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub events_debounced: u64,
    pub events_filtered: u64,
    pub hashes_computed: u64,
    pub changes_detected: u64,
    pub alerts_dispatched: u64,
    pub alerts_suppressed: u64,
    pub db_writes: u64,
    pub db_errors: u64,
    pub panics_caught: u64,
    pub scan_duration_ms: u64,
    pub last_scan_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub baseline_updates: u64,
    pub backpressure_events: u64,
    pub control_commands: u64,
    pub kernel_queue_overflows: u64,
    pub fanotify_overflow_scans_triggered: u64,
    pub fanotify_mark_failures: u64,
    pub fanotify_read_errors: u64,
    pub package_cache_failures: u64,
    pub audit_entries_lost: u64,
    pub detections_wal_appends: u64,
    pub detections_wal_audit_committed: u64,
    pub detections_wal_sink_dispatched: u64,
    pub detections_wal_replayed: u64,
    pub detections_wal_full: u64,
    pub detections_wal_tampered: u64,
    pub detections_wal_gaps: u64,
    pub detections_wal_bytes: u64,
    pub detections_wal_pending: u64,
    pub detections_wal_audit_lag: u64,
    pub detections_wal_sink_lag: u64,
    pub wal_entries_rejected_hmac: u64,
    pub inode_changes_recovered: u64,
    pub inode_changes_rejected: u64,
    pub fanotify_thread_restarts: u64,
    pub worker_db_reopen_attempts: u64,
    pub worker_db_reopen_failures: u64,
    pub auto_rebaseline_rejected: u64,
    pub uptime_start: i64,
}

impl MetricsSnapshot {
    /// Format metrics in Prometheus text exposition format.
    /// Serialize all counters as a serde_json::Value for the status endpoint.
    /// New metrics are automatically included without updating handle_status.
    pub fn status_view(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    pub fn to_prometheus(&self) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(2048);

        write_prom_counter(
            &mut out,
            "vigil_events_received_total",
            "Total filesystem events received",
            self.events_received,
        );
        write_prom_counter(
            &mut out,
            "vigil_events_processed_total",
            "Total events processed by workers",
            self.events_processed,
        );
        write_prom_counter(
            &mut out,
            "vigil_events_dropped_total",
            "Events dropped due to backpressure",
            self.events_dropped,
        );
        write_prom_counter(
            &mut out,
            "vigil_events_debounced_total",
            "Events suppressed by debounce filter",
            self.events_debounced,
        );
        write_prom_counter(
            &mut out,
            "vigil_events_filtered_total",
            "Events excluded by pattern filter",
            self.events_filtered,
        );
        write_prom_counter(
            &mut out,
            "vigil_hashes_computed_total",
            "File hashes computed",
            self.hashes_computed,
        );
        write_prom_counter(
            &mut out,
            "vigil_changes_detected_total",
            "File integrity changes detected",
            self.changes_detected,
        );
        write_prom_counter(
            &mut out,
            "vigil_alerts_dispatched_total",
            "Alerts sent to sinks",
            self.alerts_dispatched,
        );
        write_prom_counter(
            &mut out,
            "vigil_alerts_suppressed_total",
            "Alerts suppressed by cooldown or rate limit",
            self.alerts_suppressed,
        );
        write_prom_counter(
            &mut out,
            "vigil_db_writes_total",
            "Database write operations",
            self.db_writes,
        );
        write_prom_counter(
            &mut out,
            "vigil_db_errors_total",
            "Database errors",
            self.db_errors,
        );
        write_prom_counter(
            &mut out,
            "vigil_panics_caught_total",
            "Worker panics caught",
            self.panics_caught,
        );
        write_prom_gauge(
            &mut out,
            "vigil_scan_duration_ms",
            "Duration of last scan in milliseconds",
            self.scan_duration_ms,
        );
        write_prom_gauge(
            &mut out,
            "vigil_scan_files_total",
            "Files checked in last scan",
            self.last_scan_total,
        );
        write_prom_gauge(
            &mut out,
            "vigil_uptime_start_timestamp",
            "Daemon start time (unix timestamp)",
            self.uptime_start as u64,
        );
        write_prom_counter(
            &mut out,
            "vigil_kernel_queue_overflows_total",
            "Fanotify kernel queue overflow events",
            self.kernel_queue_overflows,
        );
        write_prom_counter(
            &mut out,
            "vigil_fanotify_overflow_scans_triggered_total",
            "Full scans triggered in response to fanotify queue overflow",
            self.fanotify_overflow_scans_triggered,
        );
        write_prom_counter(
            &mut out,
            "vigil_fanotify_mark_failures_total",
            "Fanotify mark add/remove failures (degrades coverage)",
            self.fanotify_mark_failures,
        );
        write_prom_counter(
            &mut out,
            "vigil_fanotify_read_errors_total",
            "Fanotify read() syscall failures other than EAGAIN",
            self.fanotify_read_errors,
        );
        write_prom_counter(
            &mut out,
            "vigil_package_cache_failures_total",
            "Package manager cache build failures or empty results",
            self.package_cache_failures,
        );
        write_prom_counter(
            &mut out,
            "vigil_control_commands_total",
            "Security-relevant control socket commands executed",
            self.control_commands,
        );
        write_prom_counter(
            &mut out,
            "vigil_backpressure_events_total",
            "Coordinator backpressure events recorded",
            self.backpressure_events,
        );
        write_prom_counter(
            &mut out,
            "vigil_audit_entries_lost_total",
            "Audit entries permanently lost due to buffer overflow",
            self.audit_entries_lost,
        );
        write_prom_counter(
            &mut out,
            "vigil_detections_wal_appends_total",
            "Detection entries appended to WAL",
            self.detections_wal_appends,
        );
        write_prom_counter(
            &mut out,
            "vigil_detections_wal_audit_committed_total",
            "Detection entries committed from WAL to audit DB",
            self.detections_wal_audit_committed,
        );
        write_prom_counter(
            &mut out,
            "vigil_detections_wal_sink_dispatched_total",
            "Detection entries dispatched from WAL to sinks",
            self.detections_wal_sink_dispatched,
        );
        write_prom_counter(
            &mut out,
            "vigil_detections_wal_replayed_total",
            "Detection entries replayed during crash recovery",
            self.detections_wal_replayed,
        );
        write_prom_counter(
            &mut out,
            "vigil_detections_wal_full_total",
            "WAL append attempts rejected because WAL is full",
            self.detections_wal_full,
        );
        write_prom_counter(
            &mut out,
            "vigil_detections_wal_tampered_total",
            "WAL entries rejected due to invalid entry HMAC",
            self.detections_wal_tampered,
        );
        write_prom_counter(
            &mut out,
            "vigil_detections_wal_gaps_total",
            "WAL sequence gaps detected during audit commit",
            self.detections_wal_gaps,
        );
        write_prom_gauge(
            &mut out,
            "vigil_detections_wal_bytes",
            "Current WAL file size in bytes",
            self.detections_wal_bytes,
        );
        write_prom_gauge(
            &mut out,
            "vigil_detections_wal_pending",
            "Current number of pending WAL entries",
            self.detections_wal_pending,
        );
        write_prom_gauge(
            &mut out,
            "vigil_detections_wal_audit_lag",
            "Current number of WAL entries pending audit commit",
            self.detections_wal_audit_lag,
        );
        write_prom_gauge(
            &mut out,
            "vigil_detections_wal_sink_lag",
            "Current number of WAL entries pending sink dispatch",
            self.detections_wal_sink_lag,
        );
        write_prom_counter(
            &mut out,
            "vigil_wal_entries_rejected_hmac_total",
            "WAL entries rejected due to HMAC failure or zero-HMAC bypass attempt",
            self.wal_entries_rejected_hmac,
        );
        write_prom_counter(
            &mut out,
            "vigil_inode_changes_recovered_total",
            "Inode changes where content verification succeeded",
            self.inode_changes_recovered,
        );
        write_prom_counter(
            &mut out,
            "vigil_inode_changes_rejected_total",
            "Inode changes where content verification failed",
            self.inode_changes_rejected,
        );
        write_prom_counter(
            &mut out,
            "vigil_fanotify_thread_restarts_total",
            "Fanotify thread supervised restarts after recoverable errors",
            self.fanotify_thread_restarts,
        );
        write_prom_counter(
            &mut out,
            "vigil_worker_db_reopen_attempts_total",
            "Worker DB reopen attempts after consecutive errors",
            self.worker_db_reopen_attempts,
        );
        write_prom_counter(
            &mut out,
            "vigil_worker_db_reopen_failures_total",
            "Worker DB reopen failures",
            self.worker_db_reopen_failures,
        );

        let _ = writeln!(out);
        out
    }
}

fn write_prom_counter(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} counter", name);
    let _ = writeln!(out, "{} {}", name, value);
}

fn write_prom_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} gauge", name);
    let _ = writeln!(out, "{} {}", name, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_new_zeroed() {
        let m = Metrics::new();
        assert_eq!(m.events_received.load(Ordering::Relaxed), 0);
        assert_eq!(m.events_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(m.scan_duration_ms.load(Ordering::Relaxed), 0);
        assert_eq!(m.last_scan_total.load(Ordering::Relaxed), 0);
        assert!(m.uptime_start > 0);
    }

    #[test]
    fn metrics_snapshot_reflects_increments() {
        let m = Metrics::new();
        m.events_received.fetch_add(42, Ordering::Relaxed);
        m.changes_detected.fetch_add(3, Ordering::Relaxed);
        let snap = m.snapshot();
        assert_eq!(snap.events_received, 42);
        assert_eq!(snap.changes_detected, 3);
        assert_eq!(snap.events_dropped, 0);
    }

    #[test]
    fn prometheus_format_contains_expected_metrics() {
        let m = Metrics::new();
        m.events_received.fetch_add(100, Ordering::Relaxed);
        m.changes_detected.fetch_add(5, Ordering::Relaxed);
        let snap = m.snapshot();
        let prom = snap.to_prometheus();

        assert!(prom.contains("# TYPE vigil_events_received_total counter"));
        assert!(prom.contains("vigil_events_received_total 100"));
        assert!(prom.contains("# TYPE vigil_changes_detected_total counter"));
        assert!(prom.contains("vigil_changes_detected_total 5"));
        assert!(prom.contains("# TYPE vigil_scan_duration_ms gauge"));
        assert!(prom.contains("# TYPE vigil_uptime_start_timestamp gauge"));
        assert!(prom.contains("# HELP vigil_events_received_total"));
    }
}
