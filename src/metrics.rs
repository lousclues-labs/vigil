use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Operational metrics for the Vigil daemon.
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
    /// Audit entries permanently lost due to buffer overflow.
    pub audit_entries_lost: AtomicU64,
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
            audit_entries_lost: AtomicU64::new(0),
            uptime_start: chrono::Utc::now().timestamp(),
        }
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
            audit_entries_lost: self.audit_entries_lost.load(Ordering::Relaxed),
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
    pub audit_entries_lost: u64,
    pub uptime_start: i64,
}

impl MetricsSnapshot {
    /// Format metrics in Prometheus text exposition format.
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
            "vigil_audit_entries_lost_total",
            "Audit entries permanently lost due to buffer overflow",
            self.audit_entries_lost,
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
