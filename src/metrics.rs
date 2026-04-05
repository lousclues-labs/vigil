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
    pub uptime_start: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_new_zeroed() {
        let m = Metrics::new();
        assert_eq!(m.events_received.load(Ordering::Relaxed), 0);
        assert_eq!(m.events_dropped.load(Ordering::Relaxed), 0);
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
}
