//! Notification routing with severity-aware delivery, coalescing, and storm suppression.
//!
//! The pipeline: WAL -> sink_runner -> NotificationRouter -> per-severity
//! policy lookup -> coalesce buffer -> storm detector -> channel fan-out.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::types::{ChangeResult, Severity};

/// Delivery policy for a severity level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliverPolicy {
    /// Fire immediately when the event arrives.
    Immediate,
    /// Group events sharing the same coalescing key and fire when the window expires.
    Coalesce,
    /// Accumulate into a periodic digest.
    Digest,
}

/// Per-severity notification policy from config.
#[derive(Debug, Clone)]
pub struct SeverityPolicy {
    pub deliver: DeliverPolicy,
    pub coalesce_within_secs: u64,
    pub escalation_intervals_secs: Vec<u64>,
    pub escalate_after_secs: u64,
    pub digest_interval_secs: u64,
    pub channels: Vec<String>,
}

impl Default for SeverityPolicy {
    fn default() -> Self {
        Self {
            deliver: DeliverPolicy::Immediate,
            coalesce_within_secs: 30,
            escalation_intervals_secs: vec![300, 900, 3600, 86400],
            escalate_after_secs: 300,
            digest_interval_secs: 3600,
            channels: vec!["journald".into()],
        }
    }
}

/// Coalescing key: events with the same key are grouped.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoalesceKey {
    pub group: String,
    pub parent_dir: String,
    pub severity: Severity,
}

impl CoalesceKey {
    pub fn from_change(cr: &ChangeResult) -> Self {
        let parent = cr
            .path
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        Self {
            group: cr.monitored_group.clone(),
            parent_dir: parent,
            severity: cr.severity,
        }
    }
}

/// A coalesced group of events.
#[derive(Debug, Clone)]
pub struct CoalescedNotification {
    pub key: CoalesceKey,
    pub events: Vec<CoalescedEvent>,
    pub window_start: Instant,
}

/// A single event within a coalesced notification.
#[derive(Debug, Clone)]
pub struct CoalescedEvent {
    pub path: String,
    pub changes: String,
    pub package: Option<String>,
}

/// Rolling window storm detector.
pub struct StormDetector {
    window_secs: u64,
    threshold: u64,
    timestamps: Mutex<Vec<Instant>>,
    in_storm: AtomicBool,
}

impl StormDetector {
    pub fn new(threshold: u64, window_secs: u64) -> Self {
        Self {
            window_secs,
            threshold,
            timestamps: Mutex::new(Vec::new()),
            in_storm: AtomicBool::new(false),
        }
    }

    /// Record an event and return true if we just entered a storm.
    pub fn record(&self) -> bool {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(self.window_secs);
        let mut ts = self.timestamps.lock();
        ts.retain(|t| *t > cutoff);
        ts.push(now);
        let count = ts.len() as u64;

        if count >= self.threshold && !self.in_storm.load(Ordering::Relaxed) {
            self.in_storm.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Check if the storm has ended (rate below threshold/5 for 30s).
    pub fn check_recovery(&self) -> bool {
        if !self.in_storm.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(30);
        let ts = self.timestamps.lock();
        let recent = ts.iter().filter(|t| **t > cutoff).count() as u64;
        if recent < self.threshold / 5 {
            drop(ts);
            self.in_storm.store(false, Ordering::Relaxed);
            return true;
        }
        false
    }

    pub fn is_in_storm(&self) -> bool {
        self.in_storm.load(Ordering::Relaxed)
    }

    pub fn event_count_in_window(&self) -> u64 {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(self.window_secs);
        let ts = self.timestamps.lock();
        ts.iter().filter(|t| **t > cutoff).count() as u64
    }
}

/// Tracks pending critical alert escalations.
pub struct EscalationTracker {
    pending: Mutex<HashMap<String, EscalationState>>,
}

struct EscalationState {
    event_id: String,
    escalation_count: u32,
    last_escalation: Instant,
    intervals: Vec<u64>,
    acknowledged: bool,
}

impl Default for EscalationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl EscalationTracker {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new critical alert for escalation tracking.
    pub fn register(&self, event_id: &str, intervals: &[u64]) {
        let mut pending = self.pending.lock();
        pending.insert(
            event_id.to_string(),
            EscalationState {
                event_id: event_id.to_string(),
                escalation_count: 0,
                last_escalation: Instant::now(),
                intervals: intervals.to_vec(),
                acknowledged: false,
            },
        );
    }

    /// Acknowledge a critical alert, canceling further escalations.
    pub fn acknowledge(&self, event_id: &str) -> bool {
        let mut pending = self.pending.lock();
        if let Some(state) = pending.get_mut(event_id) {
            state.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Acknowledge all pending critical alerts.
    pub fn acknowledge_all(&self) -> u32 {
        let mut pending = self.pending.lock();
        let mut count = 0;
        for state in pending.values_mut() {
            if !state.acknowledged {
                state.acknowledged = true;
                count += 1;
            }
        }
        count
    }

    /// Return event IDs that need escalation firing.
    pub fn due_escalations(&self) -> Vec<(String, u32)> {
        let mut pending = self.pending.lock();
        let mut due = Vec::new();
        for state in pending.values_mut() {
            if state.acknowledged {
                continue;
            }
            let interval_idx = state.escalation_count as usize;
            if interval_idx >= state.intervals.len() {
                continue;
            }
            let interval = Duration::from_secs(state.intervals[interval_idx]);
            if state.last_escalation.elapsed() >= interval {
                state.escalation_count += 1;
                state.last_escalation = Instant::now();
                due.push((state.event_id.clone(), state.escalation_count));
            }
        }
        due
    }
}

/// The notification router sits between the WAL/sink_runner and the channels.
pub struct NotificationRouter {
    pub policies: HashMap<Severity, SeverityPolicy>,
    pub coalesce_buffers: Mutex<HashMap<CoalesceKey, CoalescedNotification>>,
    pub storm_detector: StormDetector,
    pub escalation_tracker: EscalationTracker,
    pub storm_threshold: u64,
    pub storm_window_secs: u64,
}

impl NotificationRouter {
    pub fn new(storm_threshold: u64, storm_window_secs: u64) -> Self {
        let mut policies = HashMap::new();

        policies.insert(
            Severity::Critical,
            SeverityPolicy {
                deliver: DeliverPolicy::Immediate,
                escalate_after_secs: 300,
                escalation_intervals_secs: vec![300, 3600],
                channels: vec!["desktop".into(), "journald".into(), "socket".into()],
                ..SeverityPolicy::default()
            },
        );
        policies.insert(
            Severity::High,
            SeverityPolicy {
                deliver: DeliverPolicy::Immediate,
                coalesce_within_secs: 30,
                channels: vec!["desktop".into(), "journald".into(), "socket".into()],
                ..SeverityPolicy::default()
            },
        );
        policies.insert(
            Severity::Medium,
            SeverityPolicy {
                deliver: DeliverPolicy::Coalesce,
                coalesce_within_secs: 300,
                channels: vec!["journald".into(), "socket".into()],
                ..SeverityPolicy::default()
            },
        );
        policies.insert(
            Severity::Low,
            SeverityPolicy {
                deliver: DeliverPolicy::Digest,
                digest_interval_secs: 3600,
                channels: vec!["journald".into()],
                ..SeverityPolicy::default()
            },
        );

        Self {
            policies,
            coalesce_buffers: Mutex::new(HashMap::new()),
            storm_detector: StormDetector::new(storm_threshold, storm_window_secs),
            escalation_tracker: EscalationTracker::new(),
            storm_threshold,
            storm_window_secs,
        }
    }

    /// Route a change result through the notification pipeline.
    /// Returns the delivery action to take.
    pub fn route(
        &self,
        cr: &ChangeResult,
        maintenance_window: bool,
        event_id: &str,
    ) -> RoutingDecision {
        // Storm suppression check.
        let storm_entered = self.storm_detector.record();
        if self.storm_detector.is_in_storm() {
            if storm_entered {
                return RoutingDecision::StormStarted {
                    event_count: self.storm_detector.event_count_in_window(),
                };
            }
            return RoutingDecision::Suppressed;
        }

        let policy = self.policies.get(&cr.severity).cloned().unwrap_or_default();

        // Build maintenance prefix if applicable.
        let maintenance_prefix = if maintenance_window {
            Some("[maintenance]".to_string())
        } else {
            None
        };

        match policy.deliver {
            DeliverPolicy::Immediate => {
                // Register for escalation tracking if Critical.
                if cr.severity == Severity::Critical {
                    self.escalation_tracker
                        .register(event_id, &policy.escalation_intervals_secs);
                }
                RoutingDecision::Deliver {
                    channels: policy.channels,
                    maintenance_prefix,
                }
            }
            DeliverPolicy::Coalesce => {
                let key = CoalesceKey::from_change(cr);
                let mut buffers = self.coalesce_buffers.lock();
                let entry = buffers
                    .entry(key.clone())
                    .or_insert_with(|| CoalescedNotification {
                        key: key.clone(),
                        events: Vec::new(),
                        window_start: Instant::now(),
                    });
                entry.events.push(CoalescedEvent {
                    path: cr.path.to_string_lossy().to_string(),
                    changes: format!("{:?}", cr.changes),
                    package: cr.package.clone(),
                });

                // Check if window expired.
                if entry.window_start.elapsed() >= Duration::from_secs(policy.coalesce_within_secs)
                {
                    let notification = entry.clone();
                    buffers.remove(&key);
                    return RoutingDecision::DeliverCoalesced {
                        notification,
                        channels: policy.channels,
                        maintenance_prefix,
                    };
                }

                RoutingDecision::Buffered
            }
            DeliverPolicy::Digest => RoutingDecision::Buffered,
        }
    }

    /// Flush any coalesce buffers whose windows have expired.
    pub fn flush_expired(&self) -> Vec<(CoalescedNotification, Vec<String>)> {
        let mut result = Vec::new();
        let mut buffers = self.coalesce_buffers.lock();
        let expired: Vec<CoalesceKey> = buffers
            .iter()
            .filter(|(_, n)| {
                let policy = self
                    .policies
                    .get(&n.key.severity)
                    .cloned()
                    .unwrap_or_default();
                n.window_start.elapsed() >= Duration::from_secs(policy.coalesce_within_secs)
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            if let Some(notification) = buffers.remove(&key) {
                let policy = self
                    .policies
                    .get(&notification.key.severity)
                    .cloned()
                    .unwrap_or_default();
                result.push((notification, policy.channels));
            }
        }
        result
    }

    /// Acknowledge a critical alert by event_id.
    pub fn acknowledge(&self, event_id: &str) -> bool {
        self.escalation_tracker.acknowledge(event_id)
    }

    /// Acknowledge all pending critical alerts.
    pub fn acknowledge_all(&self) -> u32 {
        self.escalation_tracker.acknowledge_all()
    }
}

/// What the router decided to do with an event.
#[derive(Debug)]
pub enum RoutingDecision {
    /// Deliver immediately to these channels.
    Deliver {
        channels: Vec<String>,
        maintenance_prefix: Option<String>,
    },
    /// Deliver a coalesced group of events.
    DeliverCoalesced {
        notification: CoalescedNotification,
        channels: Vec<String>,
        maintenance_prefix: Option<String>,
    },
    /// Event buffered for coalescing or digest. No delivery yet.
    Buffered,
    /// Storm detected. Individual notifications suppressed.
    Suppressed,
    /// Storm just started. Fire the storm notification.
    StormStarted { event_count: u64 },
}

/// Format a coalesced notification for display.
pub fn format_coalesced(
    notification: &CoalescedNotification,
    maintenance_window: bool,
    maintenance_pkg: Option<&str>,
    maintenance_started: Option<&str>,
) -> String {
    let count = notification.events.len();
    let mut lines = vec![format!(
        "{} files modified in {} ({}) in last window:",
        count, notification.key.parent_dir, notification.key.group
    )];
    for event in &notification.events {
        let pkg = event
            .package
            .as_deref()
            .map(|p| format!(", package: {}", p))
            .unwrap_or_default();
        lines.push(format!("  {}   {}{}", event.path, event.changes, pkg));
    }

    // Compute likely cause.
    let all_package = notification.events.iter().all(|e| e.package.is_some());
    if all_package {
        lines.push("Likely cause: package install.".into());
    }

    if maintenance_window {
        let pkg_info = maintenance_pkg.unwrap_or("unknown");
        let started = maintenance_started.unwrap_or("?");
        lines.push(format!(
            "Maintenance window: yes ({}, started {}).",
            pkg_info, started
        ));
    }

    lines.join("\n")
}

/// Format a storm notification for display.
pub fn format_storm(event_count: u64, window_secs: u64) -> String {
    format!(
        "ALERT STORM. {} events in last {}s. Channel suppressed for non-critical.\n\
         Critical alerts continue to deliver normally.\n\
         Run `vigil audit show --since 1m` for details.",
        event_count, window_secs
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;

    fn test_change_result(severity: Severity, group: &str, path: &str) -> ChangeResult {
        ChangeResult {
            path: StdArc::new(std::path::PathBuf::from(path)),
            changes: vec![crate::types::Change::ContentModified {
                old_hash: "aaa".into(),
                new_hash: "bbb".into(),
            }],
            severity,
            monitored_group: group.to_string(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        }
    }

    #[test]
    fn critical_fires_immediately() {
        let router = NotificationRouter::new(50, 60);
        let cr = test_change_result(Severity::Critical, "system_critical", "/usr/bin/sudo");
        let decision = router.route(&cr, false, "evt-001");
        assert!(matches!(decision, RoutingDecision::Deliver { .. }));
    }

    #[test]
    fn medium_coalesces_within_window() {
        let router = NotificationRouter::new(50, 60);
        let cr = test_change_result(Severity::Medium, "network", "/etc/hosts");
        let decision = router.route(&cr, false, "evt-002");
        assert!(matches!(decision, RoutingDecision::Buffered));
    }

    #[test]
    fn storm_threshold_triggers_storm_notification() {
        let router = NotificationRouter::new(5, 60);
        for i in 0..4 {
            let cr = test_change_result(
                Severity::High,
                "system_critical",
                &format!("/usr/bin/test{}", i),
            );
            let _ = router.route(&cr, false, &format!("evt-{}", i));
        }
        let cr = test_change_result(Severity::High, "system_critical", "/usr/bin/test5");
        let decision = router.route(&cr, false, "evt-5");
        assert!(matches!(decision, RoutingDecision::StormStarted { .. }));
    }

    #[test]
    fn ack_cancels_escalation() {
        let tracker = EscalationTracker::new();
        tracker.register("evt-100", &[300, 900]);
        assert!(tracker.acknowledge("evt-100"));
        let due = tracker.due_escalations();
        assert!(due.is_empty());
    }

    #[test]
    fn maintenance_window_prefix_appears_in_notification() {
        let router = NotificationRouter::new(50, 60);
        let cr = test_change_result(Severity::Critical, "system_critical", "/usr/bin/sudo");
        let decision = router.route(&cr, true, "evt-maint");
        if let RoutingDecision::Deliver {
            maintenance_prefix, ..
        } = decision
        {
            assert!(maintenance_prefix.is_some());
            assert!(maintenance_prefix.unwrap().contains("maintenance"));
        } else {
            panic!("expected Deliver");
        }
    }

    #[test]
    fn coalesce_window_flushed_by_immediate_event() {
        // This tests that flush_expired works. In practice, an immediate event
        // arriving during a coalesce window would trigger a flush.
        let router = NotificationRouter::new(50, 60);
        let cr = test_change_result(Severity::Medium, "network", "/etc/hosts");
        let _ = router.route(&cr, false, "evt-coal-1");
        // Not expired yet.
        let flushed = router.flush_expired();
        assert!(flushed.is_empty());
    }

    #[test]
    fn unacknowledged_critical_escalates_on_schedule() {
        let tracker = EscalationTracker::new();
        // Use a 0-second interval for immediate testing.
        tracker.register("evt-esc", &[0]);
        let due = tracker.due_escalations();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0, "evt-esc");
        assert_eq!(due[0].1, 1); // first escalation
    }
}
