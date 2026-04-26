// tests/control_status_reports_userspace_drops.rs
//
// Regression test for VIGIL-VULN-075: the daemon state and metrics correctly
// surface user-space event drop information for operator visibility.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use vigil::metrics::Metrics;
use vigil::types::DegradedReason;

/// When user-space drops trigger a compensating scan, the
/// userspace_drop_scans_triggered metric must be visible in the
/// MetricsSnapshot so operators see it via `vigil status` JSON.
#[test]
fn metrics_snapshot_includes_userspace_drop_scans_triggered() {
    let metrics = Arc::new(Metrics::new());
    metrics
        .userspace_drop_scans_triggered
        .fetch_add(3, Ordering::Relaxed);
    metrics.events_dropped.fetch_add(200, Ordering::Relaxed);

    let snap = metrics.snapshot();
    assert_eq!(snap.userspace_drop_scans_triggered, 3);
    assert_eq!(snap.events_dropped, 200);

    // Verify it appears in the status view (JSON)
    let view = snap.status_view();
    assert_eq!(
        view.get("userspace_drop_scans_triggered")
            .and_then(|v| v.as_u64()),
        Some(3),
        "userspace_drop_scans_triggered must be visible in status_view"
    );
}

/// The Prometheus output must include the new metric.
#[test]
fn prometheus_output_includes_userspace_drop_scans() {
    let metrics = Metrics::new();
    metrics
        .userspace_drop_scans_triggered
        .fetch_add(5, Ordering::Relaxed);

    let prom = metrics.snapshot().to_prometheus();
    assert!(
        prom.contains("vigil_userspace_drop_scans_triggered_total 5"),
        "Prometheus output must include userspace_drop_scans_triggered_total"
    );
}

/// DegradedReason::UserspaceEventDrops Display format is operator-readable.
#[test]
fn userspace_event_drops_reason_display() {
    let reason = DegradedReason::UserspaceEventDrops {
        dropped: 150,
        window_secs: 60,
    };
    let display = reason.to_string();
    assert!(
        display.contains("userspace_event_drops"),
        "display should contain 'userspace_event_drops'"
    );
    assert!(display.contains("150"), "display should contain drop count");
    assert!(
        display.contains("60"),
        "display should contain window seconds"
    );
}
