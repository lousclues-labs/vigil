use crate::types::Alert;

/// Log an alert to the system journal (via log crate/syslog).
pub fn log_alert(alert: &Alert) {
    let path = alert.file.path.display();
    let severity = &alert.severity;
    let change = &alert.change_type;

    match alert.severity {
        crate::types::Severity::Critical => {
            log::error!(
                "[VIGIL] CRITICAL: {} — {} ({})",
                change,
                path,
                alert.event_id
            );
        }
        crate::types::Severity::High => {
            log::warn!("[VIGIL] HIGH: {} — {} ({})", change, path, alert.event_id);
        }
        crate::types::Severity::Medium => {
            log::warn!("[VIGIL] MEDIUM: {} — {} ({})", change, path, alert.event_id);
        }
        crate::types::Severity::Low => {
            log::info!("[VIGIL] LOW: {} — {} ({})", change, path, alert.event_id);
        }
    }

    // Log full details at debug level
    log::debug!(
        "[VIGIL] Detail: severity={} change={} path={} old_hash={:?} new_hash={:?} package={:?} group={}",
        severity, change, path,
        alert.file.baseline_hash,
        alert.file.current_hash,
        alert.file.package,
        alert.context.monitored_group,
    );
}
