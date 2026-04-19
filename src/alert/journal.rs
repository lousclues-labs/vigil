//! Systemd journal alert sink via the `tracing` crate.

use crate::alert::AlertSink;
use crate::error::Result;
use crate::types::Alert;

pub struct JournalSink;

impl AlertSink for JournalSink {
    fn name(&self) -> &str {
        "journal"
    }

    fn dispatch(&self, alert: &Alert) -> Result<()> {
        tracing::info!(
            path = %alert.file.path.display(),
            severity = %alert.severity,
            group = %alert.context.monitored_group,
            event_id = %alert.event_id,
            "file integrity violation detected"
        );
        Ok(())
    }
}
