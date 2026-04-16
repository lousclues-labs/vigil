use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::Sender;

use crate::alert::AlertPayload;
use crate::metrics::Metrics;
use crate::types::ChangeResult;
use crate::wal::{DetectionRecord, DetectionSource, DetectionWal};

/// Dispatch a detection through WAL if available, falling back to the alert channel.
///
/// Returns `true` if the alert channel returned a send error (disconnected),
/// signalling the caller should shut down.
pub fn dispatch_detection(
    change: ChangeResult,
    wal: &Option<Arc<DetectionWal>>,
    alert_tx: &Sender<AlertPayload>,
    metrics: &Metrics,
    maintenance_active: &AtomicBool,
    source: DetectionSource,
) -> bool {
    let maintenance_window = maintenance_active.load(Ordering::Acquire);

    if let Some(ref wal) = wal {
        let record = DetectionRecord::from_change_result(&change, maintenance_window, source);
        match wal.append(&record) {
            Ok(_) => {
                metrics
                    .detections_wal_appends
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
            Err(e) => {
                tracing::error!(error = %e, "WAL append failed; falling back to alert channel");
                metrics
                    .detections_wal_full
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // No WAL or WAL append failed — send directly to alert channel.
    // Log at error level if the channel is disconnected (detection would be lost).
    if let Err(e) = alert_tx.send(AlertPayload {
        change,
        maintenance_window,
    }) {
        tracing::error!(
            path = %e.0.change.path.display(),
            "alert channel disconnected — detection lost"
        );
        return true;
    }

    false
}
