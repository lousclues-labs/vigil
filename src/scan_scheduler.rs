use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::Sender;

use crate::alert::AlertPayload;
use crate::config::Config;
use crate::control::{ScanRequest, ScanResponse};
use crate::metrics::Metrics;

pub fn spawn(
    config: Arc<ArcSwap<Config>>,
    shutdown: Arc<AtomicBool>,
    alert_tx: Sender<AlertPayload>,
    metrics: Arc<Metrics>,
    shutdown_rx: crossbeam_channel::Receiver<()>,
    scan_trigger_rx: crossbeam_channel::Receiver<ScanRequest>,
    baseline_conn: rusqlite::Connection,
) -> crate::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vigil-scan-scheduler".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                // Service on-demand scan requests first
                while let Ok(request) = scan_trigger_rx.try_recv() {
                    let cfg = config.load();
                    let response =
                        match crate::scanner::run_scan(&baseline_conn, &cfg, request.mode) {
                            Ok(scan_result) => {
                                for change in scan_result.changes {
                                    let _ = alert_tx.send(AlertPayload {
                                        change,
                                        maintenance_window: false,
                                    });
                                }
                                metrics
                                    .changes_detected
                                    .fetch_add(scan_result.changes_found, Ordering::Relaxed);
                                metrics
                                    .scan_duration_ms
                                    .store(scan_result.duration_ms, Ordering::Relaxed);
                                metrics
                                    .last_scan_total
                                    .store(scan_result.total_checked, Ordering::Relaxed);

                                tracing::info!(
                                    checked = scan_result.total_checked,
                                    changes = scan_result.changes_found,
                                    errors = scan_result.errors,
                                    "on-demand scan completed"
                                );

                                ScanResponse {
                                    ok: true,
                                    total_checked: scan_result.total_checked,
                                    changes_found: scan_result.changes_found,
                                    errors: scan_result.errors,
                                    duration_ms: scan_result.duration_ms,
                                    error: None,
                                }
                            }
                            Err(e) => ScanResponse {
                                ok: false,
                                total_checked: 0,
                                changes_found: 0,
                                errors: 0,
                                duration_ms: 0,
                                error: Some(format!("{}", e)),
                            },
                        };
                    let _ = request.response_tx.send(response);
                }

                let cfg = config.load();
                let schedule = match croner::Cron::new(&cfg.scanner.schedule).parse() {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            schedule = %cfg.scanner.schedule,
                            error = %e,
                            "invalid cron schedule; retrying in 60s"
                        );
                        if shutdown_rx.recv_timeout(Duration::from_secs(60)).is_ok() {
                            return;
                        }
                        continue;
                    }
                };

                let now = chrono::Utc::now();
                let next = schedule.find_next_occurrence(&now, false);

                if let Ok(next_time) = next {
                    let wait = (next_time.timestamp() - now.timestamp()).max(0) as u64;

                    // Block until shutdown or the wait expires
                    if shutdown_rx.recv_timeout(Duration::from_secs(wait)).is_ok() {
                        return;
                    }

                    if shutdown.load(Ordering::Acquire) {
                        return;
                    }

                    // Use startup baseline connection — never re-open by path
                    match crate::scanner::run_scan(&baseline_conn, &cfg, cfg.scanner.scheduled_mode)
                    {
                        Ok(scan_result) => {
                            for change in scan_result.changes {
                                let _ = alert_tx.send(AlertPayload {
                                    change,
                                    maintenance_window: false,
                                });
                            }
                            metrics
                                .changes_detected
                                .fetch_add(scan_result.changes_found, Ordering::Relaxed);
                            metrics
                                .scan_duration_ms
                                .store(scan_result.duration_ms, Ordering::Relaxed);
                            metrics
                                .last_scan_total
                                .store(scan_result.total_checked, Ordering::Relaxed);

                            tracing::info!(
                                checked = scan_result.total_checked,
                                changes = scan_result.changes_found,
                                errors = scan_result.errors,
                                "scheduled scan completed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "scheduled scan failed");
                        }
                    }
                } else if shutdown_rx.recv_timeout(Duration::from_secs(60)).is_ok() {
                    return;
                }
            }
        })
        .map_err(|e| {
            crate::VigilError::Daemon(format!("cannot spawn scan scheduler thread: {}", e))
        })
}
