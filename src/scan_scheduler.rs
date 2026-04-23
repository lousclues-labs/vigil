//! Cron-scheduled and on-demand scan orchestration.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::Sender;

use crate::alert::AlertPayload;
use crate::config::Config;
use crate::control::{ScanRequest, ScanResponse};
use crate::detection;
use crate::metrics::Metrics;
use crate::wal::{DetectionSource, DetectionWal};

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    config: Arc<ArcSwap<Config>>,
    shutdown: Arc<AtomicBool>,
    alert_tx: Sender<AlertPayload>,
    metrics: Arc<Metrics>,
    shutdown_rx: crossbeam_channel::Receiver<()>,
    scan_trigger_rx: crossbeam_channel::Receiver<ScanRequest>,
    baseline_conn: rusqlite::Connection,
    wal: Option<Arc<DetectionWal>>,
    maintenance_active: Arc<AtomicBool>,
    baseline_generation: Arc<AtomicU64>,
) -> crate::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vigil-scan-scheduler".into())
        .spawn(move || {
            let mut conn = baseline_conn;
            let mut local_generation = baseline_generation.load(Ordering::Acquire);
            while !shutdown.load(Ordering::Acquire) {
                // Reopen connection if baseline was refreshed since last check.
                let current_gen = baseline_generation.load(Ordering::Acquire);
                if current_gen != local_generation {
                    let cfg = config.load();
                    match crate::db::open_baseline_db_at_path(&cfg.daemon.db_path) {
                        Ok(new_conn) => {
                            conn = new_conn;
                            local_generation = current_gen;
                            tracing::info!(
                                generation = current_gen,
                                "scan scheduler reopened baseline after refresh"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "scan scheduler failed to reopen baseline; using stale connection"
                            );
                        }
                    }
                }

                // Service on-demand scan requests first
                while let Ok(request) = scan_trigger_rx.try_recv() {
                    let cfg = config.load();
                    let response =
                        match crate::scanner::run_scan(&conn, &cfg, request.mode) {
                            Ok(scan_result) => {
                                for change in scan_result.changes {
                                    detection::dispatch_detection(
                                        change,
                                        &wal,
                                        &alert_tx,
                                        &metrics,
                                        &maintenance_active,
                                        DetectionSource::OnDemandScan,
                                    );
                                }
                                metrics.record_scan(
                                    scan_result.changes_found,
                                    scan_result.duration_ms,
                                    scan_result.total_checked,
                                );

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
                    if request.response_tx.send(response).is_err() {
                        tracing::warn!(
                            "on-demand scan response not delivered; requester disconnected"
                        );
                    }
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

                    // Reopen if baseline was refreshed since the last generation check.
                    let current_gen = baseline_generation.load(Ordering::Acquire);
                    if current_gen != local_generation {
                        match crate::db::open_baseline_db_at_path(&cfg.daemon.db_path) {
                            Ok(new_conn) => {
                                conn = new_conn;
                                local_generation = current_gen;
                                tracing::info!(
                                    generation = current_gen,
                                    "scan scheduler reopened baseline before scheduled scan"
                                );
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "failed to reopen baseline for scheduled scan");
                            }
                        }
                    }

                    match crate::scanner::run_scan(&conn, &cfg, cfg.scanner.scheduled_mode)
                    {
                        Ok(scan_result) => {
                            for change in scan_result.changes {
                                detection::dispatch_detection(
                                    change,
                                    &wal,
                                    &alert_tx,
                                    &metrics,
                                    &maintenance_active,
                                    DetectionSource::ScheduledScan,
                                );
                            }
                            metrics.record_scan(
                                scan_result.changes_found,
                                scan_result.duration_ms,
                                scan_result.total_checked,
                            );

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
