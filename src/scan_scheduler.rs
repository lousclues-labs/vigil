use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::Sender;

use crate::alert::AlertPayload;
use crate::config::Config;
use crate::metrics::Metrics;

pub fn spawn(
    config: Arc<ArcSwap<Config>>,
    shutdown: Arc<AtomicBool>,
    alert_tx: Sender<AlertPayload>,
    metrics: Arc<Metrics>,
) -> crate::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vigil-scan-scheduler".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                let cfg = config.load();
                let schedule = match croner::Cron::new(&cfg.scanner.schedule).parse() {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            schedule = %cfg.scanner.schedule,
                            error = %e,
                            "invalid cron schedule; retrying in 60s"
                        );
                        std::thread::sleep(Duration::from_secs(60));
                        continue;
                    }
                };

                let now = chrono::Utc::now();
                let next = schedule.find_next_occurrence(&now, false);

                if let Ok(next_time) = next {
                    let wait = (next_time.timestamp() - now.timestamp()).max(0) as u64;
                    for _ in 0..wait {
                        if shutdown.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }

                    if shutdown.load(Ordering::Acquire) {
                        return;
                    }

                    match crate::db::open_baseline_db(&cfg) {
                        Ok(scan_conn) => {
                            match crate::scanner::run_scan(&scan_conn, &cfg, cfg.scanner.scheduled_mode) {
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
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "cannot open baseline DB for scheduled scan");
                        }
                    }
                } else {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
        })
        .map_err(|e| crate::VigilError::Daemon(format!("cannot spawn scan scheduler thread: {}", e)))
}
