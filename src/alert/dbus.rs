use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use parking_lot::Mutex;

use crate::error::{Result, VigilError};
use crate::types::Alert;

/// D-Bus desktop notification sender with per-window rate limiting.
// TODO: Native D-Bus integration via the `zbus` crate would eliminate the
// process spawning entirely and should be done in a future iteration.
pub struct DbusNotifier {
    reaper_tx: crossbeam_channel::Sender<std::process::Child>,
    /// In-flight notify-send process count (capped at MAX_INFLIGHT).
    inflight: std::sync::Arc<AtomicU32>,
    /// Rate limiter state.
    rate_state: Mutex<NotificationRateState>,
    /// Max notifications per window.
    rate_limit: u32,
    /// Window duration in seconds.
    rate_window_secs: u64,
}

struct NotificationRateState {
    count: u32,
    window_start: Instant,
    /// Buffered changes within the rate window for batching.
    pending: Vec<PendingNotification>,
}

struct PendingNotification {
    path: String,
    group: String,
}

const MAX_INFLIGHT: u32 = 10;

impl DbusNotifier {
    pub fn new() -> Result<Self> {
        Self::with_rate_config(5, 10)
    }

    pub fn with_rate_config(rate_limit: u32, rate_window_secs: u64) -> Result<Self> {
        // Verify notify-send is available
        if std::process::Command::new("notify-send")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return Err(VigilError::DBus("notify-send not available".into()));
        }

        let (reaper_tx, reaper_rx) = crossbeam_channel::unbounded::<std::process::Child>();
        let inflight = std::sync::Arc::new(AtomicU32::new(0));
        let inflight_clone = inflight.clone();
        std::thread::Builder::new()
            .name("vigil-reaper".into())
            .spawn(move || {
                for mut child in reaper_rx {
                    let _ = child.wait();
                    inflight_clone.fetch_sub(1, Ordering::Relaxed);
                }
            })
            .map_err(|e| VigilError::DBus(format!("cannot spawn reaper thread: {}", e)))?;

        Ok(Self {
            reaper_tx,
            inflight,
            rate_state: Mutex::new(NotificationRateState {
                count: 0,
                window_start: Instant::now(),
                pending: Vec::new(),
            }),
            rate_limit,
            rate_window_secs,
        })
    }

    /// Send a desktop notification for the given alert, with rate limiting.
    /// When rate limited, changes are batched into summary notifications.
    pub fn notify(&self, alert: &Alert) {
        let mut state = self.rate_state.lock();

        // Reset window if expired
        if state.window_start.elapsed() > std::time::Duration::from_secs(self.rate_window_secs) {
            // If there are pending items from the last window, flush a summary
            if !state.pending.is_empty() {
                let summary = self.build_batch_summary(&state.pending);
                state.pending.clear();
                state.count = 1; // The summary counts as one notification
                state.window_start = Instant::now();
                drop(state);
                self.spawn_notification("Vigil — Multiple Changes", &summary, "normal");
                return;
            }
            state.count = 0;
            state.window_start = Instant::now();
        }

        if state.count < self.rate_limit {
            state.count += 1;
            drop(state);
            // Send individual notification
            let urgency = match alert.severity {
                crate::types::Severity::Critical => "critical",
                crate::types::Severity::High => "critical",
                crate::types::Severity::Medium => "normal",
                crate::types::Severity::Low => "low",
            };

            let title = format!(
                "Vigil — File {}",
                capitalize(&alert.change_type.to_string())
            );

            let hash_info = match (&alert.file.baseline_hash, &alert.file.current_hash) {
                (Some(old), Some(new)) => format!(
                    "Hash: {}… → {}…",
                    &old[..6.min(old.len())],
                    &new[..6.min(new.len())]
                ),
                (Some(old), None) => format!("Hash: {}… (deleted)", &old[..6.min(old.len())]),
                (None, Some(new)) => format!("Hash: {}… (new)", &new[..6.min(new.len())]),
                (None, None) => String::new(),
            };

            let pkg_info = if let Some(ref pkg) = alert.file.package {
                format!(
                    "\nPackage: {} (update: {})",
                    pkg,
                    if alert.file.package_update {
                        "yes"
                    } else {
                        "no"
                    }
                )
            } else {
                String::new()
            };

            let body = format!(
                "{} has been {}.\n\nSeverity: {}\n{}{}",
                alert.file.path.display(),
                alert.change_type,
                alert.severity.to_string().to_uppercase(),
                hash_info,
                pkg_info,
            );

            self.spawn_notification(&title, &body, urgency);
        } else {
            // Rate limited — buffer for batch notification
            state.pending.push(PendingNotification {
                path: alert.file.path.display().to_string(),
                group: alert.context.monitored_group.clone(),
            });
        }
    }

    fn build_batch_summary(&self, pending: &[PendingNotification]) -> String {
        let count = pending.len();
        let group = pending
            .first()
            .map(|p| p.group.as_str())
            .unwrap_or("unknown");
        let paths_summary: String = if count <= 3 {
            pending
                .iter()
                .map(|p| p.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            let first_three: Vec<&str> = pending.iter().take(3).map(|p| p.path.as_str()).collect();
            format!("{} ... and {} more", first_three.join(", "), count - 3)
        };
        format!(
            "Vigil: {} files changed in {} ({})",
            count, group, paths_summary
        )
    }

    fn spawn_notification(&self, title: &str, body: &str, urgency: &str) {
        // Cap inflight processes
        if self.inflight.load(Ordering::Relaxed) >= MAX_INFLIGHT {
            log::debug!("Too many inflight notify-send processes, dropping notification");
            return;
        }

        let result = std::process::Command::new("notify-send")
            .args([
                "--urgency",
                urgency,
                "--app-name",
                "Vigil",
                "--icon",
                "dialog-warning",
                title,
                body,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        match result {
            Ok(child) => {
                self.inflight.fetch_add(1, Ordering::Relaxed);
                let _ = self.reaper_tx.send(child);
            }
            Err(e) => {
                log::warn!("Failed to send D-Bus notification: {}", e);
            }
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
