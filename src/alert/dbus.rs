use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::alert::AlertSink;
use crate::error::Result;
use crate::types::{Alert, Severity};

/// Resolve the absolute path to `notify-send` once at startup. The daemon
/// runs as root, so we must avoid PATH-injection.
fn notify_send_binary() -> PathBuf {
    static CACHED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    CACHED
        .get_or_init(|| {
            for cand in ["/usr/bin/notify-send", "/bin/notify-send"] {
                let p = PathBuf::from(cand);
                if p.is_file() {
                    return p;
                }
            }
            PathBuf::from("notify-send")
        })
        .clone()
}

struct NotifyRate {
    count: u32,
    start: Instant,
}

pub struct DbusSink {
    limit: u32,
    window: Duration,
    state: Mutex<NotifyRate>,
}

impl DbusSink {
    pub fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            limit,
            window: Duration::from_secs(window_secs.max(1)),
            state: Mutex::new(NotifyRate {
                count: 0,
                start: Instant::now(),
            }),
        }
    }

    fn allow(&self) -> bool {
        let mut s = self.state.lock();
        if s.start.elapsed() > self.window {
            s.count = 0;
            s.start = Instant::now();
        }
        if s.count >= self.limit {
            return false;
        }
        s.count += 1;
        true
    }
}

impl AlertSink for DbusSink {
    fn name(&self) -> &str {
        "dbus"
    }

    fn dispatch(&self, alert: &Alert) -> Result<()> {
        if !self.allow() {
            return Ok(());
        }

        let urgency = match alert.severity {
            Severity::Critical | Severity::High => "critical",
            Severity::Medium => "normal",
            Severity::Low => "low",
        };

        let title = format!(
            "Vigil Baseline — {} {}",
            alert.severity.to_string().to_uppercase(),
            alert.change_type,
        );

        let mut body = format!("{}", alert.file.path.display());

        if let Some(ref pkg) = alert.file.package {
            body.push_str(&format!(" ({})", pkg));
        }

        if let Some(ref exe) = alert.file.responsible_exe {
            body.push_str(&format!("\nBy: {}", exe));
        }

        if alert.context.maintenance_window {
            body.push_str("\n[during maintenance window]");
        }

        body.push_str("\nRun 'vigil audit show --last 5' for details.");

        let status = Command::new(notify_send_binary())
            .arg("--app-name=Vigil Baseline")
            .arg(format!("--urgency={}", urgency))
            .arg(&title)
            .arg(&body)
            .status();

        if let Err(e) = status {
            tracing::debug!(error = %e, "desktop notification failed");
        }

        Ok(())
    }

    fn min_severity(&self) -> Severity {
        Severity::Medium
    }
}
