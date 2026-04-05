use std::process::Command;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::alert::AlertSink;
use crate::error::Result;
use crate::types::{Alert, Severity};

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

        let title = format!("Vigil {}", alert.severity.to_string().to_uppercase());
        let body = format!("{} ({})", alert.file.path.display(), alert.change_type);

        let status = Command::new("notify-send").arg(title).arg(body).status();

        if let Err(e) = status {
            tracing::debug!(error = %e, "notify-send failed");
        }

        Ok(())
    }

    fn min_severity(&self) -> Severity {
        Severity::Medium
    }
}
