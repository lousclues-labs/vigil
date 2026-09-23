//! D-Bus desktop notification sink with per-severity rate limiting.

use std::path::PathBuf;

use std::process::Command;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::alert::AlertSink;
use crate::error::{Result, VigilError};
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

/// Whether a desktop notification channel is plausibly reachable.
///
/// A root daemon started by systemd normally has no session bus and no
/// display, so `notify-send` cannot deliver anything. That is a *structural*
/// absence, not a failure: the sink is not broken, it has nowhere to send.
///
/// The distinction matters because the sink runner degrades the daemon after
/// `sink_failure_threshold` consecutive sink errors. Treating an absent
/// channel as an error would put every headless deployment into
/// `AlertSinkFailing` -- the desktop sink is enabled by default -- which
/// devalues a state that should mean something is genuinely wrong. Treating a
/// *failing* channel as success is the defect this replaced. So: absent
/// channels are reported once and not registered; present channels that fail
/// are real errors.
pub fn notification_channel_available() -> bool {
    ["DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
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
            "Vigil Baseline -- {} {}",
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

        body.push_str(&format!("\nvigil why {}", alert.file.path.display()));

        // `.output()` rather than `.status()`: a notify-send that *runs* and
        // exits non-zero is the case that matters -- the notification was not
        // shown. Returning Ok there made the desktop channel the one sink that
        // could never report itself broken, so a machine that had delivered
        // zero notifications since boot still looked healthy: `SinkRunner`
        // keys its failure accounting, and the `AlertSinkFailing` degraded
        // state, entirely off `Err`.
        //
        // Structurally undeliverable channels never reach here -- the sink is
        // not registered when no bus or display exists -- so a failure at this
        // point means a channel that should work did not.
        let output = Command::new(notify_send_binary())
            .arg("--app-name=Vigil Baseline")
            .arg(format!("--urgency={}", urgency))
            .arg(&title)
            .arg(&body)
            .output();

        classify_notify_output(output)
    }

    fn min_severity(&self) -> Severity {
        Severity::Medium
    }
}

/// Decide whether a `notify-send` invocation actually delivered.
///
/// Split out from `dispatch` so the non-zero-exit path is reachable in a test
/// without a session bus: the defect this guards was a silent `Ok(())` on
/// every failed delivery.
fn classify_notify_output(output: std::io::Result<std::process::Output>) -> Result<()> {
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let detail = String::from_utf8_lossy(&out.stderr);
            let detail = detail.lines().next().unwrap_or("no detail").trim();
            tracing::warn!(
                status = ?out.status.code(),
                detail = %detail,
                "desktop notification was not shown"
            );
            Err(VigilError::Alert(format!(
                "notify-send exited {}: {}",
                out.status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into()),
                detail
            )))
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not run notify-send");
            Err(VigilError::Alert(format!("notify-send failed to run: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    fn output(code: i32, stderr: &str) -> std::io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    #[test]
    fn successful_delivery_is_ok() {
        assert!(classify_notify_output(output(0, "")).is_ok());
    }

    #[test]
    fn nonzero_exit_is_an_error_not_a_silent_ok() {
        // The sink runner's failure accounting and the AlertSinkFailing
        // degraded state key entirely off Err. Returning Ok here made a
        // desktop channel that delivered nothing look permanently healthy.
        let err = classify_notify_output(output(1, "cannot autolaunch d-bus"))
            .expect_err("failed delivery reported as success");
        let msg = err.to_string();
        assert!(msg.contains('1'), "exit status not surfaced: {msg}");
        assert!(
            msg.contains("cannot autolaunch"),
            "stderr detail not surfaced: {msg}"
        );
    }

    #[test]
    fn spawn_failure_is_an_error() {
        let err = classify_notify_output(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file",
        )));
        assert!(err.is_err());
    }

    #[test]
    fn missing_stderr_still_reports_the_failure() {
        let err =
            classify_notify_output(output(3, "")).expect_err("failed delivery reported as success");
        assert!(err.to_string().contains("no detail"));
    }
}
