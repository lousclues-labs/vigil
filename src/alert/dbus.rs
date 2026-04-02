use crate::error::{Result, VigilError};
use crate::types::Alert;

/// D-Bus desktop notification sender.
pub struct DbusNotifier {
    // We use the /usr/bin/notify-send fallback approach for simplicity,
    // since zbus blocking mode can be complex in a threaded daemon.
    // A future version can use zbus directly.
}

impl DbusNotifier {
    pub fn new() -> Result<Self> {
        // Verify notify-send is available
        if std::process::Command::new("notify-send")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return Err(VigilError::DBus(
                "notify-send not available".into(),
            ));
        }
        Ok(Self {})
    }

    /// Send a desktop notification for the given alert.
    pub fn notify(&self, alert: &Alert) {
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
            format!("\nPackage: {} (update: {})", pkg, if alert.file.package_update { "yes" } else { "no" })
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

        let result = std::process::Command::new("notify-send")
            .args([
                "--urgency", urgency,
                "--app-name", "Vigil",
                "--icon", "dialog-warning",
                &title,
                &body,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        if let Err(e) = result {
            log::warn!("Failed to send D-Bus notification: {}", e);
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
