//! Journald query helpers.

use std::process::Command;

/// Result of querying journald for a hook trigger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookTriggerResult {
    /// journalctl returned no entries for this tag.
    NeverTriggered,
    /// Last entry indicates success; timestamp attached.
    Success(String),
    /// Last entry indicates failure; timestamp and syslog tag attached.
    Failure(String, String),
    /// journalctl unavailable or unparseable.
    Unknown,
}

/// Query journald for the last hook trigger entry and return structured result.
pub fn hook_last_trigger_parsed(syslog_tag: &str) -> HookTriggerResult {
    let output = Command::new("journalctl")
        .args([
            "-t",
            syslog_tag,
            "--output=short-iso",
            "-n",
            "1",
            "--no-pager",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let line = text.lines().last().unwrap_or("").trim();
            if line.is_empty()
                || line.starts_with("-- No entries")
                || line.starts_with("-- Journal")
            {
                HookTriggerResult::NeverTriggered
            } else {
                let ts = line.split_whitespace().next().unwrap_or("?").to_string();
                if line.contains("failed") || line.contains("error") {
                    HookTriggerResult::Failure(ts, syslog_tag.to_string())
                } else {
                    HookTriggerResult::Success(ts)
                }
            }
        }
        _ => HookTriggerResult::Unknown,
    }
}
