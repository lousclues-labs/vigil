//! Journald query helpers.
//!
//! # Why this reads syslog priority rather than message text
//!
//! The package-manager hooks classify their own outcomes. `hooks/apt/*.sh`,
//! `hooks/pacman/*.hook` and `hooks/dnf/vigil.py` all log failures with an
//! explicit priority (`logger -p daemon.err`) and successes without one. That
//! priority is the hook's own verdict, and it is authoritative.
//!
//! This module previously ignored it and guessed from the message body
//! instead, asking whether the text contained "failed" or "error". The hooks'
//! most serious message does not:
//!
//! > vigild is running but /usr/bin/vigil is missing; baseline NOT refreshed
//! > after this transaction. Vigil now reports inconsistent state.
//!
//! That is logged at `daemon.err`, contains neither word, and was therefore
//! reported by `vigil doctor` as "last trigger ok" — the tool answering "is
//! everything fine?" with yes at exactly the moment it was not. Reading the
//! priority removes the guess.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// Time budget for a journalctl invocation.
///
/// journald can block on a corrupt or very large journal. Doctor calls this
/// once per package-manager hook, and a hung probe would hang the whole
/// health report.
const JOURNALCTL_TIMEOUT: Duration = Duration::from_secs(5);

/// Syslog priorities at or below this are failures: emerg, alert, crit, err.
const PRIORITY_ERR: u8 = 3;

/// Resolve the journalctl binary, preferring absolute paths.
///
/// A PATH lookup would let anything earlier on `PATH` answer a question Vigil
/// asks about its own health.
pub fn journalctl_binary() -> PathBuf {
    for candidate in ["/usr/bin/journalctl", "/bin/journalctl"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }
    // Last resort. Reaching here means journald is not installed where it
    // normally lives, and the caller handles the failure.
    PathBuf::from("journalctl")
}

/// Result of querying journald for a hook trigger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookTriggerResult {
    /// journalctl returned no entries for this tag.
    NeverTriggered,
    /// Last entry was logged at a normal priority; timestamp attached.
    Success(String),
    /// Last entry was logged at error priority or worse; timestamp and syslog
    /// tag attached.
    Failure(String, String),
    /// journalctl unavailable, timed out, or output unparseable.
    ///
    /// Never collapsed into `Success`: not knowing is not the same as knowing
    /// it went well.
    Unknown,
}

/// Run journalctl with a timeout, returning stdout on success.
fn run_journalctl(args: &[&str]) -> Option<String> {
    let mut child = Command::new(journalctl_binary())
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = child.wait_with_output().ok()?;
                if !status.success() {
                    return None;
                }
                return Some(String::from_utf8_lossy(&out.stdout).into_owned());
            }
            Ok(None) => {
                if start.elapsed() > JOURNALCTL_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::warn!(
                        "journalctl exceeded {:?}; hook status unknown",
                        JOURNALCTL_TIMEOUT
                    );
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

/// Query journald for the last hook trigger entry and return a structured
/// result.
///
/// Uses `--output=json` so the entry's own `PRIORITY` decides the verdict
/// rather than a substring match on operator-facing prose.
pub fn hook_last_trigger_parsed(syslog_tag: &str) -> HookTriggerResult {
    let Some(stdout) =
        run_journalctl(&["-t", syslog_tag, "--output=json", "-n", "1", "--no-pager"])
    else {
        return HookTriggerResult::Unknown;
    };

    parse_hook_entry_checked(&stdout, syslog_tag)
}

/// Classify an entry, resolving the ambiguity of empty output.
fn parse_hook_entry_checked(stdout: &str, syslog_tag: &str) -> HookTriggerResult {
    let result = parse_hook_entry(stdout, syslog_tag);

    // Empty output is ambiguous. journalctl prints nothing and exits 0 both
    // when the tag was never logged *and* when it cannot read the journal at
    // all -- the normal case for an operator outside the `adm` and
    // `systemd-journal` groups, and after a reboot under `Storage=volatile`.
    // Reporting "never triggered" there turns "we could not look" into a clean
    // result, which is the one thing this module must not do.
    //
    // Resolved only in the ambiguous case, so the common path costs nothing.
    if result == HookTriggerResult::NeverTriggered && !journal_is_readable() {
        return HookTriggerResult::Unknown;
    }

    result
}

/// Whether this process can read any journal entry at all.
///
/// A tag-less single-entry query: a readable journal always has something in
/// it, and an unreadable one yields empty output with exit status 0.
fn journal_is_readable() -> bool {
    run_journalctl(&["-n", "1", "--output=json", "--no-pager"])
        .is_some_and(|out| out.lines().any(|l| l.trim_start().starts_with('{')))
}

/// Classify a single journalctl JSON entry.
///
/// Split out from the invocation so it can be tested against real journald
/// output without a journal.
pub fn parse_hook_entry(stdout: &str, syslog_tag: &str) -> HookTriggerResult {
    let line = stdout.lines().map(str::trim).find(|l| !l.is_empty());
    let Some(line) = line else {
        // journalctl prints nothing at all for a tag it has never seen.
        return HookTriggerResult::NeverTriggered;
    };
    // `-- No entries --` is the short-format sentinel; json mode emits nothing,
    // but tolerate both so a format change cannot be read as a failure.
    if line.starts_with("-- No entries") || line.starts_with("-- Journal") {
        return HookTriggerResult::NeverTriggered;
    }

    let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
        return HookTriggerResult::Unknown;
    };

    let timestamp = entry_timestamp(&entry).unwrap_or_else(|| "?".to_string());

    // PRIORITY is a decimal string in journald's JSON output.
    let priority = entry
        .get("PRIORITY")
        .and_then(|p| p.as_str())
        .and_then(|p| p.parse::<u8>().ok());

    match priority {
        Some(p) if p <= PRIORITY_ERR => {
            HookTriggerResult::Failure(timestamp, syslog_tag.to_string())
        }
        Some(_) => HookTriggerResult::Success(timestamp),
        // An entry exists but carries no readable priority. The hook's verdict
        // is unavailable, which is not the same as a passing one.
        None => HookTriggerResult::Unknown,
    }
}

/// Format an entry's `__REALTIME_TIMESTAMP` (microseconds since the epoch) as
/// a local ISO-8601 timestamp, matching what operators saw previously.
fn entry_timestamp(entry: &serde_json::Value) -> Option<String> {
    let raw = entry.get("__REALTIME_TIMESTAMP")?.as_str()?;
    let micros: i64 = raw.parse().ok()?;
    let dt = chrono::DateTime::from_timestamp_micros(micros)?;
    Some(
        dt.with_timezone(&chrono::Local)
            .format("%Y-%m-%dT%H:%M:%S%z")
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped after real `journalctl -t <tag> --output=json -n 1` output.
    fn entry(priority: &str, message: &str) -> String {
        format!(
            r#"{{"__REALTIME_TIMESTAMP":"1790096400000000","PRIORITY":"{priority}","SYSLOG_IDENTIFIER":"vigil-apt","MESSAGE":"{message}"}}"#
        )
    }

    /// The message that exposed the old heuristic: logged at daemon.err,
    /// containing neither "failed" nor "error".
    #[test]
    fn an_err_priority_entry_is_a_failure_whatever_the_wording() {
        let stdout = entry(
            "3",
            "vigild is running but /usr/bin/vigil is missing; baseline NOT refreshed \
             after this transaction. Vigil now reports inconsistent state.",
        );
        let result = parse_hook_entry(&stdout, "vigil-apt");
        assert!(
            matches!(result, HookTriggerResult::Failure(_, _)),
            "an entry logged at daemon.err is a failure regardless of wording, got {result:?}"
        );
    }

    #[test]
    fn informational_entries_are_successes() {
        let stdout = entry("6", "baseline refreshed after transaction");
        assert!(matches!(
            parse_hook_entry(&stdout, "vigil-apt"),
            HookTriggerResult::Success(_)
        ));
    }

    /// The inverse of the old bug: a routine message mentioning a path that
    /// happens to contain "error" must not be reported as a failure.
    #[test]
    fn success_wording_containing_error_is_not_a_failure() {
        let stdout = entry("6", "refreshed; /var/log/myapp-error.log unchanged");
        assert!(
            matches!(
                parse_hook_entry(&stdout, "vigil-apt"),
                HookTriggerResult::Success(_)
            ),
            "the message body must not override the priority"
        );
    }

    #[test]
    fn every_failing_priority_is_treated_as_failure() {
        for p in ["0", "1", "2", "3"] {
            assert!(
                matches!(
                    parse_hook_entry(&entry(p, "x"), "t"),
                    HookTriggerResult::Failure(_, _)
                ),
                "priority {p} must be a failure"
            );
        }
        for p in ["4", "5", "6", "7"] {
            assert!(
                matches!(
                    parse_hook_entry(&entry(p, "x"), "t"),
                    HookTriggerResult::Success(_)
                ),
                "priority {p} must be a success"
            );
        }
    }

    #[test]
    fn no_entries_is_never_triggered() {
        assert_eq!(
            parse_hook_entry("", "vigil-apt"),
            HookTriggerResult::NeverTriggered
        );
        assert_eq!(
            parse_hook_entry("-- No entries --", "vigil-apt"),
            HookTriggerResult::NeverTriggered
        );
    }

    /// Unparseable output is unknown, never a pass.
    #[test]
    fn unparseable_output_is_unknown_not_success() {
        assert_eq!(
            parse_hook_entry("this is not json", "vigil-apt"),
            HookTriggerResult::Unknown
        );
    }

    /// An entry with no priority field cannot be graded, so it is unknown.
    #[test]
    fn missing_priority_is_unknown_not_success() {
        let stdout = r#"{"__REALTIME_TIMESTAMP":"1790096400000000","MESSAGE":"x"}"#;
        assert_eq!(
            parse_hook_entry(stdout, "vigil-apt"),
            HookTriggerResult::Unknown
        );
    }

    #[test]
    fn timestamp_is_rendered_from_the_realtime_field() {
        let stdout = entry("6", "x");
        match parse_hook_entry(&stdout, "vigil-apt") {
            HookTriggerResult::Success(ts) => {
                assert!(ts.starts_with("2026-"), "unexpected timestamp {ts}");
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn journalctl_is_resolved_to_an_absolute_path_when_present() {
        let resolved = journalctl_binary();
        if std::path::Path::new("/usr/bin/journalctl").is_file() {
            assert!(
                resolved.is_absolute(),
                "journalctl must not be resolved through PATH when it exists at a known location"
            );
        }
    }
}
