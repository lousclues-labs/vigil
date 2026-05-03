//! `vigil recover` subcommand: guided recovery from degraded daemon states.

use std::io::{self, Write};
use std::path::Path;

use vigil::types::DegradedReason;

use super::common::query_control_socket;

/// Operator-facing description for a degraded reason. Pure UI text; the
/// authoritative list of reasons comes from `DegradedReason` itself, which
/// guarantees we cannot drift behind a newly-added variant (the exhaustive
/// `match` in `describe()` is a compile-time error if a variant is missing).
struct ReasonInfo {
    code: &'static str,
    situation: &'static str,
    action: &'static str,
}

fn describe(reason: &DegradedReason) -> ReasonInfo {
    let code = reason.reason_code();
    match reason {
        DegradedReason::BaselineDbReplaced => ReasonInfo {
            code,
            situation: "The baseline database file was replaced (inode changed) outside \
                of a baseline refresh. This can happen if the file was manually \
                moved, restored from backup, or tampered with.",
            action: "Verify the current baseline database is valid, re-record its \
                identity, and return the daemon to healthy state.",
        },
        DegradedReason::BaselineHmacMismatch => ReasonInfo {
            code,
            situation: "The baseline HMAC does not match the stored value. The baseline \
                may have been modified outside of vigil, or the HMAC key may have \
                changed.",
            action: "Recompute the baseline HMAC from the current database contents and \
                return the daemon to healthy state. Refused unless `[security] \
                trust_baseline_on_hmac_mismatch = true` is set in vigil.toml.",
        },
        DegradedReason::AuditDbReplaced => ReasonInfo {
            code,
            situation: "The audit database file was replaced outside of normal operation.",
            action: "Verify the current audit database, re-record its identity, and \
                return the daemon to healthy state.",
        },
        DegradedReason::WalFileReplaced => ReasonInfo {
            code,
            situation: "The detection WAL file was replaced outside of normal operation.",
            action: "Verify the current WAL file, re-record its identity, and return \
                the daemon to healthy state.",
        },
        DegradedReason::EventBackpressure => ReasonInfo {
            code,
            situation: "The event channel is full. Workers cannot keep up with \
                filesystem events.",
            action: "Wait for the backlog to drain, or restart the daemon to clear it.",
        },
        DegradedReason::EventLossDetected { .. } => ReasonInfo {
            code,
            situation: "Userspace event drops crossed the configured threshold. The \
                kernel queued events that vigil could not consume in time.",
            action: "Trigger a compensating full scan and return to healthy state. \
                Increase `monitor.event_loss_alert_threshold` if the rate is normal \
                for this host.",
        },
        DegradedReason::ClockSkewDetected { .. } => ReasonInfo {
            code,
            situation: "Wall-clock time moved backwards or jumped beyond the configured \
                tolerance. Timestamps in new audit entries would be inconsistent \
                with the chain.",
            action: "Confirm the clock has stabilised (NTP synced, no manual changes) \
                and return to healthy state. Configurable via \
                `security.clock_skew_threshold_seconds`.",
        },
        DegradedReason::FanotifyMarkFailed { .. } => ReasonInfo {
            code,
            situation: "Vigil failed to install a fanotify mark on a watched mount. \
                Coverage of that mount is incomplete.",
            action: "Check journal logs for the mount path. Once resolved (mount \
                returned, permissions restored), recover to retry the mark.",
        },
        DegradedReason::FanotifyReadFailed => ReasonInfo {
            code,
            situation: "The fanotify read loop returned a fatal error. Live monitoring \
                is suspended.",
            action: "Check journal logs for the cause. Recovery re-opens the fanotify \
                fd and resumes monitoring.",
        },
        DegradedReason::FanotifyQueueOverflow => ReasonInfo {
            code,
            situation: "The kernel fanotify queue overflowed. Some events were lost \
                between vigil reads.",
            action: "Trigger a compensating full scan to verify state, then recover.",
        },
        DegradedReason::WorkerDbUnrecoverable => ReasonInfo {
            code,
            situation: "A worker thread could not re-open its baseline database \
                connection after repeated retries.",
            action: "Verify the baseline database file is intact (`vigil check`), then \
                recover to retry. Restart vigild if recovery fails twice.",
        },
        DegradedReason::AuditLogFull => ReasonInfo {
            code,
            situation: "The audit log has reached its size cap. The daemon refuses new \
                audit writes until space is reclaimed.",
            action: "Prune old audit entries (`vigil audit prune --before <date> \
                --confirm`) or raise `audit.max_size_mb` in vigil.toml, then \
                return the daemon to healthy state.",
        },
        DegradedReason::RetentionPolicyMismatch { .. } => ReasonInfo {
            code,
            situation: "The retention sweep would have deleted an unexpectedly large \
                fraction of the audit log and was skipped to prevent accidental \
                history loss.",
            action: "Review `audit.retention_days` and `audit.min_entries_to_keep` in \
                vigil.toml. If the policy is correct, run `vigil audit prune \
                --before <date> --confirm` manually, then recover.",
        },
        DegradedReason::UserspaceEventDrops { .. } => ReasonInfo {
            code,
            situation: "VIGIL-VULN-075: userspace dropped events the kernel delivered. \
                A compensating full scan was triggered automatically; this state \
                tracks the residual gap.",
            action: "Wait for the compensating scan to complete, then recover. \
                Persistent recurrence indicates undersized worker pool or a slow \
                disk; see `monitor.userspace_drop_threshold`.",
        },
        DegradedReason::AlertSinkFailing { ref sink, .. } => ReasonInfo {
            code,
            situation: match sink.as_str() {
                "socket" => {
                    "A configured alert socket sink is failing to deliver. \
                    Alerts are silently dropped until the sink recovers."
                }
                "webhook" => {
                    "A configured webhook sink is failing to deliver. \
                    Alerts are silently dropped until the sink recovers."
                }
                _ => {
                    "A configured alert sink is failing to deliver. \
                    Alerts are silently dropped until the sink recovers."
                }
            },
            action: "Investigate the sink configuration and connectivity, fix the \
                underlying issue, then recover.",
        },
        DegradedReason::ControlSocketDrift { ref kind } => ReasonInfo {
            code,
            situation: match kind.as_str() {
                "ownership_drift" => {
                    "The control socket ownership has changed from \
                    the daemon's effective UID. Another process or operator may have \
                    modified the socket file."
                }
                "permission_drift" => {
                    "The control socket permissions have changed \
                    from the expected mode. This could allow unauthorized access."
                }
                "missing" => {
                    "The control socket file has been removed while the \
                    daemon is running. CLI commands will fail until it is recreated."
                }
                _ => "The control socket file has drifted from its expected state.",
            },
            action: "Restore the control socket to its expected ownership and \
                permissions, or restart vigild to recreate it.",
        },
    }
}

pub(crate) fn cmd_recover(
    config_path: Option<&Path>,
    reason: Option<String>,
    list: bool,
    yes: bool,
) -> vigil::Result<()> {
    if list {
        println!();
        println!("Known degraded reasons:");
        println!();
        for variant in DegradedReason::all_variants_for_introspection() {
            let info = describe(&variant);
            println!("  {}:", info.code);
            println!("    {}", info.situation);
            println!();
        }
        return Ok(());
    }

    let reason = reason.ok_or_else(|| {
        vigil::VigilError::Config(
            "specify --reason <reason> or --list to see known reasons. \
             Run `vigil doctor` to see the current daemon state."
                .into(),
        )
    })?;

    // Validate against the typed enum: no possibility of drift.
    let known: Option<ReasonInfo> = DegradedReason::all_variants_for_introspection()
        .iter()
        .find(|v| v.reason_code() == reason)
        .map(describe);
    let info = match known {
        Some(i) => i,
        None => {
            let known_names: Vec<&'static str> = DegradedReason::all_variants_for_introspection()
                .iter()
                .map(|v| v.reason_code())
                .collect();
            return Err(vigil::VigilError::Config(format!(
                "unknown degraded reason '{}'. Known reasons: {}",
                reason,
                known_names.join(", ")
            )));
        }
    };

    println!();
    println!("Recovery: {}", info.code);
    println!();
    println!("  Situation:  {}", info.situation);
    println!("  Action:     {}", info.action);
    println!();

    // Confirm unless --yes
    if !yes {
        print!("Proceed with recovery? Type 'yes' to confirm: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            println!("Recovery cancelled.");
            return Ok(());
        }
    }

    // Send recovery command via control socket
    let cfg = vigil::config::load_config(config_path)?;
    let socket_path = &cfg.daemon.control_socket;

    if socket_path.as_os_str().is_empty() || !socket_path.exists() {
        return Err(vigil::VigilError::Config(
            "daemon control socket not available. Is vigild running? \
             Check with: sudo systemctl status vigild"
                .into(),
        ));
    }

    let request = serde_json::json!({
        "method": "recover",
        "reason": reason,
    });

    match query_control_socket(socket_path, &request.to_string()) {
        Ok(resp) => {
            if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                println!("Recovery successful. Daemon state: healthy.");
                if let Some(seq) = resp.get("audit_sequence") {
                    println!("Audit record: sequence {}", seq);
                }
            } else {
                let err = resp
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown error");
                println!("Recovery failed: {}", err);
            }
        }
        Err(e) => {
            return Err(vigil::VigilError::Control(format!(
                "failed to send recovery command: {}. \
                 The daemon may require authentication; try with HMAC key configured.",
                e
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time-equivalent guard: every DegradedReason variant must be
    /// describable. This loop is the runtime cousin of the exhaustive match
    /// in `describe()`. If a new variant is added without a description, the
    /// match in `describe()` fails to compile -- this test exists only to
    /// prove that the introspection list and the describe() table stay in
    /// lock-step.
    #[test]
    fn every_degraded_reason_has_recovery_description() {
        for variant in DegradedReason::all_variants_for_introspection() {
            let info = describe(&variant);
            assert!(!info.situation.is_empty(), "{}: empty situation", info.code);
            assert!(!info.action.is_empty(), "{}: empty action", info.code);
            assert_eq!(
                info.code,
                variant.reason_code(),
                "describe()/reason_code() drift for {:?}",
                variant
            );
        }
    }

    /// Reason codes must be parameter-free and shell-safe (alnum + underscore).
    /// `vigil recover --reason <code>` would break otherwise.
    #[test]
    fn reason_codes_are_shell_safe() {
        for variant in DegradedReason::all_variants_for_introspection() {
            let code = variant.reason_code();
            assert!(
                code.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "reason_code {:?} contains shell-unsafe characters",
                code
            );
            assert!(!code.is_empty(), "empty reason_code");
        }
    }
}
