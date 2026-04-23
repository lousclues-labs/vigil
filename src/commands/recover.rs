//! `vigil recover` subcommand: guided recovery from degraded daemon states.

use std::io::{self, Write};
use std::path::Path;

use super::common::query_control_socket;

/// Known degraded reasons and their recovery descriptions.
const KNOWN_REASONS: &[(&str, &str, &str)] = &[
    (
        "baseline_db_replaced",
        "The baseline database file was replaced (inode changed) outside of a \
         baseline refresh. This can happen if the file was manually moved, \
         restored from backup, or tampered with.",
        "Verify the current baseline database is valid, re-record its identity, \
         and return the daemon to healthy state.",
    ),
    (
        "baseline_hmac_mismatch",
        "The baseline HMAC does not match the stored value. The baseline may \
         have been modified outside of vigil, or the HMAC key may have changed.",
        "Recompute the baseline HMAC from the current database contents and \
         return the daemon to healthy state.",
    ),
    (
        "audit_db_replaced",
        "The audit database file was replaced outside of normal operation.",
        "Verify the current audit database, re-record its identity, and return \
         the daemon to healthy state.",
    ),
    (
        "wal_file_replaced",
        "The detection WAL file was replaced outside of normal operation.",
        "Verify the current WAL file, re-record its identity, and return the \
         daemon to healthy state.",
    ),
    (
        "event_backpressure",
        "The event channel is full. Workers cannot keep up with filesystem events.",
        "Wait for the backlog to drain, or restart the daemon to clear it.",
    ),
];

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
        for (name, description, _recovery) in KNOWN_REASONS {
            println!("  {}:", name);
            println!("    {}", description);
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

    // Validate that the reason is known
    let known = KNOWN_REASONS.iter().find(|(name, _, _)| *name == reason);
    if known.is_none() {
        let known_names: Vec<&str> = KNOWN_REASONS.iter().map(|(n, _, _)| *n).collect();
        return Err(vigil::VigilError::Config(format!(
            "unknown degraded reason '{}'. Known reasons: {}",
            reason,
            known_names.join(", ")
        )));
    }

    let (_name, description, recovery) = known.unwrap();

    println!();
    println!("Recovery: {}", reason);
    println!();
    println!("  Situation:  {}", description);
    println!("  Action:     {}", recovery);
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
