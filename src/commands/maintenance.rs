//! `vigil maintenance` subcommand: enter/exit maintenance windows.

use std::path::Path;

use super::common::query_control_socket;

use vigil::cli::MaintenanceAction;

pub(crate) fn cmd_maintenance(
    config_path: Option<&Path>,
    action: MaintenanceAction,
) -> vigil::Result<()> {
    let quiet = match &action {
        MaintenanceAction::Enter { quiet, .. } => *quiet,
        MaintenanceAction::Exit { quiet } => *quiet,
        MaintenanceAction::Status => false,
    };

    let method = match &action {
        MaintenanceAction::Enter { .. } => "maintenance_enter",
        MaintenanceAction::Exit { .. } => "maintenance_exit",
        MaintenanceAction::Status => "status",
    };

    let cfg = match vigil::config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            if quiet {
                return Ok(());
            }
            return Err(e);
        }
    };

    if cfg.daemon.control_socket.as_os_str().is_empty() {
        if quiet {
            return Ok(());
        }
        return Err(vigil::VigilError::Config(
            "control_socket not configured".into(),
        ));
    }

    // Seal first: the verdict has to be taken before the window opens and
    // before the package manager writes anything, or it is not a statement
    // about the state the transaction started from.
    if let MaintenanceAction::Enter { seal: true, .. } = &action {
        seal_before_transaction(&cfg.daemon.control_socket, quiet);
    }

    let request = format!(r#"{{"method":"{}"}}"#, method);
    match query_control_socket(&cfg.daemon.control_socket, &request) {
        Ok(response) => {
            if !quiet {
                match &action {
                    MaintenanceAction::Enter { .. } => {
                        println!("Maintenance window entered.");
                    }
                    MaintenanceAction::Exit { .. } => {
                        println!("Maintenance window exited.");
                    }
                    MaintenanceAction::Status => {
                        let maint = response
                            .pointer("/daemon/maintenance_window")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if maint {
                            println!("Maintenance window: active");
                        } else {
                            println!("Maintenance window: inactive");
                        }
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            if quiet {
                // Hooks must not block package operations
                return Ok(());
            }
            Err(vigil::VigilError::Daemon(format!(
                "cannot connect to daemon: {} (is vigild running?)",
                e
            )))
        }
    }
}

/// Marker the package-manager hooks grep for when a seal finds the system was
/// already drifting before the transaction. Stable contract.
pub(crate) const SEAL_DIRTY_MARKER: &str = "VIGIL PRE-UPDATE DEVIATIONS";

/// Take the pre-transaction seal and report its verdict.
///
/// Never fails the caller. A seal that cannot be taken is reported and the
/// transaction proceeds: vigil watches, it does not block (Principle I). But
/// it must not stay quiet about failing, because a silent failure here would
/// look exactly like a clean system.
fn seal_before_transaction(socket: &Path, quiet: bool) {
    let response = match query_control_socket(socket, r#"{"method":"seal"}"#) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Vigil: could not seal pre-transaction state: {e}");
            return;
        }
    };

    if response.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err = response
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("Vigil: pre-transaction seal did not complete: {err}");
        return;
    }

    let checked = response
        .get("files_checked")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let paths: Vec<String> = response
        .get("deviation_paths")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if paths.is_empty() {
        // Printed even under --quiet: a clean verdict is the whole point of
        // taking one, and the hooks log it as the record that the system was
        // intact going in.
        println!(
            "Vigil: sealed clean before this transaction ({} files checked)",
            checked
        );
        return;
    }

    // Never truncated (Principle V: Actionable).
    println!(
        "{}: {} (checked {})",
        SEAL_DIRTY_MARKER,
        paths.len(),
        checked
    );
    for path in &paths {
        println!("  {}    already deviating before this transaction", path);
    }
    if !quiet {
        println!("  these predate the update; anything new will appear after it");
    }
}
