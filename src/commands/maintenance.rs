//! `vigil maintenance` subcommand: enter/exit maintenance windows.

use std::path::Path;

use super::common::query_control_socket;

use vigil::cli::MaintenanceAction;

pub(crate) fn cmd_maintenance(
    config_path: Option<&Path>,
    action: MaintenanceAction,
) -> vigil::Result<()> {
    let quiet = match &action {
        MaintenanceAction::Enter { quiet } => *quiet,
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
