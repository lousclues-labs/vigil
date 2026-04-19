//! `vigil baseline` subcommand: refresh via control socket or direct scan.

use std::path::Path;

use vigil::cli::BaselineAction;

use super::common::{format_count, query_control_socket};

pub(crate) fn cmd_baseline(
    config_path: Option<&Path>,
    action: BaselineAction,
) -> vigil::Result<()> {
    match action {
        BaselineAction::Refresh { quiet } => cmd_baseline_refresh(config_path, quiet),
    }
}

fn cmd_baseline_refresh(config_path: Option<&Path>, quiet: bool) -> vigil::Result<()> {
    let cfg = match vigil::config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            if quiet {
                return Ok(());
            }
            return Err(e);
        }
    };

    // Try control socket first (daemon is running)
    if !cfg.daemon.control_socket.as_os_str().is_empty() {
        let request = r#"{"method":"baseline_refresh"}"#;
        match query_control_socket(&cfg.daemon.control_socket, request) {
            Ok(response) => {
                if !quiet {
                    let count = response
                        .get("total_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    println!("Baseline refreshed ({} files).", format_count(count));
                }
                return Ok(());
            }
            Err(_) => {
                // Daemon not running; fall through to direct DB access
            }
        }
    }

    // Fallback: direct DB access (daemon not running)
    let conn = match vigil::db::open_baseline_db(&cfg) {
        Ok(c) => c,
        Err(e) => {
            if quiet {
                return Ok(());
            }
            return Err(e);
        }
    };

    match vigil::scanner::build_initial_baseline(&conn, &cfg) {
        Ok(result) => {
            vigil::db::baseline_ops::set_config_state(&conn, "baseline_initialized", "true")?;
            if !quiet {
                println!(
                    "Baseline refreshed ({} files in {:.1}s).",
                    format_count(result.total_count),
                    result.duration.as_secs_f64()
                );
            }
            Ok(())
        }
        Err(e) => {
            if quiet {
                return Ok(());
            }
            Err(e)
        }
    }
}
