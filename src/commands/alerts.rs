//! `vigil alerts` subcommand: alert sink operations.

use std::path::Path;

use vigil::cli::{AlertsAction, AlertsSocketAction};

use super::common::resolve_config_path;

pub(crate) fn cmd_alerts(config_path: Option<&Path>, action: AlertsAction) -> vigil::Result<()> {
    match action {
        AlertsAction::Socket { action } => cmd_alerts_socket(config_path, action),
    }
}

fn cmd_alerts_socket(config_path: Option<&Path>, action: AlertsSocketAction) -> vigil::Result<()> {
    match action {
        AlertsSocketAction::Status => cmd_socket_status(config_path),
        AlertsSocketAction::Enable { path } => cmd_socket_enable(config_path, &path),
        AlertsSocketAction::Disable => cmd_socket_disable(config_path),
    }
}

fn cmd_socket_status(config_path: Option<&Path>) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let socket_path = cfg.hooks.signal_socket.trim();

    if socket_path.is_empty() {
        println!("alert socket: not configured");
        return Ok(());
    }

    println!("alert socket: configured at {}", socket_path);

    let path = Path::new(socket_path);
    if !path.exists() {
        println!("listener: not attached (alerts being dropped)");
    } else {
        println!("listener: attached");
    }

    Ok(())
}

fn cmd_socket_enable(config_path: Option<&Path>, socket_path: &str) -> vigil::Result<()> {
    let path = Path::new(socket_path);

    if !path.is_absolute() {
        return Err(vigil::VigilError::Config(
            "socket path must be absolute".into(),
        ));
    }

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(vigil::VigilError::Config(format!(
                "directory {} does not exist",
                parent.display()
            )));
        }
    }

    let toml_path = resolve_config_path(config_path)
        .ok_or_else(|| vigil::VigilError::Config("cannot locate vigil.toml".into()))?;

    super::common::update_config_toml(
        &toml_path,
        &[("hooks", "signal_socket", &format!("\"{}\"", socket_path))],
    )?;

    super::config::reload_daemon_if_running();

    println!("alert socket enabled at {}", socket_path);
    if !path.exists() {
        println!("(note: no listener currently attached -- alerts will be dropped until one is)");
    }

    Ok(())
}

fn cmd_socket_disable(config_path: Option<&Path>) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let socket_path = cfg.hooks.signal_socket.trim();

    if socket_path.is_empty() {
        println!("alert socket is not configured");
        return Ok(());
    }

    let toml_path = resolve_config_path(config_path)
        .ok_or_else(|| vigil::VigilError::Config("cannot locate vigil.toml".into()))?;

    super::common::update_config_toml(&toml_path, &[("hooks", "signal_socket", "\"\"")])?;

    super::config::reload_daemon_if_running();

    println!("alert socket disabled");

    Ok(())
}
