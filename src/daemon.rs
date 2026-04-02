//! vigild — Vigil daemon entry point.
//!
//! Runs the real-time file integrity monitor as a long-running daemon.
//! Designed to be managed by systemd via vigild.service.

use std::process;

use vigil::config;
use vigil::error::Result;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    log::info!("vigild {} starting", env!("CARGO_PKG_VERSION"));

    if let Err(e) = run() {
        log::error!("Fatal: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let config_path = std::env::var("VIGIL_CONFIG").ok().map(std::path::PathBuf::from);
    let cfg = config::load_config(config_path.as_deref())?;

    vigil::daemon_run(&cfg)
}
