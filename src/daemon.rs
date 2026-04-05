//! vigild — Vigil daemon entry point.
//!
//! Runs the real-time file integrity monitor as a long-running daemon.
//! Designed to be managed by systemd via vigild.service.

use std::process;

use vigil::config;
use vigil::error::Result;

fn main() {
    let log_format = std::env::var("VIGIL_LOG_FORMAT").unwrap_or_default();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    // Bridge log crate macros to tracing
    tracing_log::LogTracer::init().ok();

    log::info!("vigild {} starting", env!("CARGO_PKG_VERSION"));

    if let Err(e) = run() {
        log::error!("Fatal: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let config_path = std::env::var("VIGIL_CONFIG")
        .ok()
        .map(std::path::PathBuf::from);
    let cfg = config::load_config(config_path.as_deref())?;

    // Re-initialize logging with config's log_format if different
    // (the initial setup uses env var, but config takes precedence for daemon)

    vigil::daemon_run(&cfg)
}
