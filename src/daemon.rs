//! vigild daemon entrypoint.

use std::process;

fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!("vigild {} starting", env!("CARGO_PKG_VERSION"));

    if let Err(e) = run() {
        tracing::error!(error = %e, "fatal daemon error");
        eprintln!("vigild: fatal error: {}", e);
        // Ensure the error message reaches journald before exit
        std::thread::sleep(std::time::Duration::from_millis(100));
        process::exit(1);
    }
}

fn run() -> vigil::Result<()> {
    let config_path = std::env::var("VIGIL_CONFIG")
        .ok()
        .map(std::path::PathBuf::from);

    let cfg = vigil::config::load_config(config_path.as_deref())?;
    vigil::Daemon::from_config(cfg)?.run()
}
