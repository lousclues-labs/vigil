//! vigild daemon entrypoint.

use std::process;

fn main() {
    // vigild takes no operational flags; configuration is the
    // vigil.toml read from VIGIL_CONFIG (or the compiled default).
    // The two recognised flags exist solely so packaging gates and
    // operators can verify the binary without starting the daemon.
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("vigild {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            other => {
                eprintln!("vigild: unexpected argument '{other}'");
                eprintln!("vigild accepts no operational arguments; configuration is the");
                eprintln!("vigil.toml referenced by the VIGIL_CONFIG environment variable.");
                eprintln!("Run 'vigild --help' for the short reference.");
                process::exit(2);
            }
        }
    }

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

fn print_help() {
    println!(
        "vigild {} -- vigil file-integrity monitoring daemon\n\n\
         USAGE:\n    vigild [FLAGS]\n\n\
         FLAGS:\n    \
         -h, --help       Print this message and exit\n    \
         -V, --version    Print version and exit\n\n\
         ENVIRONMENT:\n    \
         VIGIL_CONFIG     Path to vigil.toml (default: /etc/vigil/vigil.toml)\n    \
         RUST_LOG         tracing-subscriber filter (default: info)\n\n\
         vigild is normally started by systemd via vigild.service. The vigil(1)\n\
         command interacts with the running daemon over a Unix-domain socket.\n\n\
         See vigild(8) and vigil.toml(5) for full operational reference.",
        env!("CARGO_PKG_VERSION")
    );
}

fn run() -> vigil::Result<()> {
    let config_path = std::env::var("VIGIL_CONFIG")
        .ok()
        .map(std::path::PathBuf::from);

    let cfg = vigil::config::load_config(config_path.as_deref())?;
    vigil::Daemon::from_config(cfg)?.run()
}
