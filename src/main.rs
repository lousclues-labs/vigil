use std::process;

use clap::Parser;

use vigil::cli::{AuditAction, Cli, Command, ConfigAction};
use vigil::types::{OutputFormat, ScanMode};

fn main() {
    init_tracing();

    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn run(cli: Cli) -> vigil::Result<()> {
    let config_path = cli.config;
    let format = cli.format;

    match cli.command {
        Command::Init => cmd_init(config_path.as_deref()),
        Command::Watch => cmd_watch(config_path.as_deref()),
        Command::Check { full } => cmd_check(config_path.as_deref(), full),
        Command::Status => cmd_status(config_path.as_deref(), format),
        Command::Audit { action } => cmd_audit(config_path.as_deref(), action, format),
        Command::Config { action } => cmd_config(config_path.as_deref(), action),
        Command::Version => {
            println!("vigil {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn cmd_init(config_path: Option<&std::path::Path>) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    println!("Initializing baseline...");
    let count = vigil::scanner::build_initial_baseline(&conn, &cfg)?;
    println!("Baseline initialized: {} entries", count);

    Ok(())
}

fn cmd_watch(config_path: Option<&std::path::Path>) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    println!("Starting vigilant monitor in foreground mode (Ctrl+C to stop)...");
    vigil::Daemon::from_config(cfg)?.run()
}

fn cmd_check(config_path: Option<&std::path::Path>, full: bool) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    let mode = if full {
        ScanMode::Full
    } else {
        ScanMode::Incremental
    };

    println!("Running {} scan...", mode);
    let result = vigil::scanner::run_scan(&conn, &cfg, mode)?;

    println!("Checked: {}", result.total_checked);
    println!("Changes: {}", result.changes_found);
    println!("Errors: {}", result.errors);

    for change in result.changes.iter().take(20) {
        println!(
            "  [{}] {} ({})",
            change.severity,
            change.path.display(),
            change.primary_change_name()
        );
    }

    Ok(())
}

fn cmd_status(config_path: Option<&std::path::Path>, format: OutputFormat) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    let metrics_path = cfg.daemon.runtime_dir.join("metrics.json");
    let state_path = cfg.daemon.runtime_dir.join("state.json");

    let metrics = std::fs::read_to_string(&metrics_path).unwrap_or_else(|_| "{}".to_string());
    let state = std::fs::read_to_string(&state_path).unwrap_or_else(|_| "{}".to_string());

    match format {
        OutputFormat::Json => {
            let metrics_json: serde_json::Value = serde_json::from_str(&metrics).unwrap_or(serde_json::json!({}));
            let state_json: serde_json::Value = serde_json::from_str(&state).unwrap_or(serde_json::json!({}));
            let out = serde_json::json!({
                "metrics": metrics_json,
                "state": state_json,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        _ => {
            println!("Status");
            println!("------");
            println!("Metrics file: {}", metrics_path.display());
            println!("State file:   {}", state_path.display());
            println!("\nState JSON:\n{}", state);
            println!("\nMetrics JSON:\n{}", metrics);
        }
    }

    Ok(())
}

fn cmd_audit(
    config_path: Option<&std::path::Path>,
    action: AuditAction,
    format: OutputFormat,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;

    match action {
        AuditAction::Show { last } => {
            let entries = vigil::db::audit_ops::get_recent(&conn, last)?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&entries_to_json(&entries))?);
            } else {
                for e in entries {
                    println!("{} {} {}", e.timestamp, e.severity, e.path);
                }
            }
        }
        AuditAction::Verify => {
            let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn)?;
            println!("Audit Chain Verification");
            println!("------------------------");
            println!("Total entries: {}", total);
            println!("Valid links:   {}", valid);
            println!("Missing hash:  {}", missing);
            println!("Breaks:        {}", breaks.len());
            if !breaks.is_empty() {
                for (id, ts) in breaks {
                    println!("  break at id={} timestamp={}", id, ts);
                }
            }
        }
    }

    Ok(())
}

fn entries_to_json(entries: &[vigil::db::audit_ops::AuditEntry]) -> serde_json::Value {
    serde_json::Value::Array(
        entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "path": e.path,
                    "changes_json": e.changes_json,
                    "severity": e.severity,
                    "monitored_group": e.monitored_group,
                    "process_json": e.process_json,
                    "package": e.package,
                    "maintenance": e.maintenance,
                    "suppressed": e.suppressed,
                    "hmac": e.hmac,
                    "chain_hash": e.chain_hash,
                })
            })
            .collect(),
    )
}

fn cmd_config(
    config_path: Option<&std::path::Path>,
    action: ConfigAction,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    match action {
        ConfigAction::Show => {
            println!("{}", toml::to_string_pretty(&cfg).map_err(|e| vigil::VigilError::Config(e.to_string()))?);
        }
        ConfigAction::Validate => {
            vigil::config::validate_config(&cfg)?;
            let warnings = vigil::config::validate_config_deep(&cfg)?;
            println!("Configuration is valid.");
            if !warnings.is_empty() {
                println!("Warnings:");
                for w in warnings {
                    println!("  - {}", w);
                }
            }
        }
    }

    Ok(())
}
