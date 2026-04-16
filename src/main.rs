use std::process;

use clap::Parser;

use vigil::cli::{Cli, Command};

mod commands;
use commands::{
    cmd_audit, cmd_baseline, cmd_check, cmd_check_live, cmd_config, cmd_diff, cmd_doctor, cmd_init,
    cmd_log, cmd_maintenance, cmd_setup, cmd_status, cmd_update, cmd_watch, CheckOpts,
};

fn main() {
    init_tracing();

    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn run(cli: Cli) -> vigil::Result<i32> {
    let config_path = cli.config;
    let format = cli.format;

    match cli.command {
        Command::Init { force } => {
            cmd_init(config_path.as_deref(), format, force)?;
            Ok(0)
        }
        Command::Watch => {
            cmd_watch(config_path.as_deref())?;
            Ok(0)
        }
        Command::Check {
            full,
            now,
            accept,
            path: accept_path,
            dry_run,
            accept_severity,
            accept_group,
            verbose,
            brief,
            no_pager,
            since,
        } => {
            if now && accept {
                eprintln!("error: --accept cannot be used with --now (baseline updates require direct database access)");
                return Ok(1);
            }
            if now && since.is_some() {
                eprintln!(
                    "error: --since cannot be used with --now (time-bound filtering needs local audit DB access)"
                );
                return Ok(1);
            }
            if now {
                cmd_check_live(config_path.as_deref(), full)?;
                Ok(0)
            } else {
                cmd_check(CheckOpts {
                    config_path: config_path.clone(),
                    format,
                    full,
                    accept,
                    accept_path,
                    accept_dry_run: dry_run,
                    accept_severity,
                    accept_group,
                    verbose,
                    brief,
                    no_pager,
                    since,
                })
            }
        }
        Command::Diff { path } => {
            cmd_diff(config_path.as_deref(), &path)?;
            Ok(0)
        }
        Command::Status => {
            cmd_status(config_path.as_deref(), format)?;
            Ok(0)
        }
        Command::Doctor {
            format: doctor_format,
        } => cmd_doctor(config_path.as_deref(), doctor_format.unwrap_or(format)),
        Command::Update { repo } => {
            cmd_update(repo)?;
            Ok(0)
        }
        Command::Audit { action } => {
            cmd_audit(config_path.as_deref(), action, format)?;
            Ok(0)
        }
        Command::Config { action } => {
            cmd_config(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Setup { action } => {
            cmd_setup(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Log { action } => {
            cmd_log(action)?;
            Ok(0)
        }
        Command::Maintenance { action } => {
            cmd_maintenance(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Baseline { action } => {
            cmd_baseline(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Version => {
            println!("vigil {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
    }
}
