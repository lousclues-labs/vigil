//! CLI entry point for the `vigil` binary.

use std::process;

use clap::Parser;

use vigil::cli::{Cli, Command};

mod commands;
use commands::{
    cmd_alerts, cmd_attest, cmd_audit, cmd_baseline, cmd_check, cmd_check_live, cmd_config,
    cmd_diff, cmd_doctor, cmd_explain, cmd_hooks, cmd_init, cmd_inspect, cmd_log, cmd_maintenance,
    cmd_recover, cmd_selftest, cmd_setup, cmd_status, cmd_test_alert, cmd_update, cmd_watch,
    cmd_welcome, cmd_why, cmd_why_silent, CheckOpts,
};

fn main() {
    init_tracing();

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Strip clap's automatic "did you mean" suggestions that are
            // based on string distance rather than operational similarity.
            // A wrong hint is worse than no hint (Principle V).
            let msg = e.to_string();
            if msg.contains("tip: a similar argument exists:") {
                let cleaned = msg
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("tip:"))
                    .collect::<Vec<_>>()
                    .join("\n");
                eprint!("{}", cleaned);
                process::exit(2);
            }
            e.exit();
        }
    };

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

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            // `vigil` with no args defaults to `vigil status`
            cmd_status(config_path.as_deref(), format)?;
            return Ok(0);
        }
    };

    match command {
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
            reason,
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
                    reason,
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
        Command::Welcome => cmd_welcome(config_path.as_deref()),
        Command::Why { path } => cmd_why(config_path.as_deref(), path.as_deref(), format),
        Command::Selftest => cmd_selftest(config_path.as_deref()),
        Command::Explain { path, verbose } => {
            cmd_explain(config_path.as_deref(), &path, verbose, format)?;
            Ok(0)
        }
        Command::WhySilent => {
            cmd_why_silent(config_path.as_deref(), format)?;
            Ok(0)
        }
        Command::Inspect {
            path,
            baseline_db,
            recursive,
            root,
            brief,
        } => {
            cmd_inspect(
                config_path.as_deref(),
                &path,
                baseline_db.as_deref(),
                recursive,
                root.as_deref(),
                brief,
                format,
            )?;
            Ok(0)
        }
        Command::Test { action } => match action {
            vigil::cli::TestAction::Alert { severity } => {
                cmd_test_alert(config_path.as_deref(), severity, format)
            }
        },
        Command::Doctor {
            format: doctor_format,
            now: _now,
            verbose,
        } => cmd_doctor(
            config_path.as_deref(),
            doctor_format.unwrap_or(format),
            verbose,
        ),
        Command::Update {
            repo,
            quiet,
            verbose,
            no_progress,
        } => {
            cmd_update(repo, format, quiet, verbose, no_progress)?;
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
        Command::Attest { action } => cmd_attest(config_path.as_deref(), action),
        Command::Recover { reason, list, yes } => {
            cmd_recover(config_path.as_deref(), reason, list, yes)?;
            Ok(0)
        }
        Command::Alerts { action } => {
            cmd_alerts(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Hooks { action } => cmd_hooks(action),
        Command::Version => {
            println!("vigil {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
    }
}
