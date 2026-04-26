//! `vigil doctor` subcommand: system health diagnostics.

use std::path::Path;

use vigil::doctor;
use vigil::types::OutputFormat;

pub(crate) fn cmd_doctor(
    config_path: Option<&Path>,
    format: OutputFormat,
    verbose: bool,
) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let checks = doctor::run_diagnostics(&cfg);

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
        return Ok(doctor::diagnostics_exit_code(&checks));
    }

    let failures = checks
        .iter()
        .filter(|c| c.status == doctor::CheckStatus::Failed)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == doctor::CheckStatus::Warning)
        .count();

    if !verbose && failures == 0 {
        // Compact healthy preamble (5 lines)
        print_compact(&checks, &cfg, warnings);
    } else {
        // Full diagnostic breakdown
        print_verbose(&checks, &cfg);
    }

    Ok(doctor::diagnostics_exit_code(&checks))
}

fn print_compact(
    checks: &[doctor::DiagnosticCheck],
    _cfg: &vigil::config::Config,
    warning_count: usize,
) {
    // Line 1: version + verdict
    if warning_count == 0 {
        eprintln!("Vigil Baseline v{}. Healthy.", env!("CARGO_PKG_VERSION"));
    } else {
        eprintln!(
            "Vigil Baseline v{}. {} {}.",
            env!("CARGO_PKG_VERSION"),
            warning_count,
            if warning_count == 1 {
                "warning"
            } else {
                "warnings"
            }
        );
    }
    eprintln!();

    // Line 2: Daemon
    if let Some(c) = checks.iter().find(|c| c.name == "Daemon") {
        eprintln!("  {:<14} {}", "Daemon", c.detail);
    }

    // Line 3: Baseline
    if let Some(c) = checks.iter().find(|c| c.name == "Baseline") {
        let detail = if c.status == doctor::CheckStatus::Ok {
            format!("fresh, {}", c.detail)
        } else {
            c.detail.clone()
        };
        eprintln!("  {:<14} {}", "Baseline", detail);
    }

    // Line 4: Audit log
    if let Some(c) = checks.iter().find(|c| c.name == "Audit log") {
        eprintln!("  {:<14} {}", "Audit log", c.detail);
    }

    // Line 5: Config
    if let Some(c) = checks.iter().find(|c| c.name == "Config") {
        let detail = if c.status == doctor::CheckStatus::Ok {
            "valid, no warnings".to_string()
        } else {
            c.detail.clone()
        };
        eprintln!("  {:<14} {}", "Config", detail);
    }

    // Inline warnings with urgency
    if warning_count > 0 {
        eprintln!();
        for check in checks
            .iter()
            .filter(|c| c.status == doctor::CheckStatus::Warning)
        {
            eprintln!(
                "  {} {:<16} {}",
                check.status.marker(),
                check.name,
                check.detail
            );
            render_recovery_compact(&check.recovery);
        }

        eprintln!();
        let issue_word = if warning_count == 1 {
            "warning"
        } else {
            "warnings"
        };
        eprintln!("{} {}.", warning_count, issue_word);
    }

    eprintln!();
    eprintln!("Use --verbose for the full diagnostic.");
}

fn print_verbose(checks: &[doctor::DiagnosticCheck], cfg: &vigil::config::Config) {
    eprintln!();
    eprintln!(
        "Vigil Baseline v{}; System Health Check",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("════════════════════════════════════");

    // Runtime
    eprintln!();
    eprintln!("  Runtime");
    eprintln!("  ───────");
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "Daemon" | "State" | "Backend" | "Control"))
    {
        print_check_verbose(check);
    }

    // Pipeline
    eprintln!();
    eprintln!("  Pipeline");
    eprintln!("  ────────");
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "WAL pipeline"))
    {
        print_check_verbose(check);
    }

    // Data
    eprintln!();
    eprintln!("  Data");
    eprintln!("  ────");
    for check in checks.iter().filter(|c| {
        matches!(
            c.name.as_str(),
            "Baseline" | "Database" | "Audit log" | "Audit retention" | "Data dir"
        )
    }) {
        print_check_verbose(check);
    }

    // Configuration
    eprintln!();
    eprintln!("  Configuration");
    eprintln!("  ─────────────");
    for check in checks.iter().filter(|c| {
        matches!(
            c.name.as_str(),
            "Config" | "HMAC key" | "Attest key" | "Scan timer"
        )
    }) {
        print_check_verbose(check);
    }

    if let Some(config_check) = checks.iter().find(|c| c.name == "Config") {
        if config_check.status == doctor::CheckStatus::Warning {
            if let Ok(warnings) = vigil::config::validate_config_deep(cfg) {
                if !warnings.is_empty() {
                    eprintln!();
                    eprintln!("  Config warnings:");
                    for w in &warnings {
                        eprintln!("    - {}", w);
                    }
                }
            }
        }
    }

    // Integrations
    eprintln!();
    eprintln!("  Integrations");
    eprintln!("  ────────────");
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "Hooks" | "Notify" | "Socket"))
    {
        print_check_verbose(check);
    }

    // Verdict
    eprintln!();
    eprintln!("  {}", doctor::format_doctor_summary(checks));
    eprintln!();
}

fn print_check_verbose(check: &doctor::DiagnosticCheck) {
    eprintln!(
        "    {} {:<16} {}",
        check.status.marker(),
        check.name,
        check.detail
    );
    if check.status == doctor::CheckStatus::Warning || check.status == doctor::CheckStatus::Failed {
        render_recovery(&check.recovery);
    }
}

/// Render a recovery action. Each variant gets its own honest format.
fn render_recovery(recovery: &doctor::Recovery) {
    let pad = "                       "; // align under detail text
    match recovery {
        doctor::Recovery::Command(cmd) => {
            eprintln!("{}recover with: {}", pad, cmd);
        }
        doctor::Recovery::CommandWithContext { command, context } => {
            eprintln!("{}recover with: {}", pad, command);
            eprintln!("{}{}", pad, context);
        }
        doctor::Recovery::Manual(guidance) => {
            eprintln!("{}{}", pad, guidance);
        }
        doctor::Recovery::Documentation(path) => {
            eprintln!("{}see: {}", pad, path);
        }
        doctor::Recovery::None => {}
        doctor::Recovery::Multi(hints) => {
            render_multi_hints(hints, false);
        }
    }
}

/// Render a recovery action in compact mode.
fn render_recovery_compact(recovery: &doctor::Recovery) {
    let pad = "                     "; // align under detail text (compact)
    match recovery {
        doctor::Recovery::Command(cmd) => {
            eprintln!("{}recover with: {}", pad, cmd);
        }
        doctor::Recovery::CommandWithContext { command, context } => {
            eprintln!("{}recover with: {}", pad, command);
            eprintln!("{}{}", pad, context);
        }
        doctor::Recovery::Manual(guidance) => {
            eprintln!("{}{}", pad, guidance);
        }
        doctor::Recovery::Documentation(path) => {
            eprintln!("{}see: {}", pad, path);
        }
        doctor::Recovery::None => {}
        doctor::Recovery::Multi(hints) => {
            render_multi_hints(hints, true);
        }
    }
}

/// Render a list of recovery hints with appropriate verb prefixes.
fn render_multi_hints(hints: &[doctor::RecoveryHint], compact: bool) {
    let pad = if compact {
        "                     " // compact: 21 chars
    } else {
        "                       " // verbose: 23 chars
    };
    for hint in hints {
        match hint {
            doctor::RecoveryHint::Command { verb, command } => {
                if verb.is_empty() {
                    eprintln!("{}{}", pad, command);
                } else {
                    eprintln!("{}{}: {}", pad, verb, command);
                }
            }
            doctor::RecoveryHint::Manual { verb, instruction } => {
                if verb.is_empty() {
                    eprintln!("{}{}", pad, instruction);
                } else {
                    eprintln!("{}{}: {}", pad, verb, instruction);
                }
            }
            doctor::RecoveryHint::Documentation { reference } => {
                eprintln!("{}see: {}", pad, reference);
            }
        }
    }
}
