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
        let mut urgent = 0usize;
        for check in checks
            .iter()
            .filter(|c| c.status == doctor::CheckStatus::Warning)
        {
            let urgency = classify_urgency(&check.name);
            if urgency == "now" {
                urgent += 1;
            }
            let fix_hint = check.fix.as_deref().unwrap_or("");
            if !fix_hint.is_empty() {
                eprintln!(
                    "  {:<14} {} {}",
                    check.name,
                    check.status.marker(),
                    check.detail
                );
                eprintln!(
                    "  {:<14} Run `{}` when convenient. {}.",
                    "",
                    fix_hint,
                    capitalize_first(urgency)
                );
            } else {
                eprintln!(
                    "  {:<14} {} {} {}.",
                    check.name,
                    check.status.marker(),
                    check.detail,
                    capitalize_first(urgency)
                );
            }
        }

        eprintln!();
        if urgent == 0 {
            eprintln!("{} warnings, none urgent.", warning_count);
        } else {
            eprintln!("{} warnings, {} urgent.", warning_count, urgent);
        }
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
        .filter(|c| matches!(c.name.as_str(), "Daemon" | "Backend" | "Control"))
    {
        print_check_verbose(check);
    }

    // Data
    eprintln!();
    eprintln!("  Data");
    eprintln!("  ────");
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "Baseline" | "Database" | "Audit log"))
    {
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

    let failures = checks
        .iter()
        .filter(|c| c.status == doctor::CheckStatus::Failed)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == doctor::CheckStatus::Warning)
        .count();
    let ok_count = checks
        .iter()
        .filter(|c| c.status == doctor::CheckStatus::Ok)
        .count();

    if failures == 0 && warnings == 0 {
        eprintln!("  {}/{} checks passed.", ok_count, checks.len());
    } else {
        let mut urgent = 0usize;
        for c in checks.iter().filter(|c| {
            c.status == doctor::CheckStatus::Warning || c.status == doctor::CheckStatus::Failed
        }) {
            if classify_urgency(&c.name) == "now" {
                urgent += 1;
            }
        }
        let total_issues = failures + warnings;
        if urgent == 0 {
            eprintln!("  {} warnings, none urgent.", total_issues);
        } else {
            eprintln!("  {} warnings, {} urgent.", total_issues, urgent);
        }
    }

    eprintln!();
}

fn print_check_verbose(check: &doctor::DiagnosticCheck) {
    let urgency = classify_urgency(&check.name);
    eprintln!(
        "    {:<14} {} {}",
        check.name,
        check.status.marker(),
        check.detail
    );
    if (check.status == doctor::CheckStatus::Warning || check.status == doctor::CheckStatus::Failed)
        && check.fix.is_some()
    {
        eprintln!(
            "    {:<14}   Run `{}` when convenient. {}.",
            "",
            check.fix.as_deref().unwrap_or(""),
            capitalize_first(urgency)
        );
    }
}

/// Classify urgency of a warning: "not urgent", "soon", or "now".
fn classify_urgency(check_name: &str) -> &'static str {
    match check_name {
        "Daemon" | "Control" => "now",
        "Baseline" | "Database" | "HMAC key" => "soon",
        _ => "not urgent",
    }
}

fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
