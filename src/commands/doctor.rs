//! `vigil doctor` subcommand: system health diagnostics.

use std::path::Path;

use vigil::doctor;
use vigil::types::OutputFormat;

pub(crate) fn cmd_doctor(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let checks = doctor::run_diagnostics(&cfg);

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
        return Ok(doctor::diagnostics_exit_code(&checks));
    }

    println!();
    println!(
        "Vigil Baseline v{}; System Health Check",
        env!("CARGO_PKG_VERSION")
    );
    println!("════════════════════════════════════");

    // ── Runtime ──
    println!();
    println!("  Runtime");
    println!("  ───────");
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "Daemon" | "Backend" | "Control"))
    {
        print_check(check);
    }

    // ── Data ──
    println!();
    println!("  Data");
    println!("  ────");
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "Baseline" | "Database" | "Audit log"))
    {
        print_check(check);
    }

    // ── Configuration ──
    println!();
    println!("  Configuration");
    println!("  ─────────────");
    for check in checks.iter().filter(|c| {
        matches!(
            c.name.as_str(),
            "Config" | "HMAC key" | "Attest key" | "Scan timer"
        )
    }) {
        print_check(check);
    }

    // If config has warnings, inline them here
    if let Some(config_check) = checks.iter().find(|c| c.name == "Config") {
        if config_check.status == doctor::CheckStatus::Warning {
            if let Ok(warnings) = vigil::config::validate_config_deep(&cfg) {
                if !warnings.is_empty() {
                    println!();
                    println!("  Config warnings:");
                    for w in &warnings {
                        println!("    ─ {}", w);
                    }
                }
            }
        }
    }

    // ── Integrations ──
    println!();
    println!("  Integrations");
    println!("  ────────────");
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "Hooks" | "Notify" | "Socket"))
    {
        print_check(check);
    }

    // ── Verdict ──
    println!();

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
        println!(
            "  {}/{} checks passed. Vigil Baseline is watching.",
            ok_count,
            checks.len()
        );
    } else {
        println!("  {}", doctor::diagnostics_verdict(&checks));
    }

    println!();

    Ok(doctor::diagnostics_exit_code(&checks))
}

fn print_check(check: &doctor::DiagnosticCheck) {
    println!(
        "    {:<14} {} {}",
        check.name,
        check.status.marker(),
        check.detail
    );
    if (check.status == doctor::CheckStatus::Warning || check.status == doctor::CheckStatus::Failed)
        && check.fix.is_some()
    {
        println!("    {:<14}   → {}", "", check.fix.as_deref().unwrap_or(""));
    }
}
