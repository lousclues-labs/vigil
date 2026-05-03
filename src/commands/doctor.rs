//! `vigil doctor` subcommand: system health diagnostics.
//!
//! The output is structured into three zones:
//! 1. Headline summary (one line, counts only)
//! 2. "Needs attention" zone (failures then warnings, severity order)
//! 3. "Healthy" zone (compact, one line per item)
//!
//! Optional/not-configured items appear below the healthy list with ○ glyph.

use std::path::Path;

use vigil::doctor::{self, CheckStatus, DiagnosticCheck, Recovery, RecoveryHint};
use vigil::types::OutputFormat;

/// Maximum number of recovery hints rendered per row.
const MAX_HINTS_PER_ROW: usize = 3;

/// Width of zone separator lines.
const SEPARATOR_WIDTH: usize = 62;

pub(crate) fn cmd_doctor(
    config_path: Option<&Path>,
    format: OutputFormat,
    _verbose: bool,
) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let checks = doctor::run_diagnostics(&cfg);

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
        return Ok(doctor::diagnostics_exit_code(&checks));
    }

    let output = render_doctor(&checks);
    eprint!("{}", output);

    Ok(doctor::diagnostics_exit_code(&checks))
}

/// Render the full doctor output into a string.
///
/// Groups items at render time: failures and warnings into the "Needs
/// attention" zone, healthy items into a compact list, optional/not-configured
/// items at the bottom. The headline counts come from the same collected list
/// that populates the zones, so a mismatch is impossible by construction.
pub(crate) fn render_doctor(checks: &[DiagnosticCheck]) -> String {
    let mut out = String::with_capacity(2048);

    // Partition checks into zones.
    let mut needs_attention: Vec<&DiagnosticCheck> = Vec::new();
    let mut healthy: Vec<&DiagnosticCheck> = Vec::new();
    let mut optional: Vec<&DiagnosticCheck> = Vec::new();

    for check in checks {
        if check.is_optional_not_configured() {
            optional.push(check);
        } else {
            match check.status {
                CheckStatus::Failed | CheckStatus::Warning => {
                    needs_attention.push(check);
                }
                CheckStatus::Ok => {
                    healthy.push(check);
                }
                CheckStatus::Unknown => {
                    // Unknown but not optional-not-configured: show in healthy
                    // zone (e.g., daemon not running → state unknown).
                    healthy.push(check);
                }
            }
        }
    }

    // Sort needs-attention: failures first, then warnings.
    needs_attention.sort_by_key(|c| match c.status {
        CheckStatus::Failed => 0,
        CheckStatus::Warning => 1,
        _ => 2,
    });

    let fail_count = needs_attention
        .iter()
        .filter(|c| c.status == CheckStatus::Failed)
        .count();
    let warn_count = needs_attention
        .iter()
        .filter(|c| c.status == CheckStatus::Warning)
        .count();
    let healthy_count = healthy.len();
    let optional_count = optional.len();

    // ── Title ──────────────────────────────────────────────
    out.push_str(&format!(
        "Vigil Baseline {} \u{2014} Health Check\n",
        env!("CARGO_PKG_VERSION")
    ));
    let title_len = format!(
        "Vigil Baseline {} \u{2014} Health Check",
        env!("CARGO_PKG_VERSION")
    )
    .chars()
    .count();
    for _ in 0..title_len {
        out.push('\u{2550}'); // ═
    }
    out.push('\n');

    // ── Headline summary ───────────────────────────────────
    out.push('\n');
    let mut parts: Vec<String> = Vec::new();
    if fail_count > 0 {
        parts.push(format!(
            "\u{2717} {}",
            pluralize_label(fail_count, "failure", "failures")
        ));
    }
    if warn_count > 0 {
        parts.push(format!(
            "\u{26A0} {}",
            pluralize_label(warn_count, "warning", "warnings")
        ));
    }
    parts.push(format!("\u{25CF} {} healthy", healthy_count));
    if optional_count > 0 {
        parts.push(format!("\u{25CB} {} optional", optional_count));
    }
    out.push_str(&format!("  {}\n", parts.join("     ")));

    // ── Needs attention zone ───────────────────────────────
    if !needs_attention.is_empty() {
        out.push('\n');
        render_separator(&mut out);
        out.push_str("  Needs attention\n");
        render_separator(&mut out);

        for check in &needs_attention {
            out.push('\n');
            render_attention_row(&mut out, check);
        }
    }

    // ── Healthy zone ───────────────────────────────────────
    out.push('\n');
    render_separator(&mut out);
    out.push_str("  Healthy\n");
    render_separator(&mut out);
    out.push('\n');

    for check in &healthy {
        out.push_str(&format!(
            "  {:<16}{}\n",
            check.name, check.detail
        ));
    }

    // ── Optional items ─────────────────────────────────────
    if !optional.is_empty() {
        out.push('\n');
        for check in &optional {
            out.push_str(&format!(
                "  \u{25CB} {:<13}{}\n",
                check.name, check.detail
            ));
        }
    }

    out.push('\n');
    out
}

/// Render a single row in the "Needs attention" zone.
fn render_attention_row(out: &mut String, check: &DiagnosticCheck) {
    // Row title: marker + name + detail
    out.push_str(&format!(
        "  {} {}\n",
        check.status.marker(),
        check.name
    ));
    // Detail on next line, indented
    out.push_str(&format!("    {}\n", check.detail));

    // Recovery hints with → prefix, max 3
    render_recovery_hints(out, &check.recovery);
}

/// Render recovery hints with → leader, capped at MAX_HINTS_PER_ROW.
fn render_recovery_hints(out: &mut String, recovery: &Recovery) {
    let hints = collect_hints(recovery);
    if hints.is_empty() {
        return;
    }

    out.push('\n');
    for (i, (command, description)) in hints.iter().enumerate() {
        if i >= MAX_HINTS_PER_ROW {
            break;
        }
        if i == 0 {
            // First hint gets the arrow
            if let Some(desc) = description {
                out.push_str(&format!(
                    "      \u{2192} {:<40}{}\n",
                    command, desc
                ));
            } else {
                out.push_str(&format!("      \u{2192} {}\n", command));
            }
        } else {
            // Subsequent hints align under the command column
            if let Some(desc) = description {
                out.push_str(&format!(
                    "        {:<40}{}\n",
                    command, desc
                ));
            } else {
                out.push_str(&format!("        {}\n", command));
            }
        }
    }
}

/// Extract (command_or_instruction, optional_description) pairs from a Recovery.
fn collect_hints(recovery: &Recovery) -> Vec<(String, Option<String>)> {
    match recovery {
        Recovery::Command(cmd) => vec![(cmd.clone(), None)],
        Recovery::CommandWithContext { command, context } => {
            vec![(command.clone(), Some(context.clone()))]
        }
        Recovery::Manual(guidance) => vec![(guidance.clone(), None)],
        Recovery::Documentation(path) => vec![(format!("see: {}", path), None)],
        Recovery::None => vec![],
        Recovery::Multi(hints) => hints
            .iter()
            .map(|h| match h {
                RecoveryHint::Command { verb, command } => {
                    if verb.is_empty() {
                        (command.clone(), None)
                    } else {
                        (command.clone(), Some(verb.to_string()))
                    }
                }
                RecoveryHint::Manual { verb, instruction } => {
                    if verb.is_empty() {
                        (instruction.clone(), None)
                    } else {
                        (instruction.clone(), Some(verb.to_string()))
                    }
                }
                RecoveryHint::Documentation { reference } => {
                    (format!("see: {}", reference), None)
                }
            })
            .collect(),
    }
}

/// Render a 62-column separator line.
fn render_separator(out: &mut String) {
    out.push_str("  ");
    for _ in 0..SEPARATOR_WIDTH {
        out.push('\u{2500}'); // ─
    }
    out.push('\n');
}

fn pluralize_label(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{} {}", n, singular)
    } else {
        format!("{} {}", n, plural)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil::doctor::{CheckStatus, DiagnosticCheck, Recovery, RecoveryHint};

    fn make_check(name: &str, status: CheckStatus, detail: &str, recovery: Recovery) -> DiagnosticCheck {
        DiagnosticCheck {
            name: name.to_string(),
            status,
            detail: detail.to_string(),
            recovery,
        }
    }

    /// INVARIANT: the headline counts in doctor output exactly
    /// match the number of rendered rows of each severity.
    #[test]
    fn doctor_headline_counts_match_rendered_rows() {
        let checks = vec![
            make_check("Daemon", CheckStatus::Ok, "running", Recovery::None),
            make_check("Socket", CheckStatus::Failed, "dropping alerts",
                Recovery::Command("vigil alerts socket disable".into())),
            make_check("Audit log", CheckStatus::Warning, "chain tamper at entry 329459",
                Recovery::Command("vigil audit verify -v".into())),
            make_check("Hooks", CheckStatus::Warning, "last pacman trigger failed",
                Recovery::Command("vigil hooks verify".into())),
            make_check("Config", CheckStatus::Ok, "valid", Recovery::None),
            make_check("Attest key", CheckStatus::Unknown, "not configured (optional)", Recovery::None),
        ];

        let output = render_doctor(&checks);

        // Count markers in the Needs attention zone
        let fail_markers = output.matches("\u{2717}").count();
        let warn_markers = output.matches("\u{26A0}").count();

        // The headline should have the same counts (one occurrence each in headline)
        // Plus the attention zone rows. Headline has 1 ✗ + attention has 1 ✗ = 2 total.
        assert_eq!(fail_markers, 2, "headline + row failure markers: {}", output);
        // Headline has 1 ⚠ + 2 attention rows = 3 total ⚠
        assert_eq!(warn_markers, 3, "headline + row warning markers: {}", output);
    }

    #[test]
    fn doctor_all_healthy_omits_needs_attention() {
        let checks = vec![
            make_check("Daemon", CheckStatus::Ok, "running · pid 94773", Recovery::None),
            make_check("Config", CheckStatus::Ok, "valid", Recovery::None),
            make_check("Database", CheckStatus::Ok, "integrity OK", Recovery::None),
        ];

        let output = render_doctor(&checks);

        assert!(!output.contains("Needs attention"), "all-healthy output must not show Needs attention zone:\n{}", output);
        assert!(output.contains("Healthy"), "must show Healthy zone:\n{}", output);
        assert!(output.contains("\u{25CF} 3 healthy"), "headline must show 3 healthy:\n{}", output);
    }

    #[test]
    fn doctor_failure_only_no_warnings() {
        let checks = vec![
            make_check("Daemon", CheckStatus::Failed, "not running",
                Recovery::Command("sudo systemctl start vigild".into())),
            make_check("Config", CheckStatus::Ok, "valid", Recovery::None),
        ];

        let output = render_doctor(&checks);

        assert!(output.contains("Needs attention"));
        assert!(output.contains("\u{2717} 1 failure"));
        assert!(!output.contains("\u{26A0}"), "no warnings in headline:\n{}", output);
    }

    #[test]
    fn doctor_no_optional_omits_optional_from_headline() {
        let checks = vec![
            make_check("Daemon", CheckStatus::Ok, "running", Recovery::None),
        ];

        let output = render_doctor(&checks);

        assert!(!output.contains("\u{25CB}"), "no optional marker:\n{}", output);
        assert!(!output.contains("optional"), "no optional text:\n{}", output);
    }

    #[test]
    fn doctor_optional_items_shown_separately() {
        let checks = vec![
            make_check("Daemon", CheckStatus::Ok, "running", Recovery::None),
            // Attest key is optional-not-configured per is_optional_not_configured()
            DiagnosticCheck {
                name: "Attest key".to_string(),
                status: CheckStatus::Unknown,
                detail: "not configured (optional, for `vigil attest`)".to_string(),
                recovery: Recovery::None,
            },
        ];

        let output = render_doctor(&checks);

        assert!(output.contains("\u{25CB} 1 optional"), "headline shows optional:\n{}", output);
        assert!(output.contains("\u{25CB} Attest key"), "optional item rendered with ○:\n{}", output);
    }

    #[test]
    fn doctor_max_three_hints_per_row() {
        let checks = vec![
            make_check("Audit log", CheckStatus::Warning, "chain tamper",
                Recovery::Multi(vec![
                    RecoveryHint::Command { verb: "recover", command: "vigil audit verify -v".into() },
                    RecoveryHint::Command { verb: "investigate", command: "vigil why <path>".into() },
                    RecoveryHint::Command { verb: "acknowledge", command: "vigil ack chain-break".into() },
                    RecoveryHint::Command { verb: "backup", command: "cp audit.db audit.db.bak".into() },
                    RecoveryHint::Manual { verb: "note", instruction: "extra hint".into() },
                ])),
        ];

        let output = render_doctor(&checks);

        // Count lines starting with → or aligned under it in the hint block
        let hint_lines: Vec<&str> = output
            .lines()
            .filter(|l| {
                let trimmed = l.trim_start();
                trimmed.starts_with('\u{2192}') || (l.starts_with("        ") && !l.trim().is_empty())
            })
            .collect();
        assert!(
            hint_lines.len() <= MAX_HINTS_PER_ROW,
            "expected at most {} hint lines, got {}: {:?}",
            MAX_HINTS_PER_ROW,
            hint_lines.len(),
            hint_lines
        );
    }

    #[test]
    fn doctor_failures_appear_before_warnings() {
        let checks = vec![
            make_check("Hooks", CheckStatus::Warning, "hook failed",
                Recovery::Command("vigil hooks verify".into())),
            make_check("Socket", CheckStatus::Failed, "dropping alerts",
                Recovery::Command("vigil alerts socket disable".into())),
            make_check("Config", CheckStatus::Ok, "valid", Recovery::None),
        ];

        let output = render_doctor(&checks);

        let fail_pos = output.find("\u{2717} Socket").expect("failure row must exist");
        let warn_pos = output.find("\u{26A0} Hooks").expect("warning row must exist");
        assert!(
            fail_pos < warn_pos,
            "failures must appear before warnings in Needs attention zone"
        );
    }
}
