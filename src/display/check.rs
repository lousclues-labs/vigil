//! Check report construction and terminal rendering for `vigil check`.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Local, Utc};
use serde_json::json;

use crate::error::{ScanWarning, WarningSeverity};
use crate::scanner::ScanResult;
use crate::types::{ChangeResult, Severity};

#[cfg(test)]
use crate::types::ScanMode;

use super::explain;
use super::format::{
    exit_code_description, format_age, format_count, format_size, severity_marker, severity_style,
    truncate_path, Style, Styled,
};
use super::widgets::{render_change_oneline, render_change_table, render_histogram};
use super::{CheckReport, CheckReportMeta, InitReport, PackageGroup};

/// Build a CheckReport from scan results and baseline metadata.
pub fn build_check_report(scan: ScanResult, meta: CheckReportMeta) -> CheckReport {
    let mut modified = 0u64;
    let mut created = 0u64;
    let mut deleted = 0u64;

    for change in &scan.changes {
        let has_deleted = change
            .changes
            .iter()
            .any(|c| matches!(c, crate::types::Change::Deleted));
        let has_created = change
            .changes
            .iter()
            .any(|c| matches!(c, crate::types::Change::Created));

        if has_deleted {
            deleted += 1;
        } else if has_created {
            created += 1;
        } else {
            modified += 1;
        }
    }

    let unchanged = meta
        .total_baseline_entries
        .saturating_sub(modified + created + deleted);

    let mut severity_counts: BTreeMap<Severity, u64> = BTreeMap::new();
    for change in &scan.changes {
        *severity_counts.entry(change.severity).or_insert(0) += 1;
    }

    let mut investigate = Vec::new();
    let mut attention = Vec::new();
    let mut low_changes = Vec::new();

    for change in &scan.changes {
        match change.severity {
            Severity::Critical | Severity::High => investigate.push(change.clone()),
            Severity::Medium => attention.push(change.clone()),
            Severity::Low => low_changes.push(change.clone()),
        }
    }

    let (benign, benign_ungrouped) = group_by_package(low_changes);

    CheckReport {
        scan,
        baseline_fingerprint: meta.baseline_fingerprint,
        baseline_established: meta.baseline_established,
        hmac_signed: meta.hmac_signed,
        scan_mode: meta.mode,
        total_baseline_entries: meta.total_baseline_entries,
        previous_check_at: meta.previous_check_at,
        previous_check_changes: meta.previous_check_changes,
        unchanged_count: unchanged,
        modified_count: modified,
        created_count: created,
        deleted_count: deleted,
        severity_counts,
        investigate,
        attention,
        benign,
        benign_ungrouped,
        db_path: meta.db_path,
    }
}

/// Group LOW-severity changes by package name.
/// Grouping uses `package_update` when available, and falls back to count threshold (>=3).
fn group_by_package(changes: Vec<ChangeResult>) -> (Vec<PackageGroup>, Vec<ChangeResult>) {
    let mut by_package: BTreeMap<String, Vec<ChangeResult>> = BTreeMap::new();
    let mut ungrouped = Vec::new();

    for change in changes {
        if let Some(ref pkg) = change.package {
            by_package.entry(pkg.clone()).or_default().push(change);
        } else {
            ungrouped.push(change);
        }
    }

    let mut groups = Vec::new();
    for (pkg_name, pkg_changes) in by_package {
        let has_package_update = pkg_changes.iter().any(|c| c.package_update);
        if has_package_update || pkg_changes.len() >= 3 {
            let summary = summarize_paths(&pkg_changes);
            groups.push(PackageGroup {
                package_name: pkg_name,
                changes: pkg_changes,
                paths_summary: summary,
            });
        } else {
            ungrouped.extend(pkg_changes);
        }
    }

    (groups, ungrouped)
}

fn summarize_paths(changes: &[ChangeResult]) -> String {
    if changes.is_empty() {
        return String::new();
    }
    if changes.len() == 1 {
        return changes[0].path.display().to_string();
    }

    let paths: Vec<String> = changes
        .iter()
        .map(|c| c.path.display().to_string())
        .collect();
    let prefix = common_path_prefix(&paths);
    if prefix.is_empty() {
        format!("{} files", changes.len())
    } else {
        format!("{}*", prefix)
    }
}

fn common_path_prefix(paths: &[String]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    if paths.len() == 1 {
        if let Some(pos) = paths[0].rfind('/') {
            return paths[0][..=pos].to_string();
        }
        return String::new();
    }

    let first = &paths[0];
    let mut prefix_end = 0;

    for (i, ch) in first.char_indices() {
        if paths[1..]
            .iter()
            .all(|p| p.get(..i + ch.len_utf8()) == first.get(..i + ch.len_utf8()))
        {
            if ch == '/' {
                prefix_end = i + 1;
            }
        } else {
            break;
        }
    }

    first[..prefix_end].to_string()
}

/// Exit code based on highest severity detected.
pub fn exit_code(report: &CheckReport) -> i32 {
    if report.scan.changes.is_empty() {
        return 0;
    }
    let max_severity = report.scan.changes.iter().map(|c| c.severity).max();
    match max_severity {
        Some(Severity::Critical) => 3,
        Some(Severity::High) => 2,
        Some(Severity::Medium) | Some(Severity::Low) => 1,
        None => 0,
    }
}

/// Render full human-readable check output.
pub fn render_human(
    report: &CheckReport,
    term: &crate::display::term::TermInfo,
    verbose: bool,
) -> String {
    let styled = Styled::new(term);
    let mut out = String::new();

    let title = "Vigil Baseline -- Integrity Check";
    out.push('\n');
    out.push_str(&styled.paint(Style::Bold, title));
    out.push('\n');
    out.push_str(&"═".repeat(title.len()));
    out.push_str("\n\n");

    if let Some(ref fp) = report.baseline_fingerprint {
        out.push_str(&format!("  Baseline   {}", styled.paint(Style::Bold, fp)));
        if let Some(ts) = report.baseline_established {
            if let Some(dt) = chrono::DateTime::<Utc>::from_timestamp(ts, 0) {
                let local = dt.with_timezone(&Local);
                out.push_str(&format!("   established {}", local.format("%d %b %H:%M")));

                let age = Utc::now().timestamp().saturating_sub(ts);
                out.push_str(&format!(" ({})", format_age(age)));
            }
        }
        out.push('\n');
    }

    let hmac_status = if report.hmac_signed {
        styled.paint(Style::BoldGreen, "HMAC ● signed")
    } else {
        styled.paint(Style::Yellow, "HMAC ○ disabled")
    };
    out.push_str(&format!(
        "  Scanned    {} files in {:.1}s    mode: {} · {}\n",
        format_count(report.scan.total_checked),
        report.scan.duration_ms as f64 / 1000.0,
        report.scan_mode,
        hmac_status,
    ));

    out.push_str(&format!(
        "  Coverage   {} baseline entries · {} scan errors\n",
        format_count(report.total_baseline_entries),
        report.scan.errors,
    ));

    if let Some(last_ts) = report.previous_check_at {
        let age = Utc::now().timestamp().saturating_sub(last_ts);
        let outcome = match report.previous_check_changes {
            Some(0) => "clean".to_string(),
            Some(n) => format!("{} change{}", n, if n == 1 { "" } else { "s" }),
            None => "unknown".to_string(),
        };
        if age > 86_400 {
            out.push_str(&format!(
                "  Last check {} ({}) {}\n",
                format_age(age),
                outcome,
                styled.paint(Style::Yellow, "⚠ stale"),
            ));
        } else {
            out.push_str(&format!("  Last check {} ({})\n", format_age(age), outcome));
        }
    }

    out.push('\n');

    if report.scan.changes.is_empty() {
        out.push_str(&format!("  ╭{}╮\n", "─".repeat(46)));
        out.push_str(&format!(
            "  │  {}  │\n",
            styled.paint(Style::BoldGreen, "● Boundaries intact")
        ));
        out.push_str(&format!("  ╰{}╯\n", "─".repeat(46)));
    } else {
        out.push_str(&render_histogram(&report.severity_counts, term));
        out.push_str("\n\n");

        let change_count = report.scan.changes.len();
        let full_detail_all = verbose || change_count <= 5;
        let medium_detail = verbose || change_count <= 20;

        if full_detail_all {
            out.push_str(
                &styled.paint(Style::Bold, &format!("  ▸ Changes ({})\n\n", change_count)),
            );
            for c in &report.scan.changes {
                render_change_entry(&mut out, c, term, true);
            }
        } else {
            if !report.investigate.is_empty() {
                out.push_str(&styled.paint(
                    Style::BoldRed,
                    &format!("  ▸ Investigate ({})\n\n", report.investigate.len()),
                ));
                for c in &report.investigate {
                    render_change_entry(&mut out, c, term, true);
                }
            }

            if !report.attention.is_empty() {
                out.push_str(&styled.paint(
                    Style::BoldYellow,
                    &format!("  ▸ Attention ({})\n\n", report.attention.len()),
                ));
                for c in &report.attention {
                    render_change_entry(&mut out, c, term, medium_detail);
                }
            }

            let benign_total: usize = report.benign.iter().map(|g| g.changes.len()).sum::<usize>()
                + report.benign_ungrouped.len();
            if benign_total > 0 {
                out.push_str(&styled.paint(
                    Style::Dim,
                    &format!("  ▸ Likely benign ({})\n\n", benign_total),
                ));

                for group in &report.benign {
                    out.push_str(&format!(
                        "    {} {:<30} {} files\n",
                        styled.paint(Style::Dim, "○"),
                        styled.paint(Style::Dim, &group.package_name),
                        group.changes.len(),
                    ));

                    if verbose {
                        for change in &group.changes {
                            out.push_str(&format!(
                                "      {}\n",
                                truncate_path(
                                    &change.path.display().to_string(),
                                    term.width as usize - 8,
                                )
                            ));
                        }
                    } else {
                        out.push_str(&format!(
                            "      {}\n",
                            styled.paint(Style::Dim, &group.paths_summary),
                        ));
                    }
                }

                for c in &report.benign_ungrouped {
                    render_change_entry(&mut out, c, term, verbose);
                }
            }
        }
    }

    render_scan_issues(report, &styled, &mut out);

    out.push('\n');
    out.push_str(&styled.paint(Style::Bold, "  Next steps:\n"));

    if report.scan.changes.is_empty() {
        out.push_str("    vigil watch                      # Start continuous monitoring\n");
    } else {
        out.push_str("    vigil check --verbose            # Expand all details\n");
        out.push_str("    vigil audit show --last 50       # Review historical timeline\n");
        out.push_str("    vigil check --accept --dry-run   # Preview baseline update\n");
    }

    if report.scan.errors > 0 {
        out.push_str("    sudo vigil check                 # Re-run with elevated coverage\n");
    }

    let code = exit_code(report);
    if term.is_tty && code != 0 {
        out.push('\n');
        out.push_str(&format!(
            "  Exit code: {} ({})\n",
            code,
            exit_code_description(code)
        ));
    }

    out.push('\n');
    out
}

fn render_scan_issues(report: &CheckReport, styled: &Styled<'_>, out: &mut String) {
    if report.scan.errors == 0 && report.scan.warnings.is_empty() {
        return;
    }

    out.push_str(&styled.paint(
        Style::BoldYellow,
        &format!(
            "  ── Scan issues ({}) ─────────────────────────\n\n",
            report.scan.warnings.len()
        ),
    ));

    for warning in &report.scan.warnings {
        let marker = match warning.severity {
            WarningSeverity::Info => "○",
            WarningSeverity::Warning => "⚠",
            WarningSeverity::Error => "✗",
        };
        out.push_str(&format!(
            "  {} {}: {} ({})\n",
            marker,
            warning.path.display(),
            warning.detail,
            match warning.severity {
                WarningSeverity::Info => "info",
                WarningSeverity::Warning => "warning",
                WarningSeverity::Error => "error",
            }
        ));
    }

    if report.scan.errors > 0 {
        out.push('\n');
        out.push_str("  Coverage is reduced until these scan issues are resolved.\n");
    }

    let guidance = scan_issue_guidance(&report.scan.warnings);
    if !guidance.is_empty() {
        out.push('\n');
        for g in guidance {
            out.push_str(&format!("  {}\n", g));
        }
    }

    out.push('\n');
}

fn scan_issue_guidance(warnings: &[ScanWarning]) -> Vec<&'static str> {
    let mut tips = Vec::new();
    let mut seen = BTreeSet::new();

    for w in warnings {
        let detail = w.detail.to_ascii_lowercase();
        if detail.contains("permission denied") && seen.insert("perm") {
            tips.push("Fix: run as root for full coverage: sudo vigil check");
        }
        if (detail.contains("too large") || detail.contains("max file size")) && seen.insert("size")
        {
            tips.push("Fix: raise scanner.max_file_size in vigil.toml if needed");
        }
        if detail.contains("disappeared") && seen.insert("transient") {
            tips.push("Note: transient file disappearance can be normal on active systems");
        }
    }

    tips
}

fn render_change_entry(
    out: &mut String,
    change: &ChangeResult,
    term: &crate::display::term::TermInfo,
    expanded: bool,
) {
    let styled = Styled::new(term);
    let (marker, label) = severity_marker(&change.severity);
    let style = severity_style(&change.severity);
    let path_display = truncate_path(&change.path.display().to_string(), term.width as usize - 20);

    out.push_str(&format!(
        "    {} {} {}\n",
        styled.paint(style, marker),
        styled.paint(style, label),
        styled.paint(Style::Bold, &path_display),
    ));

    if expanded {
        out.push_str(&render_change_table(&change.changes, term));
    } else {
        for c in &change.changes {
            out.push_str(&format!("      {}\n", render_change_oneline(c)));
        }
    }

    // "Why" explanations are the most operator-helpful signal.
    let mut why_lines = BTreeSet::new();
    for c in &change.changes {
        if let Some(why) = explain::explain(c, change.path.as_ref()) {
            why_lines.insert(why);
        }
    }
    for why in why_lines {
        out.push_str(&format!("      why: {}\n", why));
    }

    if let Some(ref pkg) = change.package {
        out.push_str(&format!("      package: {}\n", pkg));
        if change.package_update {
            out.push_str("      package_update: true\n");
        }
    }

    out.push('\n');
}

/// Render brief one-line output.
pub fn render_brief(report: &CheckReport, term: &crate::display::term::TermInfo) -> String {
    let styled = Styled::new(term);

    if report.scan.changes.is_empty() {
        let msg = format!(
            "● ok ({} files, {:.1}s)",
            format_count(report.scan.total_checked),
            report.scan.duration_ms as f64 / 1000.0,
        );
        return styled.paint(Style::Green, &msg) + "\n";
    }

    let mut parts = Vec::new();
    let severity_order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];
    for sev in &severity_order {
        if let Some(&count) = report.severity_counts.get(sev) {
            let label = match sev {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
            };
            parts.push(format!("{} {}", count, label));
        }
    }

    let summary = parts.join(" · ");
    let max_sev = report
        .scan
        .changes
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(Severity::Low);
    let marker = if max_sev >= Severity::High {
        "✗"
    } else {
        "⚠"
    };
    let style = severity_style(&max_sev);

    let msg = format!(
        "{} {} ({} files, {:.1}s)",
        marker,
        summary,
        format_count(report.scan.total_checked),
        report.scan.duration_ms as f64 / 1000.0,
    );
    styled.paint(style, &msg) + "\n"
}

/// Render JSON output for check.
/// Keeps compatibility with the original `ScanResult` JSON shape.
pub fn render_json(report: &CheckReport) -> String {
    let warnings: Vec<serde_json::Value> = report
        .scan
        .warnings
        .iter()
        .map(|w| {
            json!({
                "path": w.path,
                "detail": w.detail,
                "severity": match w.severity {
                    WarningSeverity::Info => "info",
                    WarningSeverity::Warning => "warning",
                    WarningSeverity::Error => "error",
                }
            })
        })
        .collect();

    let obj = json!({
        "total_checked": report.scan.total_checked,
        "changes_found": report.scan.changes_found,
        "errors": report.scan.errors,
        "warnings": warnings,
        "changes": report.scan.changes,
        "duration_ms": report.scan.duration_ms,
    });
    serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{}".into()) + "\n"
}

/// Render human-readable init output.
pub fn render_init_human(report: &InitReport, term: &crate::display::term::TermInfo) -> String {
    let styled = Styled::new(term);
    let mut out = String::new();

    let title = "Vigil Baseline -- Baseline Initialized";
    out.push('\n');
    out.push_str(&styled.paint(Style::Bold, title));
    out.push('\n');
    out.push_str(&"═".repeat(title.len()));
    out.push_str("\n\n");

    if let Some(ref fp) = report.baseline_fingerprint {
        out.push_str(&format!("  Baseline   {}", styled.paint(Style::Bold, fp)));
        out.push_str("   ");
        let hmac_line = if report.hmac_signed {
            styled.paint(Style::BoldGreen, "HMAC ● signed")
        } else {
            styled.paint(Style::Yellow, "HMAC ○ disabled")
        };
        out.push_str(&hmac_line);
        out.push('\n');
    }

    out.push_str(&format!(
        "  Building baseline from {} watch group{}...\n\n",
        report.result.groups.len(),
        if report.result.groups.len() == 1 {
            ""
        } else {
            "s"
        },
    ));

    for group in &report.result.groups {
        let paths = if group.paths.is_empty() {
            "(no paths configured)".to_string()
        } else {
            group.paths.join(", ")
        };

        out.push_str(&format!(
            "    {:<16} {}\n",
            styled.paint(Style::Bold, &group.name),
            paths,
        ));

        if group.errors > 0 {
            out.push_str(&format!(
                "                     {} files baselined ({} capture errors)\n",
                format_count(group.file_count),
                group.errors,
            ));
        } else {
            out.push_str(&format!(
                "                     {} files baselined\n",
                format_count(group.file_count),
            ));
        }
        out.push('\n');
    }

    let duration_s = report.result.duration.as_secs_f64();
    let throughput = if duration_s > 0.0 {
        report.result.total_count as f64 / duration_s
    } else {
        0.0
    };

    out.push_str(&format!(
        "  Total: {} files in {:.1}s ({:.0} files/sec)\n",
        format_count(report.result.total_count),
        duration_s,
        throughput,
    ));
    out.push_str(&format!(
        "  Database: {} ({})\n",
        report.db_path.display(),
        format_size(report.result.db_size_bytes),
    ));

    if let Some(ref profile) = report.profile {
        out.push('\n');
        out.push_str(&styled.paint(Style::Bold, "  Baseline Profile:\n"));
        out.push_str(&format!(
            "    Executables      {}\n",
            format_count(profile.executables),
        ));
        if profile.setuid > 0 {
            out.push_str(&format!(
                "    Setuid           {}\n",
                format_count(profile.setuid)
            ));
        }
        if profile.setgid > 0 {
            out.push_str(&format!(
                "    Setgid           {}\n",
                format_count(profile.setgid)
            ));
        }
        out.push_str(&format!(
            "    Config files     {} (under /etc)\n",
            format_count(profile.config_files),
        ));
        if profile.keys_certs > 0 {
            out.push_str(&format!(
                "    Keys & certs     {}\n",
                format_count(profile.keys_certs),
            ));
        }
        out.push_str(&format!(
            "    Package-owned    {} ({:.0}%)\n",
            format_count(profile.package_owned),
            if profile.total > 0 {
                profile.package_owned as f64 / profile.total as f64 * 100.0
            } else {
                0.0
            },
        ));
        out.push_str(&format!(
            "    Unpackaged       {}\n",
            format_count(profile.unpackaged),
        ));
    }

    out.push('\n');
    out.push_str(&styled.paint(Style::Bold, "  Next steps:\n"));
    out.push_str("    vigil check                      # Verify the new baseline\n");
    out.push_str("    vigil watch                      # Start monitoring in foreground\n");
    out.push_str("    vigil doctor                     # Validate local setup\n");

    if std::path::Path::new("/run/systemd/system").exists() {
        out.push_str("    sudo systemctl enable --now vigild.service\n");
    }
    if !report.hmac_signed {
        out.push_str("    vigil setup hmac                 # Enable tamper-evident baselines\n");
    }

    out.push('\n');
    out.push_str(&format!(
        "  {}\n\n",
        styled.paint(Style::Green, "Your filesystem has a witness now."),
    ));

    out
}

/// Render init result as JSON.
pub fn render_init_json(report: &InitReport) -> String {
    let groups: Vec<serde_json::Value> = report
        .result
        .groups
        .iter()
        .map(|g| {
            json!({
                "name": g.name,
                "paths": g.paths,
                "file_count": g.file_count,
                "errors": g.errors,
            })
        })
        .collect();

    let mut obj = json!({
        "total_count": report.result.total_count,
        "groups": groups,
        "duration_secs": report.result.duration.as_secs_f64(),
        "db_size_bytes": report.result.db_size_bytes,
        "baseline_fingerprint": report.baseline_fingerprint,
        "hmac_signed": report.hmac_signed,
    });

    if let Some(ref profile) = report.profile {
        obj["profile"] = json!({
            "total": profile.total,
            "executables": profile.executables,
            "setuid": profile.setuid,
            "setgid": profile.setgid,
            "config_files": profile.config_files,
            "keys_certs": profile.keys_certs,
            "package_owned": profile.package_owned,
            "unpackaged": profile.unpackaged,
        });
    }

    serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{}".into()) + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn meta() -> CheckReportMeta {
        CheckReportMeta {
            mode: ScanMode::Incremental,
            baseline_fingerprint: None,
            baseline_established: None,
            hmac_signed: false,
            total_baseline_entries: 100,
            previous_check_at: None,
            previous_check_changes: None,
            db_path: PathBuf::from("/tmp/test.db"),
        }
    }

    fn make_change(path: &str, severity: Severity, package: Option<&str>) -> ChangeResult {
        ChangeResult {
            path: Arc::new(PathBuf::from(path)),
            changes: vec![crate::types::Change::ContentModified {
                old_hash: "aaa".into(),
                new_hash: "bbb".into(),
            }],
            severity,
            monitored_group: "system".into(),
            process: None,
            package: package.map(String::from),
            package_update: false,
        }
    }

    #[test]
    fn severity_histogram_counts() {
        let scan = ScanResult {
            total_checked: 100,
            changes_found: 3,
            errors: 0,
            warnings: vec![],
            changes: vec![
                make_change("/etc/a", Severity::Critical, None),
                make_change("/etc/b", Severity::Low, None),
                make_change("/etc/c", Severity::Low, None),
            ],
            duration_ms: 1000,
        };

        let mut m = meta();
        m.mode = ScanMode::Full;
        let report = build_check_report(scan, m);

        assert_eq!(report.severity_counts.get(&Severity::Critical), Some(&1));
        assert_eq!(report.severity_counts.get(&Severity::Low), Some(&2));
    }

    #[test]
    fn package_grouping_threshold() {
        let scan = ScanResult {
            total_checked: 100,
            changes_found: 5,
            errors: 0,
            warnings: vec![],
            changes: vec![
                make_change("/usr/lib/mod/a.ko", Severity::Low, Some("linux")),
                make_change("/usr/lib/mod/b.ko", Severity::Low, Some("linux")),
                make_change("/usr/lib/mod/c.ko", Severity::Low, Some("linux")),
                make_change("/usr/bin/foo", Severity::Low, Some("solo-pkg")),
                make_change("/usr/bin/bar", Severity::Low, None),
            ],
            duration_ms: 200,
        };

        let mut m = meta();
        m.mode = ScanMode::Full;
        let report = build_check_report(scan, m);

        assert_eq!(report.benign.len(), 1);
        assert_eq!(report.benign_ungrouped.len(), 2);
    }

    #[test]
    fn exit_code_mapping() {
        let empty = ScanResult::default();
        let mut m = meta();
        m.total_baseline_entries = 10;
        let report = build_check_report(empty, m);
        assert_eq!(exit_code(&report), 0);

        let crit = ScanResult {
            changes: vec![make_change("/etc/shadow", Severity::Critical, None)],
            changes_found: 1,
            ..ScanResult::default()
        };
        let mut m = meta();
        m.total_baseline_entries = 10;
        let report = build_check_report(crit, m);
        assert_eq!(exit_code(&report), 3);
    }
}
