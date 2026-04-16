use std::path::Path;

use vigil::types::{Change, OutputFormat};

use super::common::{
    format_audit_timestamp, format_count, parse_time_filter, print_change_detail, print_header,
};

pub(crate) fn cmd_audit(
    config_path: Option<&Path>,
    action: vigil::cli::AuditAction,
    format: OutputFormat,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;

    match action {
        vigil::cli::AuditAction::Show {
            last,
            path,
            severity,
            group,
            since,
            until,
            maintenance,
            suppressed,
            verbose,
        } => {
            let since_ts = since.as_deref().and_then(parse_time_filter);
            let until_ts = until.as_deref().and_then(parse_time_filter);

            let q = vigil::db::audit_ops::AuditQuery {
                path: path.clone(),
                severity: severity.clone(),
                group: group.clone(),
                since: since_ts,
                until: until_ts,
                maintenance_only: maintenance,
                suppressed_only: suppressed,
                limit: last,
            };

            let entries = vigil::db::audit_ops::query(&conn, &q)?;
            let total = vigil::db::audit_ops::count(&conn)?;

            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&entries_to_json(&entries))?
                );
                return Ok(());
            }

            // Build header with active filters
            let mut filter_parts = Vec::new();
            if let Some(ref p) = path {
                filter_parts.push(format!("path={}", p));
            }
            if let Some(ref s) = severity {
                filter_parts.push(format!("severity={}", s));
            }
            if let Some(ref g) = group {
                filter_parts.push(format!("group={}", g));
            }
            if let Some(ref s) = since {
                filter_parts.push(format!("since={}", s));
            }
            if let Some(ref u) = until {
                filter_parts.push(format!("until={}", u));
            }
            if maintenance {
                filter_parts.push("maintenance".to_string());
            }
            if suppressed {
                filter_parts.push("suppressed".to_string());
            }

            if filter_parts.is_empty() {
                print_header(&format!(
                    "Vigil Baseline — Audit Log ({} of {} entries)",
                    entries.len(),
                    total
                ));
            } else {
                print_header(&format!(
                    "Vigil Baseline — Audit Log ({} match{})",
                    entries.len(),
                    if entries.len() == 1 { "" } else { "es" }
                ));
                println!("  Filters: {}", filter_parts.join(", "));
                println!();
            }

            if entries.is_empty() {
                println!("  No entries found.");
            } else {
                for e in &entries {
                    let sev_marker = match e.severity.as_str() {
                        "critical" => "✗",
                        "high" => "✗",
                        "medium" => "⚠",
                        _ => "○",
                    };

                    println!(
                        "  {} {} {} {}",
                        format_audit_timestamp(e.timestamp),
                        sev_marker,
                        e.severity.to_uppercase(),
                        e.path
                    );

                    if verbose {
                        if let Ok(changes) = serde_json::from_str::<Vec<Change>>(&e.changes_json) {
                            for c in &changes {
                                print_change_detail(c);
                            }
                        }
                        if let Some(ref pkg) = e.package {
                            println!("    package: {}", pkg);
                        }
                        if let Some(ref grp) = e.monitored_group {
                            println!("    group: {}", grp);
                        }
                        if e.maintenance {
                            println!("    ○ during maintenance window");
                        }
                        if e.suppressed {
                            println!("    ○ alert suppressed");
                        }
                        println!();
                    }
                }

                if !verbose {
                    println!();
                }

                println!(
                    "  {} of {} total entr{} shown.",
                    entries.len(),
                    format_count(total),
                    if total == 1 { "y" } else { "ies" }
                );

                if !verbose && entries.iter().any(|e| !e.changes_json.is_empty()) {
                    println!("  Add -v for change details.");
                }
            }
        }
        vigil::cli::AuditAction::Stats { period } => {
            let since_ts = parse_time_filter(&period);
            let total = vigil::db::audit_ops::count(&conn)?;

            if format == OutputFormat::Json {
                let severity_counts = vigil::db::audit_ops::get_severity_counts(&conn, since_ts)?;
                let top_paths = vigil::db::audit_ops::get_top_paths(&conn, since_ts, 10)?;
                let group_counts = vigil::db::audit_ops::get_group_counts(&conn, since_ts)?;
                let period_count = match since_ts {
                    Some(ts) => vigil::db::audit_ops::count_since(&conn, ts)?,
                    None => total,
                };

                let out = serde_json::json!({
                    "period": period,
                    "total_entries": total,
                    "period_entries": period_count,
                    "by_severity": severity_counts.iter().map(|(s, c)| serde_json::json!({"severity": s, "count": c})).collect::<Vec<_>>(),
                    "top_paths": top_paths.iter().map(|(p, c)| serde_json::json!({"path": p, "count": c})).collect::<Vec<_>>(),
                    "by_group": group_counts.iter().map(|(g, c)| serde_json::json!({"group": g, "count": c})).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }

            let period_label = match period.as_str() {
                "today" => "today",
                "24h" => "last 24 hours",
                "7d" => "last 7 days",
                "30d" => "last 30 days",
                "all" => "all time",
                _ => &period,
            };

            print_header(&format!(
                "Vigil Baseline — Audit Statistics ({})",
                period_label
            ));

            let period_count = match since_ts {
                Some(ts) => vigil::db::audit_ops::count_since(&conn, ts)?,
                None => total,
            };

            println!("  Total entries    {}", format_count(total));
            println!("  Period entries   {}", format_count(period_count));
            println!();

            let severity_counts = vigil::db::audit_ops::get_severity_counts(&conn, since_ts)?;
            if !severity_counts.is_empty() {
                println!("  By Severity");
                println!("  ───────────");
                for (sev, count) in &severity_counts {
                    let marker = match sev.as_str() {
                        "critical" => "✗",
                        "high" => "✗",
                        "medium" => "⚠",
                        _ => "○",
                    };
                    println!(
                        "    {} {:<12} {}",
                        marker,
                        sev.to_uppercase(),
                        format_count(*count)
                    );
                }
            }

            let group_counts = vigil::db::audit_ops::get_group_counts(&conn, since_ts)?;
            if !group_counts.is_empty() {
                println!();
                println!("  By Watch Group");
                println!("  ──────────────");
                for (grp, count) in &group_counts {
                    println!("    {:<20} {}", grp, format_count(*count));
                }
            }

            let top_paths = vigil::db::audit_ops::get_top_paths(&conn, since_ts, 10)?;
            if !top_paths.is_empty() {
                println!();
                println!("  Most Changed Paths");
                println!("  ──────────────────");
                for (path, count) in &top_paths {
                    println!("    {:>6}  {}", format_count(*count), path);
                }
            }

            println!();
        }
        vigil::cli::AuditAction::Verify => {
            let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn)?;

            print_header("Vigil BaselineBaseline — Audit Chain Verification");

            println!("  Total entries    {}", format_count(total));
            println!("  Valid links      {}", format_count(valid));
            println!("  Missing hashes   {}", missing);
            println!("  Chain breaks     {}", breaks.len());

            if !breaks.is_empty() {
                println!();
                println!("  Break locations:");
                for (id, ts) in &breaks {
                    println!("    id={} timestamp={}", id, ts);
                }
            }

            println!();
            if breaks.is_empty() && missing == 0 {
                println!("  ● Audit chain intact. No tampering detected.");
            } else if !breaks.is_empty() {
                println!(
                    "  ✗ Audit chain broken. {} break{} detected.",
                    breaks.len(),
                    if breaks.len() == 1 { "" } else { "s" }
                );
            } else {
                println!(
                    "  ⚠ Audit chain intact but {} entr{} missing HMAC hashes.",
                    missing,
                    if missing == 1 { "y" } else { "ies" }
                );
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
                let changes: serde_json::Value = serde_json::from_str(&e.changes_json)
                    .unwrap_or_else(|_| serde_json::Value::String(e.changes_json.clone()));

                let process: serde_json::Value = e
                    .process_json
                    .as_deref()
                    .and_then(|p| serde_json::from_str(p).ok())
                    .unwrap_or(serde_json::Value::Null);

                serde_json::json!({
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "timestamp_iso": chrono::DateTime::from_timestamp(e.timestamp, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default(),
                    "path": e.path,
                    "changes": changes,
                    "severity": e.severity,
                    "monitored_group": e.monitored_group,
                    "process": process,
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
