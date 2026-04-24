//! `vigil audit` subcommand: show, stats, verify, prune.

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
                    "Vigil Baseline -- Audit Log ({} of {} entries)",
                    entries.len(),
                    total
                ));
            } else {
                print_header(&format!(
                    "Vigil Baseline -- Audit Log ({} match{})",
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
            let live = vigil::db::audit_ops::count_detection_entries(&conn).unwrap_or(total);
            let in_checkpoints =
                vigil::db::audit_ops::checkpoint_covered_entries(&conn).unwrap_or(0);
            let db_size = vigil::db::audit_ops::db_file_size(&conn).unwrap_or(0);
            let max_bytes = cfg.audit.max_size_bytes();
            let pct = if max_bytes > 0 {
                db_size as f64 / max_bytes as f64 * 100.0
            } else {
                0.0
            };
            let oldest_live =
                vigil::db::audit_ops::oldest_detection_timestamp(&conn).unwrap_or(None);

            if format == OutputFormat::Json {
                let severity_counts = vigil::db::audit_ops::get_severity_counts(&conn, since_ts)?;
                let top_paths = vigil::db::audit_ops::get_top_paths(&conn, since_ts, 10)?;
                let group_counts = vigil::db::audit_ops::get_group_counts(&conn, since_ts)?;
                let period_count = match since_ts {
                    Some(ts) => vigil::db::audit_ops::count_since(&conn, ts)?,
                    None => total,
                };

                let out = serde_json::json!({
                    "audit_log_mb": db_size / 1_048_576,
                    "cap_percent": format!("{:.1}", pct),
                    "cap_mb": cfg.audit.max_size_mb,
                    "entries_live": live,
                    "entries_in_checkpoints": in_checkpoints,
                    "oldest_live_entry": oldest_live,
                    "retention_days": cfg.audit.retention_days,
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

            print_header("Vigil Baseline -- Audit Statistics");

            // Retention summary
            println!(
                "  audit log: {} MB ({:.1}% of {} MB cap)",
                db_size / 1_048_576,
                pct,
                cfg.audit.max_size_mb
            );
            println!(
                "  entries: {} live; {} in checkpoints",
                format_count(live),
                format_count(in_checkpoints)
            );

            if let Some(ts) = oldest_live {
                let age_days = (chrono::Utc::now().timestamp() - ts) / 86400;
                let oldest_str = chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                println!(
                    "  oldest live entry: {} ({} days ago)",
                    oldest_str, age_days
                );
            } else {
                println!("  oldest live entry: none");
            }

            println!();

            let period_label = match period.as_str() {
                "today" => "today",
                "24h" => "last 24 hours",
                "7d" => "last 7 days",
                "30d" => "last 30 days",
                "all" => "all time",
                _ => &period,
            };

            let period_count = match since_ts {
                Some(ts) => vigil::db::audit_ops::count_since(&conn, ts)?,
                None => total,
            };

            println!(
                "  Period ({})  {}",
                period_label,
                format_count(period_count)
            );
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
            let detail = vigil::db::audit_ops::verify_chain_detail(&conn, None)?;

            if format == OutputFormat::Json {
                let out = serde_json::json!({
                    "total_entries": detail.total,
                    "valid_links": detail.valid,
                    "missing_hashes": detail.missing,
                    "chain_breaks": detail.breaks.len(),
                    "break_locations": detail.breaks.iter().map(|(id, ts)| {
                        serde_json::json!({"id": id, "timestamp": ts})
                    }).collect::<Vec<_>>(),
                    "checkpoints": detail.checkpoint_count,
                    "checkpoint_covered_entries": detail.checkpoint_covered_entries,
                    "oldest_checkpoint_timestamp": detail.oldest_checkpoint_timestamp,
                    "chain_intact": detail.breaks.is_empty() && detail.missing == 0,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }

            print_header("Vigil Baseline -- Audit Chain Verification");

            if detail.breaks.is_empty() && detail.missing == 0 {
                println!(
                    "  audit log: {} entries verified, chain intact",
                    format_count(detail.total)
                );

                if detail.checkpoint_count > 0 {
                    let oldest_str = detail
                        .oldest_checkpoint_timestamp
                        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!(
                        "  checkpoints: {} present, covering {} entries dating back to {}",
                        detail.checkpoint_count,
                        format_count(detail.checkpoint_covered_entries),
                        oldest_str
                    );
                }
            } else if !detail.breaks.is_empty() {
                let (first_id, _first_ts) = detail.breaks[0];
                // Check if the break is at a checkpoint
                let is_checkpoint = conn
                    .query_row(
                        "SELECT record_type FROM audit_log WHERE id = ?1",
                        rusqlite::params![first_id],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .ok()
                    .flatten();

                if is_checkpoint.as_deref() == Some("checkpoint") {
                    eprintln!(
                        "  audit log: chain broken at sequence {} (AuditCheckpoint)",
                        first_id
                    );
                    eprintln!("  the checkpoint's chain_hmac does not match its contents");
                    eprintln!("  this indicates tampering with the checkpoint record");
                    eprintln!("  recover with: vigil daemon recover --reason audit_chain_broken");
                    std::process::exit(2);
                } else {
                    println!(
                        "  ✗ Audit chain broken. {} break{} detected.",
                        detail.breaks.len(),
                        if detail.breaks.len() == 1 { "" } else { "s" }
                    );
                    println!();
                    println!("  Break locations:");
                    for (id, ts) in &detail.breaks {
                        println!("    id={} timestamp={}", id, ts);
                    }
                    eprintln!("  recover with: vigil daemon recover --reason audit_chain_broken");
                    std::process::exit(2);
                }
            } else {
                println!(
                    "  ⚠ Audit chain intact but {} entr{} missing HMAC hashes.",
                    detail.missing,
                    if detail.missing == 1 { "y" } else { "ies" }
                );
            }
        }
        vigil::cli::AuditAction::Segments => {
            let segments = vigil::db::audit_ops::list_segments(&conn)?;
            if segments.is_empty() {
                println!("No sealed segments. All entries are in the live audit log.");
            } else {
                print_header("Vigil Baseline -- Audit Segments");
                let header_archive = "Archive";
                println!(
                    "  {:<6} {:<14} {:<14} {:<22} {:<22} {}",
                    "ID",
                    "First seq",
                    "Last seq",
                    "First timestamp",
                    "Last timestamp",
                    header_archive
                );
                for seg in &segments {
                    let first_ts = format_audit_timestamp(seg.first_timestamp);
                    let last_ts = format_audit_timestamp(seg.last_timestamp);
                    let archive = seg.archive_path.as_deref().unwrap_or("(live)");
                    println!(
                        "  {:<6} {:<14} {:<14} {:<22} {:<22} {}",
                        seg.id, seg.first_sequence, seg.last_sequence, first_ts, last_ts, archive
                    );
                }
                println!();
                println!(
                    "  {} segment{}.",
                    segments.len(),
                    if segments.len() == 1 { "" } else { "s" }
                );
            }
        }
        vigil::cli::AuditAction::Prune { before, confirm } => {
            let cutoff_ts = match parse_time_filter(&before) {
                Some(ts) => ts,
                None => {
                    // Try ISO 8601 date parse
                    chrono::NaiveDate::parse_from_str(&before, "%Y-%m-%d")
                        .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp())
                        .map_err(|_| {
                            vigil::error::VigilError::Config(format!(
                                "cannot parse --before '{}'; use ISO 8601 date like '2025-01-01'",
                                before
                            ))
                        })?
                }
            };

            // Identify what would be pruned
            let range = vigil::db::audit_ops::identify_prune_range(
                &conn,
                cutoff_ts,
                cfg.audit.min_entries_to_keep,
            )?;

            match range {
                None => {
                    println!("Nothing to prune. Either no entries are older than {}, or pruning would leave fewer than {} entries.",
                        before, cfg.audit.min_entries_to_keep);
                    return Ok(());
                }
                Some((first_id, last_id, count)) => {
                    let entries =
                        vigil::db::audit_ops::read_detection_range(&conn, first_id, last_id)?;
                    let first_ts = entries.first().map(|e| e.timestamp).unwrap_or(0);
                    let last_ts = entries.last().map(|e| e.timestamp).unwrap_or(0);

                    let first_date = chrono::DateTime::from_timestamp(first_ts, 0)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    let last_date = chrono::DateTime::from_timestamp(last_ts, 0)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    if !confirm {
                        // Dry run
                        println!("Dry run (pass --confirm to execute):");
                        println!(
                            "  would prune {} entries from {} to {}",
                            count, first_date, last_date
                        );
                        println!("  ID range: {} to {}", first_id, last_id);

                        let remaining = vigil::db::audit_ops::count_detection_entries(&conn)
                            .unwrap_or(0)
                            .saturating_sub(count as u64);
                        println!(
                            "  entries remaining after prune: {}",
                            format_count(remaining)
                        );
                        return Ok(());
                    }

                    // Execute prune
                    print_header("Vigil Baseline -- Audit Prune");

                    let prev_chain =
                        vigil::db::audit_ops::get_previous_chain_hash(&conn, first_id)?;
                    let bridge = entries.last().unwrap().chain_hash.clone();

                    // Compute pruned-range HMAC
                    let pruned_hmac = {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(prev_chain.as_bytes());
                        for e in &entries {
                            let canonical = format!(
                                "{}|{}|{}|{}",
                                e.timestamp, e.path, e.changes_json, e.severity
                            );
                            hasher.update(canonical.as_bytes());
                        }
                        hasher.finalize().to_hex().to_string()
                    };

                    let now_ts = chrono::Utc::now().timestamp();

                    // Load HMAC key if available
                    let hmac_key = if cfg.security.hmac_signing {
                        vigil::hmac::load_hmac_key(&cfg.security.hmac_key_path).ok()
                    } else {
                        None
                    };
                    let hmac_key_bytes: Option<&[u8]> = hmac_key.as_ref().map(|k| k.as_slice());

                    // Atomic transaction
                    conn.execute("BEGIN IMMEDIATE", [])?;
                    let result: Result<(), vigil::error::VigilError> = (|| {
                        // Delete originals
                        conn.execute(
                            "DELETE FROM audit_log WHERE id >= ?1 AND id <= ?2 AND (record_type = 'detection' OR record_type IS NULL)",
                            rusqlite::params![first_id, last_id],
                        )?;

                        // Insert checkpoint
                        let hmac_val = hmac_key_bytes.map(|key| {
                            let data = vigil::db::audit_ops::build_checkpoint_hmac_data(
                                now_ts,
                                first_id,
                                last_id,
                                count,
                                &pruned_hmac,
                                &prev_chain,
                            );
                            vigil::hmac::compute_hmac(key, &data).unwrap_or_default()
                        });

                        conn.execute(
                            "INSERT INTO audit_log (
                                id, timestamp, path, changes_json, severity, monitored_group,
                                process_json, package, maintenance, suppressed, hmac, chain_hash,
                                record_type, first_sequence, last_sequence, first_timestamp,
                                last_timestamp, entry_count, pruned_range_hmac
                            ) VALUES (
                                ?1, ?2, ?3, ?4, ?5, NULL,
                                NULL, NULL, 0, 0, ?6, ?7,
                                'checkpoint', ?8, ?9, ?10,
                                ?11, ?12, ?13
                            )",
                            rusqlite::params![
                                last_id,
                                now_ts,
                                format!("vigil:checkpoint:{}-{}", first_id, last_id),
                                format!(
                                    "{{\"previous_chain_hash\":\"{}\",\"operator_prune\":true}}",
                                    prev_chain
                                ),
                                "info",
                                hmac_val,
                                bridge,
                                first_id,
                                last_id,
                                first_ts,
                                last_ts,
                                count,
                                pruned_hmac,
                            ],
                        )?;

                        // Record the operator prune as an audit entry
                        let prune_record_json = serde_json::json!({
                            "action": "operator_prune",
                            "uid": nix::unistd::getuid().as_raw(),
                            "pid": std::process::id(),
                            "exe": std::env::current_exe().ok().map(|p| p.display().to_string()),
                            "argv": std::env::args().collect::<Vec<_>>(),
                            "entries_pruned": count,
                            "range": format!("{} to {}", first_date, last_date),
                        });

                        let last_hash = vigil::db::audit_ops::get_last_chain_hash(&conn)?
                            .unwrap_or_else(|| bridge.clone());

                        vigil::db::audit_ops::insert_self_check_entry(
                            &conn,
                            &prune_record_json.to_string(),
                            "Info",
                            &last_hash,
                            hmac_key_bytes,
                        )?;

                        conn.execute("COMMIT", [])?;
                        Ok(())
                    })();

                    match result {
                        Ok(()) => {
                            println!(
                                "  pruned {} entries from {} to {}",
                                count, first_date, last_date
                            );
                            println!("  checkpoint written at id {}", last_id);
                            println!("  operator action recorded in audit log");
                        }
                        Err(e) => {
                            let _ = conn.execute("ROLLBACK", []);
                            return Err(vigil::error::VigilError::Daemon(
                                format!("prune failed: {}. No entries were deleted. Run `vigil audit verify` to check chain integrity.", e),
                            ));
                        }
                    }
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
