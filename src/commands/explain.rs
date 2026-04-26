//! `vigil explain` subcommand: why a path is or is not watched.

use std::path::Path;

use vigil::db::{self, audit_ops, baseline_ops};
use vigil::doctor;
use vigil::types::OutputFormat;

pub(crate) fn cmd_explain(
    config_path: Option<&Path>,
    target_path: &Path,
    verbose: bool,
    format: OutputFormat,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let target = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf());
    let target_str = target.to_string_lossy();

    // Find matching watch group
    let mut matched_group: Option<(String, &vigil::config::WatchGroup, String)> = None;
    for (name, group) in &cfg.watch {
        for pattern in &group.paths {
            let expanded = expand_path(pattern);
            if path_matches(&target_str, &expanded) {
                let match_reason = if expanded == target_str.as_ref() {
                    format!("literal path in [watch.{}]", name)
                } else if expanded.ends_with('/') && target_str.starts_with(&expanded) {
                    format!("directory prefix in [watch.{}]", name)
                } else {
                    format!("pattern '{}' in [watch.{}]", pattern, name)
                };
                matched_group = Some((name.clone(), group, match_reason));
                break;
            }
        }
        if matched_group.is_some() {
            break;
        }
    }

    // Try to read baseline entry
    let baseline_entry = if cfg.daemon.db_path.exists() {
        if let Ok(conn) = doctor::open_existing_db_pub(&cfg.daemon.db_path) {
            baseline_ops::get_by_path(&conn, &target_str).ok().flatten()
        } else {
            None
        }
    } else {
        None
    };

    // Try to read audit history
    let audit_entries = {
        let audit_path = db::audit_db_path(&cfg);
        if audit_path.exists() {
            if let Ok(conn) = doctor::open_existing_db_pub(&audit_path) {
                audit_ops::search(&conn, Some(&target_str), None, if verbose { 50 } else { 8 })
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    if format == OutputFormat::Json {
        let json = serde_json::json!({
            "path": target_str,
            "watch_group": matched_group.as_ref().map(|(name, group, reason)| serde_json::json!({
                "name": name,
                "severity": group.severity.to_string(),
                "matched_by": reason,
                "mode": group.mode.as_str(),
            })),
            "baseline": baseline_entry.as_ref().map(|e| serde_json::json!({
                "hash": e.content.hash,
                "mode": e.permissions.mode,
                "owner_uid": e.permissions.owner_uid,
                "owner_gid": e.permissions.owner_gid,
                "inode": e.identity.inode,
                "mtime": e.mtime,
                "size": e.content.size,
            })),
            "audit_history_count": audit_entries.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("{}", target_str);

    if let Some((name, group, reason)) = &matched_group {
        println!("  watch group:    {}", name);
        println!("  severity:       {}", group.severity);
        println!("  matched by:     {}", reason);
        if group.mode != vigil::config::WatchMode::PerFile {
            println!("  mode:           {}", group.mode.as_str());
        }

        if let Some(entry) = &baseline_entry {
            let hash_display = if verbose {
                entry.content.hash.clone()
            } else {
                format!(
                    "blake3:{}",
                    entry.content.hash.chars().take(16).collect::<String>()
                )
            };
            println!(
                "  baseline:       hash {} mode {:04o} owner {}:{} inode {}",
                hash_display,
                entry.permissions.mode,
                entry.permissions.owner_uid,
                entry.permissions.owner_gid,
                entry.identity.inode
            );

            println!(
                "  last verified:  {}",
                vigil::display::time::format_absolute(entry.updated_at)
            );
        } else {
            println!("  baseline:       no entry (run `vigil init` or `vigil check --accept`)");
        }

        if !audit_entries.is_empty() {
            let label = if verbose { "all" } else { "recent" };
            println!("  audit history:  {} {} events", audit_entries.len(), label);
            if verbose {
                for entry in &audit_entries {
                    let ts = vigil::display::time::format_absolute(entry.timestamp);
                    let suppressed = if entry.suppressed {
                        " (suppressed)"
                    } else {
                        ""
                    };
                    let maintenance = if entry.maintenance {
                        " (maintenance)"
                    } else {
                        ""
                    };
                    println!(
                        "    {} {} {}{}{}",
                        ts,
                        entry.severity,
                        summarize_changes(&entry.changes_json),
                        suppressed,
                        maintenance
                    );
                }
            }
        } else {
            println!("  audit history:  none");
        }
    } else {
        println!("  watch group:    not watched");
        println!();

        // Find nearby watched paths
        let mut nearby: Vec<String> = Vec::new();
        let parent = target.parent();
        for group in cfg.watch.values() {
            for pattern in &group.paths {
                let expanded = expand_path(pattern);
                // Check if parent is watched
                if let Some(p) = parent {
                    let ps = p.to_string_lossy();
                    if expanded.starts_with(ps.as_ref())
                        || ps.starts_with(expanded.trim_end_matches('/'))
                    {
                        nearby.push(expanded);
                    }
                }
            }
        }
        nearby.sort();
        nearby.dedup();

        if !nearby.is_empty() {
            println!("  Nearby watched paths:");
            for p in nearby.iter().take(5) {
                println!("    {}", p);
            }
        } else {
            println!("  No nearby watched paths found.");
        }

        println!();
        println!("  To watch this path, add it to a watch group in your config.");
    }

    Ok(())
}

fn expand_path(pattern: &str) -> String {
    if pattern.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &pattern[1..]);
        }
    }
    pattern.to_string()
}

fn path_matches(target: &str, pattern: &str) -> bool {
    if pattern == target {
        return true;
    }
    // Directory prefix match
    if pattern.ends_with('/') && target.starts_with(pattern) {
        return true;
    }
    // Target is the directory itself
    if pattern.ends_with('/') && format!("{}/", target) == pattern {
        return true;
    }
    // Glob match
    if let Ok(matcher) = globset::Glob::new(pattern).map(|g| g.compile_matcher()) {
        return matcher.is_match(target);
    }
    false
}

fn summarize_changes(changes_json: &str) -> String {
    let changes: Vec<serde_json::Value> = serde_json::from_str(changes_json).unwrap_or_default();
    if changes.is_empty() {
        return "unknown".to_string();
    }
    changes
        .iter()
        .filter_map(|c| {
            // Changes are serialized as enum variants
            if let Some(obj) = c.as_object() {
                obj.keys().next().map(|k| k.to_string())
            } else {
                c.as_str().map(|s| s.to_string())
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
