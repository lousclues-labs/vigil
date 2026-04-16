use std::path::Path;

use vigil::types::Change;

use super::common::{
    format_audit_timestamp, print_change_detail, print_header,
    truncate_hash,
};

pub(crate) fn cmd_diff(config_path: Option<&Path>, file_path: &Path) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;
    let audit_conn = match vigil::db::open_audit_db(&cfg) {
        Ok(conn) => Some(conn),
        Err(e) => {
            eprintln!(
                "warning: failed to open audit database (history panel disabled): {}",
                e
            );
            None
        }
    };

    let canonical = std::fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_path_buf());
    let path_str = canonical.to_string_lossy();

    let baseline = match vigil::db::baseline_ops::get_by_path(&conn, &path_str)? {
        Some(b) => b,
        None => {
            println!();
            println!("  ○ {} is not in the baseline.", canonical.display());
            println!();
            println!("  This file is not monitored. To include it, add its");
            println!("  parent directory to a watch group in vigil.toml and");
            println!("  run vigil init.");
            return Ok(());
        }
    };

    let opts = vigil::types::CaptureOpts {
        force_hash: true,
        max_file_size: cfg.scanner.max_file_size,
        mmap_threshold: cfg.scanner.mmap_threshold,
        baseline_mtime: None,
        baseline_hash: None,
    };

    match vigil::types::FileSnapshot::from_path(&canonical, &opts)? {
        vigil::types::SnapshotOrDeleted::Deleted => {
            print_header(&format!("Vigil Baseline — Diff: {}", canonical.display()));
            println!("  ✗ File has been deleted from the filesystem.");
            println!(
                "    Last known hash: {}",
                truncate_hash(&baseline.content.hash)
            );
            if let Some(ref pkg) = baseline.package {
                println!("    Package: {}", pkg);
            }
            println!();
        }
        vigil::types::SnapshotOrDeleted::Snapshot(snapshot) => {
            let changes = snapshot.diff(&baseline);
            print_header(&format!("Vigil Baseline — Diff: {}", canonical.display()));

            if changes.is_empty() {
                println!("  ● No changes. File matches baseline.");
                println!();
                println!("    Hash:        {}", truncate_hash(&baseline.content.hash));
                println!("    Size:        {} bytes", baseline.content.size);
                println!("    Permissions: {:04o}", baseline.permissions.mode);
                println!(
                    "    Owner:       {}:{}",
                    baseline.permissions.owner_uid, baseline.permissions.owner_gid
                );
                if let Some(ref pkg) = baseline.package {
                    println!("    Package:     {}", pkg);
                }
                println!("    Source:       {}", baseline.source);
            } else {
                println!(
                    "  ⚠ {} change{} detected:",
                    changes.len(),
                    if changes.len() == 1 { "" } else { "s" }
                );
                println!();

                for c in &changes {
                    print_change_detail(c);
                }

                if let Some(ref pkg) = baseline.package {
                    println!();
                    println!("    package: {}", pkg);
                }
            }

            println!();
        }
    }

    if let Some(conn) = audit_conn.as_ref() {
        render_diff_history_panel(conn, canonical.as_path())?;
    }

    Ok(())
}

fn render_diff_history_panel(conn: &rusqlite::Connection, path: &Path) -> vigil::Result<()> {
    let path_str = path.to_string_lossy();
    let entries = vigil::db::audit_ops::get_recent_for_path(conn, path_str.as_ref(), 8)?;

    println!("  Recent audit history");
    println!("  ────────────────────");

    if entries.is_empty() {
        println!("    No audit entries found for this path.");
        println!();
        return Ok(());
    }

    for entry in &entries {
        let mut flags = Vec::new();
        if entry.maintenance {
            flags.push("maintenance");
        }
        if entry.suppressed {
            flags.push("suppressed");
        }

        let suffix = if flags.is_empty() {
            String::new()
        } else {
            format!(" ({})", flags.join(", "))
        };

        println!(
            "    {} {:<8} {}{}",
            format_audit_timestamp(entry.timestamp),
            entry.severity.to_uppercase(),
            summarize_audit_changes(&entry.changes_json),
            suffix
        );
    }

    println!(
        "    showing {} most recent entr{} for this path.",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    println!();

    Ok(())
}

fn summarize_audit_changes(changes_json: &str) -> String {
    let changes = match serde_json::from_str::<Vec<Change>>(changes_json) {
        Ok(parsed) => parsed,
        Err(_) => return "unparseable change set".to_string(),
    };

    if changes.is_empty() {
        return "(no change details)".to_string();
    }

    let mut labels: Vec<String> = Vec::new();
    for change in &changes {
        let label = change.to_string();
        if !labels.iter().any(|existing| existing == &label) {
            labels.push(label);
        }
    }

    let shown: Vec<String> = labels.iter().take(3).cloned().collect();
    let mut summary = shown.join(", ");

    if labels.len() > shown.len() {
        summary.push_str(&format!(", +{} more", labels.len() - shown.len()));
    }

    summary
}
