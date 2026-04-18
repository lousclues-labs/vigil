use std::path::Path;

use vigil::types::OutputFormat;

use super::common::format_count;
use super::status::build_status_summary;

pub(crate) fn cmd_why_silent(
    config_path: Option<&Path>,
    format: OutputFormat,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let summary = build_status_summary(&cfg);

    let mut reasons: Vec<String> = Vec::new();

    if !summary.daemon_running {
        reasons.push("vigild is not running. Real-time coverage is OFF.".to_string());
    }

    if summary.backend_degraded {
        reasons.push(format!("backend {} — reduced coverage", summary.backend));
    }

    if summary.audit_chain_status == "broken" {
        reasons.push("audit chain has breaks — tamper evidence degraded".to_string());
    }

    if summary.audit_chain_status == "unverified" {
        reasons.push("audit chain not yet verified".to_string());
    }

    if summary.wal_state != "empty" && summary.wal_state != "unknown" {
        reasons.push(format!("detection WAL: {}", summary.wal_state));
    }

    if summary.suppressions > 0 {
        reasons.push(format!("{} active suppressions", summary.suppressions));
    }

    let headline = if reasons.is_empty() {
        "nothing has changed.".to_string()
    } else {
        reasons[0].clone()
    };

    if format == OutputFormat::Json {
        let json = serde_json::json!({
            "watching_paths": summary.watching_paths,
            "watching_groups": summary.watching_groups,
            "backend": summary.backend,
            "backend_degraded": summary.backend_degraded,
            "daemon_running": summary.daemon_running,
            "suppressions": summary.suppressions,
            "wal_state": summary.wal_state,
            "audit_chain_status": summary.audit_chain_status,
            "last_check": summary.last_check,
            "last_check_result": summary.last_check_result,
            "reason": headline,
            "issues": reasons,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // Print structured report
    if let (Some(paths), Some(groups)) = (summary.watching_paths, summary.watching_groups) {
        println!(
            "Watching:                  {} paths across {} watch groups",
            format_count(paths),
            groups
        );
    }

    let backend_detail = if summary.backend_degraded {
        format!("{} (fallback — reduced coverage)", summary.backend)
    } else if summary.backend == "fanotify" {
        "fanotify (kernel-level, full coverage)".to_string()
    } else if summary.backend == "none" {
        "none (daemon not running)".to_string()
    } else {
        summary.backend.clone()
    };
    println!("Backend:                   {}", backend_detail);

    println!(
        "Suppressions active:       {}",
        if summary.suppressions == 0 {
            "none".to_string()
        } else {
            format_count(summary.suppressions)
        }
    );

    if let Some(ref last) = summary.last_check {
        let result = summary.last_check_result.as_deref().unwrap_or("unknown");
        println!("Last successful check:     {} ({})", last, result);
    } else {
        println!("Last successful check:     unknown");
    }

    println!("Detection WAL:             {}", summary.wal_state);

    if let Some(ref verified) = summary.audit_chain_last_verified {
        println!(
            "Audit chain:               {}, last verified {}",
            summary.audit_chain_status, verified
        );
    } else {
        println!("Audit chain:               {}", summary.audit_chain_status);
    }

    if !summary.daemon_running {
        println!();
        println!("Daemon:                    not running");
    }

    println!();
    println!("Reason for current silence: {}", headline);

    Ok(())
}
