//! `vigil status` subcommand: daemon health and baseline summary.

use std::path::Path;

use chrono::Utc;

use vigil::db::{self, audit_ops, baseline_ops};
use vigil::doctor;
use vigil::types::OutputFormat;

use super::common::{format_count, query_control_socket};

/// Collected status summary used by both `vigil status` and `vigil why-silent`.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct StatusSummary {
    pub verdict: String,
    pub reason: Option<String>,
    pub daemon_running: bool,
    pub daemon_pid: Option<i32>,
    pub daemon_uptime: Option<String>,
    pub version: String,
    pub backend: String,
    pub backend_degraded: bool,
    pub watching_paths: Option<u64>,
    pub watching_groups: Option<usize>,
    pub baseline_epoch: Option<String>,
    pub baseline_entries: Option<i64>,
    pub last_check: Option<String>,
    pub last_check_result: Option<String>,
    pub audit_chain_status: String,
    pub audit_chain_last_verified: Option<String>,
    pub suppressions: u64,
    pub wal_state: String,
}

/// Build a StatusSummary from live daemon or offline sources.
pub(crate) fn build_status_summary(cfg: &vigil::config::Config) -> StatusSummary {
    let daemon = doctor::probe_daemon(cfg);
    let backend = doctor::monitor_backend_label(cfg);
    let backend_degraded = backend.contains("inotify") || backend.contains("fallback");

    let baseline_entries = doctor::baseline_count_with_fallback(cfg);
    let last_scan_at = doctor::metrics_file_timestamp(cfg);
    let recent_changes = doctor::recent_audit_change_count(cfg, Utc::now().timestamp() - 86_400);

    // Audit chain status
    let audit_path = db::audit_db_path(cfg);
    let (chain_status, chain_last_verified) = if audit_path.exists() {
        if let Ok(conn) = doctor::open_existing_db_pub(&audit_path) {
            match audit_ops::verify_chain(&conn) {
                Ok((_total, _valid, breaks, _missing)) => {
                    if breaks.is_empty() {
                        ("intact".to_string(), Some(format_utc_now()))
                    } else {
                        ("broken".to_string(), None)
                    }
                }
                Err(_) => ("unverified".to_string(), None),
            }
        } else {
            ("unverified".to_string(), None)
        }
    } else {
        ("unverified".to_string(), None)
    };

    // WAL state
    let wal_path = cfg.daemon.runtime_dir.join("detection.wal");
    let wal_state = if !wal_path.exists() {
        "empty".to_string()
    } else {
        match std::fs::metadata(&wal_path) {
            Ok(m) if m.len() <= 64 => "empty".to_string(),
            Ok(m) => format!("{} bytes pending", m.len()),
            Err(_) => "unknown".to_string(),
        }
    };

    let watching_groups = Some(cfg.watch.len());
    let watching_paths: Option<u64> = baseline_entries.map(|c| c.max(0) as u64);

    let last_check = last_scan_at.map(vigil::display::time::format_absolute);

    let last_check_result = recent_changes.map(|c| {
        if c == 0 {
            "clean".to_string()
        } else {
            format!("{} changes", c)
        }
    });

    // Baseline epoch from config_state
    let baseline_epoch = if cfg.daemon.db_path.exists() {
        if let Ok(conn) = doctor::open_existing_db_pub(&cfg.daemon.db_path) {
            baseline_ops::get_config_state(&conn, "baseline_initialized")
                .ok()
                .flatten()
                .or(Some("1".to_string()))
        } else {
            None
        }
    } else {
        None
    };

    // Determine verdict
    let (verdict, reason) = if !daemon.running {
        (
            "down".to_string(),
            Some("vigild is not running. Real-time coverage is OFF.".to_string()),
        )
    } else if backend_degraded {
        (
            "degraded".to_string(),
            Some(format!("backend {} -- reduced coverage", backend)),
        )
    } else if chain_status == "broken" {
        (
            "degraded".to_string(),
            Some("audit chain has breaks".to_string()),
        )
    } else {
        ("ok".to_string(), None)
    };

    StatusSummary {
        verdict,
        reason,
        daemon_running: daemon.running,
        daemon_pid: daemon.pid,
        daemon_uptime: daemon.uptime_seconds.map(doctor::format_compact_duration),
        version: env!("CARGO_PKG_VERSION").to_string(),
        backend: if daemon.running {
            backend
        } else {
            "none".to_string()
        },
        backend_degraded,
        watching_paths,
        watching_groups,
        baseline_epoch,
        baseline_entries,
        last_check,
        last_check_result,
        audit_chain_status: chain_status,
        audit_chain_last_verified: chain_last_verified,
        suppressions: 0,
        wal_state,
    }
}

pub(crate) fn cmd_status(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    // Try live query via control socket first for richer data
    let live_data = if !cfg.daemon.control_socket.as_os_str().is_empty() {
        query_control_socket(&cfg.daemon.control_socket, r#"{"method":"status"}"#).ok()
    } else {
        None
    };

    let summary = build_status_summary(&cfg);

    if format == OutputFormat::Json {
        let json = serde_json::json!({
            "verdict": summary.verdict,
            "reason": summary.reason,
            "daemon_running": summary.daemon_running,
            "daemon_pid": summary.daemon_pid,
            "daemon_uptime": summary.daemon_uptime,
            "version": summary.version,
            "backend": summary.backend,
            "backend_degraded": summary.backend_degraded,
            "watching_paths": summary.watching_paths,
            "watching_groups": summary.watching_groups,
            "baseline_epoch": summary.baseline_epoch,
            "baseline_entries": summary.baseline_entries,
            "last_check": summary.last_check,
            "last_check_result": summary.last_check_result,
            "audit_chain_status": summary.audit_chain_status,
            "audit_chain_last_verified": summary.audit_chain_last_verified,
            "suppressions": summary.suppressions,
            "wal_state": summary.wal_state,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // Default: compact operator-friendly output.
    // Three lines. Everything an operator wants at 9am.
    if let Some(ref live) = live_data {
        if live.get("ok") == Some(&serde_json::Value::Bool(true)) {
            let daemon = live.get("daemon").cloned().unwrap_or_default();
            let state = daemon
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let uptime_secs = daemon
                .get("uptime_seconds")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let baseline_count = daemon
                .get("baseline_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let alerts_total = daemon
                .get("alerts_total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let critical_alerts_total = daemon
                .get("critical_alerts_total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let uptime_str = doctor::format_compact_duration(uptime_secs);
            let last_scan_str = summary.last_check.as_deref().unwrap_or("never");
            let last_changes = summary.last_check_result.as_deref().unwrap_or("unknown");

            eprintln!(
                "vigild {}. uptime {}. baseline {} entries.",
                state,
                uptime_str,
                format_count(baseline_count.max(0) as u64)
            );
            eprintln!(
                "last scan: {} ({}). {} alerts total ({} critical).",
                last_scan_str, last_changes, alerts_total, critical_alerts_total
            );
            return Ok(());
        }
    }

    // Fallback: offline summary
    println!("{}", summary.verdict);

    if summary.daemon_running {
        let uptime = summary.daemon_uptime.as_deref().unwrap_or("unknown");
        let pid = summary
            .daemon_pid
            .map(|p| format!(" (pid {})", p))
            .unwrap_or_default();
        println!("  daemon:        up {}{}", uptime, pid);
    } else {
        println!("  daemon:        not running");
    }

    println!("  version:       {}", summary.version);
    println!("  backend:       {}", summary.backend);

    if let (Some(paths), Some(groups)) = (summary.watching_paths, summary.watching_groups) {
        println!(
            "  watching:      {} paths across {} groups",
            format_count(paths),
            groups
        );
    }

    if let Some(entries) = summary.baseline_entries {
        let epoch = summary.baseline_epoch.as_deref().unwrap_or("?");
        println!(
            "  baseline:      epoch {}, {} entries",
            epoch,
            format_count(entries.max(0) as u64)
        );
    } else {
        println!("  baseline:      no baseline found");
    }

    if let Some(ref last) = summary.last_check {
        let result = summary.last_check_result.as_deref().unwrap_or("unknown");
        println!("  last check:    {} ({})", last, result);
    } else {
        println!("  last check:    unknown");
    }

    if let Some(ref verified) = summary.audit_chain_last_verified {
        println!(
            "  audit chain:   {} (last verified {})",
            summary.audit_chain_status, verified
        );
    } else {
        println!("  audit chain:   {}", summary.audit_chain_status);
    }

    println!(
        "  suppressions:  {}",
        if summary.suppressions == 0 {
            "none".to_string()
        } else {
            format_count(summary.suppressions)
        }
    );
    println!("  WAL:           {}", summary.wal_state);

    if let Some(ref reason) = summary.reason {
        println!("  reason:        {}", reason);
    }

    // Print detailed live data if available
    if let Some(live) = live_data {
        if let Some(metrics) = live.get("metrics") {
            println!();
            println!("  Events");
            println!("  ──────");
            let received = metrics
                .get("events_received")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let processed = metrics
                .get("events_processed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let dropped = metrics
                .get("events_dropped")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("    Received       {}", format_count(received));
            println!("    Processed      {}", format_count(processed));
            println!("    Dropped        {}", format_count(dropped));
        }
    }

    Ok(())
}

fn format_utc_now() -> String {
    vigil::display::time::format_absolute(chrono::Utc::now().timestamp())
}
