use std::path::Path;

use chrono::Utc;

use vigil::doctor;
use vigil::types::OutputFormat;

use super::common::{format_count, print_header, query_control_socket};

pub(crate) fn cmd_status(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    // Try live query via control socket first
    if !cfg.daemon.control_socket.as_os_str().is_empty() {
        if let Ok(live) = query_control_socket(&cfg.daemon.control_socket, r#"{"method":"status"}"#)
        {
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&live)?);
                return Ok(());
            }

            print_header("Vigil Baseline — Daemon Status (live)");

            // ── Daemon ──
            println!("  Daemon");
            println!("  ──────");
            if let Some(daemon) = live.get("daemon") {
                let state = daemon
                    .get("state")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let uptime = daemon
                    .get("uptime_seconds")
                    .and_then(|u| u.as_i64())
                    .unwrap_or(0);
                let version = daemon
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");

                println!("    State          ● {}", state);
                println!("    Version        v{}", version);
                println!(
                    "    Uptime         {}",
                    doctor::format_compact_duration(uptime)
                );

                // Try to get PID from daemon probe
                let probe = doctor::probe_daemon(&cfg);
                if let Some(pid) = probe.pid {
                    println!("    PID            {}", pid);
                }
            }

            // ── Events ──
            if let Some(metrics) = live.get("metrics") {
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
                let debounced = metrics
                    .get("events_debounced")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let filtered = metrics
                    .get("events_filtered")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let backpressure = metrics
                    .get("backpressure_events")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                println!();
                println!("  Events");
                println!("  ──────");
                println!("    Received       {}", format_count(received));
                println!("    Processed      {}", format_count(processed));
                println!("    Dropped        {}", format_count(dropped));
                println!("    Debounced      {}", format_count(debounced));
                println!("    Filtered       {}", format_count(filtered));
                println!("    Backpressure   {}", format_count(backpressure));

                // ── Integrity ──
                let hashes = metrics
                    .get("hashes_computed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let changes = metrics
                    .get("changes_detected")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let scan_ms = metrics
                    .get("scan_duration_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let scan_total = metrics
                    .get("last_scan_total")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                println!();
                println!("  Integrity");
                println!("  ─────────");
                println!("    Hashes         {}", format_count(hashes));
                println!("    Changes        {}", format_count(changes));
                if scan_total > 0 {
                    println!(
                        "    Last scan      {} files in {:.1}s",
                        format_count(scan_total),
                        scan_ms as f64 / 1000.0
                    );
                }

                // ── Alerts ──
                let dispatched = metrics
                    .get("alerts_dispatched")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let suppressed = metrics
                    .get("alerts_suppressed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                println!();
                println!("  Alerts");
                println!("  ──────");
                println!("    Dispatched     {}", format_count(dispatched));
                println!("    Suppressed     {}", format_count(suppressed));

                // ── Database ──
                let db_writes = metrics
                    .get("db_writes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let db_errors = metrics
                    .get("db_errors")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let cache_hits = metrics
                    .get("cache_hits")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let cache_misses = metrics
                    .get("cache_misses")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let baseline_updates = metrics
                    .get("baseline_updates")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                println!();
                println!("  Database");
                println!("  ────────");
                println!("    Writes         {}", format_count(db_writes));
                println!("    Errors         {}", format_count(db_errors));
                println!(
                    "    Cache          {} hits / {} misses",
                    format_count(cache_hits),
                    format_count(cache_misses)
                );
                println!(
                    "    Baseline       {} updates",
                    format_count(baseline_updates)
                );

                // ── Internal ──
                let panics = metrics
                    .get("panics_caught")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                println!();
                println!("  Internal");
                println!("  ────────");
                println!("    Panics         {}", format_count(panics));
            }

            println!();
            println!("  source: control socket");
            println!();
            return Ok(());
        }
    }

    // Fall back to stale file-based status
    let daemon = doctor::probe_daemon(&cfg);
    let backend = doctor::monitor_backend_label(&cfg);
    let baseline_entries = doctor::baseline_count_with_fallback(&cfg);
    let recent_changes = doctor::recent_audit_change_count(&cfg, Utc::now().timestamp() - 86_400);
    let metrics = doctor::read_metrics(&cfg);
    let metrics_json = doctor::read_metrics(&cfg)
        .and_then(|m| serde_json::to_value(m).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let state_json = doctor::read_state_json(&cfg).unwrap_or_else(|| serde_json::json!({}));
    let health_json = doctor::read_health_snapshot(&cfg)
        .and_then(|h| serde_json::to_value(h).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let last_scan_at = doctor::metrics_file_timestamp(&cfg);

    if format == OutputFormat::Json {
        let out = serde_json::json!({
            "daemon": daemon,
            "backend": backend,
            "baseline_entries": baseline_entries,
            "changes_last_24h": recent_changes,
            "last_scan_at": last_scan_at,
            "metrics": metrics_json,
            "state": state_json,
            "health": health_json,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    print_header("Vigil Baseline — Daemon Status");

    // ── Daemon ──
    println!("  Daemon");
    println!("  ──────");
    if daemon.running {
        let uptime = daemon
            .uptime_seconds
            .map(doctor::format_compact_duration)
            .unwrap_or_else(|| "unknown".to_string());
        println!("    State          ● running (uptime {})", uptime);
        println!("    Backend        {}", backend);
    } else {
        println!("    State          ✗ not running");
    }

    // ── Data ──
    println!();
    println!("  Data");
    println!("  ────");
    match baseline_entries {
        Some(count) => println!(
            "    Baseline       {} entries",
            format_count(count.max(0) as u64)
        ),
        None => println!("    Baseline       unknown"),
    }

    if daemon.running {
        println!("    Changes (24h)  {}", recent_changes.unwrap_or(0));
    } else {
        println!("    Changes (24h)  unknown (daemon offline)");
    }

    // ── Last Scan ──
    let last_scan_label = last_scan_at
        .map(doctor::format_relative_timestamp)
        .unwrap_or_else(|| "unknown".to_string());

    let cleanliness = if recent_changes.unwrap_or(0) == 0 {
        "clean".to_string()
    } else {
        format!("{} changes", recent_changes.unwrap_or(0))
    };

    println!();
    println!("  Last Scan");
    println!("  ─────────");
    println!("    Completed      {}", last_scan_label);
    if metrics.is_some() {
        println!("    Result         {}", cleanliness);
    }

    println!();
    println!("  source: file snapshot (may be up to 60s stale)");
    println!();

    Ok(())
}
