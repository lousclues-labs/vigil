use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use chrono::Utc;
use clap::Parser;

use vigil::cli::{AuditAction, Cli, Command, ConfigAction, LogAction, SetupAction};
use vigil::doctor;
use vigil::types::{Change, OutputFormat, ScanMode};

fn main() {
    init_tracing();

    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn run(cli: Cli) -> vigil::Result<i32> {
    let config_path = cli.config;
    let format = cli.format;

    match cli.command {
        Command::Init { force } => {
            cmd_init(config_path.as_deref(), force)?;
            Ok(0)
        }
        Command::Watch => {
            cmd_watch(config_path.as_deref())?;
            Ok(0)
        }
        Command::Check {
            full,
            now,
            accept,
            path: accept_path,
        } => {
            if now && accept {
                eprintln!("error: --accept cannot be used with --now (baseline updates require direct database access)");
                return Ok(1);
            }
            if now {
                cmd_check_live(config_path.as_deref(), full)?;
            } else {
                cmd_check(config_path.as_deref(), full, accept, accept_path)?;
            }
            Ok(0)
        }
        Command::Diff { path } => {
            cmd_diff(config_path.as_deref(), &path)?;
            Ok(0)
        }
        Command::Status => {
            cmd_status(config_path.as_deref(), format)?;
            Ok(0)
        }
        Command::Doctor {
            format: doctor_format,
        } => cmd_doctor(config_path.as_deref(), doctor_format.unwrap_or(format)),
        Command::Update { repo } => {
            cmd_update(repo)?;
            Ok(0)
        }
        Command::Audit { action } => {
            cmd_audit(config_path.as_deref(), action, format)?;
            Ok(0)
        }
        Command::Config { action } => {
            cmd_config(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Setup { action } => {
            cmd_setup(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Log { action } => {
            cmd_log(action)?;
            Ok(0)
        }
        Command::Version => {
            println!("vigil {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
    }
}

fn cmd_init(config_path: Option<&Path>, force: bool) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    let existing = vigil::db::baseline_ops::count(&conn).unwrap_or(0);
    if existing > 0 && !force {
        println!(
            "⚠ Existing baseline found ({} entries).",
            format_count(existing as u64)
        );
        println!("  Reinitializing will trust the current filesystem state as truth.");
        print!("  Proceed? [y/N] ");
        io::stdout().flush()?;

        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        let accepted = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !accepted {
            println!("Baseline initialization cancelled.");
            return Ok(());
        }
    }

    eprintln!("  Scanning watch paths...");
    let result = vigil::scanner::build_initial_baseline(&conn, &cfg)?;

    print_header("Vigil — Baseline Initialized");

    println!(
        "  Building baseline from {} watch groups...",
        result.groups.len()
    );
    println!();

    for group in &result.groups {
        let paths = if group.paths.is_empty() {
            "(no paths configured)".to_string()
        } else {
            group.paths.join(", ")
        };

        println!("    {:<16} {}", group.name, paths);
        if group.errors > 0 {
            println!(
                "                     {} files baselined ({} capture errors)",
                format_count(group.file_count),
                group.errors
            );
        } else {
            println!(
                "                     {} files baselined",
                format_count(group.file_count)
            );
        }
        println!();
    }

    println!(
        "  Total: {} files in {:.1}s",
        format_count(result.total_count),
        result.duration.as_secs_f64()
    );
    println!(
        "  Database: {} ({})",
        cfg.daemon.db_path.display(),
        format_size(result.db_size_bytes)
    );
    println!();
    println!("  Your filesystem has a witness now.");

    Ok(())
}

fn cmd_watch(config_path: Option<&Path>) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    println!("Starting vigilant monitor in foreground mode (Ctrl+C to stop)...");
    vigil::Daemon::from_config(cfg)?.run()
}

fn cmd_check(
    config_path: Option<&Path>,
    full: bool,
    accept: bool,
    accept_path: Option<String>,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    let mode = if full {
        ScanMode::Full
    } else {
        ScanMode::Incremental
    };

    let mode_label = if full { "Full" } else { "Incremental" };

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    let result = vigil::scanner::run_scan_with_progress(&conn, &cfg, mode, |checked, total| {
        if is_tty && total > 0 {
            let pct = (checked as f64 / total as f64 * 100.0).min(100.0);
            eprint!(
                "\r  Scanning... {}/{} files ({:.0}%)",
                format_count(checked),
                format_count(total),
                pct
            );
            let _ = std::io::stderr().flush();
        }
    })?;

    if is_tty {
        eprint!("\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }

    print_header(&format!("Vigil — {} Integrity Check", mode_label));

    println!("  Files checked   {}", format_count(result.total_checked));
    println!(
        "  Duration        {:.1}s",
        result.duration_ms as f64 / 1000.0
    );
    println!("  Errors          {}", result.errors);
    println!();

    if result.changes.is_empty() {
        println!("  ● No changes detected. Boundaries intact.");
    } else {
        let (marker, _) = severity_display_for_count(&result.changes);
        println!(
            "  {} {} change{} detected:",
            marker,
            result.changes_found,
            if result.changes_found == 1 { "" } else { "s" }
        );

        for change in &result.changes {
            println!();
            let (marker, label) = severity_display(&change.severity);
            println!("  {} {} {}", marker, label, change.path.display());
            for c in &change.changes {
                print_change_detail(c);
            }
            if let Some(ref pkg) = change.package {
                println!("    package: {}", pkg);
            }
        }

        if result.changes.len() > 100 {
            println!();
            println!("  Run vigil audit show for full history.");
        }
    }

    if accept && !result.changes.is_empty() {
        let path_filter: Option<globset::GlobMatcher> = accept_path.as_ref().map(|pattern| {
            globset::Glob::new(pattern)
                .unwrap_or_else(|_| globset::Glob::new("*").unwrap())
                .compile_matcher()
        });

        let changes_to_accept: Vec<_> = result
            .changes
            .iter()
            .filter(|c| match &path_filter {
                Some(matcher) => matcher.is_match(c.path.as_ref()),
                None => true,
            })
            .collect();

        println!();
        if !changes_to_accept.is_empty() {
            if let Some(ref pattern) = accept_path {
                println!(
                    "  Accepting {} of {} changes matching '{}'...",
                    changes_to_accept.len(),
                    result.changes_found,
                    pattern
                );
            } else {
                println!(
                    "  Accepting {} change{} into baseline...",
                    changes_to_accept.len(),
                    if changes_to_accept.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                );
            }

            let now = chrono::Utc::now().timestamp();
            let mut accepted = 0u64;
            let mut failed = 0u64;

            for change in &changes_to_accept {
                let opts = vigil::types::CaptureOpts {
                    force_hash: true,
                    max_file_size: cfg.scanner.max_file_size,
                    mmap_threshold: cfg.scanner.mmap_threshold,
                    baseline_mtime: None,
                    baseline_hash: None,
                };

                match vigil::types::FileSnapshot::from_path(&change.path, &opts) {
                    Ok(vigil::types::SnapshotOrDeleted::Snapshot(snapshot)) => {
                        let entry = vigil::types::BaselineEntry {
                            id: None,
                            path: change.path.as_ref().clone(),
                            identity: snapshot.identity,
                            content: snapshot.content,
                            permissions: snapshot.permissions,
                            security: snapshot.security,
                            mtime: snapshot.mtime,
                            package: change.package.clone(),
                            source: vigil::types::BaselineSource::Manual,
                            added_at: now,
                            updated_at: now,
                        };
                        match vigil::db::baseline_ops::upsert(&conn, &entry) {
                            Ok(()) => accepted += 1,
                            Err(e) => {
                                eprintln!("    failed to accept {}: {}", change.path.display(), e);
                                failed += 1;
                            }
                        }
                    }
                    Ok(vigil::types::SnapshotOrDeleted::Deleted) => {
                        match vigil::db::baseline_ops::remove_by_path(
                            &conn,
                            &change.path.to_string_lossy(),
                        ) {
                            Ok(_) => accepted += 1,
                            Err(e) => {
                                eprintln!("    failed to remove {}: {}", change.path.display(), e);
                                failed += 1;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("    failed to snapshot {}: {}", change.path.display(), e);
                        failed += 1;
                    }
                }
            }

            println!();
            println!("  ● {} accepted, {} failed", accepted, failed);
            println!();
            println!("  Baseline updated. Next scan will treat accepted files as expected.");
            println!("  Audit log preserved — the original detections are permanent.");

            let not_accepted = result.changes.len() - changes_to_accept.len();
            if not_accepted > 0 {
                println!(
                    "  {} change{} not accepted.",
                    not_accepted,
                    if not_accepted == 1 { " was" } else { "s were" }
                );
            }
        } else if accept_path.is_some() {
            println!("  No changes matched the filter pattern. Nothing to accept.");
        }
    }

    println!();

    Ok(())
}

fn cmd_diff(config_path: Option<&Path>, file_path: &Path) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

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
            print_header(&format!("Vigil — Diff: {}", canonical.display()));
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
            print_header(&format!("Vigil — Diff: {}", canonical.display()));

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

    Ok(())
}

fn cmd_check_live(config_path: Option<&Path>, full: bool) -> vigil::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let cfg = vigil::config::load_config(config_path)?;

    if cfg.daemon.control_socket.as_os_str().is_empty() {
        return Err(vigil::VigilError::Config(
            "control_socket not configured".into(),
        ));
    }

    let mode = if full { "full" } else { "incremental" };
    let mode_label = if full { "Full" } else { "Incremental" };
    let request = format!(r#"{{"method":"scan","params":{{"mode":"{}"}}}}"#, mode);

    let mut stream = UnixStream::connect(&cfg.daemon.control_socket).map_err(|e| {
        vigil::VigilError::Daemon(format!(
            "cannot connect to control socket: {} (is vigild running?)",
            e
        ))
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    writeln!(stream, "{}", request)?;
    stream.flush()?;

    let spinner_shutdown = Arc::new(AtomicBool::new(false));
    let spinner_flag = spinner_shutdown.clone();
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    let spinner_handle = if is_tty {
        Some(std::thread::spawn(move || {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0;
            while !spinner_flag.load(std::sync::atomic::Ordering::Relaxed) {
                eprint!(
                    "\r  {} Waiting for daemon scan...",
                    frames[i % frames.len()]
                );
                let _ = std::io::stderr().flush();
                std::thread::sleep(std::time::Duration::from_millis(100));
                i += 1;
            }
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }))
    } else {
        None
    };

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    spinner_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(h) = spinner_handle {
        let _ = h.join();
    }

    let result: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| vigil::VigilError::Daemon(format!("invalid response: {}", e)))?;

    if result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let checked = result
            .get("total_checked")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let changes = result
            .get("changes_found")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let errors = result.get("errors").and_then(|v| v.as_u64()).unwrap_or(0);
        let duration = result
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        print_header(&format!("Vigil — {} Integrity Check (live)", mode_label));

        println!("  Files checked   {}", format_count(checked));
        println!("  Duration        {:.1}s", duration as f64 / 1000.0);
        println!("  Errors          {}", errors);
        println!();

        if changes == 0 {
            println!("  ● No changes detected. Boundaries intact.");
        } else {
            println!(
                "  ⚠ {} change{} detected.",
                changes,
                if changes == 1 { "" } else { "s" }
            );
            println!();
            println!("  Run vigil check for per-file details.");
        }
        println!();
    } else {
        let err = result
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown");
        return Err(vigil::VigilError::Daemon(format!("scan failed: {}", err)));
    }

    Ok(())
}

fn cmd_status(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    // Try live query via control socket first
    if !cfg.daemon.control_socket.as_os_str().is_empty() {
        if let Ok(live) = query_control_socket(&cfg.daemon.control_socket, r#"{"method":"status"}"#)
        {
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&live)?);
                return Ok(());
            }

            print_header("Vigil — Daemon Status (live)");

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

    print_header("Vigil — Daemon Status");

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

fn cmd_doctor(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let checks = doctor::run_diagnostics(&cfg);

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
        return Ok(doctor::diagnostics_exit_code(&checks));
    }

    println!();
    println!("Vigil v{} — System Health Check", env!("CARGO_PKG_VERSION"));
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
    for check in checks
        .iter()
        .filter(|c| matches!(c.name.as_str(), "Config" | "HMAC key" | "Scan timer"))
    {
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
            "  {}/{} checks passed. Vigil is watching.",
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

fn cmd_update(repo: Option<PathBuf>) -> vigil::Result<()> {
    let repo_path = repo.unwrap_or(std::env::current_dir()?);
    validate_vigil_repo(&repo_path)?;

    println!("Building update from {}", repo_path.display());
    let mut build_cmd = ProcessCommand::new("cargo");
    build_cmd
        .current_dir(&repo_path)
        .arg("build")
        .arg("--release");
    let build_output = build_cmd.output()?;
    print!("{}", String::from_utf8_lossy(&build_output.stdout));
    eprint!("{}", String::from_utf8_lossy(&build_output.stderr));
    if !build_output.status.success() {
        return Err(vigil::VigilError::Daemon(
            "update failed: cargo build --release did not succeed".to_string(),
        ));
    }

    let repo_vigil = repo_path.join("target/release/vigil");
    let repo_vigild = repo_path.join("target/release/vigild");
    if !repo_vigil.exists() || !repo_vigild.exists() {
        return Err(vigil::VigilError::Daemon(
            "update build is incomplete: target/release/vigil and vigild must exist".to_string(),
        ));
    }

    let new_version = version_from_binary(&repo_vigil)?;
    let current_version = installed_version().unwrap_or_else(|| "unknown".to_string());

    if current_version != "unknown" && current_version == new_version {
        println!("Already up to date: {}", current_version);
        return Ok(());
    }

    println!("Updating: {} → {}", current_version, new_version);

    let mut daemon_stop_cmd = ProcessCommand::new("sudo");
    daemon_stop_cmd
        .arg("systemctl")
        .arg("stop")
        .arg("vigild.service");
    let daemon_stopped = run_best_effort(daemon_stop_cmd);
    if !daemon_stopped {
        eprintln!("warning: could not stop vigild.service; continuing");
    }

    let mut install_vigil_cmd = ProcessCommand::new("sudo");
    install_vigil_cmd
        .arg("install")
        .arg("-Dm755")
        .arg(&repo_vigil)
        .arg("/usr/local/bin/vigil");
    run_checked(install_vigil_cmd, "install /usr/local/bin/vigil")?;

    let mut install_vigild_cmd = ProcessCommand::new("sudo");
    install_vigild_cmd
        .arg("install")
        .arg("-Dm755")
        .arg(&repo_vigild)
        .arg("/usr/local/bin/vigild");
    run_checked(install_vigild_cmd, "install /usr/local/bin/vigild")?;

    let mut symlink_vigil_cmd = ProcessCommand::new("sudo");
    symlink_vigil_cmd
        .arg("ln")
        .arg("-sf")
        .arg("/usr/local/bin/vigil")
        .arg("/usr/bin/vigil");
    run_checked(symlink_vigil_cmd, "create /usr/bin/vigil symlink")?;

    let mut symlink_vigild_cmd = ProcessCommand::new("sudo");
    symlink_vigild_cmd
        .arg("ln")
        .arg("-sf")
        .arg("/usr/local/bin/vigild")
        .arg("/usr/bin/vigild");
    run_checked(symlink_vigild_cmd, "create /usr/bin/vigild symlink")?;

    let mut updated_units = Vec::new();
    for unit in ["vigild.service", "vigil-scan.service", "vigil-scan.timer"] {
        let src = repo_path.join("systemd").join(unit);
        let dst = PathBuf::from("/etc/systemd/system").join(unit);
        if install_file_if_changed(&src, &dst)? {
            updated_units.push(unit.to_string());
        }
    }

    if !updated_units.is_empty() {
        let mut daemon_reload_cmd = ProcessCommand::new("sudo");
        daemon_reload_cmd.arg("systemctl").arg("daemon-reload");
        run_checked(daemon_reload_cmd, "systemctl daemon-reload")?;
    }

    let updated_hooks = update_hooks_if_changed(&repo_path)?;

    let mut daemon_start_cmd = ProcessCommand::new("sudo");
    daemon_start_cmd
        .arg("systemctl")
        .arg("start")
        .arg("vigild.service");
    let daemon_started = run_best_effort(daemon_start_cmd);
    if !daemon_started {
        eprintln!("warning: could not start vigild.service");
    }

    let _ = ProcessCommand::new("vigil").arg("doctor").status();

    let baseline_summary = match vigil::config::load_config(None)
        .ok()
        .and_then(|cfg| doctor::baseline_count_with_fallback(&cfg))
    {
        Some(count) => format!("preserved ({} entries)", format_count(count.max(0) as u64)),
        None => "preserved".to_string(),
    };

    print_header("Vigil — Update Complete");

    println!("  ✓ {} → {}", current_version, new_version);
    println!(
        "  Daemon:   {}",
        if daemon_started {
            "restarted"
        } else {
            "restart failed"
        }
    );
    println!(
        "  Units:    {}",
        if updated_units.is_empty() {
            "unchanged".to_string()
        } else {
            updated_units.join(", ")
        }
    );
    println!(
        "  Hooks:    {}",
        if updated_hooks.is_empty() {
            "unchanged".to_string()
        } else {
            updated_hooks.join(", ")
        }
    );
    println!("  Baseline: {}", baseline_summary);

    Ok(())
}

fn cmd_audit(
    config_path: Option<&Path>,
    action: AuditAction,
    format: OutputFormat,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;

    match action {
        AuditAction::Show {
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
                    "Vigil — Audit Log ({} of {} entries)",
                    entries.len(),
                    total
                ));
            } else {
                print_header(&format!(
                    "Vigil — Audit Log ({} match{})",
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
        AuditAction::Stats { period } => {
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

            print_header(&format!("Vigil — Audit Statistics ({})", period_label));

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
        AuditAction::Verify => {
            let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn)?;

            print_header("Vigil — Audit Chain Verification");

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

fn format_audit_timestamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| {
            let local = dt.with_timezone(&chrono::Local);
            let now = chrono::Local::now();
            if local.date_naive() == now.date_naive() {
                local.format("today %H:%M:%S").to_string()
            } else if local.date_naive() == (now - chrono::Duration::days(1)).date_naive() {
                local.format("yesterday %H:%M:%S").to_string()
            } else if (now - local).num_days() < 7 {
                local.format("%A %H:%M:%S").to_string()
            } else {
                local.format("%Y-%m-%d %H:%M:%S").to_string()
            }
        })
        .unwrap_or_else(|| ts.to_string())
}

fn parse_time_filter(input: &str) -> Option<i64> {
    if let Some(hours) = input.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        return Some(chrono::Utc::now().timestamp() - (hours * 3600));
    }
    if let Some(days) = input.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        return Some(chrono::Utc::now().timestamp() - (days * 86400));
    }
    if input == "today" {
        let today = chrono::Local::now().date_naive().and_hms_opt(0, 0, 0)?;
        return Some(today.and_local_timezone(chrono::Local).unwrap().timestamp());
    }
    if input == "all" {
        return None;
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        let dt = date.and_hms_opt(0, 0, 0)?;
        return Some(dt.and_local_timezone(chrono::Local).unwrap().timestamp());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_local_timezone(chrono::Local).unwrap().timestamp());
    }
    input.parse::<i64>().ok()
}

fn cmd_config(config_path: Option<&Path>, action: ConfigAction) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    match action {
        ConfigAction::Show => {
            println!(
                "{}",
                toml::to_string_pretty(&cfg)
                    .map_err(|e| vigil::VigilError::Config(e.to_string()))?
            );
        }
        ConfigAction::Validate => {
            vigil::config::validate_config(&cfg)?;
            let warnings = vigil::config::validate_config_deep(&cfg)?;

            println!();
            println!("  ● Configuration is valid.");

            if !warnings.is_empty() {
                println!();
                println!(
                    "  {} {}:",
                    warnings.len(),
                    if warnings.len() == 1 {
                        "warning"
                    } else {
                        "warnings"
                    }
                );
                for w in &warnings {
                    println!("    ─ {}", w);
                }
            }
            println!();
        }
    }

    Ok(())
}

fn cmd_setup(config_path: Option<&Path>, action: SetupAction) -> vigil::Result<()> {
    match action {
        SetupAction::Hmac { key_path, force } => cmd_setup_hmac(config_path, &key_path, force),
        SetupAction::Socket { path, disable } => cmd_setup_socket(config_path, &path, disable),
    }
}

fn cmd_setup_hmac(config_path: Option<&Path>, key_path: &Path, force: bool) -> vigil::Result<()> {
    // Must be root to write to /etc/vigil
    if !nix::unistd::geteuid().is_root() {
        return Err(vigil::VigilError::Config(
            "HMAC key setup requires root. Run with sudo.".into(),
        ));
    }

    if key_path.exists() && !force {
        print!(
            "HMAC key file {} already exists. Overwrite? [y/N] ",
            key_path.display()
        );
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("HMAC key setup cancelled.");
            return Ok(());
        }
    }

    // Generate 32 random bytes from /dev/urandom
    let mut key_bytes = [0u8; 32];
    {
        use std::io::Read;
        let mut urandom = std::fs::File::open("/dev/urandom")?;
        urandom.read_exact(&mut key_bytes)?;
    }
    let hex_key = hex::encode(key_bytes);

    // Write key file
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(key_path, &hex_key)?;

    // Set permissions to 0400 (owner read-only)
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o400))?;

    // Set ownership to root:root
    nix::unistd::chown(
        key_path,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    )
    .map_err(|e| vigil::VigilError::Config(format!("failed to chown key file: {}", e)))?;

    // Update the config file
    let toml_path = resolve_config_path(config_path);
    if let Some(ref toml_path) = toml_path {
        update_config_toml(
            toml_path,
            &[
                ("security", "hmac_signing", "true"),
                (
                    "security",
                    "hmac_key_path",
                    &format!("\"{}\"", key_path.display()),
                ),
            ],
        )?;
    }

    println!();
    println!("  ● HMAC key written to {}", key_path.display());
    println!("    Permissions: 0400 (owner read-only)");
    println!("    Owner: root:root");
    println!("    Config updated: hmac_signing = true");
    println!();
    println!("  Restart vigild for changes to take effect:");
    println!("    sudo systemctl restart vigild.service");

    Ok(())
}

fn cmd_setup_socket(
    config_path: Option<&Path>,
    socket_path: &Path,
    disable: bool,
) -> vigil::Result<()> {
    let toml_path = resolve_config_path(config_path);

    if disable {
        if let Some(ref toml_path) = toml_path {
            update_config_toml(toml_path, &[("hooks", "signal_socket", "\"\"")])?;
        }
        println!("Socket sink disabled in config.");
        println!("Restart vigild for changes to take effect.");
        return Ok(());
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            println!("Created directory: {}", parent.display());
        }
    }

    if let Some(ref toml_path) = toml_path {
        update_config_toml(
            toml_path,
            &[(
                "hooks",
                "signal_socket",
                &format!("\"{}\"", socket_path.display()),
            )],
        )?;
    }

    println!();
    println!("  ● Socket sink configured: {}", socket_path.display());
    println!();
    println!("  Restart vigild for changes to take effect:");
    println!("    sudo systemctl restart vigild.service");
    println!();
    println!("  To listen for alerts:");
    println!("    socat UNIX-LISTEN:{} -", socket_path.display());

    Ok(())
}

/// Resolve the config file path that should be updated.
fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    let etc = PathBuf::from("/etc/vigil/vigil.toml");
    if etc.exists() {
        return Some(etc);
    }
    // If no config file exists yet, create in /etc/vigil/
    Some(etc)
}

/// Update specific keys in a TOML config file. Creates the file and sections if needed.
fn update_config_toml(path: &Path, updates: &[(&str, &str, &str)]) -> vigil::Result<()> {
    let content = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| vigil::VigilError::Config(format!("failed to parse TOML: {}", e)))?;

    for &(section, key, value) in updates {
        if doc.get(section).is_none() {
            doc[section] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let val: toml_edit::Value = value.parse().map_err(|e| {
            vigil::VigilError::Config(format!("invalid TOML value '{}': {}", value, e))
        })?;
        doc[section][key] = toml_edit::value(val);
    }

    std::fs::write(path, doc.to_string())?;
    Ok(())
}

fn validate_vigil_repo(repo: &Path) -> vigil::Result<()> {
    let cargo_toml = repo.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(vigil::VigilError::Config(format!(
            "Not a Vigil repository: {}",
            repo.display()
        )));
    }

    let content = std::fs::read_to_string(&cargo_toml)?;
    let parsed: toml::Value = toml::from_str(&content)
        .map_err(|e| vigil::VigilError::Config(format!("invalid Cargo.toml: {}", e)))?;

    let package_name = parsed
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str());

    if package_name != Some("vigil") {
        return Err(vigil::VigilError::Config(format!(
            "Not a Vigil repository: {}",
            repo.display()
        )));
    }

    Ok(())
}

fn installed_version() -> Option<String> {
    let out = ProcessCommand::new("vigil")
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(normalize_version(&String::from_utf8_lossy(&out.stdout)))
}

fn version_from_binary(path: &Path) -> vigil::Result<String> {
    let out = ProcessCommand::new(path).arg("--version").output()?;
    if !out.status.success() {
        return Err(vigil::VigilError::Daemon(format!(
            "failed to query version from {}",
            path.display()
        )));
    }
    Ok(normalize_version(&String::from_utf8_lossy(&out.stdout)))
}

fn normalize_version(raw: &str) -> String {
    let token = raw
        .split_whitespace()
        .last()
        .map(str::trim)
        .unwrap_or("unknown");

    if token == "unknown" {
        "unknown".to_string()
    } else if token.starts_with('v') {
        token.to_string()
    } else {
        format!("v{}", token)
    }
}

fn run_checked(mut cmd: ProcessCommand, label: &str) -> vigil::Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        return Err(vigil::VigilError::Daemon(format!(
            "{} failed with status {}",
            label, status
        )));
    }
    Ok(())
}

fn run_best_effort(mut cmd: ProcessCommand) -> bool {
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

fn install_file_if_changed(src: &Path, dst: &Path) -> vigil::Result<bool> {
    let src_bytes = std::fs::read(src)?;
    let dst_bytes = std::fs::read(dst).ok();

    if dst_bytes.as_deref() == Some(src_bytes.as_slice()) {
        return Ok(false);
    }

    let mut install_cmd = ProcessCommand::new("sudo");
    install_cmd.arg("install").arg("-Dm644").arg(src).arg(dst);
    run_checked(install_cmd, &format!("install {}", dst.display()))?;
    Ok(true)
}

fn update_hooks_if_changed(repo_path: &Path) -> vigil::Result<Vec<String>> {
    let mut updated = Vec::new();

    if command_exists("pacman") {
        let pre_src = repo_path.join("hooks/pacman/vigil-pre.hook");
        let pre_dst = PathBuf::from("/etc/pacman.d/hooks/vigil-pre.hook");
        if install_file_if_changed(&pre_src, &pre_dst)? {
            updated.push("pacman pre".to_string());
        }

        let post_src = repo_path.join("hooks/pacman/vigil-post.hook");
        let post_dst = PathBuf::from("/etc/pacman.d/hooks/vigil-post.hook");
        if install_file_if_changed(&post_src, &post_dst)? {
            updated.push("pacman post".to_string());
        }
    } else if command_exists("apt-get") || command_exists("apt") {
        let apt_src = repo_path.join("hooks/apt/99vigil");
        let apt_dst = PathBuf::from("/etc/apt/apt.conf.d/99vigil");
        if install_file_if_changed(&apt_src, &apt_dst)? {
            updated.push("apt".to_string());
        }
    }

    Ok(updated)
}

fn command_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(cmd).is_file()))
        .unwrap_or(false)
}

fn query_control_socket(
    socket_path: &Path,
    request: &str,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    writeln!(stream, "{}", request)?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    let value: serde_json::Value = serde_json::from_str(&response)?;
    if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(value)
    } else {
        Err(value
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error")
            .into())
    }
}

fn format_count(value: u64) -> String {
    let s = value.to_string();
    let mut out = String::with_capacity(s.len() + (s.len() / 3));

    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }

    out.chars().rev().collect()
}

fn format_size(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_048_576.0)
}

/// Print a section header with Unicode box-drawing separator.
fn print_header(title: &str) {
    println!();
    println!("{}", title);
    println!("{}", "═".repeat(title.len()));
    println!();
}

/// Truncate a hash to 16 hex chars for display.
fn truncate_hash(hash: &str) -> &str {
    if hash.len() > 16 {
        &hash[..16]
    } else {
        hash
    }
}

/// Format a severity for display: returns (marker, label).
fn severity_display(severity: &vigil::types::Severity) -> (&'static str, &'static str) {
    match severity {
        vigil::types::Severity::Critical => ("✗", "CRITICAL"),
        vigil::types::Severity::High => ("✗", "HIGH"),
        vigil::types::Severity::Medium => ("⚠", "MEDIUM"),
        vigil::types::Severity::Low => ("○", "LOW"),
    }
}

/// Pick the highest-severity marker for a set of changes.
fn severity_display_for_count(
    changes: &[vigil::types::ChangeResult],
) -> (&'static str, &'static str) {
    let max_severity = changes
        .iter()
        .map(|c| c.severity)
        .max()
        .unwrap_or(vigil::types::Severity::Medium);
    severity_display(&max_severity)
}

/// Print detail lines for a single Change variant.
fn print_change_detail(change: &Change) {
    match change {
        Change::ContentModified { old_hash, new_hash } => {
            println!(
                "    content: {} → {}",
                truncate_hash(old_hash),
                truncate_hash(new_hash)
            );
        }
        Change::PermissionsChanged { old, new } => {
            println!("    permissions: {:04o} → {:04o}", old, new);
        }
        Change::OwnerChanged {
            old_uid,
            new_uid,
            old_gid,
            new_gid,
        } => {
            println!(
                "    owner: {}:{} → {}:{}",
                old_uid, old_gid, new_uid, new_gid
            );
        }
        Change::InodeChanged { old, new } => {
            println!("    inode: {} → {}", old, new);
        }
        Change::TypeChanged { old, new } => {
            println!("    type: {} → {}", old, new);
        }
        Change::SymlinkTargetChanged { old, new } => {
            println!("    symlink: {} → {}", old.display(), new.display());
        }
        Change::CapabilitiesChanged { old, new } => {
            println!(
                "    capabilities: {} → {}",
                old.as_deref().unwrap_or("none"),
                new.as_deref().unwrap_or("none")
            );
        }
        Change::XattrChanged { key, old, new } => {
            println!(
                "    xattr {}: {} → {}",
                key,
                old.as_deref().unwrap_or("none"),
                new.as_deref().unwrap_or("none")
            );
        }
        Change::SecurityContextChanged { old, new } => {
            println!("    security context: {} → {}", old, new);
        }
        Change::Deleted => {
            println!("    file deleted from filesystem");
        }
        Change::Created => {
            println!("    new file not in baseline");
        }
    }
}

fn cmd_log(action: LogAction) -> vigil::Result<()> {
    match action {
        LogAction::Show {
            lines,
            level,
            follow,
            since,
            grep,
        } => {
            let mut args: Vec<String> = vec![
                "--no-pager".into(),
                "-u".into(),
                "vigild.service".into(),
            ];

            if follow {
                args.push("-f".into());
            } else {
                args.push("-n".into());
                args.push(lines.to_string());
            }

            if let Some(ref s) = since {
                args.push("--since".into());
                args.push(s.clone());
            }

            if let Some(ref lvl) = level {
                let priority = match lvl.to_lowercase().as_str() {
                    "error" | "err" => "3",
                    "warn" | "warning" => "4",
                    "info" | "notice" => "6",
                    "debug" => "7",
                    other => {
                        eprintln!("error: unknown log level '{}' (use: error, warn, info, debug)", other);
                        return Ok(());
                    }
                };
                args.push("-p".into());
                args.push(format!("0..{}", priority));
            }

            if let Some(ref pattern) = grep {
                args.push("--grep".into());
                args.push(pattern.clone());
            }

            args.push("-o".into());
            args.push("short-iso".into());

            let status = ProcessCommand::new("journalctl")
                .args(&args)
                .status()
                .map_err(vigil::VigilError::Io)?;

            if !status.success() {
                eprintln!("journalctl exited with status {}", status);
                eprintln!("hint: you may need to run this command with sudo");
            }
        }
        LogAction::Errors { lines, since } => {
            let mut args: Vec<String> = vec![
                "--no-pager".into(),
                "-u".into(),
                "vigild.service".into(),
                "-p".into(),
                "0..4".into(),
                "-n".into(),
                lines.to_string(),
                "-o".into(),
                "short-iso".into(),
            ];

            if let Some(ref s) = since {
                args.push("--since".into());
                args.push(s.clone());
            }

            let status = ProcessCommand::new("journalctl")
                .args(&args)
                .status()
                .map_err(vigil::VigilError::Io)?;

            if !status.success() {
                eprintln!("journalctl exited with status {}", status);
                eprintln!("hint: you may need to run this command with sudo");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_vigil_repo_accepts_valid_package_name() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let cargo_toml = dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo_toml,
            r#"
                [package]
                name = "vigil"
                version = "0.0.1"
                edition = "2021"
            "#,
        )
        .expect("write Cargo.toml");

        let result = validate_vigil_repo(dir.path());
        assert!(result.is_ok(), "expected valid vigil repository");
    }

    #[test]
    fn validate_vigil_repo_rejects_other_package_name() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let cargo_toml = dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo_toml,
            r#"
                [package]
                name = "not-vigil"
                version = "0.0.1"
                edition = "2021"
            "#,
        )
        .expect("write Cargo.toml");

        let result = validate_vigil_repo(dir.path());
        assert!(result.is_err(), "expected repository validation to fail");
    }

    #[test]
    fn normalize_version_prefixes_v_when_missing() {
        assert_eq!(normalize_version("vigil 0.12.1"), "v0.12.1");
        assert_eq!(normalize_version("vigil v0.12.1"), "v0.12.1");
    }
}
