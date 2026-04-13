use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use chrono::Utc;
use clap::Parser;

use vigil::cli::{
    AuditAction, BaselineAction, Cli, Command, ConfigAction, LogAction, MaintenanceAction,
    SetupAction,
};
use vigil::display;
use vigil::doctor;
use vigil::types::{Change, OutputFormat, ScanMode, Severity};

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
            cmd_init(config_path.as_deref(), format, force)?;
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
            dry_run,
            accept_severity,
            accept_group,
            verbose,
            brief,
            no_pager,
            since,
        } => {
            if now && accept {
                eprintln!("error: --accept cannot be used with --now (baseline updates require direct database access)");
                return Ok(1);
            }
            if now && since.is_some() {
                eprintln!(
                    "error: --since cannot be used with --now (time-bound filtering needs local audit DB access)"
                );
                return Ok(1);
            }
            if now {
                cmd_check_live(config_path.as_deref(), full)?;
                Ok(0)
            } else {
                cmd_check(CheckOpts {
                    config_path: config_path.clone(),
                    format,
                    full,
                    accept,
                    accept_path,
                    accept_dry_run: dry_run,
                    accept_severity,
                    accept_group,
                    verbose,
                    brief,
                    no_pager,
                    since,
                })
            }
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
        Command::Maintenance { action } => {
            cmd_maintenance(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Baseline { action } => {
            cmd_baseline(config_path.as_deref(), action)?;
            Ok(0)
        }
        Command::Version => {
            println!("vigil {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
    }
}

fn cmd_init(config_path: Option<&Path>, format: OutputFormat, force: bool) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    let existing = vigil::db::baseline_ops::count(&conn).unwrap_or(0);
    if existing > 0 && !force {
        println!(
            "⚠ Existing baseline found ({} entries).",
            display::fmt_count(existing as u64)
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
    vigil::db::baseline_ops::set_config_state(&conn, "baseline_initialized", "true")?;

    // Gather baseline metadata for report
    let baseline_fingerprint = vigil::db::baseline_ops::get_baseline_fingerprint(&conn);
    let hmac_signed = cfg.security.hmac_signing;
    let profile = vigil::db::baseline_ops::compute_baseline_profile(&conn).ok();

    let init_report = display::InitReport {
        result,
        baseline_fingerprint,
        hmac_signed,
        db_path: cfg.daemon.db_path.clone(),
        profile,
    };

    let term = display::term::TermInfo::detect();
    let output = display::render_init(&init_report, format, &term);
    print!("{}", output);

    Ok(())
}

fn cmd_watch(config_path: Option<&Path>) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    println!("Starting vigilant monitor in foreground mode (Ctrl+C to stop)...");
    vigil::Daemon::from_config(cfg)?.run()
}

struct CheckOpts {
    config_path: Option<PathBuf>,
    format: OutputFormat,
    full: bool,
    accept: bool,
    accept_path: Option<String>,
    accept_dry_run: bool,
    accept_severity: Option<Severity>,
    accept_group: Option<String>,
    verbose: bool,
    brief: bool,
    no_pager: bool,
    since: Option<String>,
}

fn cmd_check(opts: CheckOpts) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(opts.config_path.as_deref())?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    let mode = if opts.full {
        ScanMode::Full
    } else {
        ScanMode::Incremental
    };

    let since_ts = match opts.since.as_deref() {
        Some(value) => parse_time_filter_strict(value, "--since")?,
        None => None,
    };

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let mut result =
        vigil::scanner::run_scan_with_progress(&conn, &cfg, mode, |checked, total| {
            if is_tty && total > 0 {
                let pct = (checked as f64 / total as f64 * 100.0).min(100.0);
                eprint!(
                    "\r  Scanning... {}/{} files ({:.0}%)",
                    display::fmt_count(checked),
                    display::fmt_count(total),
                    pct
                );
                let _ = std::io::stderr().flush();
            }
        })?;
    let scan_finished_at = chrono::Utc::now().timestamp();

    if is_tty {
        eprint!("\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }

    if let Some(since_ts) = since_ts {
        if since_ts > scan_finished_at {
            return Err(vigil::VigilError::Config(
                "--since resolves to a future timestamp".into(),
            ));
        }

        let audit_conn = vigil::db::open_audit_db(&cfg)?;
        let total_before = result.changes.len() as u64;
        let mut filtered = Vec::with_capacity(result.changes.len());
        let mut dropped_before_window = 0u64;
        let mut no_history = 0u64;
        let mut lookup_failures = 0u64;

        for change in result.changes.drain(..) {
            let path = change.path.to_string_lossy();
            match vigil::db::audit_ops::get_path_window_state(
                &audit_conn,
                path.as_ref(),
                since_ts,
                scan_finished_at,
            ) {
                Ok(state) => {
                    if state.latest_in_window.is_some() {
                        filtered.push(change);
                    } else if state.latest_any.is_some() {
                        dropped_before_window += 1;
                    } else {
                        // Keep unknown-history paths visible to avoid hiding blind spots.
                        no_history += 1;
                        filtered.push(change);
                    }
                }
                Err(e) => {
                    lookup_failures += 1;
                    result.warnings.push(vigil::error::ScanWarning {
                        path: change.path.as_ref().clone(),
                        detail: format!(
                            "audit lookup failed while applying --since: {}; showing this change",
                            e
                        ),
                        severity: vigil::error::WarningSeverity::Warning,
                    });
                    filtered.push(change);
                }
            }
        }

        result.changes = filtered;
        result.changes_found = result.changes.len() as u64;

        result.warnings.push(vigil::error::ScanWarning {
            path: PathBuf::from("audit.db"),
            detail: format!(
                "--since={} kept {} of {} current change{} (window {}..{})",
                opts.since.as_deref().unwrap_or("all"),
                result.changes_found,
                total_before,
                if total_before == 1 { "" } else { "s" },
                since_ts,
                scan_finished_at
            ),
            severity: vigil::error::WarningSeverity::Info,
        });

        if dropped_before_window > 0 {
            result.warnings.push(vigil::error::ScanWarning {
                path: PathBuf::from("audit.db"),
                detail: format!(
                    "{} change{} excluded because last audit evidence was before --since",
                    dropped_before_window,
                    if dropped_before_window == 1 { "" } else { "s" }
                ),
                severity: vigil::error::WarningSeverity::Info,
            });
        }

        if no_history > 0 {
            result.warnings.push(vigil::error::ScanWarning {
                path: PathBuf::from("audit.db"),
                detail: format!(
                    "{} change{} kept without prior audit history (coverage gap)",
                    no_history,
                    if no_history == 1 { "" } else { "s" }
                ),
                severity: vigil::error::WarningSeverity::Warning,
            });
        }

        if lookup_failures > 0 {
            result.warnings.push(vigil::error::ScanWarning {
                path: PathBuf::from("audit.db"),
                detail: format!(
                    "{} path lookup{} failed while applying --since",
                    lookup_failures,
                    if lookup_failures == 1 { "" } else { "s" }
                ),
                severity: vigil::error::WarningSeverity::Warning,
            });
        }
    }

    // Gather baseline metadata
    let baseline_fingerprint = vigil::db::baseline_ops::get_baseline_fingerprint(&conn);
    let baseline_established = vigil::db::baseline_ops::get_baseline_established(&conn);
    let hmac_signed = cfg.security.hmac_signing;
    let total_baseline_entries = vigil::db::baseline_ops::count(&conn).unwrap_or(0) as u64;
    let previous_check_at = vigil::db::baseline_ops::get_config_state(&conn, "last_check_at")
        .ok()
        .flatten()
        .and_then(|s| s.parse::<i64>().ok());
    let previous_check_changes =
        vigil::db::baseline_ops::get_config_state(&conn, "last_check_changes")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u64>().ok());

    // Build the report
    let report = display::CheckReport::from_scan(
        result,
        display::CheckReportMeta {
            mode,
            baseline_fingerprint,
            baseline_established,
            hmac_signed,
            total_baseline_entries,
            previous_check_at,
            previous_check_changes,
            db_path: cfg.daemon.db_path.clone(),
        },
    );

    // Compute exit code before rendering
    let code = report.exit_code();

    // Render output
    let term = display::term::TermInfo::detect();
    let output = display::render_check(&report, opts.format, &term, opts.verbose, opts.brief);

    // Pager support: pipe through $PAGER when output exceeds terminal height.
    // Never auto-page when mutating baseline (accept flow) so the operator sees receipts directly.
    let line_count = output.lines().count();
    let use_pager = !opts.no_pager
        && !opts.brief
        && !opts.accept
        && opts.format == OutputFormat::Human
        && term.is_tty
        && line_count > term.height as usize;

    if use_pager {
        pipe_to_pager(&output);
    } else {
        print!("{}", output);
    }

    // Handle --accept
    if opts.accept && !report.scan.changes.is_empty() {
        let path_filter: Option<globset::GlobMatcher> = opts.accept_path.as_ref().map(|pattern| {
            globset::Glob::new(pattern)
                .unwrap_or_else(|_| globset::Glob::new("*").unwrap())
                .compile_matcher()
        });

        let severity_filter = opts.accept_severity;
        let group_filter = opts.accept_group.as_deref();

        let changes_to_accept: Vec<_> = report
            .scan
            .changes
            .iter()
            .filter(|c| {
                let path_ok = match &path_filter {
                    Some(matcher) => matcher.is_match(c.path.as_ref()),
                    None => true,
                };
                let severity_ok = match severity_filter {
                    Some(sev) => c.severity == sev,
                    None => true,
                };
                let group_ok = match group_filter {
                    Some(group) => c.monitored_group == group,
                    None => true,
                };
                path_ok && severity_ok && group_ok
            })
            .collect();

        println!();
        if !changes_to_accept.is_empty() {
            println!(
                "  Accept preview: {} of {} change{} selected.",
                changes_to_accept.len(),
                report.scan.changes_found,
                if report.scan.changes_found == 1 {
                    ""
                } else {
                    "s"
                }
            );

            if let Some(ref pattern) = opts.accept_path {
                println!("    path filter: '{}'", pattern);
            }
            if let Some(sev) = opts.accept_severity {
                println!("    severity filter: {}", sev);
            }
            if let Some(ref group) = opts.accept_group {
                println!("    group filter: {}", group);
            }

            // Show condensed preview lines before mutating baseline.
            for change in changes_to_accept.iter().take(10) {
                println!(
                    "    - [{}] {} ({})",
                    change.severity,
                    change.path.display(),
                    change.monitored_group
                );
            }
            if changes_to_accept.len() > 10 {
                println!(
                    "    ... and {} more",
                    changes_to_accept.len().saturating_sub(10)
                );
            }

            if opts.accept_dry_run {
                println!();
                println!("  Dry run only. Baseline was not modified.");
                println!("  To apply: rerun without --dry-run");

                let _ = vigil::db::baseline_ops::set_config_state(
                    &conn,
                    "last_check_at",
                    &chrono::Utc::now().timestamp().to_string(),
                );
                let _ = vigil::db::baseline_ops::set_config_state(
                    &conn,
                    "last_check_changes",
                    &report.scan.changes_found.to_string(),
                );
                return Ok(code);
            }

            let old_fingerprint = vigil::db::baseline_ops::get_baseline_fingerprint(&conn);

            println!();
            println!(
                "  Accepting {} change{} into baseline...",
                changes_to_accept.len(),
                if changes_to_accept.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );

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

            // Recompute baseline HMAC after accepting changes
            if cfg.security.hmac_signing {
                if let Ok(key) = vigil::hmac::load_hmac_key(&cfg.security.hmac_key_path) {
                    match vigil::db::baseline_ops::compute_baseline_hmac(&conn, &key) {
                        Ok(hmac) => {
                            let _ = vigil::db::baseline_ops::set_config_state(
                                &conn,
                                "baseline_hmac",
                                &hmac,
                            );
                        }
                        Err(e) => {
                            eprintln!("  warning: failed to update baseline HMAC: {}", e);
                        }
                    }
                }
            }

            let new_fingerprint = vigil::db::baseline_ops::get_baseline_fingerprint(&conn);
            println!();
            println!("  Accept receipt:");
            println!(
                "    Baseline fingerprint: {} → {}",
                old_fingerprint.unwrap_or_else(|| "(none)".into()),
                new_fingerprint.unwrap_or_else(|| "(none)".into())
            );

            let not_accepted = report.scan.changes.len() - changes_to_accept.len();
            if not_accepted > 0 {
                println!(
                    "  {} change{} not accepted.",
                    not_accepted,
                    if not_accepted == 1 { " was" } else { "s were" }
                );
            }
        } else {
            println!("  No changes matched the accept filters. Nothing to accept.");
        }
    }

    // Persist last-check metadata for temporal context in future runs.
    let _ = vigil::db::baseline_ops::set_config_state(
        &conn,
        "last_check_at",
        &chrono::Utc::now().timestamp().to_string(),
    );
    let _ = vigil::db::baseline_ops::set_config_state(
        &conn,
        "last_check_changes",
        &report.scan.changes_found.to_string(),
    );

    Ok(code)
}

/// Pipe output through $PAGER (defaulting to `less -R`) for long output.
fn pipe_to_pager(output: &str) {
    if output.is_empty() {
        return;
    }

    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".into());
    let pager = pager.trim();
    if pager.is_empty() {
        print!("{}", output);
        return;
    }

    let mut parts: Vec<&str> = pager.split_whitespace().collect();
    if parts.is_empty() {
        print!("{}", output);
        return;
    }

    let cmd = parts.remove(0);
    let mut args = parts;

    // Add -R to preserve ANSI colors in less
    if cmd == "less" && !args.iter().any(|a| a.contains('R')) {
        args.push("-R");
    }

    match ProcessCommand::new(cmd)
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(output.as_bytes());
            }
            let _ = child.wait();
        }
        Err(_) => {
            // Pager failed — fall back to direct print
            print!("{}", output);
        }
    }
}

fn cmd_diff(config_path: Option<&Path>, file_path: &Path) -> vigil::Result<()> {
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

        print_header(&format!(
            "Vigil Baseline — {} Integrity Check (live)",
            mode_label
        ));

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

fn cmd_doctor(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let checks = doctor::run_diagnostics(&cfg);

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
        return Ok(doctor::diagnostics_exit_code(&checks));
    }

    println!();
    println!(
        "Vigil Baseline v{} — System Health Check",
        env!("CARGO_PKG_VERSION")
    );
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
            "  {}/{} checks passed. Vigil Baseline is watching.",
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
    let repo_path = match repo {
        Some(p) => {
            validate_vigil_repo(&p)?;
            p
        }
        None => discover_vigil_repo()?,
    };

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

    println!("  Stopping vigild.service...");
    let mut daemon_stop_cmd = ProcessCommand::new("sudo");
    daemon_stop_cmd
        .arg("systemctl")
        .arg("stop")
        .arg("vigild.service");
    let daemon_stopped = run_best_effort(daemon_stop_cmd);
    if daemon_stopped {
        println!("  ✓ Daemon stopped");
    } else {
        eprintln!("  ⚠ could not stop vigild.service; continuing");
    }

    println!("  Installing vigil → /usr/local/bin...");
    atomic_install(&repo_vigil, Path::new("/usr/local/bin/vigil"))?;

    println!("  Installing vigild → /usr/local/bin...");
    atomic_install(&repo_vigild, Path::new("/usr/local/bin/vigild"))?;

    println!("  Updating symlinks...");
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

    println!("  Checking systemd units...");
    let mut updated_units = Vec::new();
    for unit in ["vigild.service", "vigil-scan.service", "vigil-scan.timer"] {
        let src = repo_path.join("systemd").join(unit);
        let dst = PathBuf::from("/etc/systemd/system").join(unit);
        if install_file_if_changed(&src, &dst)? {
            updated_units.push(unit.to_string());
        }
    }

    if !updated_units.is_empty() {
        println!("  Reloading systemd daemon...");
        let mut daemon_reload_cmd = ProcessCommand::new("sudo");
        daemon_reload_cmd.arg("systemctl").arg("daemon-reload");
        run_checked(daemon_reload_cmd, "systemctl daemon-reload")?;
    }

    println!("  Checking hooks...");
    let updated_hooks = update_hooks_if_changed(&repo_path)?;

    // Tighten data directory permissions for v0.25.0+ security hardening.
    // Older installs may have 0755; the daemon now requires 0700 or 0750.
    let mut chmod_cmd = ProcessCommand::new("sudo");
    chmod_cmd.arg("chmod").arg("750").arg("/var/lib/vigil");
    let _ = run_best_effort(chmod_cmd);

    println!("  Starting vigild.service...");
    let mut daemon_start_cmd = ProcessCommand::new("sudo");
    daemon_start_cmd
        .arg("systemctl")
        .arg("start")
        .arg("vigild.service");
    let daemon_started = run_best_effort(daemon_start_cmd);
    if daemon_started {
        println!("  ✓ Daemon started");
    } else {
        eprintln!("  ⚠ could not start vigild.service");
    }

    // Post-start health check: verify daemon is actually responding
    let healthy = if daemon_started {
        std::thread::sleep(std::time::Duration::from_secs(2));
        vigil::config::load_config(None)
            .ok()
            .and_then(|cfg| {
                if !cfg.daemon.control_socket.as_os_str().is_empty() {
                    query_control_socket(&cfg.daemon.control_socket, r#"{"method":"status"}"#).ok()
                } else {
                    None
                }
            })
            .is_some()
    } else {
        false
    };

    let baseline_summary = match vigil::config::load_config(None)
        .ok()
        .and_then(|cfg| doctor::baseline_count_with_fallback(&cfg))
    {
        Some(count) => format!("preserved ({} entries)", format_count(count.max(0) as u64)),
        None => "preserved".to_string(),
    };

    let daemon_status = if daemon_started && healthy {
        "restarted"
    } else if daemon_started {
        "started but not responding (check: sudo journalctl -u vigild.service -n 20)"
    } else {
        "restart failed"
    };

    print_header("Vigil Baseline — Update Complete");

    println!("  ✓ {} → {}", current_version, new_version);
    println!("  Daemon:   {}", daemon_status);
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

    println!();
    println!("  Running health check...");
    let _ = ProcessCommand::new("vigil").arg("doctor").status();

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
        AuditAction::Verify => {
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

fn parse_time_filter_strict(input: &str, flag_name: &str) -> vigil::Result<Option<i64>> {
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok(None);
    }

    parse_time_filter(trimmed)
        .map(Some)
        .ok_or_else(|| {
            vigil::VigilError::Config(format!(
                "invalid {} value '{}'; expected 24h, 7d, today, YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS, or unix timestamp",
                flag_name, input
            ))
        })
}

fn parse_time_filter(input: &str) -> Option<i64> {
    let input = input.trim();
    let lower = input.to_ascii_lowercase();

    if let Some(hours) = lower.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        return Some(chrono::Utc::now().timestamp() - (hours * 3600));
    }
    if let Some(days) = lower.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        return Some(chrono::Utc::now().timestamp() - (days * 86400));
    }
    if lower == "today" {
        let today = chrono::Local::now().date_naive().and_hms_opt(0, 0, 0)?;
        return Some(today.and_local_timezone(chrono::Local).unwrap().timestamp());
    }
    if lower == "all" {
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
            "current directory is not a Vigil Baseline repository: {}\n\
             hint: run from the Vigil Baseline source directory, or use: vigil update --repo /path/to/vigil",
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

    if package_name != Some("vigilbaseline") && package_name != Some("vigil") {
        return Err(vigil::VigilError::Config(format!(
            "current directory is not a Vigil Baseline repository: {}\n\
             hint: run from the Vigil Baseline source directory, or use: vigil update --repo /path/to/vigil",
            repo.display()
        )));
    }

    Ok(())
}

fn discover_vigil_repo() -> vigil::Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut labels: Vec<String> = Vec::new();

    // 1. Current working directory
    if let Ok(cwd) = std::env::current_dir() {
        labels.push(format!("{} (cwd)", cwd.display()));
        candidates.push(cwd);
    }

    // 2. Binary-relative: walk up from the executable's location
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.as_path().parent();
        while let Some(d) = dir {
            if d.join("Cargo.toml").exists() {
                labels.push(format!("{} (binary relative)", d.display()));
                candidates.push(d.to_path_buf());
                break;
            }
            dir = d.parent();
        }
    }

    // 3. Well-known home paths
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        for sub in ["vigil", "src/vigil", "projects/vigil"] {
            let p = home.join(sub);
            labels.push(format!("{}", p.display()));
            candidates.push(p);
        }
    }

    // 4. /opt/vigil
    let opt = PathBuf::from("/opt/vigil");
    labels.push(format!("{}", opt.display()));
    candidates.push(opt);

    for candidate in &candidates {
        if validate_vigil_repo(candidate).is_ok() {
            println!("  Using repository: {}", candidate.display());
            return Ok(candidate.clone());
        }
    }

    let checked = labels
        .iter()
        .map(|l| format!("    {}", l))
        .collect::<Vec<_>>()
        .join("\n");

    Err(vigil::VigilError::Config(format!(
        "could not locate Vigil Baseline source repository\n  checked:\n{}\n  \
         hint: run from the Vigil Baseline source directory, or use: vigil update --repo /path/to/vigil",
        checked
    )))
}

fn atomic_install(src: &Path, dst: &Path) -> vigil::Result<()> {
    let file_name = dst
        .file_name()
        .ok_or_else(|| vigil::VigilError::Daemon("invalid destination path".to_string()))?;
    let tmp_name = format!(".{}.new", file_name.to_string_lossy());
    let tmp_dst = dst.with_file_name(&tmp_name);

    let mut cp_cmd = ProcessCommand::new("sudo");
    cp_cmd.arg("cp").arg(src).arg(&tmp_dst);
    run_checked(
        cp_cmd,
        &format!("cp {} to {}", src.display(), tmp_dst.display()),
    )?;

    let mut chmod_cmd = ProcessCommand::new("sudo");
    chmod_cmd.arg("chmod").arg("755").arg(&tmp_dst);
    run_checked(chmod_cmd, &format!("chmod 755 {}", tmp_dst.display()))?;

    let mut mv_cmd = ProcessCommand::new("sudo");
    mv_cmd.arg("mv").arg(&tmp_dst).arg(dst);
    run_checked(
        mv_cmd,
        &format!("mv {} to {}", tmp_dst.display(), dst.display()),
    )?;

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

fn cmd_maintenance(config_path: Option<&Path>, action: MaintenanceAction) -> vigil::Result<()> {
    let quiet = match &action {
        MaintenanceAction::Enter { quiet } => *quiet,
        MaintenanceAction::Exit { quiet } => *quiet,
        MaintenanceAction::Status => false,
    };

    let method = match &action {
        MaintenanceAction::Enter { .. } => "maintenance_enter",
        MaintenanceAction::Exit { .. } => "maintenance_exit",
        MaintenanceAction::Status => "status",
    };

    let cfg = match vigil::config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            if quiet {
                return Ok(());
            }
            return Err(e);
        }
    };

    if cfg.daemon.control_socket.as_os_str().is_empty() {
        if quiet {
            return Ok(());
        }
        return Err(vigil::VigilError::Config(
            "control_socket not configured".into(),
        ));
    }

    let request = format!(r#"{{"method":"{}"}}"#, method);
    match query_control_socket(&cfg.daemon.control_socket, &request) {
        Ok(response) => {
            if !quiet {
                match &action {
                    MaintenanceAction::Enter { .. } => {
                        println!("Maintenance window entered.");
                    }
                    MaintenanceAction::Exit { .. } => {
                        println!("Maintenance window exited.");
                    }
                    MaintenanceAction::Status => {
                        let maint = response
                            .pointer("/daemon/maintenance_window")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if maint {
                            println!("Maintenance window: active");
                        } else {
                            println!("Maintenance window: inactive");
                        }
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            if quiet {
                // Hooks must not block package operations
                return Ok(());
            }
            Err(vigil::VigilError::Daemon(format!(
                "cannot connect to daemon: {} (is vigild running?)",
                e
            )))
        }
    }
}

fn cmd_baseline(config_path: Option<&Path>, action: BaselineAction) -> vigil::Result<()> {
    match action {
        BaselineAction::Refresh { quiet } => cmd_baseline_refresh(config_path, quiet),
    }
}

fn cmd_baseline_refresh(config_path: Option<&Path>, quiet: bool) -> vigil::Result<()> {
    let cfg = match vigil::config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            if quiet {
                return Ok(());
            }
            return Err(e);
        }
    };

    // Try control socket first (daemon is running)
    if !cfg.daemon.control_socket.as_os_str().is_empty() {
        let request = r#"{"method":"baseline_refresh"}"#;
        match query_control_socket(&cfg.daemon.control_socket, request) {
            Ok(response) => {
                if !quiet {
                    let count = response
                        .get("total_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    println!("Baseline refreshed ({} files).", format_count(count));
                }
                return Ok(());
            }
            Err(_) => {
                // Daemon not running — fall through to direct DB access
            }
        }
    }

    // Fallback: direct DB access (daemon not running)
    let conn = match vigil::db::open_baseline_db(&cfg) {
        Ok(c) => c,
        Err(e) => {
            if quiet {
                return Ok(());
            }
            return Err(e);
        }
    };

    match vigil::scanner::refresh_baseline(&conn, &cfg) {
        Ok(result) => {
            vigil::db::baseline_ops::set_config_state(&conn, "baseline_initialized", "true")?;
            if !quiet {
                println!(
                    "Baseline refreshed ({} files in {:.1}s).",
                    format_count(result.total_count),
                    result.duration.as_secs_f64()
                );
            }
            Ok(())
        }
        Err(e) => {
            if quiet {
                return Ok(());
            }
            Err(e)
        }
    }
}

fn query_control_socket(
    socket_path: &Path,
    request: &str,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send request
    (&stream).write_all(request.as_bytes())?;
    (&stream).write_all(b"\n")?;
    (&stream).flush()?;

    let mut reader = BufReader::new(&stream);
    let mut first_line = String::new();
    reader.read_line(&mut first_line)?;

    let first_value: serde_json::Value = serde_json::from_str(first_line.trim())?;

    // If the server sent a challenge, reconnect with authenticated request
    if first_value
        .get("challenge")
        .and_then(|v| v.as_str())
        .is_some()
    {
        drop(reader);
        drop(stream);
        return query_control_socket_authenticated(socket_path, request);
    }

    // No challenge — use first_value as the response
    if first_value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(first_value)
    } else {
        Err(first_value
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error")
            .into())
    }
}

fn query_control_socket_authenticated(
    socket_path: &Path,
    request: &str,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Read challenge
    let mut reader = BufReader::new(&stream);
    let mut challenge_line = String::new();
    reader.read_line(&mut challenge_line)?;
    let challenge: serde_json::Value = serde_json::from_str(challenge_line.trim())?;
    let nonce = challenge
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or("missing challenge nonce")?;

    // Load HMAC key and compute response
    let hmac_key_path = std::path::PathBuf::from("/etc/vigil/hmac.key");
    let key = vigil::hmac::load_hmac_key(&hmac_key_path)?;
    let hmac_response = vigil::hmac::compute_hmac(&key, nonce.as_bytes())?;

    // Build authenticated request
    let mut req_value: serde_json::Value = serde_json::from_str(request)?;
    if let Some(obj) = req_value.as_object_mut() {
        obj.insert("response".into(), serde_json::Value::String(hmac_response));
    }
    let auth_request = serde_json::to_string(&req_value)?;

    // Need to drop reader to get mutable access to stream
    drop(reader);
    (&stream).write_all(auth_request.as_bytes())?;
    (&stream).write_all(b"\n")?;
    (&stream).flush()?;

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
    display::fmt_count(value)
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
    display::truncate_hash(hash)
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
        Change::SizeChanged { old, new } => {
            println!("    size: {} → {} bytes", old, new);
        }
        Change::DeviceChanged { old, new } => {
            println!("    device: {} → {}", old, new);
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
            let mut args: Vec<String> =
                vec!["--no-pager".into(), "-u".into(), "vigild.service".into()];

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
                        eprintln!(
                            "error: unknown log level '{}' (use: error, warn, info, debug)",
                            other
                        );
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
                name = "vigilbaseline"
                version = "0.0.1"
                edition = "2021"
            "#,
        )
        .expect("write Cargo.toml");

        let result = validate_vigil_repo(dir.path());
        assert!(result.is_ok(), "expected valid vigil repository");
    }

    #[test]
    fn validate_vigil_repo_accepts_legacy_package_name() {
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
        assert!(result.is_ok(), "expected legacy vigil name to be accepted");
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
