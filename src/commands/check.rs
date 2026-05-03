//! `vigil check` subcommand: integrity verification with optional accept flow.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use vigil::display;
use vigil::types::{OutputFormat, ScanMode, Severity};

use super::common::{
    format_count, parse_time_filter, parse_time_filter_strict, pipe_to_pager, print_header,
};

pub(crate) struct CheckOpts {
    pub config_path: Option<PathBuf>,
    pub format: OutputFormat,
    pub full: bool,
    pub accept: bool,
    pub accept_path: Option<String>,
    pub accept_dry_run: bool,
    pub accept_severity: Option<Severity>,
    pub accept_group: Option<String>,
    pub verbose: bool,
    pub brief: bool,
    pub no_pager: bool,
    pub since: Option<String>,
    pub reason: bool,
    /// When true, every detected content mismatch triggers a forensic
    /// disambiguation re-read after dropping the file's page cache.
    pub disambiguate_cause: bool,
}

pub(crate) fn cmd_check(opts: CheckOpts) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(opts.config_path.as_deref())?;
    let conn = vigil::db::open_baseline_db(&cfg)
        .map_err(|e| e.with_context("opening baseline database for check"))?;

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

    // Forensic disambiguation pass (--disambiguate-cause).
    //
    // For every change that contains a ContentModified, re-open the file,
    // drop its page cache, and classify the modification. This is opt-in
    // and adds ~one read per detected mismatch.
    if opts.disambiguate_cause {
        run_disambiguation_pass(&mut result.changes, cfg.scanner.mmap_threshold);
    }

    // Record a verification receipt if --reason is set (before report consumes result)
    let receipt_msg = if opts.reason {
        let receipt = vigil::receipt::CheckReceipt::from_scan(
            scan_finished_at - (result.duration_ms as i64 / 1000).max(1),
            scan_finished_at,
            mode,
            &result,
        );
        if let Ok(audit_conn) = vigil::db::open_audit_db(&cfg) {
            let last_hash = vigil::db::audit_ops::get_last_chain_hash(&audit_conn)
                .ok()
                .flatten()
                .unwrap_or_else(|| {
                    blake3::hash(b"vigil-audit-chain-genesis")
                        .to_hex()
                        .to_string()
                });

            match receipt.record(&audit_conn, &last_hash, None) {
                Ok(_) => Some(format!(
                    "blake3:{}",
                    &receipt.receipt_hash[..16.min(receipt.receipt_hash.len())]
                )),
                Err(e) => {
                    eprintln!("warning: failed to record receipt: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

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
    let mut output = display::render_check(&report, opts.format, &term, opts.verbose, opts.brief);

    // Verbose mode: append recent audit activity timeline.
    if opts.verbose && opts.format == OutputFormat::Human {
        let activity = render_recent_activity(&cfg, &opts);
        if !activity.is_empty() {
            output.push_str(&activity);
        }
    }

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
            println!("  Audit log preserved. The original detections are permanent.");

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

    // Print receipt reference if recorded
    if let Some(ref receipt_hash) = receipt_msg {
        if opts.format != OutputFormat::Json {
            println!("  Receipt:   {} (recorded in audit chain)", receipt_hash);
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

pub(crate) fn cmd_check_live(config_path: Option<&Path>, full: bool) -> vigil::Result<()> {
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
            "Vigil Baseline -- {} Integrity Check (live)",
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

/// Render a "Recent baseline activity" timeline from the audit log.
///
/// Shows the last 7 days of audit entries (or the window specified by --since),
/// grouped by day, one line per event. Filters out internal vigil events
/// (operator acknowledgments, checkpoints) to focus on file changes.
fn render_recent_activity(cfg: &vigil::config::Config, opts: &CheckOpts) -> String {
    let audit_conn = match vigil::db::open_audit_db(cfg) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let since_ts = opts
        .since
        .as_deref()
        .and_then(parse_time_filter)
        .unwrap_or_else(|| chrono::Utc::now().timestamp() - 7 * 86_400);

    let q = vigil::db::audit_ops::AuditQuery {
        since: Some(since_ts),
        limit: 200,
        ..Default::default()
    };

    let entries = match vigil::db::audit_ops::query(&audit_conn, &q) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    // Filter out internal vigil events — only show real file changes.
    // Filesystem paths start with '/'; internal events do not.
    let file_entries: Vec<_> = entries.iter().filter(|e| e.path.starts_with('/')).collect();

    if file_entries.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(2048);

    let window_label = opts.since.as_deref().unwrap_or("7 days");

    out.push_str("\n  ");
    for _ in 0..62 {
        out.push('\u{2500}');
    }
    out.push_str("\n  Recent baseline activity (");
    out.push_str(window_label);
    out.push_str(")\n  ");
    for _ in 0..62 {
        out.push('\u{2500}');
    }
    out.push('\n');

    // Group by day (local time), most recent first.
    let mut current_day = String::new();
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let yesterday = (chrono::Local::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    for entry in &file_entries {
        let Some(dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(entry.timestamp, 0) else {
            continue;
        };
        let local = dt.with_timezone(&chrono::Local);
        let day_key = local.format("%Y-%m-%d").to_string();

        if day_key != current_day {
            let day_label = if day_key == today {
                "Today".to_string()
            } else if day_key == yesterday {
                "Yesterday".to_string()
            } else {
                local.format("%b %d").to_string()
            };
            out.push_str(&format!("\n  {}\n", day_label));
            current_day = day_key;
        }

        let time = local.format("%H:%M");
        let sev_upper = entry.severity.to_uppercase();
        let sev_marker = match entry.severity.as_str() {
            "critical" | "high" => "\u{25CF}",
            "medium" => "\u{25CF}",
            _ => "\u{25CB}",
        };

        // Extract a short change description from the JSON.
        let change_desc = short_change_description(&entry.changes_json);

        let maint_flag = if entry.maintenance { " [maint]" } else { "" };

        out.push_str(&format!(
            "    {}  {} {:<8} {:<36} {}{}\n",
            time,
            sev_marker,
            sev_upper,
            truncate_for_activity(&entry.path, 36),
            change_desc,
            maint_flag,
        ));
    }

    // Summary line.
    let mut unique_paths = std::collections::HashSet::new();
    let mut maint_count = 0usize;
    for e in &file_entries {
        unique_paths.insert(&e.path);
        if e.maintenance {
            maint_count += 1;
        }
    }

    out.push_str(&format!(
        "\n  {} event{} in last {} \u{00B7} {} path{} affected",
        file_entries.len(),
        if file_entries.len() == 1 { "" } else { "s" },
        window_label,
        unique_paths.len(),
        if unique_paths.len() == 1 { "" } else { "s" },
    ));
    if maint_count > 0 {
        out.push_str(&format!(" \u{00B7} {} during maintenance", maint_count));
    }
    out.push_str("\n\n");

    out
}

/// Extract a short human-readable description from changes_json.
fn short_change_description(json: &str) -> &'static str {
    if json.contains("ContentModified") {
        "content modified"
    } else if json.contains("Created") {
        "created"
    } else if json.contains("Deleted") {
        "deleted"
    } else if json.contains("PermissionsChanged") {
        "permissions changed"
    } else if json.contains("OwnerChanged") {
        "owner changed"
    } else if json.contains("SizeChanged") {
        "size changed"
    } else {
        "changed"
    }
}

/// Truncate a path for the activity timeline, preserving the filename.
fn truncate_for_activity(path: &str, max: usize) -> String {
    if path.len() <= max {
        return path.to_string();
    }
    if let Some(pos) = path.rfind('/') {
        let filename = &path[pos..];
        if filename.len() >= max {
            return format!("…{}", &filename[filename.len() - (max - 1)..]);
        }
        let avail = max - filename.len() - 1; // 1 for ellipsis
        if avail > 0 {
            return format!("{}…{}", &path[..avail], filename);
        }
    }
    format!("{}…", &path[..max - 1])
}

/// Runs forensic disambiguation against every change with a `ContentModified`,
/// attaching the result to `change.disambiguation`. Best-effort: failures
/// are silently skipped (the file may have been deleted or become unreadable
/// between the scan and the disambiguation pass).
fn run_disambiguation_pass(changes: &mut [vigil::types::ChangeResult], mmap_threshold: u64) {
    for change in changes.iter_mut() {
        // Find a ContentModified change to extract observed/baseline hashes.
        let (observed, baseline) = match change.changes.iter().find_map(|c| {
            if let vigil::types::Change::ContentModified { old_hash, new_hash } = c {
                Some((new_hash.clone(), old_hash.clone()))
            } else {
                None
            }
        }) {
            Some(pair) => pair,
            None => continue,
        };

        let path = change.path.as_ref();
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => continue,
        };

        if let Ok(result) = vigil::hash::disambiguate_via_cache_drop(
            &file,
            size,
            mmap_threshold,
            &observed,
            &baseline,
        ) {
            change.disambiguation = Some(result);
        }
        // Errors are intentionally swallowed: disambiguation is best-effort
        // metadata, not detection.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_change_description_detects_content_modified() {
        assert_eq!(
            short_change_description(r#"[{"ContentModified":{"old":"a","new":"b"}}]"#),
            "content modified"
        );
    }

    #[test]
    fn short_change_description_detects_created() {
        assert_eq!(short_change_description(r#"["Created"]"#), "created");
    }

    #[test]
    fn short_change_description_detects_deleted() {
        assert_eq!(short_change_description(r#"["Deleted"]"#), "deleted");
    }

    #[test]
    fn short_change_description_fallback() {
        assert_eq!(short_change_description(r#"[]"#), "changed");
    }

    #[test]
    fn truncate_for_activity_short_path() {
        let result = truncate_for_activity("/usr/bin/vigil", 36);
        assert_eq!(result, "/usr/bin/vigil");
    }

    #[test]
    fn truncate_for_activity_long_path() {
        let long = "/very/long/path/that/exceeds/limit/file.txt";
        let result = truncate_for_activity(long, 30);
        // Display width: the ellipsis occupies 1 column but 3 bytes.
        let display_width = result.chars().count();
        assert!(
            display_width <= 30,
            "truncated display width {} exceeds 30: {}",
            display_width,
            result
        );
        assert!(
            result.contains("file.txt"),
            "must keep filename: {}",
            result
        );
        assert!(result.contains('…'), "must have ellipsis: {}", result);
    }

    #[test]
    fn truncate_for_activity_exact_boundary() {
        let path = "/usr/bin/vigil"; // 14 chars
        let result = truncate_for_activity(path, 14);
        assert_eq!(result, path);
    }
}
