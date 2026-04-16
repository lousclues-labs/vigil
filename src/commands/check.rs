use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use vigil::display;
use vigil::types::{OutputFormat, ScanMode, Severity};

use super::common::{format_count, parse_time_filter_strict, pipe_to_pager, print_header};

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
}

pub(crate) fn cmd_check(opts: CheckOpts) -> vigil::Result<i32> {
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
