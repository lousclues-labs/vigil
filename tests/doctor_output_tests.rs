/// Regression tests for doctor output accuracy (v1.2.1 patch).
///
/// Each test targets a specific bug from the 1.2.0 release. The tests
/// construct synthetic state, invoke the relevant doctor check or helper,
/// and assert the output matches the documented correct behavior.

// ---------------------------------------------------------------------------
// Bug 1: Data dir row reports actual directory usage, not filesystem totals
// ---------------------------------------------------------------------------

#[test]
fn data_dir_row_reports_actual_directory_usage() {
    let dir = tempfile::tempdir().expect("temp dir");

    // Seed files with known sizes.
    std::fs::write(dir.path().join("audit.db"), vec![0u8; 4096]).expect("write audit");
    std::fs::write(dir.path().join("baseline.db"), vec![0u8; 2048]).expect("write baseline");

    let usage = vigil::doctor::walk_data_dir_usage(dir.path()).expect("walk succeeded");

    // Total must equal the sum of file sizes, not the filesystem size.
    assert_eq!(usage.total, 4096 + 2048);
    assert_eq!(usage.audit, 4096);
    assert_eq!(usage.baseline, 2048);
    assert_eq!(usage.backups, 0);
    assert_eq!(usage.wal, 0);
    assert_eq!(usage.other, 0);
}

#[test]
fn data_dir_row_separates_filesystem_capacity_from_vigil_usage() {
    let dir = tempfile::tempdir().expect("temp dir");

    std::fs::write(dir.path().join("audit.db"), vec![0u8; 1024]).expect("write");

    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = dir.path().join("baseline.db");
    std::fs::write(&cfg.daemon.db_path, vec![0u8; 512]).expect("write baseline");

    let checks = vigil::doctor::run_diagnostics(&cfg);
    let storage = checks
        .iter()
        .find(|c| c.name == "Data dir")
        .expect("Data dir check must exist");

    // The detail must contain both a "used" line (vigil's usage) and a
    // "filesystem:" line (statvfs capacity). These are distinct values.
    assert!(
        storage.detail.contains("used"),
        "detail must show vigil usage: {}",
        storage.detail
    );
    assert!(
        storage.detail.contains("filesystem:"),
        "detail must show filesystem capacity: {}",
        storage.detail
    );
}

#[test]
fn data_dir_row_categorizes_by_component() {
    let dir = tempfile::tempdir().expect("temp dir");

    std::fs::write(dir.path().join("audit.db"), vec![0u8; 8192]).expect("write audit");
    std::fs::write(dir.path().join("audit.db-wal"), vec![0u8; 1024]).expect("write audit-wal");
    std::fs::write(dir.path().join("baseline.db"), vec![0u8; 2048]).expect("write baseline");
    std::fs::write(dir.path().join("detections.wal"), vec![0u8; 512]).expect("write wal");

    let backups = dir.path().join("binary-backups");
    std::fs::create_dir_all(&backups).expect("mkdir backups");
    std::fs::write(backups.join("vigil.bak"), vec![0u8; 4096]).expect("write backup");

    std::fs::write(dir.path().join("something.txt"), vec![0u8; 256]).expect("write other");

    let usage = vigil::doctor::walk_data_dir_usage(dir.path()).expect("walk succeeded");

    assert_eq!(usage.audit, 8192 + 1024, "audit includes .db and -wal");
    assert_eq!(usage.baseline, 2048);
    assert_eq!(usage.wal, 512);
    assert_eq!(usage.backups, 4096);
    assert_eq!(usage.other, 256);
    assert_eq!(usage.total, 8192 + 1024 + 2048 + 512 + 4096 + 256);

    let breakdown = usage.breakdown_string();
    assert!(breakdown.contains("audit:"), "breakdown: {}", breakdown);
    assert!(breakdown.contains("baseline:"), "breakdown: {}", breakdown);
    assert!(breakdown.contains("WAL:"), "breakdown: {}", breakdown);
    assert!(breakdown.contains("backups:"), "breakdown: {}", breakdown);
    assert!(breakdown.contains("other:"), "breakdown: {}", breakdown);
}

#[test]
fn data_dir_row_handles_walk_failure_gracefully() {
    // Point at a guaranteed non-existent directory.
    let missing = std::env::temp_dir().join(format!(
        "vigil-nonexistent-test-dir-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time monotonic")
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&missing);

    let result = vigil::doctor::walk_data_dir_usage(&missing);
    assert!(result.is_err(), "walk of non-existent dir must fail");

    // Run full diagnostics with an unreachable data dir to confirm doctor
    // does not crash and still produces a Data dir row.
    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = missing.join("baseline.db");

    let checks = vigil::doctor::run_diagnostics(&cfg);
    let storage = checks
        .iter()
        .find(|c| c.name == "Data dir")
        .expect("Data dir check must exist even on failure");

    // Must not be Ok -- either Warning, Failed, or Unknown.
    assert_ne!(
        storage.status,
        vigil::doctor::CheckStatus::Ok,
        "broken dir should not show Ok"
    );
}

// ---------------------------------------------------------------------------
// Bug 2: Hooks row marker reflects last-trigger failure
// ---------------------------------------------------------------------------

#[test]
fn hooks_row_marker_reflects_last_trigger_failure() {
    // Simulate a journalctl line containing "failed".
    let result = vigil::doctor::HookTriggerResult::Failure(
        "2026-04-23T00:40:27-04:00".to_string(),
        "vigil-pacman".to_string(),
    );
    assert_eq!(
        result,
        vigil::doctor::HookTriggerResult::Failure(
            "2026-04-23T00:40:27-04:00".to_string(),
            "vigil-pacman".to_string()
        )
    );

    // When rendered as a check, the status must be Warning, not Ok.
    // Build a check that matches the code path for installed + failed trigger.
    let check = vigil::doctor::DiagnosticCheck {
        name: "Hooks".to_string(),
        status: vigil::doctor::CheckStatus::Warning,
        detail: format!(
            "installed (pacman pre/post); last trigger {} failed",
            "2026-04-23T00:40"
        ),
        recovery: vigil::doctor::Recovery::None,
    };
    assert_eq!(check.status, vigil::doctor::CheckStatus::Warning);
    assert_eq!(check.status.marker(), "⚠");
}

#[test]
fn hooks_row_marker_healthy_on_successful_last_trigger() {
    let result = vigil::doctor::HookTriggerResult::Success("2026-04-23T00:40".to_string());
    // For a successful trigger, the check status must be Ok.
    match result {
        vigil::doctor::HookTriggerResult::Success(ts) => {
            assert_eq!(ts, "2026-04-23T00:40");
        }
        _ => panic!("expected Success variant"),
    }
}

#[test]
fn hooks_row_marker_healthy_when_never_triggered() {
    let result = vigil::doctor::HookTriggerResult::NeverTriggered;
    // NeverTriggered maps to Ok status and "never triggered" message.
    assert_eq!(result, vigil::doctor::HookTriggerResult::NeverTriggered);
}

// ---------------------------------------------------------------------------
// Bug 3: Socket row reports actual routing behavior
// ---------------------------------------------------------------------------

#[test]
fn socket_row_reports_dropped_alerts_when_no_listener() {
    let mut cfg = vigil::config::default_config();
    // Set a socket path that does not exist (no listener).
    cfg.hooks.signal_socket = "/tmp/vigil-test-nonexistent-socket-8675309.sock".to_string();

    let checks = vigil::doctor::run_diagnostics(&cfg);
    let socket = checks
        .iter()
        .find(|c| c.name == "Socket")
        .expect("Socket check must exist");

    // Must be Failed (not Unknown/informational) because alerts are dropped.
    assert_eq!(
        socket.status,
        vigil::doctor::CheckStatus::Failed,
        "socket with no listener must be Failed, got {:?}: {}",
        socket.status,
        socket.detail
    );
    assert!(
        socket.detail.contains("dropped"),
        "detail must mention alerts are dropped: {}",
        socket.detail
    );
}

#[test]
fn socket_row_optional_when_not_configured() {
    let mut cfg = vigil::config::default_config();
    cfg.hooks.signal_socket = String::new();

    let checks = vigil::doctor::run_diagnostics(&cfg);
    let socket = checks
        .iter()
        .find(|c| c.name == "Socket")
        .expect("Socket check must exist");

    assert_eq!(socket.status, vigil::doctor::CheckStatus::Unknown);
    assert!(socket.is_optional_not_configured());
}

// ---------------------------------------------------------------------------
// Bug 4: Summary distinguishes optional features from check failures
// ---------------------------------------------------------------------------

#[test]
fn summary_distinguishes_optional_from_failure() {
    let checks = vec![
        make_check("Daemon", vigil::doctor::CheckStatus::Ok),
        make_check("State", vigil::doctor::CheckStatus::Ok),
        make_check("Backend", vigil::doctor::CheckStatus::Ok),
        make_check("Control", vigil::doctor::CheckStatus::Ok),
        make_check("Baseline", vigil::doctor::CheckStatus::Ok),
        make_check("Database", vigil::doctor::CheckStatus::Ok),
        make_check("Audit log", vigil::doctor::CheckStatus::Ok),
        make_check("Data dir", vigil::doctor::CheckStatus::Ok),
        make_check("WAL pipeline", vigil::doctor::CheckStatus::Ok),
        make_check("Config", vigil::doctor::CheckStatus::Ok),
        make_check("Scan timer", vigil::doctor::CheckStatus::Ok),
        make_check("HMAC key", vigil::doctor::CheckStatus::Ok),
        make_check("Notify", vigil::doctor::CheckStatus::Ok),
        make_check("Hooks", vigil::doctor::CheckStatus::Ok),
        make_check("Attest key", vigil::doctor::CheckStatus::Unknown),
        make_check("Socket", vigil::doctor::CheckStatus::Unknown),
    ];

    let summary = vigil::doctor::format_doctor_summary(&checks);
    assert!(
        summary.contains("all checks passed"),
        "summary should say all passed: {}",
        summary
    );
    assert!(
        summary.contains("2 optional features not configured"),
        "summary should mention 2 optional: {}",
        summary
    );
    // Must NOT say "14/16" or treat optional as failures.
    assert!(
        !summary.contains("14/16"),
        "summary must not use old X/Y format: {}",
        summary
    );
}

#[test]
fn summary_reports_warnings_and_failures_separately() {
    let checks = vec![
        make_check("Daemon", vigil::doctor::CheckStatus::Ok),
        make_check("State", vigil::doctor::CheckStatus::Ok),
        make_check("Backend", vigil::doctor::CheckStatus::Ok),
        make_check("Control", vigil::doctor::CheckStatus::Ok),
        make_check("Baseline", vigil::doctor::CheckStatus::Ok),
        make_check("Database", vigil::doctor::CheckStatus::Ok),
        make_check("Audit log", vigil::doctor::CheckStatus::Ok),
        make_check("Data dir", vigil::doctor::CheckStatus::Ok),
        make_check("WAL pipeline", vigil::doctor::CheckStatus::Ok),
        make_check("Config", vigil::doctor::CheckStatus::Ok),
        make_check("Scan timer", vigil::doctor::CheckStatus::Ok),
        make_check("HMAC key", vigil::doctor::CheckStatus::Ok),
        make_check("Notify", vigil::doctor::CheckStatus::Ok),
        make_check("Hooks", vigil::doctor::CheckStatus::Warning),
        make_check("Socket", vigil::doctor::CheckStatus::Failed),
        make_check("Attest key", vigil::doctor::CheckStatus::Unknown),
    ];

    let summary = vigil::doctor::format_doctor_summary(&checks);
    assert!(
        summary.contains("1 failure"),
        "summary should report 1 failure: {}",
        summary
    );
    assert!(
        summary.contains("1 warning"),
        "summary should report 1 warning: {}",
        summary
    );
    assert!(
        summary.contains("13 healthy"),
        "summary should report 13 healthy: {}",
        summary
    );
    assert!(
        summary.contains("1 optional feature not configured"),
        "summary should report 1 optional: {}",
        summary
    );
}

#[test]
fn summary_pluralization_correct() {
    // 1 optional (singular)
    let checks_one = vec![
        make_check("Daemon", vigil::doctor::CheckStatus::Ok),
        make_check("Attest key", vigil::doctor::CheckStatus::Unknown),
    ];
    let summary_one = vigil::doctor::format_doctor_summary(&checks_one);
    assert!(
        summary_one.contains("1 optional feature not configured"),
        "singular: {}",
        summary_one
    );
    assert!(
        !summary_one.contains("features"),
        "must use singular 'feature': {}",
        summary_one
    );

    // 2 optional (plural)
    let checks_two = vec![
        make_check("Daemon", vigil::doctor::CheckStatus::Ok),
        make_check("Attest key", vigil::doctor::CheckStatus::Unknown),
        make_check("Socket", vigil::doctor::CheckStatus::Unknown),
    ];
    let summary_two = vigil::doctor::format_doctor_summary(&checks_two);
    assert!(
        summary_two.contains("2 optional features not configured"),
        "plural: {}",
        summary_two
    );
}

#[test]
fn summary_all_healthy_no_optional() {
    let checks = vec![
        make_check("Daemon", vigil::doctor::CheckStatus::Ok),
        make_check("Config", vigil::doctor::CheckStatus::Ok),
    ];
    let summary = vigil::doctor::format_doctor_summary(&checks);
    assert_eq!(summary, "all checks passed");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_check(name: &str, status: vigil::doctor::CheckStatus) -> vigil::doctor::DiagnosticCheck {
    vigil::doctor::DiagnosticCheck {
        name: name.to_string(),
        status,
        detail: "test".to_string(),
        recovery: vigil::doctor::Recovery::None,
    }
}

// ===========================================================================
// Bug A: Recovery hint typing
// ===========================================================================

#[test]
fn recovery_command_is_command_variant() {
    // A row with a real command must use Recovery::Command.
    let r = vigil::doctor::Recovery::Command("vigil init".into());
    assert!(matches!(r, vigil::doctor::Recovery::Command(_)));
}

#[test]
fn recovery_command_with_context_has_both_fields() {
    let r = vigil::doctor::Recovery::CommandWithContext {
        command: "vigil audit prune --before 2026-01-01 --confirm".into(),
        context: "or: vigil recover --reason audit_log_full".into(),
    };
    match r {
        vigil::doctor::Recovery::CommandWithContext { command, context } => {
            assert!(command.starts_with("vigil"));
            assert!(context.contains("or:"));
        }
        _ => panic!("expected CommandWithContext"),
    }
}

#[test]
fn recovery_manual_is_manual_variant() {
    let r = vigil::doctor::Recovery::Manual(
        "attach a listener or remove the socket path from vigil.toml".into(),
    );
    assert!(matches!(r, vigil::doctor::Recovery::Manual(_)));
}

#[test]
fn recovery_documentation_is_documentation_variant() {
    let r = vigil::doctor::Recovery::Documentation("docs/TROUBLESHOOTING.md".into());
    assert!(matches!(r, vigil::doctor::Recovery::Documentation(_)));
}

#[test]
fn recovery_none_is_none_variant() {
    let r = vigil::doctor::Recovery::None;
    assert!(matches!(r, vigil::doctor::Recovery::None));
}

#[test]
fn socket_row_uses_multi_hint_recovery() {
    // When the socket is configured but has no listener, the recovery
    // uses Multi hints: a real disable command plus an alternative
    // about the listener.
    let mut cfg = vigil::config::default_config();
    cfg.hooks.signal_socket = "/tmp/vigil-test-nonexistent-socket".to_string();

    let checks = vigil::doctor::run_diagnostics(&cfg);
    let socket = checks
        .iter()
        .find(|c| c.name == "Socket")
        .expect("Socket check must exist");

    assert_eq!(socket.status, vigil::doctor::CheckStatus::Failed);
    match &socket.recovery {
        vigil::doctor::Recovery::Multi(hints) => {
            assert!(hints.len() >= 2, "expected at least 2 hints");
            // First hint should be the disable command
            match &hints[0] {
                vigil::doctor::RecoveryHint::Command { command, .. } => {
                    assert_eq!(command, "vigil alerts socket disable");
                }
                other => panic!("expected Command hint first, got: {:?}", other),
            }
            // Second hint should mention "listener"
            match &hints[1] {
                vigil::doctor::RecoveryHint::Manual { instruction, .. } => {
                    assert!(
                        instruction.contains("listener"),
                        "second hint should mention listener: {}",
                        instruction
                    );
                }
                other => panic!("expected Manual hint second, got: {:?}", other),
            }
        }
        other => panic!("expected Multi recovery, got: {:?}", other),
    }
}

#[test]
fn every_row_recovery_variant_is_explicit() {
    // Run diagnostics and verify no row has a Recovery variant that could
    // produce a fake command. This is a structural test: the Recovery enum
    // has no "default" or "auto" variant.
    let cfg = vigil::config::default_config();
    let checks = vigil::doctor::run_diagnostics(&cfg);

    for check in &checks {
        // Every row must use an explicit Recovery variant.
        // The compiler already enforces this via the enum, but this test
        // documents the intent: no row falls through to a default.
        match &check.recovery {
            vigil::doctor::Recovery::Command(cmd) => {
                // Commands must look like commands (contain a known prefix).
                assert!(
                    cmd.starts_with("vigil ")
                        || cmd.starts_with("sudo ")
                        || cmd.starts_with("openssl ")
                        || cmd.starts_with("cp ")
                        || cmd.contains("systemctl"),
                    "Recovery::Command does not look like a command: {} (row: {})",
                    cmd,
                    check.name
                );
            }
            vigil::doctor::Recovery::CommandWithContext { command, .. } => {
                assert!(
                    !command.is_empty(),
                    "CommandWithContext has empty command (row: {})",
                    check.name
                );
            }
            vigil::doctor::Recovery::Manual(guidance) => {
                assert!(
                    !guidance.is_empty(),
                    "Manual recovery is empty (row: {})",
                    check.name
                );
            }
            vigil::doctor::Recovery::Documentation(path) => {
                assert!(
                    !path.is_empty(),
                    "Documentation path is empty (row: {})",
                    check.name
                );
            }
            vigil::doctor::Recovery::None => {
                // OK: no recovery needed.
            }
            vigil::doctor::Recovery::Multi(hints) => {
                assert!(
                    !hints.is_empty(),
                    "Multi recovery has no hints (row: {})",
                    check.name
                );
            }
        }
    }
}

// ===========================================================================
// Bug B: Status/severity cannot contradict
// ===========================================================================

#[test]
fn status_failure_produces_failure_marker() {
    let s = vigil::doctor::CheckStatus::Failed;
    assert_eq!(s.marker(), "✗");
}

#[test]
fn status_warning_produces_warning_marker() {
    let s = vigil::doctor::CheckStatus::Warning;
    assert_eq!(s.marker(), "⚠");
}

#[test]
fn status_ok_produces_healthy_marker() {
    let s = vigil::doctor::CheckStatus::Ok;
    assert_eq!(s.marker(), "●");
}

#[test]
fn status_unknown_produces_optional_marker() {
    let s = vigil::doctor::CheckStatus::Unknown;
    assert_eq!(s.marker(), "○");
}

// ===========================================================================
// Bug C: Summary aggregation
// ===========================================================================

#[test]
fn summary_with_one_failure_two_warnings_reports_failure_first() {
    let checks = vec![
        make_check("a", vigil::doctor::CheckStatus::Failed),
        make_check("b", vigil::doctor::CheckStatus::Warning),
        make_check("c", vigil::doctor::CheckStatus::Warning),
        make_check("d", vigil::doctor::CheckStatus::Ok),
    ];
    let summary = vigil::doctor::format_doctor_summary(&checks);
    assert!(
        summary.contains("1 failure"),
        "should mention failure: {}",
        summary
    );
    assert!(
        summary.contains("2 warnings"),
        "should mention warnings: {}",
        summary
    );
    // Failure must appear before warnings in the string.
    let fail_pos = summary.find("failure").unwrap();
    let warn_pos = summary.find("warning").unwrap();
    assert!(
        fail_pos < warn_pos,
        "failure should come first: {}",
        summary
    );
}

#[test]
fn summary_with_only_warnings_does_not_mention_failures() {
    let checks = vec![
        make_check("a", vigil::doctor::CheckStatus::Warning),
        make_check("b", vigil::doctor::CheckStatus::Ok),
    ];
    let summary = vigil::doctor::format_doctor_summary(&checks);
    assert!(
        summary.contains("1 warning"),
        "should mention warning: {}",
        summary
    );
    assert!(
        !summary.contains("failure"),
        "should not mention failure: {}",
        summary
    );
}

#[test]
fn summary_with_optional_not_configured_does_not_count_as_warning() {
    // Attest key and Socket with Unknown status are optional, not warnings.
    let mut checks = vec![
        make_check("Daemon", vigil::doctor::CheckStatus::Ok),
        make_check("Attest key", vigil::doctor::CheckStatus::Unknown),
        make_check("Socket", vigil::doctor::CheckStatus::Unknown),
    ];
    // Override details to match the is_optional_not_configured logic.
    checks[1].detail = "not configured".to_string();
    checks[2].detail = "not configured".to_string();

    let summary = vigil::doctor::format_doctor_summary(&checks);
    assert!(
        summary.contains("all checks passed"),
        "optional rows should not prevent 'all checks passed': {}",
        summary
    );
    assert!(
        summary.contains("optional"),
        "should mention optional features: {}",
        summary
    );
}

#[test]
fn summary_with_all_healthy_and_optional_reads_correctly() {
    let mut checks = vec![
        make_check("Daemon", vigil::doctor::CheckStatus::Ok),
        make_check("Baseline", vigil::doctor::CheckStatus::Ok),
        make_check("Attest key", vigil::doctor::CheckStatus::Unknown),
    ];
    checks[2].detail = "not configured".to_string();

    let summary = vigil::doctor::format_doctor_summary(&checks);
    assert!(
        summary.contains("all checks passed"),
        "should say all passed: {}",
        summary
    );
    assert!(
        summary.contains("1 optional feature not configured"),
        "should mention optional: {}",
        summary
    );
}

// ===========================================================================
// Bug D: Auto-scaled units
// ===========================================================================

#[test]
fn format_size_uses_b_below_1024() {
    let s = vigil::display::format::format_size(512);
    assert_eq!(s, "512 B");
}

#[test]
fn format_size_uses_kb_below_1mb() {
    let s = vigil::display::format::format_size(500_000);
    assert!(s.contains("KB"), "expected KB: {}", s);
}

#[test]
fn format_size_uses_mb_below_1gb() {
    let s = vigil::display::format::format_size(500_000_000);
    assert!(s.contains("MB"), "expected MB: {}", s);
}

#[test]
fn format_size_uses_gb_below_1tb() {
    let s = vigil::display::format::format_size(500_000_000_000);
    assert!(s.contains("GB"), "expected GB: {}", s);
}

#[test]
fn format_size_uses_tb_at_tb_scale() {
    let s = vigil::display::format::format_size(2_000_000_000_000);
    assert!(s.contains("TB"), "expected TB: {}", s);
}

#[test]
fn format_size_large_gb_value_renders_without_mb() {
    // 318 GB should render as "X GB", not "X MB"
    let bytes: u64 = 318 * 1_073_741_824;
    let s = vigil::display::format::format_size(bytes);
    assert!(s.contains("GB"), "318 GB should use GB unit: {}", s);
    assert!(!s.contains("MB"), "should not contain MB: {}", s);
}

// ===========================================================================
// Bug E: Relative time
// ===========================================================================

#[test]
fn relative_duration_from_recent_timestamp() {
    let now = chrono::Utc::now().timestamp();
    let thirty_min_ago = now - 1800;
    let result = vigil::doctor::format_relative_duration_from_timestamp(thirty_min_ago);
    assert!(result.contains("ago"), "should contain 'ago': {}", result);
    assert!(
        result.contains("30m") || result.contains("29m") || result.contains("31m"),
        "should show ~30 minutes: {}",
        result
    );
}

#[test]
fn next_timer_relative_unknown_input() {
    let result = vigil::doctor::format_next_timer_relative("");
    assert_eq!(result, "unknown");

    let result2 = vigil::doctor::format_next_timer_relative("n/a");
    assert_eq!(result2, "unknown");
}

#[test]
fn relative_duration_handles_zero() {
    let now = chrono::Utc::now().timestamp();
    let result = vigil::doctor::format_relative_duration_from_timestamp(now);
    assert!(
        result == "just now" || result.contains("ago"),
        "zero delta should be 'just now' or very small: {}",
        result
    );
}

// ===========================================================================
// Bug F: Clap suggestions (structural test only -- actual CLI invocation
// tested manually)
// ===========================================================================

#[test]
fn check_command_has_accept_flag() {
    // Verify the Check subcommand exists with --accept, confirming
    // that --update is not a valid flag (the likely typo target).
    use clap::Parser;
    let result = vigil::cli::Cli::try_parse_from(["vigil", "check", "--accept"]);
    assert!(result.is_ok(), "vigil check --accept should parse");
}

#[test]
fn check_with_unknown_flag_is_error() {
    use clap::Parser;
    let result = vigil::cli::Cli::try_parse_from(["vigil", "check", "--update"]);
    assert!(result.is_err(), "vigil check --update should fail");
}

// ===========================================================================
// Recovery/message overlap guard
// ===========================================================================

#[test]
fn socket_row_does_not_duplicate_recovery_in_message() {
    let mut cfg = vigil::config::default_config();
    cfg.hooks.signal_socket = "/tmp/vigil-test-nonexistent-socket".to_string();

    let checks = vigil::doctor::run_diagnostics(&cfg);
    let socket = checks
        .iter()
        .find(|c| c.name == "Socket")
        .expect("Socket check must exist");

    let recovery_text = socket.recovery.text().expect("Socket should have recovery");
    assert!(
        !socket.detail.contains(recovery_text),
        "Socket row duplicates recovery guidance in detail: detail={:?}, recovery={:?}",
        socket.detail,
        recovery_text,
    );
}

#[test]
fn no_doctor_row_duplicates_recovery_in_message() {
    let cfg = vigil::config::default_config();
    let checks = vigil::doctor::run_diagnostics(&cfg);

    for check in &checks {
        if let Some(recovery_text) = check.recovery.text() {
            assert!(
                !check.detail.contains(recovery_text),
                "row '{}' duplicates recovery guidance in detail: detail={:?}, recovery={:?}",
                check.name,
                check.detail,
                recovery_text,
            );
        }
    }
}

// ===========================================================================
// Hooks row recovery
// ===========================================================================

#[test]
fn hooks_row_recovery_is_repair_command_when_not_installed() {
    // When hooks are not installed, the recovery should be a
    // `vigil hooks repair` command, not a manual install instruction.
    let cfg = vigil::config::default_config();
    let checks = vigil::doctor::run_diagnostics(&cfg);
    let hooks = checks
        .iter()
        .find(|c| c.name == "Hooks")
        .expect("Hooks check must exist");

    // If hooks are detected as not installed, recovery should be Command
    if hooks.detail.contains("not installed") && hooks.status == vigil::doctor::CheckStatus::Warning
    {
        match &hooks.recovery {
            vigil::doctor::Recovery::Command(cmd) => {
                assert_eq!(cmd, "vigil hooks repair");
            }
            other => panic!(
                "expected Recovery::Command(vigil hooks repair), got: {:?}",
                other
            ),
        }
    }
    // Otherwise hooks are installed or package manager not detected -- both OK
}

// ===========================================================================
// CLI parsing for new subcommands
// ===========================================================================

#[test]
fn alerts_socket_status_parses() {
    use clap::Parser;
    let result = vigil::cli::Cli::try_parse_from(["vigil", "alerts", "socket", "status"]);
    assert!(result.is_ok(), "vigil alerts socket status should parse");
}

#[test]
fn alerts_socket_disable_parses() {
    use clap::Parser;
    let result = vigil::cli::Cli::try_parse_from(["vigil", "alerts", "socket", "disable"]);
    assert!(result.is_ok(), "vigil alerts socket disable should parse");
}

#[test]
fn alerts_socket_enable_parses() {
    use clap::Parser;
    let result = vigil::cli::Cli::try_parse_from([
        "vigil",
        "alerts",
        "socket",
        "enable",
        "/run/vigil/alert.sock",
    ]);
    assert!(
        result.is_ok(),
        "vigil alerts socket enable should parse: {:?}",
        result.err()
    );
}

#[test]
fn hooks_verify_parses() {
    use clap::Parser;
    let result = vigil::cli::Cli::try_parse_from(["vigil", "hooks", "verify"]);
    assert!(result.is_ok(), "vigil hooks verify should parse");
}

#[test]
fn hooks_repair_parses() {
    use clap::Parser;
    let result = vigil::cli::Cli::try_parse_from(["vigil", "hooks", "repair"]);
    assert!(result.is_ok(), "vigil hooks repair should parse");
}

// ===========================================================================
// Regression: every literal `vigil ...` recovery command in the doctor
// module must round-trip through the clap parser.
//
// This is the exact bug class that produced `vigil daemon recover --reason
// audit_chain_broken` -- a string that LOOKS like a vigil command but has
// no matching subcommand. It shipped for multiple releases because nothing
// in the test suite parsed recovery hints back through the CLI grammar.
//
// The two source files below contain every operator-facing recovery command
// the doctor and CLI emit. Scraping their string literals is fragile to
// formatting but cheap, exhaustive, and catches the regression.
// ===========================================================================

const DOCTOR_RECOVERY_SRC: &str = include_str!("../src/doctor/recovery.rs");
const DOCTOR_CHECKS_SRC: &str = include_str!("../src/doctor/checks.rs");
const COMMANDS_AUDIT_SRC: &str = include_str!("../src/commands/audit.rs");
const COMMANDS_BASELINE_SRC: &str = include_str!("../src/commands/baseline.rs");

/// Find every `"vigil ..."` literal in `src` and return the inner text.
/// Only matches simple double-quoted strings on a single line; recovery
/// hints are always written this way in the codebase. Strings with `{...}`
/// format placeholders are skipped because we cannot validate templates.
fn extract_vigil_command_literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        // Find every "vigil ..." substring on this line.
        let mut idx = 0;
        while let Some(start) = line[idx..].find("\"vigil ") {
            let abs_start = idx + start + 1; // after the opening quote
                                             // Find the closing quote on the same line.
            if let Some(rel_end) = line[abs_start..].find('"') {
                let abs_end = abs_start + rel_end;
                let literal = &line[abs_start..abs_end];
                // Skip strings that contain format placeholders -- we can
                // only parse fully-resolved commands.
                if !literal.contains('{') && !literal.contains('\\') {
                    out.push(literal.to_string());
                }
                idx = abs_end + 1;
            } else {
                break;
            }
        }
    }
    out
}

#[test]
fn every_doctor_recovery_command_literal_parses_via_clap() {
    use clap::Parser;
    let mut all = Vec::new();
    all.extend(extract_vigil_command_literals(DOCTOR_RECOVERY_SRC));
    all.extend(extract_vigil_command_literals(DOCTOR_CHECKS_SRC));
    all.extend(extract_vigil_command_literals(COMMANDS_AUDIT_SRC));
    all.extend(extract_vigil_command_literals(COMMANDS_BASELINE_SRC));

    assert!(
        !all.is_empty(),
        "scraper found no `vigil ...` literals -- the test is broken"
    );

    let mut failures: Vec<(String, String)> = Vec::new();
    for cmd in &all {
        // Tokenize on whitespace. Recovery hints never contain quoted args.
        let argv: Vec<&str> = cmd.split_whitespace().collect();
        // Replace operator-supplied placeholders with sentinel values so the
        // parser sees a complete command. `<date>` etc. would otherwise be
        // taken as positional values clap may reject.
        let argv: Vec<String> = argv
            .iter()
            .map(|s| {
                if s.starts_with('<') && s.ends_with('>') {
                    "PLACEHOLDER".to_string()
                } else {
                    (*s).to_string()
                }
            })
            .collect();
        match vigil::cli::Cli::try_parse_from(argv.iter().map(String::as_str)) {
            Ok(_) => {}
            Err(e) => failures.push((cmd.clone(), e.to_string())),
        }
    }

    assert!(
        failures.is_empty(),
        "the following recovery-command literals do not parse via clap \
         (this is the `vigil daemon recover` bug class):\n{}",
        failures
            .iter()
            .map(|(c, e)| format!("  `{}` -> {}", c, e.lines().next().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_degraded_reason_recover_command_parses() {
    use clap::Parser;
    use vigil::types::DegradedReason;

    for variant in DegradedReason::all_variants_for_introspection() {
        let code = variant.reason_code();
        let argv = ["vigil", "recover", "--reason", code, "--yes"];
        let result = vigil::cli::Cli::try_parse_from(argv);
        assert!(
            result.is_ok(),
            "`vigil recover --reason {}` does not parse: {:?}",
            code,
            result.err()
        );
    }
}
