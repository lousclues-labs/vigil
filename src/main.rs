use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand};

use chrono::Utc;
use clap::Parser;

use vigil::cli::{AuditAction, Cli, Command, ConfigAction, SetupAction};
use vigil::doctor;
use vigil::types::{OutputFormat, ScanMode};

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
        Command::Check { full, now } => {
            if now {
                cmd_check_live(config_path.as_deref(), full)?;
            } else {
                cmd_check(config_path.as_deref(), full)?;
            }
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

    let result = vigil::scanner::build_initial_baseline(&conn, &cfg)?;

    println!(
        "Building baseline from {} watch groups...",
        result.groups.len()
    );
    println!();

    for group in &result.groups {
        let paths = if group.paths.is_empty() {
            "(no paths configured)".to_string()
        } else {
            group.paths.join(", ")
        };

        println!("  {:<16} {}", group.name, paths);
        if group.errors > 0 {
            println!(
                "                   {} files baselined ({} capture errors)",
                format_count(group.file_count),
                group.errors
            );
        } else {
            println!(
                "                   {} files baselined",
                format_count(group.file_count)
            );
        }
        println!();
    }

    println!(
        "Total: {} files in {:.1}s",
        format_count(result.total_count),
        result.duration.as_secs_f64()
    );
    println!(
        "Database: {} ({})",
        cfg.daemon.db_path.display(),
        format_size(result.db_size_bytes)
    );
    println!();
    println!("Your filesystem has a witness now.");

    Ok(())
}

fn cmd_watch(config_path: Option<&Path>) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    println!("Starting vigilant monitor in foreground mode (Ctrl+C to stop)...");
    vigil::Daemon::from_config(cfg)?.run()
}

fn cmd_check(config_path: Option<&Path>, full: bool) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_baseline_db(&cfg)?;

    let mode = if full {
        ScanMode::Full
    } else {
        ScanMode::Incremental
    };

    println!("Running {} scan...", mode);
    let result = vigil::scanner::run_scan(&conn, &cfg, mode)?;

    println!("Checked: {}", result.total_checked);
    println!("Changes: {}", result.changes_found);
    println!("Errors: {}", result.errors);

    for change in result.changes.iter().take(20) {
        println!(
            "  [{}] {} ({})",
            change.severity,
            change.path.display(),
            change.primary_change_name()
        );
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
    let request = format!(r#"{{"method":"scan","params":{{"mode":"{}"}}}}"#, mode);

    println!("Triggering {} scan on running daemon...", mode);

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

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

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

        println!("Checked:  {}", format_count(checked));
        println!("Changes:  {}", changes);
        println!("Errors:   {}", errors);
        println!("Duration: {:.1}s", duration as f64 / 1000.0);
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
                println!(
                    "vigild    ● {} (v{}, uptime {})",
                    state,
                    version,
                    doctor::format_compact_duration(uptime)
                );
            }
            if let Some(metrics) = live.get("metrics") {
                let received = metrics
                    .get("events_received")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let changes = metrics
                    .get("changes_detected")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let dropped = metrics
                    .get("events_dropped")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!(
                    "events    {} received, {} changes, {} dropped",
                    format_count(received),
                    format_count(changes),
                    format_count(dropped)
                );

                let scan_ms = metrics
                    .get("scan_duration_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let scan_total = metrics
                    .get("last_scan_total")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if scan_total > 0 {
                    println!(
                        "last scan {} files in {:.1}s",
                        format_count(scan_total),
                        scan_ms as f64 / 1000.0
                    );
                }
            }
            println!("source    live (control socket)");
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

    if daemon.running {
        let uptime = daemon
            .uptime_seconds
            .map(doctor::format_compact_duration)
            .unwrap_or_else(|| "unknown".to_string());
        println!("vigild    ● running ({})", uptime);
        println!("backend   {}", backend);
    } else {
        println!("vigild    ✗ not running");
    }

    match baseline_entries {
        Some(count) => println!("baseline  {} entries", format_count(count.max(0) as u64)),
        None => println!("baseline  unknown"),
    }

    if daemon.running {
        println!(
            "changes   {} detected (last 24h)",
            recent_changes.unwrap_or(0)
        );
    } else {
        println!("changes   unknown (daemon offline)");
    }

    let last_scan_label = last_scan_at
        .map(doctor::format_relative_timestamp)
        .unwrap_or_else(|| "unknown".to_string());

    let cleanliness = if recent_changes.unwrap_or(0) == 0 {
        "clean".to_string()
    } else {
        format!("{} changes", recent_changes.unwrap_or(0))
    };

    if metrics.is_some() {
        println!("last scan {} — {}", last_scan_label, cleanliness);
    } else {
        println!("last scan {}", last_scan_label);
    }

    Ok(())
}

fn cmd_doctor(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let checks = doctor::run_diagnostics(&cfg);

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
        return Ok(doctor::diagnostics_exit_code(&checks));
    }

    println!("Vigil v{} — System Health Check", env!("CARGO_PKG_VERSION"));
    println!("════════════════════════════════════");
    println!();

    for check in &checks {
        println!(
            "  {:<12} {} {}",
            check.name,
            check.status.marker(),
            check.detail
        );
        if (check.status == doctor::CheckStatus::Warning
            || check.status == doctor::CheckStatus::Failed)
            && check.fix.is_some()
        {
            println!("               → {}", check.fix.as_deref().unwrap_or(""));
        }
    }

    println!();
    println!("  {}", doctor::diagnostics_verdict(&checks));

    Ok(doctor::diagnostics_exit_code(&checks))
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

    println!("✓ Vigil updated: {} → {}", current_version, new_version);
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
        AuditAction::Show { last } => {
            let entries = vigil::db::audit_ops::get_recent(&conn, last)?;
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&entries_to_json(&entries))?
                );
            } else {
                for e in entries {
                    println!("{} {} {}", e.timestamp, e.severity, e.path);
                }
            }
        }
        AuditAction::Verify => {
            let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn)?;
            println!("Audit Chain Verification");
            println!("------------------------");
            println!("Total entries: {}", total);
            println!("Valid links:   {}", valid);
            println!("Missing hash:  {}", missing);
            println!("Breaks:        {}", breaks.len());
            if !breaks.is_empty() {
                for (id, ts) in breaks {
                    println!("  break at id={} timestamp={}", id, ts);
                }
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
                serde_json::json!({
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "path": e.path,
                    "changes_json": e.changes_json,
                    "severity": e.severity,
                    "monitored_group": e.monitored_group,
                    "process_json": e.process_json,
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
            println!("Configuration is valid.");
            if !warnings.is_empty() {
                println!("Warnings:");
                for w in warnings {
                    println!("  - {}", w);
                }
            }
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

    println!("HMAC key written to {}", key_path.display());
    println!("Config updated: hmac_signing = true");
    println!();
    println!("Restart vigild for changes to take effect:");
    println!("  sudo systemctl restart vigild.service");

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

    println!("Socket sink configured: {}", socket_path.display());
    println!();
    println!("Restart vigild for changes to take effect:");
    println!("  sudo systemctl restart vigild.service");
    println!();
    println!("To listen for alerts:");
    println!("  socat UNIX-LISTEN:{} -", socket_path.display());

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
