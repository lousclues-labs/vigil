use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand};

use chrono::Utc;
use clap::Parser;

use vigil::cli::{AuditAction, Cli, Command, ConfigAction};
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
        Command::Check { full } => {
            cmd_check(config_path.as_deref(), full)?;
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

fn cmd_status(config_path: Option<&Path>, format: OutputFormat) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    let daemon = doctor::probe_daemon(&cfg);
    let backend = doctor::monitor_backend_label(&cfg);
    let baseline_entries = doctor::baseline_count(&cfg);
    let recent_changes = doctor::recent_audit_change_count(&cfg, Utc::now().timestamp() - 86_400);
    let metrics = doctor::read_metrics(&cfg);
    let metrics_json = doctor::read_metrics(&cfg)
        .and_then(|m| serde_json::to_value(m).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let state_json = doctor::read_state_json(&cfg).unwrap_or_else(|| serde_json::json!({}));
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
        .and_then(|cfg| doctor::baseline_count(&cfg))
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
