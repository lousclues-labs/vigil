use std::process;

use clap::Parser;

use vigil::alert::AlertEngine;
use vigil::baseline;
use vigil::cli::{BaselineAction, Cli, Command, ConfigAction, LogAction, MaintenanceAction};
use vigil::config;
use vigil::db;
use vigil::error::Result;
use vigil::types::{OutputFormat, ScanMode};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        log::error!("{}", e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config;
    let format = cli.format;

    match cli.command {
        Command::Init => cmd_init(config_path.as_deref()),
        Command::Baseline { action } => cmd_baseline(config_path.as_deref(), format, action),
        Command::Watch => cmd_watch(config_path.as_deref()),
        Command::Check { full } => cmd_check(config_path.as_deref(), full),
        Command::Maintenance { action } => cmd_maintenance(config_path.as_deref(), action),
        Command::Log { action } => cmd_log(config_path.as_deref(), action),
        Command::Status => cmd_status(config_path.as_deref()),
        Command::Config { action } => cmd_config(config_path.as_deref(), action),
        Command::Doctor => cmd_doctor(config_path.as_deref()),
        Command::Version => {
            println!("vigil {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

// ── Commands ───────────────────────────────────────────────

fn print_warnings(warnings: &[vigil::error::ScanWarning]) {
    if warnings.is_empty() {
        return;
    }
    println!("\nWarnings ({}):", warnings.len());
    for w in warnings {
        let level = match w.severity {
            vigil::error::WarningSeverity::Info => "INFO",
            vigil::error::WarningSeverity::Warning => "WARN",
            vigil::error::WarningSeverity::Error => "ERROR",
        };
        println!("  [{}] {}: {}", level, w.path.display(), w.detail);
    }
}

fn cmd_init(config_path: Option<&std::path::Path>) -> Result<()> {
    let cfg = config::load_config(config_path)?;
    let conn = db::open_db(&cfg)?;

    println!("Initializing baseline...");
    let (count, warnings) = baseline::init_baseline(&conn, &cfg, false)?;
    println!("Baseline initialized: {} entries", count);
    print_warnings(&warnings);

    Ok(())
}

fn cmd_baseline(
    config_path: Option<&std::path::Path>,
    _format: OutputFormat,
    action: BaselineAction,
) -> Result<()> {
    let cfg = config::load_config(config_path)?;
    let conn = db::open_db(&cfg)?;

    match action {
        BaselineAction::Init => {
            let (count, warnings) = baseline::init_baseline(&conn, &cfg, false)?;
            println!("Baseline initialized: {} entries", count);
            print_warnings(&warnings);
        }
        BaselineAction::Refresh { paths, quiet } => {
            let filter = paths.map(|p| vec![p]);
            let (count, warnings) =
                baseline::refresh_baseline(&conn, &cfg, filter.as_deref(), quiet)?;
            if !quiet {
                println!("Baseline refreshed: {} entries", count);
                print_warnings(&warnings);
            }
        }
        BaselineAction::Diff => {
            let changes = baseline::diff_baseline(&conn, &cfg)?;
            if changes.is_empty() {
                println!("No changes detected.");
            } else {
                println!("{} change(s) detected:\n", changes.len());
                for change in &changes {
                    let types: Vec<String> =
                        change.change_types.iter().map(|c| c.to_string()).collect();
                    println!(
                        "  {} [{}] {} ({})",
                        change.severity.to_string().to_uppercase(),
                        types.join(", "),
                        change.path.display(),
                        change.monitored_group,
                    );

                    if let (Some(old), Some(new)) = (&change.old_hash, &change.new_hash) {
                        println!(
                            "    Hash: {}… → {}…",
                            &old[..8.min(old.len())],
                            &new[..8.min(new.len())]
                        );
                    }
                    if let (Some(old_p), Some(new_p)) =
                        (change.old_permissions, change.new_permissions)
                    {
                        if old_p != new_p {
                            println!("    Perms: {:04o} → {:04o}", old_p & 0o7777, new_p & 0o7777);
                        }
                    }
                }
            }
        }
        BaselineAction::Add { path } => {
            baseline::add_file(&conn, &path, &cfg)?;
            println!("Added to baseline: {}", path.display());
        }
        BaselineAction::Remove { path } => {
            baseline::remove_file(&conn, &path)?;
            println!("Removed from baseline: {}", path.display());
        }
        BaselineAction::Stats => {
            let stats = baseline::baseline_stats(&conn)?;
            println!("Baseline Statistics");
            println!("━━━━━━━━━━━━━━━━━━━");
            println!("  Total entries: {}", stats.total_entries);
            for (source, count) in &stats.by_source {
                println!("  {}: {}", source, count);
            }
            if let Some(ref refresh) = stats.last_refresh {
                println!("  Last refresh: {}", refresh);
            }
        }
        BaselineAction::Export => {
            let entries = db::ops::get_all_baselines(&conn)?;
            let json = serde_json::to_string_pretty(&entries)?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn cmd_watch(config_path: Option<&std::path::Path>) -> Result<()> {
    let cfg = config::load_config(config_path)?;

    // The 'watch' command in the CLI starts the daemon inline (foreground mode).
    // For systemd-managed daemon, use vigild binary instead.
    println!("Starting Vigil real-time monitor (foreground mode)...");
    println!("Press Ctrl+C to stop.\n");

    vigil::daemon_run(&cfg)?;

    Ok(())
}

fn cmd_check(config_path: Option<&std::path::Path>, full: bool) -> Result<()> {
    let cfg = config::load_config(config_path)?;
    let conn = db::open_db(&cfg)?;
    let alert_engine = AlertEngine::new(&cfg)?;

    let mode = if full {
        ScanMode::Full
    } else {
        ScanMode::Incremental
    };

    println!("Running {} integrity check...", mode);

    let is_tty = atty_is_tty();
    let progress_cb = |step: &str| {
        eprint!("\r\x1b[K [>] {}", step);
    };
    let progress: vigil::ProgressCallback = if is_tty { Some(&progress_cb) } else { None };

    let result = vigil::scanner::run_scan(&conn, &cfg, &alert_engine, mode, progress)?;

    if is_tty {
        eprint!("\r\x1b[K"); // Clear progress line
    }

    println!("\nScan complete:");
    println!("  Files checked: {}", result.total_checked);
    println!("  Changes found: {}", result.changes_found);
    println!("  Errors: {}", result.errors);
    print_warnings(&result.warnings);

    Ok(())
}

fn cmd_maintenance(config_path: Option<&std::path::Path>, action: MaintenanceAction) -> Result<()> {
    let cfg = config::load_config(config_path)?;
    let conn = db::open_db(&cfg)?;

    match action {
        MaintenanceAction::Enter { quiet } => {
            db::ops::set_config_state(&conn, "maintenance_window_active", "1")?;
            db::ops::set_config_state(
                &conn,
                "maintenance_window_started",
                &chrono::Utc::now().timestamp().to_string(),
            )?;
            if !quiet {
                println!("Maintenance window entered. Notifications suppressed for package-managed paths.");
            }
        }
        MaintenanceAction::Exit { quiet } => {
            db::ops::set_config_state(&conn, "maintenance_window_active", "0")?;
            if !quiet {
                println!("Maintenance window exited. Normal alerting resumed.");
            }
        }
        MaintenanceAction::Status => {
            let active = db::ops::get_config_state(&conn, "maintenance_window_active")?
                .map(|v| v == "1")
                .unwrap_or(false);
            if active {
                let started = db::ops::get_config_state(&conn, "maintenance_window_started")?
                    .unwrap_or_else(|| "unknown".into());
                println!("Maintenance window: ACTIVE (since {})", started);
            } else {
                println!("Maintenance window: INACTIVE");
            }
        }
    }

    Ok(())
}

fn cmd_log(config_path: Option<&std::path::Path>, action: LogAction) -> Result<()> {
    let cfg = config::load_config(config_path)?;
    let conn = db::open_db(&cfg)?;

    match action {
        LogAction::Show { severity, last } => {
            let entries = db::ops::get_recent_audit(&conn, last)?;
            if entries.is_empty() {
                println!("No audit entries found.");
                return Ok(());
            }

            for entry in &entries {
                if let Some(ref sev_filter) = severity {
                    if entry.severity != *sev_filter {
                        continue;
                    }
                }

                let ts = chrono::DateTime::from_timestamp(entry.timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| entry.timestamp.to_string());

                println!(
                    "  {} [{}] {} — {}{}",
                    ts,
                    entry.severity.to_uppercase(),
                    entry.change_type,
                    entry.path,
                    if entry.suppressed {
                        " (suppressed)"
                    } else {
                        ""
                    },
                );
            }
        }
        LogAction::Search { path, severity } => {
            let entries = db::ops::search_audit(&conn, path.as_deref(), severity.as_deref(), 1000)?;
            for entry in &entries {
                println!(
                    "  {} [{}] {} — {}",
                    entry.timestamp, entry.severity, entry.change_type, entry.path
                );
            }
            println!("\n{} entries found.", entries.len());
        }
        LogAction::Stats => {
            let entries = db::ops::get_recent_audit(&conn, 10000)?;
            let total = entries.len();
            let suppressed = entries.iter().filter(|e| e.suppressed).count();
            let critical = entries.iter().filter(|e| e.severity == "critical").count();
            let high = entries.iter().filter(|e| e.severity == "high").count();
            let medium = entries.iter().filter(|e| e.severity == "medium").count();
            let low = entries.iter().filter(|e| e.severity == "low").count();

            println!("Alert Statistics");
            println!("━━━━━━━━━━━━━━━━");
            println!("  Total events: {}", total);
            println!("  Suppressed:   {}", suppressed);
            println!("  Critical:     {}", critical);
            println!("  High:         {}", high);
            println!("  Medium:       {}", medium);
            println!("  Low:          {}", low);
        }
        LogAction::Verify => {
            if !cfg.security.hmac_signing {
                println!("HMAC signing is not enabled in configuration.");
                println!("Set security.hmac_signing = true and provide a key file.");
                return Ok(());
            }

            let key = vigil::hmac::load_hmac_key(&cfg.security.hmac_key_path)?;
            let entries = db::ops::get_recent_audit(&conn, u32::MAX)?;

            let mut valid = 0u64;
            let mut invalid = 0u64;
            let mut missing = 0u64;

            for entry in &entries {
                // Reconstruct the HMAC data from entry fields
                let data = vigil::hmac::build_audit_hmac_data(
                    entry.timestamp,
                    &entry.path,
                    &entry.change_type,
                    &entry.severity,
                    entry.old_hash.as_deref(),
                    entry.new_hash.as_deref(),
                );

                // Get the stored HMAC from the database
                match db::ops::get_audit_hmac(&conn, entry.id) {
                    Ok(Some(stored_hmac)) => {
                        if vigil::hmac::verify_hmac(&key, &data, &stored_hmac) {
                            valid += 1;
                        } else {
                            invalid += 1;
                            println!(
                                "  INVALID: {} [{}] {} (id={})",
                                entry.timestamp, entry.severity, entry.path, entry.id
                            );
                        }
                    }
                    Ok(None) => {
                        missing += 1;
                    }
                    Err(e) => {
                        log::debug!("Error reading HMAC for entry {}: {}", entry.id, e);
                        missing += 1;
                    }
                }
            }

            println!("HMAC Verification Results");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Total entries: {}", entries.len());
            println!("  Valid:         {}", valid);
            println!("  Invalid:       {}", invalid);
            println!("  Missing HMAC:  {}", missing);

            if invalid > 0 {
                println!(
                    "\n  ⚠ {} entries have invalid HMACs — possible tampering!",
                    invalid
                );
            }
        }
    }

    Ok(())
}

fn cmd_status(config_path: Option<&std::path::Path>) -> Result<()> {
    let cfg = config::load_config(config_path)?;
    let conn = db::open_db(&cfg)?;

    let count = db::ops::baseline_count(&conn)?;
    let last_refresh = db::ops::get_config_state(&conn, "last_baseline_refresh")?;
    let maint = db::ops::get_config_state(&conn, "maintenance_window_active")?
        .map(|v| v == "1")
        .unwrap_or(false);

    println!("Vigil Status");
    println!("━━━━━━━━━━━━");
    println!("  Baseline entries:    {}", count);
    println!(
        "  Last refresh:        {}",
        last_refresh.unwrap_or_else(|| "never".into())
    );
    println!(
        "  Maintenance window:  {}",
        if maint { "ACTIVE" } else { "inactive" }
    );
    println!("  Database:            {}", cfg.daemon.db_path.display());
    println!("  Monitor backend:     {}", cfg.daemon.monitor_backend);

    // Check if daemon PID file exists
    if cfg.daemon.pid_file.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&cfg.daemon.pid_file) {
            println!("  Daemon PID:          {}", pid_str.trim());
        }
    } else {
        println!("  Daemon:              not running");
    }

    Ok(())
}

fn cmd_config(config_path: Option<&std::path::Path>, action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            let cfg = config::load_config(config_path)?;
            // Print the loaded config as TOML
            println!("{:#?}", cfg);
        }
        ConfigAction::Validate => match config::load_config(config_path) {
            Ok(_) => println!("Configuration is valid."),
            Err(e) => {
                println!("Configuration error: {}", e);
                process::exit(1);
            }
        },
    }

    Ok(())
}

fn cmd_doctor(config_path: Option<&std::path::Path>) -> Result<()> {
    println!("\nVigil — Self-Diagnostics");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // fanotify availability
    // SAFETY: fanotify_init is a Linux syscall. We pass valid flags
    // (FAN_CLOEXEC) and O_RDONLY. The returned fd is checked before use.
    let fan_fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            0x00000001u32, // FAN_CLOEXEC | FAN_CLASS_NOTIF
            libc::O_RDONLY,
        )
    };
    if fan_fd >= 0 {
        // SAFETY: fan_fd is a valid fd returned by fanotify_init (checked >= 0).
        unsafe { libc::close(fan_fd as i32) };
        let uname = nix::sys::utsname::uname().ok();
        let release = uname
            .as_ref()
            .map(|u| u.release().to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        println!("  ✓ fanotify available (kernel {})", release);
    } else {
        println!("  ✗ fanotify unavailable (requires CAP_SYS_ADMIN)");
    }

    // CAP_SYS_ADMIN check
    if nix::unistd::geteuid().is_root() {
        println!("  ✓ Running as root (full capability)");
    } else {
        println!("  ⚠ Not running as root (fanotify may be unavailable)");
    }

    // Config
    let cfg_result = config::load_config(config_path);
    match &cfg_result {
        Ok(_) => println!("  ✓ Config valid"),
        Err(e) => println!("  ✗ Config error: {}", e),
    }

    if let Ok(ref cfg) = cfg_result {
        // Database
        match db::open_db(cfg) {
            Ok(conn) => {
                println!("  ✓ Database writable ({})", cfg.daemon.db_path.display());
                match db::integrity_check(&conn) {
                    Ok(()) => println!("  ✓ Database integrity check passed"),
                    Err(e) => println!("  ✗ Database integrity check failed: {}", e),
                }

                let count = db::ops::baseline_count(&conn).unwrap_or(0);
                let last = db::ops::get_config_state(&conn, "last_baseline_refresh")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "never".into());
                println!("  ✓ Baseline: {} entries (last refresh: {})", count, last);
            }
            Err(e) => println!("  ✗ Database error: {}", e),
        }

        // HMAC key
        if cfg.security.hmac_signing {
            if cfg.security.hmac_key_path.exists() {
                println!(
                    "  ✓ HMAC key present ({})",
                    cfg.security.hmac_key_path.display()
                );
            } else {
                println!(
                    "  ✗ HMAC key missing ({})",
                    cfg.security.hmac_key_path.display()
                );
            }
        } else {
            println!("  ⚠ HMAC signing disabled");
        }

        // D-Bus
        if std::process::Command::new("notify-send")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            println!("  ✓ D-Bus notifications available (notify-send)");
        } else {
            println!("  ⚠ notify-send not found (D-Bus notifications unavailable)");
        }

        // Log file
        if let Some(parent) = cfg.alerts.log_file.parent() {
            if parent.exists() {
                println!("  ✓ Log file writable ({})", cfg.alerts.log_file.display());
            } else {
                println!("  ⚠ Log directory does not exist: {}", parent.display());
            }
        }

        // Package manager
        let pkg_backend = vigil::package::detect_backend();
        println!("  ✓ Package manager detected: {}", pkg_backend);

        // Signal socket
        if cfg.hooks.signal_socket.is_empty() {
            println!("  ⚠ Signal socket not configured (optional)");
        } else {
            println!("  ✓ Signal socket: {}", cfg.hooks.signal_socket);
        }
    }

    println!();
    Ok(())
}

/// Check if stderr is a TTY (for progress output).
fn atty_is_tty() -> bool {
    // SAFETY: isatty is a POSIX function safe to call with any fd.
    // STDERR_FILENO (2) is always a valid fd number.
    unsafe { libc::isatty(libc::STDERR_FILENO) != 0 }
}
