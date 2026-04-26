//! `vigil welcome` subcommand: first-run configuration flow.

use std::io::{self, BufRead, Write};
use std::path::Path;

use vigil::config;
use vigil::display;

/// Detected system identity from three reads: /etc/os-release, /proc/mounts, $PATH.
struct SystemIdentity {
    distro: String,
    root_fs: String,
    package_manager: Option<&'static str>,
}

fn detect_system() -> SystemIdentity {
    let distro = read_distro_name().unwrap_or_else(|| "Linux".to_string());
    let root_fs = read_root_filesystem().unwrap_or_else(|| "unknown".to_string());
    let package_manager = detect_package_manager();

    SystemIdentity {
        distro,
        root_fs,
        package_manager,
    }
}

fn read_distro_name() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
            return Some(val.trim_matches('"').to_string());
        }
    }
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("NAME=") {
            return Some(val.trim_matches('"').to_string());
        }
    }
    None
}

fn read_root_filesystem() -> Option<String> {
    let content = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "/" {
            return Some(parts[2].to_string());
        }
    }
    None
}

fn detect_package_manager() -> Option<&'static str> {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        if std::path::Path::new(dir).join("pacman").is_file() {
            return Some("pacman");
        }
    }
    for dir in path.split(':') {
        if std::path::Path::new(dir).join("apt").is_file() {
            return Some("apt");
        }
    }
    for dir in path.split(':') {
        if std::path::Path::new(dir).join("dnf").is_file() {
            return Some("dnf");
        }
    }
    None
}

struct WelcomeGroup {
    label: &'static str,
    paths: Vec<String>,
    severity: &'static str,
}

fn default_suggestions() -> Vec<WelcomeGroup> {
    vec![
        WelcomeGroup {
            label: "system",
            paths: vec![
                "/etc".into(),
                "/usr/bin".into(),
                "/usr/sbin".into(),
                "/boot".into(),
            ],
            severity: "critical",
        },
        WelcomeGroup {
            label: "persist",
            paths: vec![
                "/etc/systemd".into(),
                "/etc/cron*".into(),
                "/etc/rc.local".into(),
            ],
            severity: "high",
        },
        WelcomeGroup {
            label: "you",
            paths: vec![
                "~/.ssh".into(),
                "~/.bashrc".into(),
                "~/.config/autostart".into(),
            ],
            severity: "high",
        },
    ]
}

fn print_suggestions(groups: &[WelcomeGroup]) {
    for g in groups {
        let paths_str = g.paths.join(", ");
        eprintln!("  [{:<8}] {:<44} {}", g.label, paths_str, g.severity);
    }
}

pub(crate) fn cmd_welcome(config_path: Option<&Path>) -> vigil::Result<i32> {
    let sys = detect_system();

    // Check for existing config divergence
    let existing_config = config::load_config(config_path).ok();
    let config_file = config_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/vigil/vigil.toml"));
    let config_exists = config_file.exists();

    if config_exists {
        if let Some(ref cfg) = existing_config {
            if !cfg.watch.is_empty() {
                eprintln!("Existing configuration found at {}", config_file.display());
                eprintln!();
                eprintln!("Current watch groups:");
                for (name, group) in &cfg.watch {
                    eprintln!(
                        "  [{}]  {} paths, severity {}",
                        name,
                        group.paths.len(),
                        group.severity
                    );
                }
                eprintln!();
                eprint!("Overwrite with new configuration? [y/N] ");
                io::stderr().flush()?;

                let mut answer = String::new();
                io::stdin().lock().read_line(&mut answer)?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    eprintln!("Keeping existing configuration.");
                    eprintln!(
                        "Edit {} directly, or re-run `vigil welcome` to start over.",
                        config_file.display()
                    );
                    return Ok(0);
                }
            }
        }
    }

    eprintln!("Step 1 of 3: Configure watch paths\n");

    let pm_label = sys.package_manager.unwrap_or("none");
    eprintln!(
        "System detected: {}, {}, {}.",
        sys.distro, sys.root_fs, pm_label
    );
    eprintln!();
    eprintln!("Suggested baseline (standard Linux file integrity targets):");
    eprintln!();

    let mut groups = default_suggestions();
    print_suggestions(&groups);

    eprintln!();
    eprintln!("Suggestions are static. Vigil has not read your filesystem.");
    eprintln!("Edit before accepting if your system is unusual.");
    eprintln!();
    eprintln!("Press enter to accept, or:");
    eprintln!("  a   add a path");
    eprintln!("  r   remove a path");
    eprintln!("  s   show what's in a group");
    eprintln!("  q   quit and edit {} directly", config_file.display());
    eprintln!();

    let stdin = io::stdin();
    loop {
        eprint!("> ");
        io::stderr().flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break; // EOF
        }
        let input = line.trim();

        if input.is_empty() {
            break; // accept
        }

        match input {
            "q" | "Q" => {
                eprintln!(
                    "Edit {} and run `vigil welcome` again when ready.",
                    config_file.display()
                );
                return Ok(0);
            }
            "a" | "A" => {
                eprint!("Path to add: ");
                io::stderr().flush()?;
                let mut path_line = String::new();
                stdin.lock().read_line(&mut path_line)?;
                let new_path = path_line.trim().to_string();
                if new_path.is_empty() {
                    continue;
                }

                eprint!("Group (system/persist/you) [system]: ");
                io::stderr().flush()?;
                let mut group_line = String::new();
                stdin.lock().read_line(&mut group_line)?;
                let group_name = group_line.trim();
                let group_name = if group_name.is_empty() {
                    "system"
                } else {
                    group_name
                };

                if let Some(g) = groups.iter_mut().find(|g| g.label == group_name) {
                    g.paths.push(new_path.clone());
                    eprintln!("Added {} to [{}].", new_path, group_name);
                } else {
                    eprintln!(
                        "Unknown group: {}. Use system, persist, or you.",
                        group_name
                    );
                }
            }
            "r" | "R" => {
                eprint!("Path to remove: ");
                io::stderr().flush()?;
                let mut path_line = String::new();
                stdin.lock().read_line(&mut path_line)?;
                let rm_path = path_line.trim();

                let mut found = false;
                for g in &mut groups {
                    if let Some(pos) = g.paths.iter().position(|p| p == rm_path) {
                        g.paths.remove(pos);
                        eprintln!("Removed {} from [{}].", rm_path, g.label);
                        found = true;
                        break;
                    }
                }
                if !found {
                    eprintln!("Path not found in any group: {}", rm_path);
                }
            }
            "s" | "S" => {
                eprint!("Group name (system/persist/you): ");
                io::stderr().flush()?;
                let mut group_line = String::new();
                stdin.lock().read_line(&mut group_line)?;
                let group_name = group_line.trim();

                if let Some(g) = groups.iter().find(|g| g.label == group_name) {
                    eprintln!("[{}] severity: {}", g.label, g.severity);
                    for p in &g.paths {
                        eprintln!("  {}", p);
                    }
                } else {
                    eprintln!("Unknown group: {}", group_name);
                }
            }
            _ => {
                eprintln!("Unrecognized option: {}", input);
                eprintln!("Press enter to accept, a/r/s/q for options.");
            }
        }
        eprintln!();
    }

    // Write config
    write_welcome_config(&config_file, &groups)?;

    let path_count: usize = groups.iter().map(|g| g.paths.len()).sum();
    eprintln!(
        "\nWrote {} ({} groups, {} paths)",
        config_file.display(),
        groups.iter().filter(|g| !g.paths.is_empty()).count(),
        path_count
    );

    eprintln!("\nStep 2 of 3: Build baseline\n");

    // Load the config we wrote
    let cfg = config::load_config(Some(&config_file))?;

    // Build baseline
    let conn = vigil::db::open_baseline_db(&cfg)?;
    let existing = vigil::db::baseline_ops::count(&conn).unwrap_or(0);
    if existing > 0 {
        conn.execute_batch("DELETE FROM baseline")?;
    }

    eprintln!("Building baseline. This may take a few minutes.");
    let result = vigil::scanner::build_initial_baseline(&conn, &cfg)?;
    vigil::db::baseline_ops::set_config_state(&conn, "baseline_initialized", "true")?;

    eprintln!(
        "Baseline written: {} files, {}",
        display::fmt_count(result.total_count),
        cfg.daemon.db_path.display()
    );

    // Start vigild via systemd
    eprintln!("\nStep 3 of 3: Start the daemon\n");
    let daemon_pid = start_daemon();

    if let Some(pid) = daemon_pid {
        eprintln!("vigild started: pid {}", pid);
    } else {
        eprintln!("vigild not started. Run: sudo systemctl start vigild");
    }

    eprintln!();
    eprintln!("Vigil is ready. Next: run `vigil check` to verify your baseline.");
    eprintln!();
    eprintln!("Verifying installation:");

    // Run selftest inline
    let selftest_code = super::selftest::run_selftest_inline(&cfg);

    if selftest_code == 0 {
        eprintln!("Selftest passed.");
    }

    Ok(selftest_code)
}

fn write_welcome_config(path: &Path, groups: &[WelcomeGroup]) -> vigil::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut content = String::new();
    content.push_str("# Generated by `vigil welcome`\n");
    content.push_str("# Edit paths and severities as needed.\n\n");

    content.push_str("[daemon]\n");
    content.push_str("monitor_backend = \"fanotify\"\n");
    content.push_str("log_level = \"info\"\n");
    content.push_str("control_socket = \"/run/vigil/control.sock\"\n\n");

    content.push_str("[scanner]\n");
    content.push_str("schedule = \"0 3 * * *\"\n");
    content.push_str("mode = \"incremental\"\n\n");

    content.push_str("[alerts]\n");
    content.push_str("desktop_notifications = true\n\n");

    for g in groups {
        if g.paths.is_empty() {
            continue;
        }
        let group_name = match g.label {
            "system" => "system_critical",
            "persist" => "persistent_configs",
            "you" => "user_space",
            other => other,
        };
        content.push_str(&format!("[watch.{}]\n", group_name));
        content.push_str(&format!("severity = \"{}\"\n", g.severity));
        content.push_str("paths = [\n");
        for p in &g.paths {
            content.push_str(&format!("    \"{}\",\n", p));
        }
        content.push_str("]\n\n");
    }

    std::fs::write(path, content)?;
    eprintln!("Configuration written to {}", path.display());
    Ok(())
}

fn start_daemon() -> Option<i32> {
    use std::process::Command;

    // Try systemctl start
    let status = Command::new("/usr/bin/systemctl")
        .args(["start", "vigild"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;

    if !status.success() {
        return None;
    }

    // Read PID
    std::thread::sleep(std::time::Duration::from_millis(500));
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", "--property=MainPID", "vigild"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(pid_str) = line.strip_prefix("MainPID=") {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if pid > 0 {
                    return Some(pid);
                }
            }
        }
    }
    None
}
