use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use vigil::doctor;

use super::common::{format_count, print_header, query_control_socket};

pub(crate) fn cmd_update(repo: Option<PathBuf>) -> vigil::Result<()> {
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

    if package_name != Some("vigil-baseline")
        && package_name != Some("vigilbaseline")
        && package_name != Some("vigil")
    {
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
                name = "vigil-baseline"
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
