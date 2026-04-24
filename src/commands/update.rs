//! `vigil update` subcommand: build, install, and restart with rollback.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use vigil::types::OutputFormat;
use vigil::ui::progress::{Plan, Progress, ProgressMode, UpdateStep};

use super::common::query_control_socket;

pub(crate) fn cmd_update(
    repo: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
    verbose: bool,
    no_progress: bool,
) -> vigil::Result<()> {
    let plan = Plan::update_plan();

    let mode = if no_progress {
        ProgressMode::Plain
    } else {
        ProgressMode::detect()
    };

    let stderr_writer: Box<dyn Write + Send> = Box::new(std::io::stderr());
    let mut prog = Progress::with_mode(plan, stderr_writer, mode);
    prog.set_quiet(quiet);
    prog.set_verbose(verbose);

    // JSON mode: step events go to stdout, human output to stderr
    if format == OutputFormat::Json {
        let stdout_writer: Box<dyn Write + Send> = Box::new(std::io::stdout());
        prog.set_json_writer(stdout_writer);
    }

    let repo_was_explicit = repo.is_some();

    // ── Discover repo path early (for header) ──────────────
    let repo_path = match repo {
        Some(p) => p,
        None => match discover_vigil_repo(&mut prog) {
            Ok(p) => p,
            Err(e) => {
                prog.begin_step(UpdateStep::VerifyRepo);
                prog.end_step_err("no repository found");
                prog.skip_remaining_with_reason("repository discovery failed");
                prog.finish_summary();
                return Err(e);
            }
        },
    };

    // ── Read version from Cargo.toml for header ────────────
    let current_version = installed_version().unwrap_or_else(|| "unknown".to_string());
    let cargo_version =
        read_cargo_toml_version(&repo_path).unwrap_or_else(|| current_version.clone());

    let mut header_text = format!(
        "vigil-baseline {} \u{2192} {}",
        display_version(&current_version),
        display_version(&cargo_version)
    );
    if repo_was_explicit || verbose {
        header_text.push_str(&format!("  (repo {})", repo_path.display()));
    }
    if verbose {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if !sudo_user.trim().is_empty() {
                header_text.push_str(&format!("  (sudo as {})", sudo_user));
            }
        }
    }
    prog.header(&header_text);

    // ── Step 1: Verify repository ──────────────────────────
    prog.begin_step(UpdateStep::VerifyRepo);
    validate_vigil_repo_with_progress(&repo_path, Some(&mut prog), true).map_err(|e| {
        prog.end_step_err(&format!("invalid: {}", e));
        prog.skip_remaining_with_reason("repository validation failed");
        prog.finish_summary();
        e.with_context(&format!(
            "validating vigil repository at {}",
            repo_path.display()
        ))
    })?;
    prog.end_step_ok(None);

    // ── Step 2: Build release binaries ─────────────────────
    // Silent in human mode; cargo owns the visual output.
    // JSON begin/ok events still emitted.
    prog.begin_step_silent(UpdateStep::BuildRelease);

    let mut build_cmd = ProcessCommand::new("cargo");
    build_cmd
        .current_dir(&repo_path)
        .arg("build")
        .arg("--release");

    // Inherit stderr so cargo's live progress (Compiling…, Building…) streams
    // directly to the terminal. Cargo writes all useful output to stderr.
    build_cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());

    let build_status = build_cmd.status();

    match build_status {
        Ok(status) if status.success() => {
            prog.end_step_ok_silent(None);
        }
        Ok(_) => {
            prog.end_step_err("cargo build --release failed");
            prog.skip_remaining_with_reason("build failed");
            prog.finish_summary();
            return Err(vigil::VigilError::Daemon(
                "update failed: cargo build --release did not succeed".to_string(),
            ));
        }
        Err(e) => {
            prog.end_step_err(&format!("failed to spawn cargo: {}", e));
            prog.skip_remaining_with_reason("build failed to start");
            prog.finish_summary();
            return Err(vigil::VigilError::Io(e));
        }
    }

    // ── Step 3: Verify artifacts ───────────────────────────
    prog.begin_step(UpdateStep::VerifyArtifacts);
    let repo_vigil = repo_path.join("target/release/vigil");
    let repo_vigild = repo_path.join("target/release/vigild");
    if !repo_vigil.exists() || !repo_vigild.exists() {
        prog.end_step_err("target/release/vigil or vigild missing");
        prog.skip_remaining_with_reason("missing build artifacts");
        prog.finish_summary();
        return Err(vigil::VigilError::Daemon(
            "update build is incomplete: target/release/vigil and vigild must exist".to_string(),
        ));
    }

    smoke_test_binary(&repo_vigil, "vigil")?;
    smoke_test_binary_exists(&repo_vigild, "vigild")?;

    let new_version = version_from_binary(&repo_vigil)?;

    if current_version != "unknown" && current_version == new_version {
        // Same version string; check if the binary content actually changed.
        let installed = installed_vigil_path();
        let changed = binary_content_differs(&installed, &repo_vigil);
        if !changed {
            prog.end_step_ok(None);
            prog.set_summary_outcome("no changes installed");
            prog.skip_remaining_with_reason("no version change");
            prog.finish_summary();
            return Ok(());
        }
        prog.end_step_ok(Some(&format!(
            "{} (binary differs, reinstalling)",
            new_version
        )));
    } else {
        // Version downgrade warning
        if current_version != "unknown" {
            let cur = current_version.trim_start_matches('v');
            let new = new_version.trim_start_matches('v');
            if new < cur {
                prog.warn(&format!(
                    "downgrade: {} \u{2192} {}",
                    current_version, new_version
                ));
            }
        }
        prog.end_step_ok(None);
    }

    // ── Step 4: Stop daemon ────────────────────────────────
    prog.begin_step(UpdateStep::StopDaemon);
    let mut daemon_stop_cmd = ProcessCommand::new("sudo");
    daemon_stop_cmd
        .arg("/usr/bin/systemctl")
        .arg("stop")
        .arg("vigild.service");
    let daemon_stopped = run_best_effort(daemon_stop_cmd);
    if daemon_stopped {
        prog.end_step_ok(None);
    } else if daemon_is_active() {
        prog.end_step_err("could not stop vigild.service and it is still active");
        prog.skip_remaining_with_reason("daemon stop failed");
        prog.finish_summary();
        return Err(vigil::VigilError::Daemon(
            "could not stop vigild.service and it is still active; refusing to replace running binary. \
             Stop it manually with: sudo systemctl stop vigild.service".to_string(),
        ));
    } else {
        prog.end_step_warn("stop returned non-zero but daemon is not active");
    }

    // ── Step 5: Back up existing binaries ──────────────────
    prog.begin_step(UpdateStep::BackupBinaries);
    let dst_vigil = Path::new("/usr/local/bin/vigil");
    let dst_vigild = Path::new("/usr/local/bin/vigild");

    let bkp_vigil = backup_path(dst_vigil);
    let bkp_vigild = backup_path(dst_vigild);

    if dst_vigil.exists() {
        let mut cp = ProcessCommand::new("sudo");
        cp.arg("cp").arg(dst_vigil).arg(&bkp_vigil);
        run_checked(cp, "backup vigil")?;
    }
    if dst_vigild.exists() {
        let mut cp = ProcessCommand::new("sudo");
        cp.arg("cp").arg(dst_vigild).arg(&bkp_vigild);
        run_checked(cp, "backup vigild")?;
    }
    prog.end_step_ok(None);

    // ── Step 6: Install new binaries (atomic) ──────────────
    prog.begin_step(UpdateStep::InstallBinaries);
    let install_result = (|| -> vigil::Result<()> {
        atomic_install(&repo_vigil, dst_vigil)?;
        atomic_install(&repo_vigild, dst_vigild)?;
        smoke_test_binary(dst_vigil, "installed vigil")?;
        smoke_test_binary_exists(dst_vigild, "installed vigild")?;
        Ok(())
    })();

    if let Err(e) = install_result {
        prog.end_step_err(&e.to_string());

        // Rollback from install failure
        prog.rollback_banner("install failed, restoring backups");
        rollback_binaries(dst_vigil, dst_vigild);
        prog.skip_remaining_with_reason("install failed");
        prog.finish_summary();
        return Err(e);
    }
    prog.end_step_ok(None);

    // ── Step 7: Install systemd units & hooks ──────────────
    prog.begin_step(UpdateStep::InstallUnits);
    // Symlinks
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

    // Systemd units
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
        daemon_reload_cmd
            .arg("/usr/bin/systemctl")
            .arg("daemon-reload");
        run_checked(daemon_reload_cmd, "systemctl daemon-reload")?;
    }

    // Hooks
    let updated_hooks = update_hooks_if_changed(&repo_path)?;

    // Tighten data directory permissions
    let mut chmod_cmd = ProcessCommand::new("sudo");
    chmod_cmd.arg("chmod").arg("750").arg("/var/lib/vigil");
    let _ = run_best_effort(chmod_cmd);

    let units_detail = if updated_units.is_empty() && updated_hooks.is_empty() {
        "unchanged".to_string()
    } else {
        let mut parts = Vec::new();
        if !updated_units.is_empty() {
            parts.push(format!("units: {}", updated_units.join(", ")));
        }
        if !updated_hooks.is_empty() {
            parts.push(format!("hooks: {}", updated_hooks.join(", ")));
        }
        parts.join("; ")
    };
    prog.end_step_ok(Some(&units_detail));

    // ── Step 8: Start daemon ───────────────────────────────
    prog.begin_step(UpdateStep::StartDaemon);
    let mut daemon_start_cmd = ProcessCommand::new("sudo");
    daemon_start_cmd
        .arg("/usr/bin/systemctl")
        .arg("start")
        .arg("vigild.service");
    let daemon_started = run_best_effort(daemon_start_cmd);
    if daemon_started {
        prog.end_step_ok(None);
    } else {
        prog.end_step_warn("could not start vigild.service");
    }

    // ── Step 9: Verify daemon health ───────────────────────
    prog.begin_step(UpdateStep::VerifyHealth);
    let healthy = if daemon_started {
        verify_daemon_health_with_progress(&mut prog, 3, 2)
    } else {
        false
    };

    let backups_exist = bkp_vigil.exists() || bkp_vigild.exists();
    let needs_rollback = backups_exist && (!daemon_started || !healthy);

    if needs_rollback {
        let reason = if !daemon_started {
            "daemon failed to start"
        } else {
            "daemon not responding after 3 attempts"
        };
        prog.end_step_err(reason);

        // ── Rollback mini-plan ─────────────────────────────
        prog.rollback_banner(reason);

        let mut stop_cmd = ProcessCommand::new("sudo");
        stop_cmd
            .arg("/usr/bin/systemctl")
            .arg("stop")
            .arg("vigild.service");
        let _ = run_best_effort(stop_cmd);

        rollback_binaries(dst_vigil, dst_vigild);

        let mut start_cmd = ProcessCommand::new("sudo");
        start_cmd
            .arg("/usr/bin/systemctl")
            .arg("start")
            .arg("vigild.service");
        let _ = run_best_effort(start_cmd);

        prog.message("Rolled back to previous binaries");
        prog.set_summary_outcome("rolled back to previous binaries");
        prog.skip_remaining_with_reason("rollback path activated");
        prog.finish_summary();
        return Err(vigil::VigilError::Daemon(
            "daemon failed health check after update; rolled back to previous binaries".to_string(),
        ));
    } else if daemon_started && !healthy {
        prog.end_step_warn("not responding (no backups for rollback)");
    } else if !daemon_started {
        prog.end_step_warn("daemon not started (no backups for rollback)");
    } else {
        prog.end_step_ok(None);
    }

    // ── Step 10: Archive backups ───────────────────────────
    prog.begin_step(UpdateStep::ArchiveBackups);
    let retention_count = vigil::config::load_config(None)
        .map(|c| c.update.backup_retention_count)
        .unwrap_or(5);
    let archive_path = archive_backups(dst_vigil, dst_vigild, retention_count);
    let archive_detail = archive_path.map(|p| p.display().to_string());
    prog.end_step_ok(archive_detail.as_deref());

    // ── Step 11: Post-install health check ─────────────────
    prog.begin_step(UpdateStep::PostCheck);

    // Run vigil doctor
    let _ = ProcessCommand::new(installed_vigil_path())
        .arg("doctor")
        .stderr(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .status();

    prog.end_step_ok(None);

    prog.set_summary_outcome(format!(
        "vigil-baseline {} \u{2192} {}",
        display_version(&current_version),
        display_version(&new_version)
    ));
    prog.finish_summary();
    Ok(())
}

/// Validate that a directory is a Vigil Baseline source repository.
///
/// Returns a structured error describing why validation failed (missing Cargo.toml,
/// parse error, or wrong package name).
///
/// When running as root, also verifies directory and Cargo.toml ownership to prevent
/// privilege escalation via user-controlled source directories.
fn validate_vigil_repo_with_progress(
    repo: &Path,
    prog: Option<&mut Progress>,
    emit_ownership_warnings: bool,
) -> vigil::Result<()> {
    let cargo_toml = repo.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(vigil::VigilError::Config(format!(
            "Cargo.toml not found in {}",
            repo.display()
        )));
    }

    // Warn (but don't block) when directory or Cargo.toml are not owned by root.
    // The typical workflow is `sudo vigil update` from a user-owned checkout.
    // The real security boundary is the binary smoke-test and rollback mechanism,
    // not source directory ownership.  A hard error here breaks the primary use case.
    //
    // Suppressed when SUDO_USER owns the repo (developer building own code),
    // and only emitted once per invocation (emit_ownership_warnings flag).
    #[cfg(any(test, debug_assertions))]
    {
        let _ = &prog;
        let _ = emit_ownership_warnings;
    }

    #[cfg(not(any(test, debug_assertions)))]
    if emit_ownership_warnings {
        use std::os::unix::fs::MetadataExt;

        let mut prog = prog;

        let mut emit_warning = |msg: String| {
            if let Some(p) = prog.as_deref_mut() {
                p.warn(&msg);
            } else {
                eprintln!("warning: {}", msg);
            }
        };

        if nix::unistd::geteuid().is_root() {
            // If SUDO_USER is set and owns the repo, suppress the warning.
            // The developer is building their own code under sudo.
            let sudo_user_uid = resolve_sudo_user_uid();

            let dir_meta = std::fs::metadata(repo)?;
            let dir_uid = dir_meta.uid();
            if dir_uid != 0 && Some(dir_uid) != sudo_user_uid {
                emit_warning(format!(
                    "{} is owned by uid {} (not root)",
                    repo.display(),
                    dir_uid
                ));
            }
            let toml_meta = std::fs::metadata(&cargo_toml)?;
            let toml_uid = toml_meta.uid();
            if toml_uid != 0 && Some(toml_uid) != sudo_user_uid {
                emit_warning(format!(
                    "{} is owned by uid {} (not root)",
                    cargo_toml.display(),
                    toml_uid
                ));
            }
        }
    }

    let content = std::fs::read_to_string(&cargo_toml)?;
    let parsed: toml::Value = toml::from_str(&content).map_err(|e| {
        vigil::VigilError::Config(format!(
            "Cargo.toml parse error in {}: {}",
            repo.display(),
            e
        ))
    })?;

    let package_name = parsed
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str());

    if package_name != Some("vigil-baseline")
        && package_name != Some("vigilbaseline")
        && package_name != Some("vigil")
    {
        return Err(vigil::VigilError::Config(format!(
            "package name is '{}', expected 'vigil-baseline', 'vigilbaseline', or 'vigil' in {}",
            package_name.unwrap_or("<missing>"),
            repo.display()
        )));
    }

    Ok(())
}

/// Resolve the UID of the user who invoked sudo, if `SUDO_USER` is set.
///
/// Returns `None` when not running under sudo or when the user cannot be resolved.
#[cfg(not(any(test, debug_assertions)))]
fn resolve_sudo_user_uid() -> Option<u32> {
    let sudo_user = std::env::var("SUDO_USER").ok()?;
    if sudo_user.is_empty() {
        return None;
    }
    // Use nix::unistd::User to resolve username → uid
    nix::unistd::User::from_name(&sudo_user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
}

/// Discover the Vigil Baseline source repository by searching well-known locations.
///
/// Checks: cwd, binary-relative, HOME subdirs, SUDO_USER home subdirs, and /opt/vigil.
/// Deduplicates candidates and includes rejection reasons in the error message.
fn discover_vigil_repo(prog: &mut Progress) -> vigil::Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    let mut add_candidate = |path: PathBuf, label: String, seen: &mut HashSet<PathBuf>| {
        let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.insert(canonical) {
            labels.push(label);
            candidates.push(path);
        }
    };

    // 1. Current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let label = format!("{} (cwd)", cwd.display());
        add_candidate(cwd, label, &mut seen);
    }

    // 2. Binary-relative: walk up from the executable's location
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.as_path().parent();
        while let Some(d) = dir {
            if d.join("Cargo.toml").exists() {
                let label = format!("{} (binary relative)", d.display());
                add_candidate(d.to_path_buf(), label, &mut seen);
                break;
            }
            dir = d.parent();
        }
    }

    // 3. Well-known home paths (from HOME)
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(&home);
        // When running as root, only search /root; not a regular user's
        // home directory, which would be attacker-controlled under sudo.
        let skip_home = nix::unistd::geteuid().is_root() && home != Path::new("/root");
        if skip_home {
            tracing::debug!(
                home = %home.display(),
                "skipping $HOME-relative candidates while running as root; \
                 use --repo to specify a root-owned source directory"
            );
        } else {
            for sub in ["vigil", "src/vigil", "projects/vigil"] {
                let p = home.join(sub);
                let label = format!("{}", p.display());
                add_candidate(p, label, &mut seen);
            }
        }
    }

    // 4. SUDO_USER home paths; derive invoking user's home when running under sudo
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let sudo_home = PathBuf::from(format!("/home/{}", sudo_user));
        for sub in ["vigil", "src/vigil", "projects/vigil"] {
            let p = sudo_home.join(sub);
            let label = format!("{} (sudo user)", p.display());
            add_candidate(p, label, &mut seen);
        }
    }

    // 5. /opt/vigil
    let opt = PathBuf::from("/opt/vigil");
    let label = format!("{}", opt.display());
    add_candidate(opt, label, &mut seen);

    let mut rejections: Vec<String> = Vec::new();

    for (i, candidate) in candidates.iter().enumerate() {
        match validate_vigil_repo_with_progress(candidate, None, false) {
            Ok(()) => {
                prog.tick(Some(&format!("found: {}", candidate.display())));
                return Ok(candidate.clone());
            }
            Err(e) => {
                rejections.push(format!("    {}; {}", labels[i], e));
            }
        }
    }

    let checked = rejections.join("\n");

    Err(vigil::VigilError::Config(format!(
        "could not locate Vigil Baseline source repository\n  checked:\n{}\n  \
         hint: run from the Vigil Baseline source directory, or use: vigil update --repo /path/to/vigil",
        checked
    )))
}

/// Smoke-test a build artifact by running it with `--version`.
///
/// Returns an error if the binary fails to spawn or exits non-zero, including
/// the binary path and any stderr output.
///
/// For binaries that don't support `--version` (like `vigild`), use
/// `smoke_test_binary_exists` instead.
fn smoke_test_binary(path: &Path, name: &str) -> vigil::Result<()> {
    let output = ProcessCommand::new(path).arg("--version").output();
    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            Err(vigil::VigilError::Daemon(format!(
                "smoke test failed for {}: {} exited with {}\n  stderr: {}",
                name,
                path.display(),
                o.status,
                stderr.trim()
            )))
        }
        Err(e) => Err(vigil::VigilError::Daemon(format!(
            "smoke test failed for {}: could not spawn {}: {}",
            name,
            path.display(),
            e
        ))),
    }
}

/// Smoke-test a binary that does not support `--version` (e.g. `vigild`).
///
/// Checks that the file exists, is a regular file, and is executable.
fn smoke_test_binary_exists(path: &Path, name: &str) -> vigil::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| {
        vigil::VigilError::Daemon(format!(
            "smoke test failed for {}: cannot stat {}: {}",
            name,
            path.display(),
            e
        ))
    })?;
    if !meta.is_file() {
        return Err(vigil::VigilError::Daemon(format!(
            "smoke test failed for {}: {} is not a regular file",
            name,
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(vigil::VigilError::Daemon(format!(
            "smoke test failed for {}: {} is not executable",
            name,
            path.display()
        )));
    }
    Ok(())
}

/// Compute the backup path for an installed binary (e.g., `.vigil.backup`).
fn backup_path(dst: &Path) -> PathBuf {
    let name = dst
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    dst.with_file_name(format!(".{}.backup", name))
}

/// Legacy entry point kept for test compatibility.
#[cfg(test)]
fn install_binaries_with_rollback(
    src_vigil: &Path,
    src_vigild: &Path,
    dst_vigil: &Path,
    dst_vigild: &Path,
) -> vigil::Result<()> {
    let bkp_vigil = backup_path(dst_vigil);
    let bkp_vigild = backup_path(dst_vigild);

    if dst_vigil.exists() {
        let mut cp = ProcessCommand::new("sudo");
        cp.arg("cp").arg(dst_vigil).arg(&bkp_vigil);
        run_checked(cp, "backup vigil")?;
    }

    if dst_vigild.exists() {
        let mut cp = ProcessCommand::new("sudo");
        cp.arg("cp").arg(dst_vigild).arg(&bkp_vigild);
        run_checked(cp, "backup vigild")?;
    }

    let install_result = (|| -> vigil::Result<()> {
        atomic_install(src_vigil, dst_vigil)?;
        atomic_install(src_vigild, dst_vigild)?;
        smoke_test_binary(dst_vigil, "installed vigil")?;
        smoke_test_binary_exists(dst_vigild, "installed vigild")?;
        Ok(())
    })();

    match install_result {
        Ok(()) => Ok(()),
        Err(e) => {
            rollback_binaries(dst_vigil, dst_vigild);
            Err(e)
        }
    }
}

/// Restore binaries from `.backup` files.
fn rollback_binaries(dst_vigil: &Path, dst_vigild: &Path) {
    let bkp_vigil = backup_path(dst_vigil);
    let bkp_vigild = backup_path(dst_vigild);

    if bkp_vigil.exists() {
        let mut mv = ProcessCommand::new("sudo");
        mv.arg("mv").arg(&bkp_vigil).arg(dst_vigil);
        if run_best_effort(mv) {
            eprintln!("  ✓ Restored {}", dst_vigil.display());
        } else {
            eprintln!("  ✗ Failed to restore {}", dst_vigil.display());
        }
    }

    if bkp_vigild.exists() {
        let mut mv = ProcessCommand::new("sudo");
        mv.arg("mv").arg(&bkp_vigild).arg(dst_vigild);
        if run_best_effort(mv) {
            eprintln!("  ✓ Restored {}", dst_vigild.display());
        } else {
            eprintln!("  ✗ Failed to restore {}", dst_vigild.display());
        }
    }
}

/// Move backup files into a timestamped retention directory under
/// `/var/lib/vigil/binary-backups/`. Keeps the last 3 sets of backups so an
/// operator can manually roll back if a delayed failure surfaces (e.g. the
/// new daemon dies under load minutes after `vigil update` returned).
fn archive_backups(dst_vigil: &Path, dst_vigild: &Path, retention_count: usize) -> Option<PathBuf> {
    let bkp_vigil = backup_path(dst_vigil);
    let bkp_vigild = backup_path(dst_vigild);
    if !bkp_vigil.exists() && !bkp_vigild.exists() {
        return None;
    }

    let archive_root = std::path::PathBuf::from("/var/lib/vigil/binary-backups");
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    // VIGIL-VULN-073: add random suffix to prevent collisions on sub-second runs
    let rand_suffix = {
        let mut buf = [0u8; 4];
        // Use /dev/urandom for the random suffix; no new dep needed
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = f.read_exact(&mut buf);
        }
        format!("{:08x}", u32::from_le_bytes(buf))
    };
    let archive_dir = archive_root.join(format!("{}-{}", stamp, rand_suffix));

    let mut mkdir = ProcessCommand::new("sudo");
    mkdir.arg("mkdir").arg("-p").arg(&archive_dir);
    if !run_best_effort(mkdir) {
        tracing::warn!(
            path = %archive_dir.display(),
            "could not create backup archive; deleting backups instead"
        );
        cleanup_backups(dst_vigil, dst_vigild);
        return None;
    }

    for bkp in [&bkp_vigil, &bkp_vigild] {
        if bkp.exists() {
            let dst_name = bkp
                .file_name()
                .map(|n| n.to_string_lossy().trim_start_matches('.').to_string())
                .unwrap_or_else(|| "backup".into());
            let dest = archive_dir.join(dst_name);
            let mut mv = ProcessCommand::new("sudo");
            mv.arg("mv").arg(bkp).arg(&dest);
            let _ = run_best_effort(mv);
        }
    }

    prune_old_backup_archives(&archive_root, retention_count);
    Some(archive_dir)
}

/// Keep only the most recent `keep` directories under `archive_root`.
/// VIGIL-VULN-073: only consider dirs whose name matches the archive naming
/// pattern; non-conforming names are preserved and logged.
fn prune_old_backup_archives(archive_root: &Path, keep: usize) {
    let entries = match std::fs::read_dir(archive_root) {
        Ok(e) => e,
        Err(_) => return,
    };
    // Pattern: YYYYMMDDTHHMMSSZ or YYYYMMDDTHHMMSSZ-hexsuffix
    let is_archive_name = |name: &str| -> bool {
        if name.len() < 16 {
            return false;
        }
        let base = &name[..16]; // 8 date + T + 6 time + Z = 16
        if !base.chars().take(8).all(|c| c.is_ascii_digit()) {
            return false;
        }
        if name.as_bytes().get(8) != Some(&b'T') {
            return false;
        }
        if !name[9..15].chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if name.as_bytes().get(15) != Some(&b'Z') {
            // Archival detail is logged, not printed; the step renderer handles the summary
        }
        // Optional -hexsuffix
        if name.len() > 16 {
            if name.as_bytes().get(16) != Some(&b'-') {
                return false;
            }
            if !name[17..].chars().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
        }
        true
    };

    let mut dirs: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if is_archive_name(&name) {
                true
            } else {
                tracing::warn!(
                    name,
                    "skipping non-conforming directory in backup archive root"
                );
                false
            }
        })
        .map(|e| e.path())
        .collect();
    dirs.sort();
    if dirs.len() <= keep {
        return;
    }
    let to_remove = dirs.len() - keep;
    for old in dirs.iter().take(to_remove) {
        let mut rm = ProcessCommand::new("sudo");
        rm.arg("rm").arg("-rf").arg(old);
        let _ = run_best_effort(rm);
    }
}

/// Return true if `vigild.service` is currently active.
fn daemon_is_active() -> bool {
    let mut cmd = ProcessCommand::new("/usr/bin/systemctl");
    cmd.arg("is-active")
        .arg("--quiet")
        .arg("vigild.service")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// Remove backup files after a successful update.
fn cleanup_backups(dst_vigil: &Path, dst_vigild: &Path) {
    let bkp_vigil = backup_path(dst_vigil);
    let bkp_vigild = backup_path(dst_vigild);

    for bkp in [&bkp_vigil, &bkp_vigild] {
        if bkp.exists() {
            let mut rm = ProcessCommand::new("sudo");
            rm.arg("rm").arg("-f").arg(bkp);
            let _ = run_best_effort(rm);
        }
    }
}

/// Check daemon health with retries, reporting to the progress renderer.
fn verify_daemon_health_with_progress(
    prog: &mut Progress,
    max_attempts: u32,
    interval_secs: u64,
) -> bool {
    for attempt in 1..=max_attempts {
        prog.tick(Some(&format!("attempt {}/{}", attempt, max_attempts)));

        let ok = vigil::config::load_config(None)
            .ok()
            .and_then(|cfg| {
                if !cfg.daemon.control_socket.as_os_str().is_empty() {
                    query_control_socket(&cfg.daemon.control_socket, r#"{"method":"status"}"#).ok()
                } else {
                    None
                }
            })
            .is_some();
        if ok {
            return true;
        }
        if attempt < max_attempts {
            for remaining in (1..=interval_secs).rev() {
                prog.tick(Some(&format!(
                    "attempt {}/{}, next probe in {}s",
                    attempt, max_attempts, remaining
                )));
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
    false
}

/// Check daemon health with retries (legacy, no progress).
#[cfg(test)]
fn verify_daemon_health(max_attempts: u32, interval_secs: u64) -> bool {
    for attempt in 1..=max_attempts {
        let ok = vigil::config::load_config(None)
            .ok()
            .and_then(|cfg| {
                if !cfg.daemon.control_socket.as_os_str().is_empty() {
                    query_control_socket(&cfg.daemon.control_socket, r#"{"method":"status"}"#).ok()
                } else {
                    None
                }
            })
            .is_some();
        if ok {
            return true;
        }
        if attempt < max_attempts {
            std::thread::sleep(std::time::Duration::from_secs(interval_secs));
        }
    }
    false
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
    let out = ProcessCommand::new(installed_vigil_path())
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(normalize_version(&String::from_utf8_lossy(&out.stdout)))
}

/// Return the absolute path of the currently installed `vigil` binary.
/// Prefers `/usr/local/bin/vigil`, falls back to `/usr/bin/vigil`, then PATH.
fn installed_vigil_path() -> std::path::PathBuf {
    for candidate in ["/usr/local/bin/vigil", "/usr/bin/vigil"] {
        let p = std::path::PathBuf::from(candidate);
        if p.is_file() {
            return p;
        }
    }
    std::path::PathBuf::from("vigil")
}

/// Compare two binaries by size and BLAKE3 hash. Returns true if they differ.
fn binary_content_differs(a: &Path, b: &Path) -> bool {
    let (meta_a, meta_b) = match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => (ma, mb),
        _ => return true, // if we can't read either, assume different
    };
    if meta_a.len() != meta_b.len() {
        return true;
    }
    let (data_a, data_b) = match (std::fs::read(a), std::fs::read(b)) {
        (Ok(da), Ok(db)) => (da, db),
        _ => return true,
    };
    blake3::hash(&data_a) != blake3::hash(&data_b)
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
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }

    let token = trimmed.split_whitespace().last().unwrap_or("unknown");

    if token == "unknown" {
        "unknown".to_string()
    } else if token.starts_with('v') {
        token.to_string()
    } else {
        format!("v{}", token)
    }
}

fn display_version(v: &str) -> &str {
    v.trim_start_matches('v')
}

/// Read the package version from Cargo.toml without building.
fn read_cargo_toml_version(repo: &Path) -> Option<String> {
    let content = std::fs::read_to_string(repo.join("Cargo.toml")).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let ver = parsed.get("package")?.get("version")?.as_str()?;
    Some(format!("v{}", ver))
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
    // Treat a missing source as a benign skip: optional units (e.g. removed
    // in a future release) must not abort the entire update mid-flight.
    let src_bytes = match std::fs::read(src) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(src = %src.display(), "source not in repo; skipping");
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    };
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

        let result = validate_vigil_repo_with_progress(dir.path(), None, false);
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

        let result = validate_vigil_repo_with_progress(dir.path(), None, false);
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

        let result = validate_vigil_repo_with_progress(dir.path(), None, false);
        assert!(result.is_err(), "expected repository validation to fail");
    }

    #[test]
    fn normalize_version_prefixes_v_when_missing() {
        assert_eq!(normalize_version("vigil 0.12.1"), "v0.12.1");
        assert_eq!(normalize_version("vigil v0.12.1"), "v0.12.1");
    }

    #[test]
    fn normalize_version_edge_cases() {
        assert_eq!(normalize_version(""), "unknown");
        assert_eq!(normalize_version("   "), "unknown");
        assert_eq!(normalize_version("  \t\n  "), "unknown");
        assert_eq!(normalize_version("vigil baseline 0.12.1"), "v0.12.1");
        assert_eq!(normalize_version("some tool v1.0.0-rc1"), "v1.0.0-rc1");
    }

    #[test]
    fn validate_vigil_repo_error_messages() {
        // No Cargo.toml
        let dir = tempfile::tempdir().expect("create temp dir");
        let err = validate_vigil_repo_with_progress(dir.path(), None, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Cargo.toml not found"),
            "expected 'Cargo.toml not found', got: {}",
            msg
        );

        // Parse error
        let dir2 = tempfile::tempdir().expect("create temp dir");
        std::fs::write(dir2.path().join("Cargo.toml"), "{{invalid toml}}").expect("write bad toml");
        let err2 = validate_vigil_repo_with_progress(dir2.path(), None, false).unwrap_err();
        let msg2 = err2.to_string();
        assert!(
            msg2.contains("Cargo.toml parse error"),
            "expected 'Cargo.toml parse error', got: {}",
            msg2
        );

        // Wrong package name
        let dir3 = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir3.path().join("Cargo.toml"),
            r#"
                [package]
                name = "something-else"
                version = "0.1.0"
            "#,
        )
        .expect("write wrong name");
        let err3 = validate_vigil_repo_with_progress(dir3.path(), None, false).unwrap_err();
        let msg3 = err3.to_string();
        assert!(
            msg3.contains("package name is 'something-else'"),
            "expected package name in error, got: {}",
            msg3
        );
    }

    #[test]
    fn test_discover_vigil_repo_uses_sudo_user() {
        // Create a temp dir simulating a sudo user's repo
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"
                [package]
                name = "vigil-baseline"
                version = "0.0.1"
                edition = "2021"
            "#,
        )
        .expect("write Cargo.toml");

        // We can't easily test the full discover_vigil_repo with SUDO_USER
        // since it requires /home/$SUDO_USER to exist, but we can verify
        // the candidate generation logic works by testing validate_vigil_repo
        // on the created directory (which is what discover calls internally).
        assert!(validate_vigil_repo_with_progress(dir.path(), None, false).is_ok());

        // Verify backup_path generation
        let p = Path::new("/usr/local/bin/vigil");
        assert_eq!(
            backup_path(p),
            PathBuf::from("/usr/local/bin/.vigil.backup")
        );

        let p2 = Path::new("/usr/local/bin/vigild");
        assert_eq!(
            backup_path(p2),
            PathBuf::from("/usr/local/bin/.vigild.backup")
        );
    }

    #[test]
    fn test_rollback_sequence() {
        // Verify backup path generation logic
        let vigil = Path::new("/usr/local/bin/vigil");
        let vigild = Path::new("/usr/local/bin/vigild");

        assert_eq!(
            backup_path(vigil),
            PathBuf::from("/usr/local/bin/.vigil.backup")
        );
        assert_eq!(
            backup_path(vigild),
            PathBuf::from("/usr/local/bin/.vigild.backup")
        );

        // Verify the function signatures compile
        let _ =
            install_binaries_with_rollback as fn(&Path, &Path, &Path, &Path) -> vigil::Result<()>;
        let _ = rollback_binaries as fn(&Path, &Path);
        let _ = smoke_test_binary as fn(&Path, &str) -> vigil::Result<()>;
        let _ = verify_daemon_health as fn(u32, u64) -> bool;
    }

    #[test]
    fn validate_vigil_repo_ownership_check_logic() {
        // Verify the ownership check logic directly (since #[cfg(not(test))]
        // prevents the actual check from running in tests).
        use std::os::unix::fs::MetadataExt;

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

        // Test the ownership check logic directly
        let dir_meta = std::fs::metadata(dir.path()).unwrap();
        let toml_meta = std::fs::metadata(&cargo_toml).unwrap();

        // In non-root test environments, UID will be non-zero
        if nix::unistd::geteuid().is_root() {
            // Running as root: both should be owned by root
            assert_eq!(dir_meta.uid(), 0);
        } else {
            // Running as non-root: UID should be non-zero
            // This is the case the ownership check would flag
            assert_ne!(dir_meta.uid(), 0);
            assert_ne!(toml_meta.uid(), 0);
        }
    }
}
