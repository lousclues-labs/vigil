//! `vigil hooks` subcommand: verify and repair package manager hooks.

use std::path::Path;

use vigil::cli::HooksAction;
use vigil::db::audit_ops;
use vigil::types::PackageBackend;

/// Canonical hook contents embedded at compile time.
const CANONICAL_PACMAN_PRE: &str = include_str!("../../hooks/pacman/vigil-pre.hook");
const CANONICAL_PACMAN_POST: &str = include_str!("../../hooks/pacman/vigil-post.hook");
const CANONICAL_APT: &str = include_str!("../../hooks/apt/99vigil");

/// Installed hook locations.
const PACMAN_PRE_PATH: &str = "/etc/pacman.d/hooks/vigil-pre.hook";
const PACMAN_POST_PATH: &str = "/etc/pacman.d/hooks/vigil-post.hook";
const APT_PATH: &str = "/etc/apt/apt.conf.d/99vigil";

struct HookSpec {
    label: &'static str,
    installed_path: &'static str,
    canonical: &'static str,
    backend: PackageBackend,
}

fn hook_specs() -> Vec<HookSpec> {
    vec![
        HookSpec {
            label: "pacman pre-hook",
            installed_path: PACMAN_PRE_PATH,
            canonical: CANONICAL_PACMAN_PRE,
            backend: PackageBackend::Pacman,
        },
        HookSpec {
            label: "pacman post-hook",
            installed_path: PACMAN_POST_PATH,
            canonical: CANONICAL_PACMAN_POST,
            backend: PackageBackend::Pacman,
        },
        HookSpec {
            label: "apt hook",
            installed_path: APT_PATH,
            canonical: CANONICAL_APT,
            backend: PackageBackend::Dpkg,
        },
    ]
}

pub(crate) fn cmd_hooks(config_path: Option<&Path>, action: HooksAction) -> vigil::Result<i32> {
    match action {
        HooksAction::Verify => cmd_hooks_verify(),
        HooksAction::Repair => cmd_hooks_repair(config_path, "repair"),
        HooksAction::Disable => cmd_hooks_disable(config_path),
        HooksAction::Enable => cmd_hooks_enable(config_path),
        HooksAction::Status => cmd_hooks_status(config_path),
    }
}

fn backend_present(backend: &PackageBackend) -> bool {
    let detected = vigil::package::detect_backend();
    match backend {
        PackageBackend::Pacman => matches!(detected, PackageBackend::Pacman),
        PackageBackend::Dpkg => matches!(detected, PackageBackend::Dpkg),
        _ => false,
    }
}

fn cmd_hooks_verify() -> vigil::Result<i32> {
    let specs = hook_specs();
    let mut drift_count = 0u32;
    let mut checked = 0u32;

    for spec in &specs {
        if !backend_present(&spec.backend) {
            println!(
                "  {:<18} ○ {}    not installed ({} not detected)",
                spec.label,
                spec.installed_path,
                backend_name(&spec.backend),
            );
            continue;
        }

        let path = Path::new(spec.installed_path);
        if !path.exists() {
            println!(
                "  {:<18} ⚠ {}    not installed",
                spec.label, spec.installed_path,
            );
            drift_count += 1;
            checked += 1;
            continue;
        }

        match std::fs::read_to_string(path) {
            Ok(contents) if contents == spec.canonical => {
                println!(
                    "  {:<18} ● {}    matches canonical",
                    spec.label, spec.installed_path,
                );
                checked += 1;
            }
            Ok(_) => {
                println!(
                    "  {:<18} ⚠ {}    drift detected",
                    spec.label, spec.installed_path,
                );
                println!("  {:<18}   repair with: vigil hooks repair", "",);
                drift_count += 1;
                checked += 1;
            }
            Err(e) => {
                println!(
                    "  {:<18} ✗ {}    cannot read: {}",
                    spec.label, spec.installed_path, e,
                );
                drift_count += 1;
                checked += 1;
            }
        }
    }

    println!();
    if drift_count == 0 && checked > 0 {
        println!("all installed hooks match canonical versions.");
        Ok(0)
    } else if drift_count == 0 {
        println!("no supported package manager detected.");
        Ok(0)
    } else {
        println!(
            "{} {} from canonical version.",
            drift_count,
            if drift_count == 1 {
                "hook differs"
            } else {
                "hooks differ"
            }
        );
        Ok(2)
    }
}

fn cmd_hooks_repair(config_path: Option<&Path>, audit_operation: &str) -> vigil::Result<i32> {
    let specs = hook_specs();
    let mut repaired = 0u32;

    for spec in &specs {
        if !backend_present(&spec.backend) {
            println!(
                "  {:<18} ○ skipped ({} not detected)",
                spec.label,
                backend_name(&spec.backend),
            );
            continue;
        }

        let path = Path::new(spec.installed_path);
        let needs_repair =
            !matches!(std::fs::read_to_string(path), Ok(contents) if contents == spec.canonical);

        if !needs_repair {
            println!("  {:<18} ● already canonical", spec.label);
            continue;
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    vigil::VigilError::Io(std::io::Error::new(
                        e.kind(),
                        format!("cannot create {}: {}", parent.display(), e),
                    ))
                })?;
            }
        }

        // Write atomically: temp file, fsync, rename
        let tmp_path = path.with_extension("hook.new");
        let tmp_display = tmp_path.display().to_string();

        match write_file_atomic(&tmp_path, path, spec.canonical) {
            Ok(()) => {
                // Set mode 0644 owned by current user (root expected)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
                }
                println!(
                    "  {:<18} ● repaired (was: drift; now: canonical)",
                    spec.label,
                );
                repaired += 1;
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                eprintln!(
                    "  {:<18} ✗ repair failed: {} (tmp: {})",
                    spec.label, e, tmp_display,
                );
            }
        }
    }

    println!();
    if repaired == 0 {
        println!("all hooks already canonical.");
    } else {
        println!(
            "{} {} repaired.",
            repaired,
            if repaired == 1 { "hook" } else { "hooks" }
        );
    }

    if let Some(seq) = record_hooks_operation(config_path, audit_operation, repaired as u64)? {
        println!("audit record: sequence {}", seq);
    }

    Ok(0)
}

fn write_file_atomic(tmp_path: &Path, final_path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut f = std::fs::File::create(tmp_path)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(tmp_path, final_path)?;
    Ok(())
}

fn backend_name(backend: &PackageBackend) -> &'static str {
    match backend {
        PackageBackend::Pacman => "pacman",
        PackageBackend::Dpkg => "apt",
        PackageBackend::Rpm => "rpm",
        PackageBackend::Auto => "none",
    }
}

fn cmd_hooks_disable(config_path: Option<&Path>) -> vigil::Result<i32> {
    let specs = hook_specs();
    let mut removed = Vec::new();

    for spec in &specs {
        if !backend_present(&spec.backend) {
            continue;
        }

        let path = Path::new(spec.installed_path);
        if path.exists() {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    removed.push(spec.label);
                    println!("  {:<18} removed {}", spec.label, spec.installed_path);
                }
                Err(e) => {
                    eprintln!(
                        "  {:<18} ✗ cannot remove {}: {}",
                        spec.label, spec.installed_path, e
                    );
                    return Ok(1);
                }
            }
        }
    }

    if removed.is_empty() {
        println!("hooks are not installed");
    } else {
        println!();
        println!("hooks disabled ({} removed)", removed.join(", "));

        if let Some(seq) = record_hooks_operation(config_path, "disable", removed.len() as u64)? {
            println!("audit record: sequence {}", seq);
        }
    }

    Ok(0)
}

fn cmd_hooks_enable(config_path: Option<&Path>) -> vigil::Result<i32> {
    let code = cmd_hooks_repair(config_path, "enable")?;
    if code == 0 {
        println!("hooks enabled");
    }
    Ok(code)
}

fn record_hooks_operation(
    config_path: Option<&Path>,
    operation: &str,
    count: u64,
) -> vigil::Result<Option<i64>> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;
    let previous_chain_hash = audit_ops::get_last_chain_hash(&conn)?.unwrap_or_else(|| {
        blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string()
    });
    let hmac_key = if cfg.security.hmac_signing {
        std::fs::read(&cfg.security.hmac_key_path).ok()
    } else {
        None
    };

    let payload = serde_json::json!({
        "operation": operation,
        "count": count,
        "operator_uid": nix::unistd::geteuid().as_raw(),
        "operator_pid": std::process::id(),
        "operator_exe": std::env::current_exe().ok().map(|p| p.to_string_lossy().to_string()),
        "operator_argv": std::env::args().collect::<Vec<_>>(),
    });
    let payload_json = serde_json::to_string(&payload)?;

    let (_hash, seq) = audit_ops::insert_hooks_operation_entry(
        &conn,
        operation,
        &payload_json,
        &previous_chain_hash,
        hmac_key.as_deref(),
    )?;
    Ok(Some(seq))
}

fn cmd_hooks_status(config_path: Option<&Path>) -> vigil::Result<i32> {
    let specs = hook_specs();
    let detected = vigil::package::detect_backend();

    let backend_label = match detected {
        PackageBackend::Pacman => "pacman",
        PackageBackend::Dpkg => "apt",
        PackageBackend::Rpm => "rpm",
        PackageBackend::Auto => {
            println!("hooks: no supported package manager detected");
            return Ok(0);
        }
    };

    let relevant_specs: Vec<&HookSpec> = specs
        .iter()
        .filter(|s| {
            matches!(
                (&s.backend, &detected),
                (PackageBackend::Pacman, PackageBackend::Pacman)
                    | (PackageBackend::Dpkg, PackageBackend::Dpkg)
            )
        })
        .collect();

    let all_installed = relevant_specs
        .iter()
        .all(|s| Path::new(s.installed_path).exists());
    let any_installed = relevant_specs
        .iter()
        .any(|s| Path::new(s.installed_path).exists());

    if all_installed {
        // Check if canonical
        let all_canonical = relevant_specs.iter().all(|s| {
            matches!(
                std::fs::read_to_string(s.installed_path),
                Ok(contents) if contents == s.canonical
            )
        });

        if all_canonical {
            println!(
                "hooks: enabled ({} pre/post installed and canonical)",
                backend_label
            );
        } else {
            println!(
                "hooks: enabled ({} hooks installed, drift detected)",
                backend_label
            );
            println!("  repair with: vigil hooks repair");
        }

        // Show last invocation status
        let tag = match detected {
            PackageBackend::Pacman => "vigil-pacman",
            PackageBackend::Dpkg => "vigil-apt",
            _ => "",
        };
        if !tag.is_empty() {
            let trigger = vigil::doctor::hook_last_trigger_parsed(tag);
            match trigger {
                vigil::doctor::HookTriggerResult::NeverTriggered => {
                    println!("last invocation: never");
                }
                vigil::doctor::HookTriggerResult::Success(ts) => {
                    println!("last invocation: {} ok", ts);
                }
                vigil::doctor::HookTriggerResult::Failure(ts, _) => {
                    println!("last invocation: {} failed", ts);
                }
                vigil::doctor::HookTriggerResult::Unknown => {
                    println!("last invocation: unknown (journalctl unavailable)");
                }
            }
        }
    } else if any_installed {
        println!(
            "hooks: partially installed ({}, some missing)",
            backend_label
        );
        println!("  repair with: vigil hooks repair");
    } else if hooks_disabled_from_audit(config_path).unwrap_or(false) {
        println!("hooks: disabled (no hooks installed)");
        println!("  restore with: vigil hooks enable");
    } else {
        println!("hooks: not installed");
        println!("  install with: vigil hooks repair");
    }

    Ok(0)
}

fn hooks_disabled_from_audit(config_path: Option<&Path>) -> vigil::Result<bool> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;
    let latest: std::result::Result<String, _> = conn.query_row(
        "SELECT path FROM audit_log \
         WHERE path IN ('vigil:hooks_disable', 'vigil:hooks_enable') \
         ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    );
    Ok(matches!(
        latest.ok().as_deref(),
        Some("vigil:hooks_disable")
    ))
}
