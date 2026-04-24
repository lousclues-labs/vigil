//! `vigil hooks` subcommand: verify and repair package manager hooks.

use std::path::Path;

use vigil::cli::HooksAction;
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

pub(crate) fn cmd_hooks(action: HooksAction) -> vigil::Result<i32> {
    match action {
        HooksAction::Verify => cmd_hooks_verify(),
        HooksAction::Repair => cmd_hooks_repair(),
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

fn cmd_hooks_repair() -> vigil::Result<i32> {
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
