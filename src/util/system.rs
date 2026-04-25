//! System-level helpers: command existence checks and systemd interaction.

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Check whether a command exists on the system PATH.
pub fn command_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(cmd).is_file()))
        .unwrap_or(false)
}

/// Resolve the absolute path of `systemctl` to avoid PATH-injection in the
/// privileged daemon. Prefers known absolute locations; falls back to PATH
/// only if none of the canonical paths exist.
pub fn systemctl_binary() -> Option<PathBuf> {
    for cand in ["/usr/bin/systemctl", "/bin/systemctl"] {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return Some(p);
        }
    }
    if command_exists("systemctl") {
        Some(PathBuf::from("systemctl"))
    } else {
        None
    }
}

/// Check whether a systemd unit is currently active.
pub fn systemctl_is_active(unit: &str) -> Option<bool> {
    let bin = systemctl_binary()?;

    let status = Command::new(&bin)
        .arg("is-active")
        .arg(unit)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    Some(status.success())
}

/// Query a systemd unit property via `systemctl show --property=X --value`.
pub fn systemctl_show(unit: &str, property: &str) -> Option<String> {
    let bin = systemctl_binary()?;

    let output = Command::new(&bin)
        .arg("show")
        .arg(unit)
        .arg(format!("--property={}", property))
        .arg("--value")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
