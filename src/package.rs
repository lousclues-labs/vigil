use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::config::PackageManagerConfig;
use crate::types::PackageBackend;

/// Timeout for package manager subprocess calls.
const PKG_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Query the system's package manager to determine which package owns a file.
/// Returns None if the file is not owned by any package.
pub fn query_package_owner(path: &Path, config: &PackageManagerConfig) -> Option<String> {
    let backend = if config.backend == PackageBackend::Auto {
        detect_backend()
    } else {
        config.backend
    };

    let path_str = path.to_string_lossy();

    match backend {
        PackageBackend::Pacman => query_pacman(&path_str),
        PackageBackend::Dpkg => query_dpkg(&path_str),
        PackageBackend::Rpm => query_rpm(&path_str),
        PackageBackend::Auto => None, // detection failed
    }
}

/// Detect which package manager is available on the system.
pub fn detect_backend() -> PackageBackend {
    if command_exists("pacman") {
        PackageBackend::Pacman
    } else if command_exists("dpkg") {
        PackageBackend::Dpkg
    } else if command_exists("rpm") {
        PackageBackend::Rpm
    } else {
        log::warn!("No supported package manager detected");
        PackageBackend::Auto
    }
}

fn query_pacman(path: &str) -> Option<String> {
    let output = run_with_timeout(
        Command::new("pacman").args(["-Qo", "--quiet", path]),
        PKG_QUERY_TIMEOUT,
    )?;

    if output.status.success() {
        let pkg = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pkg.is_empty() {
            None
        } else {
            Some(pkg)
        }
    } else {
        None
    }
}

fn query_dpkg(path: &str) -> Option<String> {
    let output = run_with_timeout(Command::new("dpkg").args(["-S", path]), PKG_QUERY_TIMEOUT)?;

    if output.status.success() {
        let line = String::from_utf8_lossy(&output.stdout);
        line.split(':').next().map(|s| s.trim().to_string())
    } else {
        None
    }
}

fn query_rpm(path: &str) -> Option<String> {
    let output = run_with_timeout(Command::new("rpm").args(["-qf", path]), PKG_QUERY_TIMEOUT)?;

    if output.status.success() {
        let pkg = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pkg.is_empty() || pkg.contains("not owned") {
            None
        } else {
            Some(pkg)
        }
    } else {
        None
    }
}

/// Run a command with a timeout. Returns None if the command times out or fails to spawn.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Option<std::process::Output> {
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child.wait_with_output().ok();
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    log::warn!("Package manager query timed out after {:?}", timeout);
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

fn command_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(cmd).is_file()))
        .unwrap_or(false)
}
