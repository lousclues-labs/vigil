use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
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

/// Batch query package ownership for multiple paths at once.
/// Batches paths into groups of ~100 for efficiency.
pub fn batch_query_package_owners(
    paths: &[&Path],
    config: &PackageManagerConfig,
) -> HashMap<PathBuf, Option<String>> {
    let backend = if config.backend == PackageBackend::Auto {
        detect_backend()
    } else {
        config.backend
    };

    let mut results = HashMap::with_capacity(paths.len());
    let batch_size = 100;

    for chunk in paths.chunks(batch_size) {
        let path_strs: Vec<String> = chunk
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let batch_results = match backend {
            PackageBackend::Pacman => batch_query_pacman(&path_strs),
            PackageBackend::Dpkg => batch_query_dpkg(&path_strs),
            PackageBackend::Rpm => batch_query_rpm(&path_strs),
            PackageBackend::Auto => HashMap::new(),
        };
        for path in chunk {
            let pkg = batch_results.get(&*path.to_string_lossy()).cloned();
            results.insert(path.to_path_buf(), pkg);
        }
    }

    results
}

fn batch_query_dpkg(paths: &[String]) -> HashMap<String, String> {
    let mut results = HashMap::new();
    let mut cmd = Command::new("dpkg");
    cmd.arg("-S");
    for p in paths {
        cmd.arg(p);
    }
    if let Some(output) = run_with_timeout(&mut cmd, PKG_QUERY_TIMEOUT) {
        // dpkg -S output: "package: /path/to/file" per line
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some((pkg, path)) = line.split_once(": ") {
                results.insert(path.trim().to_string(), pkg.trim().to_string());
            }
        }
    }
    results
}

fn batch_query_pacman(paths: &[String]) -> HashMap<String, String> {
    let mut results = HashMap::new();
    let mut cmd = Command::new("pacman");
    cmd.args(["-Qo", "--quiet"]);
    for p in paths {
        cmd.arg(p);
    }
    if let Some(output) = run_with_timeout(&mut cmd, PKG_QUERY_TIMEOUT) {
        // pacman -Qo --quiet outputs one package name per line matching input order
        let stdout = String::from_utf8_lossy(&output.stdout);
        for (path, pkg_line) in paths.iter().zip(stdout.lines()) {
            let pkg = pkg_line.trim().to_string();
            if !pkg.is_empty() {
                results.insert(path.clone(), pkg);
            }
        }
    }
    results
}

fn batch_query_rpm(paths: &[String]) -> HashMap<String, String> {
    let mut results = HashMap::new();
    let mut cmd = Command::new("rpm");
    cmd.arg("-qf");
    for p in paths {
        cmd.arg(p);
    }
    if let Some(output) = run_with_timeout(&mut cmd, PKG_QUERY_TIMEOUT) {
        // rpm -qf outputs one package per line matching input order
        let stdout = String::from_utf8_lossy(&output.stdout);
        for (path, pkg_line) in paths.iter().zip(stdout.lines()) {
            let pkg = pkg_line.trim().to_string();
            if !pkg.is_empty() && !pkg.contains("not owned") {
                results.insert(path.clone(), pkg);
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dpkg_batch_output() {
        // Simulate dpkg -S output parsing
        let output = "coreutils: /usr/bin/ls\ncoreutils: /usr/bin/cat\n";
        let mut results = HashMap::new();
        for line in output.lines() {
            if let Some((pkg, path)) = line.split_once(": ") {
                results.insert(path.trim().to_string(), pkg.trim().to_string());
            }
        }
        assert_eq!(results.get("/usr/bin/ls"), Some(&"coreutils".to_string()));
        assert_eq!(results.get("/usr/bin/cat"), Some(&"coreutils".to_string()));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn parse_pacman_batch_output() {
        let paths = ["/usr/bin/ls".to_string(), "/usr/bin/cat".to_string()];
        // Simulate pacman -Qo --quiet output: one package per line
        let output = "coreutils\ncoreutils\n";
        let mut results = HashMap::new();
        for (path, pkg_line) in paths.iter().zip(output.lines()) {
            let pkg = pkg_line.trim().to_string();
            if !pkg.is_empty() {
                results.insert(path.clone(), pkg);
            }
        }
        assert_eq!(results.get("/usr/bin/ls"), Some(&"coreutils".to_string()));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn parse_rpm_batch_output_with_not_owned() {
        let paths = ["/usr/bin/ls".to_string(), "/tmp/custom".to_string()];
        // Simulate rpm -qf output: one result per line, "not owned" for unpackaged
        let output = "coreutils-9.4-1.x86_64\nfile /tmp/custom is not owned by any package\n";
        let mut results = HashMap::new();
        for (path, pkg_line) in paths.iter().zip(output.lines()) {
            let pkg = pkg_line.trim().to_string();
            if !pkg.is_empty() && !pkg.contains("not owned") {
                results.insert(path.clone(), pkg);
            }
        }
        assert_eq!(
            results.get("/usr/bin/ls"),
            Some(&"coreutils-9.4-1.x86_64".to_string())
        );
        assert!(!results.contains_key("/tmp/custom"));
    }
}
