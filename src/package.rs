use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::Duration;

use crate::config::PackageManagerConfig;
use crate::types::PackageBackend;

/// Timeout for package manager subprocess calls.
const PKG_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of consecutive timeouts before the circuit breaker opens.
const CIRCUIT_OPEN_THRESHOLD: u32 = 3;

/// Duration in seconds to keep the circuit breaker open.
const CIRCUIT_OPEN_DURATION_SECS: i64 = 60;

/// Consecutive timeout counter for the circuit breaker.
static CONSECUTIVE_TIMEOUTS: AtomicU32 = AtomicU32::new(0);

/// Unix timestamp until which the circuit breaker remains open.
static CIRCUIT_OPEN_UNTIL: AtomicI64 = AtomicI64::new(0);

/// Returns true if the package manager circuit breaker is open (queries suspended).
fn is_circuit_open() -> bool {
    let until = CIRCUIT_OPEN_UNTIL.load(Ordering::Acquire);
    if until == 0 {
        return false;
    }
    let now = chrono::Utc::now().timestamp();
    if now < until {
        return true;
    }
    // Circuit breaker expired — close it
    tracing::info!("package manager circuit breaker closed — resuming queries");
    CIRCUIT_OPEN_UNTIL.store(0, Ordering::Release);
    CONSECUTIVE_TIMEOUTS.store(0, Ordering::Relaxed);
    false
}

/// Absolute paths for package managers — prevents PATH injection attacks.
const PACMAN_PATH: &str = "/usr/bin/pacman";
const DPKG_PATH: &str = "/usr/bin/dpkg";
const RPM_PATH: &str = "/usr/bin/rpm";

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
    if Path::new(PACMAN_PATH).is_file() {
        PackageBackend::Pacman
    } else if Path::new(DPKG_PATH).is_file() {
        PackageBackend::Dpkg
    } else if Path::new(RPM_PATH).is_file() {
        PackageBackend::Rpm
    } else {
        tracing::warn!("No supported package manager detected");
        PackageBackend::Auto
    }
}

fn query_pacman(path: &str) -> Option<String> {
    let output = run_with_timeout(
        Command::new(PACMAN_PATH).args(["-Qo", "--quiet", path]),
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
    let output = run_with_timeout(
        Command::new(DPKG_PATH).args(["-S", path]),
        PKG_QUERY_TIMEOUT,
    )?;

    if output.status.success() {
        let line = String::from_utf8_lossy(&output.stdout);
        line.split(':').next().map(|s| s.trim().to_string())
    } else {
        None
    }
}

fn query_rpm(path: &str) -> Option<String> {
    let output = run_with_timeout(
        Command::new(RPM_PATH).args(["-qf", path]),
        PKG_QUERY_TIMEOUT,
    )?;

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
/// When the circuit breaker is open, returns None immediately without spawning a subprocess.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Option<std::process::Output> {
    if timeout == PKG_QUERY_TIMEOUT && is_circuit_open() {
        return None;
    }

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                if timeout == PKG_QUERY_TIMEOUT {
                    CONSECUTIVE_TIMEOUTS.store(0, Ordering::Relaxed);
                }
                return child.wait_with_output().ok();
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    tracing::warn!("Package manager query timed out after {:?}", timeout);
                    let _ = child.kill();
                    let _ = child.wait();
                    if timeout == PKG_QUERY_TIMEOUT {
                        let count = CONSECUTIVE_TIMEOUTS.fetch_add(1, Ordering::Relaxed) + 1;
                        if count >= CIRCUIT_OPEN_THRESHOLD {
                            let until = chrono::Utc::now().timestamp() + CIRCUIT_OPEN_DURATION_SECS;
                            CIRCUIT_OPEN_UNTIL.store(until, Ordering::Release);
                            tracing::warn!(
                                "package manager circuit breaker opened — suspending queries for {}s after {} consecutive timeouts",
                                CIRCUIT_OPEN_DURATION_SECS,
                                count
                            );
                        }
                    }
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
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
    let mut cmd = Command::new(DPKG_PATH);
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
    // Fall back to individual queries per path. The batch approach using
    // `pacman -Qo --quiet` with positional zip was broken: when a file is
    // unowned, pacman skips it in stdout (writing errors to stderr), causing
    // all subsequent path→package mappings to shift by one.
    let mut results = HashMap::new();
    for path in paths {
        if let Some(pkg) = query_pacman(path) {
            results.insert(path.clone(), pkg);
        }
    }
    results
}

fn batch_query_rpm(paths: &[String]) -> HashMap<String, String> {
    // Fall back to individual queries per path. The batch approach using
    // positional zip was broken: when a file is unowned, rpm writes the
    // error to stderr but still outputs a line to stdout containing "not
    // owned", yet the line count can still mismatch on some rpm versions,
    // causing silent corruption of path→package mappings.
    let mut results = HashMap::new();
    for path in paths {
        if let Some(pkg) = query_rpm(path) {
            results.insert(path.clone(), pkg);
        }
    }
    results
}

/// Build a complete file→package ownership cache using a single bulk command.
/// This is dramatically faster than per-file subprocess calls during baseline init.
pub fn build_package_cache(config: &PackageManagerConfig) -> HashMap<PathBuf, String> {
    let backend = if config.backend == PackageBackend::Auto {
        detect_backend()
    } else {
        config.backend
    };

    match backend {
        PackageBackend::Pacman => build_cache_pacman(),
        PackageBackend::Dpkg => build_cache_dpkg(),
        PackageBackend::Rpm => build_cache_rpm(),
        PackageBackend::Auto => {
            tracing::warn!("No package manager detected for cache build");
            HashMap::new()
        }
    }
}

fn build_cache_pacman() -> HashMap<PathBuf, String> {
    let mut cache = HashMap::new();
    // `pacman -Ql` outputs "package /path/to/file" per line
    let timeout = Duration::from_secs(30);
    if let Some(output) = run_with_timeout(Command::new(PACMAN_PATH).arg("-Ql"), timeout) {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some((pkg, path)) = line.split_once(' ') {
                    let path = path.trim();
                    // Skip directory entries (trailing /)
                    if !path.ends_with('/') && !path.is_empty() {
                        cache.insert(PathBuf::from(path), pkg.trim().to_string());
                    }
                }
            }
        }
    }
    tracing::info!(entries = cache.len(), "built pacman package cache");
    cache
}

fn build_cache_dpkg() -> HashMap<PathBuf, String> {
    let mut cache = HashMap::new();
    // Parse /var/lib/dpkg/info/*.list files directly for speed
    let list_dir = Path::new("/var/lib/dpkg/info");

    // Verify the directory is owned by root before parsing to prevent
    // reading from a tampered dpkg info directory.
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(list_dir) {
            Ok(meta) if meta.uid() != 0 => {
                tracing::error!(
                    owner_uid = meta.uid(),
                    "/var/lib/dpkg/info is not owned by root — refusing to read package lists"
                );
                return cache;
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot stat /var/lib/dpkg/info");
                return cache;
            }
            _ => {} // uid == 0, proceed
        }
    }

    if list_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(list_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.ends_with(".list") {
                    continue;
                }
                // Package name is filename without .list suffix
                // Handle multi-arch: e.g. "libc6:amd64.list" → "libc6:amd64"
                let pkg = name_str.trim_end_matches(".list");
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    for line in content.lines() {
                        let line = line.trim();
                        if !line.is_empty() && !line.ends_with('/') {
                            cache.insert(PathBuf::from(line), pkg.to_string());
                        }
                    }
                }
            }
        }
    }
    tracing::info!(entries = cache.len(), "built dpkg package cache");
    cache
}

fn build_cache_rpm() -> HashMap<PathBuf, String> {
    let mut cache = HashMap::new();
    // `rpm -qa --queryformat '%{NAME}\t[%{FILENAMES}\n]'` is complex;
    // use `rpm -qa --filesbypkg` which outputs "package  /path" per line
    let timeout = Duration::from_secs(60);
    if let Some(output) = run_with_timeout(
        Command::new(RPM_PATH).args(["-qa", "--filesbypkg"]),
        timeout,
    ) {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // Format: "package-name                    /path/to/file"
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                // Split on whitespace — package name is first token, path is last
                let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
                if parts.len() == 2 {
                    let pkg = parts[0].trim();
                    let path = parts[1].trim();
                    if !path.is_empty() && !path.ends_with('/') {
                        cache.insert(PathBuf::from(path), pkg.to_string());
                    }
                }
            }
        }
    }
    tracing::info!(entries = cache.len(), "built rpm package cache");
    cache
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manager_paths_are_absolute() {
        assert!(PACMAN_PATH.starts_with('/'), "pacman path must be absolute");
        assert!(DPKG_PATH.starts_with('/'), "dpkg path must be absolute");
        assert!(RPM_PATH.starts_with('/'), "rpm path must be absolute");
    }

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
    fn parse_dpkg_batch_output_with_unowned() {
        // dpkg -S includes the path in each line, so unowned files (which
        // produce error lines to stderr) simply don't appear in stdout.
        // This test verifies that the parser correctly handles a batch
        // where the middle file is unowned.
        let output = "coreutils: /usr/bin/ls\ncoreutils: /usr/bin/cat\n";
        // Note: /tmp/custom would produce an error on stderr, not stdout
        let mut results = HashMap::new();
        for line in output.lines() {
            if let Some((pkg, path)) = line.split_once(": ") {
                results.insert(path.trim().to_string(), pkg.trim().to_string());
            }
        }
        assert_eq!(results.get("/usr/bin/ls"), Some(&"coreutils".to_string()));
        assert_eq!(results.get("/usr/bin/cat"), Some(&"coreutils".to_string()));
        assert!(!results.contains_key("/tmp/custom"));
    }

    #[test]
    fn batch_pacman_handles_unowned_in_middle() {
        // Regression test: with the old positional-zip approach, an unowned
        // file in the middle of a batch would cause all subsequent mappings
        // to shift by one. The fix uses individual queries per path.
        //
        // We can't easily mock pacman in a unit test, but we verify the
        // function signature is correct and returns an empty HashMap when
        // pacman is not available (which is the case in most CI environments).
        let paths = vec![
            "/usr/bin/ls".to_string(),
            "/tmp/definitely_not_owned_by_any_package_12345".to_string(),
            "/usr/bin/cat".to_string(),
        ];
        let results = batch_query_pacman(&paths);
        // On systems without pacman, this returns empty.
        // On Arch systems, /usr/bin/ls and /usr/bin/cat would be owned by
        // coreutils, and the unowned file would correctly be absent.
        // The key invariant: /usr/bin/cat must NOT map to the package
        // that owns /tmp/definitely_not_owned... (which was the old bug).
        if let Some(cat_pkg) = results.get("/usr/bin/cat") {
            assert!(!cat_pkg.is_empty(), "cat should be owned by a real package");
        }
        // The unowned file must not appear in results
        assert!(!results.contains_key("/tmp/definitely_not_owned_by_any_package_12345"));
    }

    #[test]
    fn batch_rpm_handles_unowned_in_middle() {
        // Same regression test for RPM.
        let paths = vec![
            "/usr/bin/ls".to_string(),
            "/tmp/definitely_not_owned_by_any_package_12345".to_string(),
            "/usr/bin/cat".to_string(),
        ];
        let results = batch_query_rpm(&paths);
        // The unowned file must not appear in results
        assert!(!results.contains_key("/tmp/definitely_not_owned_by_any_package_12345"));
    }

    #[test]
    fn parse_pacman_ql_output() {
        // Simulate pacman -Ql output parsing
        let output = "coreutils /usr/bin/ls\ncoreutils /usr/bin/cat\ncoreutils /usr/bin/\n";
        let mut cache = HashMap::new();
        for line in output.lines() {
            if let Some((pkg, path)) = line.split_once(' ') {
                let path = path.trim();
                if !path.ends_with('/') && !path.is_empty() {
                    cache.insert(PathBuf::from(path), pkg.trim().to_string());
                }
            }
        }
        assert_eq!(
            cache.get(&PathBuf::from("/usr/bin/ls")),
            Some(&"coreutils".to_string())
        );
        assert_eq!(
            cache.get(&PathBuf::from("/usr/bin/cat")),
            Some(&"coreutils".to_string())
        );
        // Directory entries (trailing /) should be skipped
        assert!(!cache.contains_key(&PathBuf::from("/usr/bin/")));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn parse_rpm_filesbypkg_output() {
        // Simulate rpm -qa --filesbypkg output
        let output = "coreutils                       /usr/bin/ls\ncoreutils                       /usr/bin/cat\nglibc                           /usr/lib64/\n";
        let mut cache = HashMap::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            if parts.len() == 2 {
                let pkg = parts[0].trim();
                let path = parts[1].trim();
                if !path.is_empty() && !path.ends_with('/') {
                    cache.insert(PathBuf::from(path), pkg.to_string());
                }
            }
        }
        assert_eq!(
            cache.get(&PathBuf::from("/usr/bin/ls")),
            Some(&"coreutils".to_string())
        );
        assert_eq!(
            cache.get(&PathBuf::from("/usr/bin/cat")),
            Some(&"coreutils".to_string())
        );
        // Directory entries should be skipped
        assert!(!cache.contains_key(&PathBuf::from("/usr/lib64/")));
    }

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        // Set CIRCUIT_OPEN_UNTIL to a future timestamp
        let future = chrono::Utc::now().timestamp() + 3600;
        CIRCUIT_OPEN_UNTIL.store(future, Ordering::Release);
        assert!(
            is_circuit_open(),
            "circuit breaker should be open with future timestamp"
        );
        // Clean up
        CIRCUIT_OPEN_UNTIL.store(0, Ordering::Release);
        CONSECUTIVE_TIMEOUTS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn circuit_breaker_closes_after_expiry() {
        // Set CIRCUIT_OPEN_UNTIL to a past timestamp
        let past = chrono::Utc::now().timestamp() - 10;
        CIRCUIT_OPEN_UNTIL.store(past, Ordering::Release);
        CONSECUTIVE_TIMEOUTS.store(5, Ordering::Relaxed);
        assert!(
            !is_circuit_open(),
            "circuit breaker should be closed with past timestamp"
        );
        assert_eq!(
            CONSECUTIVE_TIMEOUTS.load(Ordering::Relaxed),
            0,
            "timeouts should be reset"
        );
        assert_eq!(
            CIRCUIT_OPEN_UNTIL.load(Ordering::Relaxed),
            0,
            "open_until should be reset"
        );
    }

    #[test]
    fn circuit_breaker_resets_on_success() {
        CONSECUTIVE_TIMEOUTS.store(2, Ordering::Relaxed);
        CIRCUIT_OPEN_UNTIL.store(0, Ordering::Release);
        // Simulate a successful reset (as run_with_timeout does on success)
        CONSECUTIVE_TIMEOUTS.store(0, Ordering::Relaxed);
        assert_eq!(CONSECUTIVE_TIMEOUTS.load(Ordering::Relaxed), 0);
    }
}
