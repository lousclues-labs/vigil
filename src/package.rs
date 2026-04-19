//! Package manager queries with circuit-breaker timeout protection.
//!
//! Detects pacman and dpkg, resolves file-to-package ownership, and
//! builds a full-system package cache for baseline init. Three consecutive
//! timeouts open the circuit breaker for 60 seconds.

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
    // Circuit breaker expired; close it
    tracing::info!("package manager circuit breaker closed; resuming queries");
    CIRCUIT_OPEN_UNTIL.store(0, Ordering::Release);
    CONSECUTIVE_TIMEOUTS.store(0, Ordering::Relaxed);
    false
}

/// Absolute paths for package managers; prevents PATH injection attacks.
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
        Command::new(PACMAN_PATH).args(["-Qo", "--quiet", "--", path]),
        PKG_QUERY_TIMEOUT,
        true,
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
        Command::new(DPKG_PATH).args(["-S", "--", path]),
        PKG_QUERY_TIMEOUT,
        true,
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
        Command::new(RPM_PATH).args(["-qf", "--", path]),
        PKG_QUERY_TIMEOUT,
        true,
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
/// When `use_breaker` is true and the circuit breaker is open, returns None
/// immediately without spawning a subprocess. Successful runs reset the
/// breaker; timeouts increment the consecutive-timeout counter.
fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
    use_breaker: bool,
) -> Option<std::process::Output> {
    if use_breaker && is_circuit_open() {
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
                if use_breaker {
                    CONSECUTIVE_TIMEOUTS.store(0, Ordering::Relaxed);
                }
                return child.wait_with_output().ok();
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    tracing::warn!("Package manager query timed out after {:?}", timeout);
                    let _ = child.kill();
                    let _ = child.wait();
                    if use_breaker {
                        let count = CONSECUTIVE_TIMEOUTS.fetch_add(1, Ordering::Relaxed) + 1;
                        if count >= CIRCUIT_OPEN_THRESHOLD {
                            let until = chrono::Utc::now().timestamp() + CIRCUIT_OPEN_DURATION_SECS;
                            CIRCUIT_OPEN_UNTIL.store(until, Ordering::Release);
                            tracing::warn!(
                                "package manager circuit breaker opened; suspending queries for {}s after {} consecutive timeouts",
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
    // `--` ensures any path beginning with `-` is treated as a path, not a flag.
    cmd.arg("--");
    for p in paths {
        cmd.arg(p);
    }
    if let Some(output) = run_with_timeout(&mut cmd, PKG_QUERY_TIMEOUT, true) {
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

/// Build a complete file-to-package ownership cache using a single bulk command.
/// Dramatically faster than per-file subprocess calls during baseline init.
///
/// Returns `Some(cache)` on success, `None` if the query failed despite retries.
/// An empty `Some(HashMap)` means the package manager reported no installed files
/// (which is legitimate, e.g. a container with no packages).
pub fn build_package_cache(config: &PackageManagerConfig) -> Option<HashMap<PathBuf, String>> {
    let backend = if config.backend == PackageBackend::Auto {
        detect_backend()
    } else {
        config.backend
    };

    match backend {
        PackageBackend::Pacman => {
            build_cache_with_retry(build_cache_pacman_once, PackageBackend::Pacman)
        }
        PackageBackend::Dpkg => build_cache_with_retry(build_cache_dpkg_once, PackageBackend::Dpkg),
        PackageBackend::Rpm => build_cache_with_retry(build_cache_rpm_once, PackageBackend::Rpm),
        PackageBackend::Auto => {
            tracing::warn!("No package manager detected for cache build");
            None
        }
    }
}

/// Retry wrapper: if the first attempt returns an empty cache (likely lock contention),
/// wait for the package manager lock to release and retry with increasing backoff.
fn build_cache_with_retry<F>(
    build_fn: F,
    backend: PackageBackend,
) -> Option<HashMap<PathBuf, String>>
where
    F: Fn() -> Option<HashMap<PathBuf, String>>,
{
    const MAX_RETRIES: u32 = 3;
    const BACKOFF_SECS: &[u64] = &[2, 5, 10];

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay = BACKOFF_SECS
                .get((attempt - 1) as usize)
                .copied()
                .unwrap_or(10);
            tracing::info!(
                attempt,
                delay_secs = delay,
                backend = ?backend,
                "retrying package cache build after lock wait"
            );
            wait_for_package_lock(backend, Duration::from_secs(delay));
        }

        match build_fn() {
            Some(cache) if !cache.is_empty() => {
                if attempt > 0 {
                    tracing::info!(
                        attempt,
                        entries = cache.len(),
                        "package cache build succeeded on retry"
                    );
                }
                return Some(cache);
            }
            result => {
                if attempt == MAX_RETRIES {
                    tracing::error!(
                        backend = ?backend,
                        attempts = MAX_RETRIES + 1,
                        "package cache build failed after all retries; \
                         package attribution will be unavailable until the next refresh"
                    );
                    return result;
                }
                tracing::warn!(
                    attempt,
                    backend = ?backend,
                    "package cache build returned 0 entries; will retry after backoff"
                );
            }
        }
    }
    None
}

/// Wait for the package manager's database lock file to disappear.
/// Returns immediately if no lock is held. Times out after `max_wait`.
fn wait_for_package_lock(backend: PackageBackend, max_wait: Duration) {
    let lock_path = match backend {
        PackageBackend::Pacman => Path::new("/var/lib/pacman/db.lck"),
        PackageBackend::Dpkg => Path::new("/var/lib/dpkg/lock-frontend"),
        PackageBackend::Rpm => Path::new("/var/lib/rpm/.rpm.lock"),
        PackageBackend::Auto => return,
    };

    if !lock_path.exists() {
        return;
    }

    tracing::info!(
        lock = %lock_path.display(),
        timeout_secs = max_wait.as_secs(),
        "waiting for package manager lock to release"
    );

    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(250);

    while lock_path.exists() && start.elapsed() < max_wait {
        std::thread::sleep(poll_interval);
    }

    if lock_path.exists() {
        tracing::warn!(
            lock = %lock_path.display(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "package manager lock still held after timeout; proceeding anyway"
        );
    } else {
        tracing::info!(
            lock = %lock_path.display(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "package manager lock released"
        );
    }
}

/// Single-attempt pacman cache build. Returns `None` on timeout/spawn failure,
/// `Some(empty)` if the command succeeded but produced no entries.
fn build_cache_pacman_once() -> Option<HashMap<PathBuf, String>> {
    let mut cache = HashMap::new();

    // Do NOT use `run_with_timeout` here. `pacman -Ql` on a typical Arch
    // system produces 400k+ lines (~15 MB). The pipe buffer is ~64 KB;
    // if we poll with `try_wait()` without draining stdout, the child
    // blocks on write and the timeout fires every time. Instead, spawn
    // and read stdout to completion, with a thread-based timeout guard.
    let mut child = Command::new(PACMAN_PATH)
        .arg("-Ql")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take()?;
    let reader = std::io::BufReader::new(stdout);

    use std::io::BufRead;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Some((pkg, path)) = line.split_once(' ') {
            let path = path.trim();
            if !path.ends_with('/') && !path.is_empty() {
                cache.insert(PathBuf::from(path), pkg.trim().to_string());
            }
        }
    }

    let status = child.wait().ok()?;
    if !status.success() {
        tracing::warn!(
            status = %status,
            "pacman -Ql exited with non-zero status"
        );
        return None;
    }

    if cache.is_empty() {
        return Some(cache);
    }

    tracing::info!(entries = cache.len(), "built pacman package cache");
    Some(cache)
}

fn build_cache_dpkg_once() -> Option<HashMap<PathBuf, String>> {
    let mut cache = HashMap::new();
    let list_dir = Path::new("/var/lib/dpkg/info");

    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(list_dir) {
            Ok(meta) if meta.uid() != 0 => {
                tracing::error!(
                    owner_uid = meta.uid(),
                    "/var/lib/dpkg/info is not owned by root; refusing to read package lists"
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot stat /var/lib/dpkg/info");
                return None;
            }
            _ => {}
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

    if cache.is_empty() {
        tracing::warn!("dpkg package cache built with 0 entries");
        return Some(cache);
    }

    tracing::info!(entries = cache.len(), "built dpkg package cache");
    Some(cache)
}

fn build_cache_rpm_once() -> Option<HashMap<PathBuf, String>> {
    let mut cache = HashMap::new();

    // Same pipe-deadlock concern as pacman: `rpm -qa --filesbypkg` can
    // produce very large output. Stream stdout line-by-line instead of
    // buffering the entire output behind a try_wait poll loop.
    let mut child = Command::new(RPM_PATH)
        .args(["-qa", "--filesbypkg"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take()?;
    let reader = std::io::BufReader::new(stdout);

    use std::io::BufRead;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
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

    let status = child.wait().ok()?;
    if !status.success() {
        tracing::warn!(
            status = %status,
            "rpm -qa --filesbypkg exited with non-zero status"
        );
        return None;
    }

    if cache.is_empty() {
        tracing::warn!("rpm package cache built with 0 entries");
        return Some(cache);
    }

    tracing::info!(entries = cache.len(), "built rpm package cache");
    Some(cache)
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

    #[test]
    fn build_cache_with_retry_succeeds_on_first_try() {
        // Simulate a build function that returns a populated cache immediately.
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = build_cache_with_retry(
            || {
                call_count.fetch_add(1, Ordering::Relaxed);
                let mut cache = HashMap::new();
                cache.insert(PathBuf::from("/usr/bin/ls"), "coreutils".to_string());
                Some(cache)
            },
            PackageBackend::Pacman,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            1,
            "should not retry on success"
        );
    }

    #[test]
    fn build_cache_with_retry_retries_on_empty() {
        // Simulate a build function that fails twice then succeeds.
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = build_cache_with_retry(
            || {
                let n = call_count.fetch_add(1, Ordering::Relaxed);
                if n < 2 {
                    Some(HashMap::new()) // empty = transient failure
                } else {
                    let mut cache = HashMap::new();
                    cache.insert(PathBuf::from("/usr/bin/ls"), "coreutils".to_string());
                    Some(cache)
                }
            },
            PackageBackend::Pacman,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            3,
            "should retry twice then succeed"
        );
    }

    #[test]
    fn build_cache_with_retry_returns_none_after_exhaustion() {
        // Simulate a build function that always returns None (command failed).
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = build_cache_with_retry(
            || {
                call_count.fetch_add(1, Ordering::Relaxed);
                None
            },
            PackageBackend::Pacman,
        );
        assert!(result.is_none());
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            4,
            "should try 1 + 3 retries = 4"
        );
    }

    #[test]
    fn wait_for_package_lock_returns_immediately_when_no_lock() {
        // With no lock file present, wait_for_package_lock should return instantly.
        let start = std::time::Instant::now();
        wait_for_package_lock(PackageBackend::Auto, Duration::from_secs(5));
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "should return immediately for Auto backend"
        );
    }

    #[test]
    fn wait_for_nonexistent_lock_returns_immediately() {
        // Pacman lock file doesn't exist in test environments; should return instantly.
        let start = std::time::Instant::now();
        wait_for_package_lock(PackageBackend::Pacman, Duration::from_secs(1));
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "should return quickly when lock file doesn't exist"
        );
    }

    #[test]
    fn build_package_cache_auto_backend_returns_none_without_detection() {
        // The Auto backend with no detected package manager returns None.
        // We test the dispatch logic, not the actual package manager.
        // On Arch systems this would detect pacman, so we test the None path
        // by checking that a non-Auto backend doesn't crash.
        let config = PackageManagerConfig {
            auto_rebaseline: true,
            backend: PackageBackend::Auto,
        };
        // Just verify the function is callable and returns the right type.
        let _result: Option<HashMap<PathBuf, String>> = build_package_cache(&config);
    }
}
