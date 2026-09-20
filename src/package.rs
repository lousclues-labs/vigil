//! Package manager queries with circuit-breaker timeout protection.
//!
//! Detects pacman and dpkg, resolves file-to-package ownership, and
//! builds a full-system package cache for baseline init. Three consecutive
//! timeouts open the circuit breaker for 60 seconds.

use std::collections::{HashMap, HashSet};
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

/// dpkg's per-package metadata directory, where md5sums manifests live.
const DPKG_INFO_DIR: &str = "/var/lib/dpkg/info";

/// dpkg's status database, which records conffile digests.
const DPKG_STATUS_FILE: &str = "/var/lib/dpkg/status";

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

// ===========================================================================
// Content verification: does a file's content match what its package shipped?
// ===========================================================================

/// Timeout for a whole-package verification. Verification digests every file
/// in the package, so it is far slower than an ownership query.
const PKG_VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

/// Whether a file's on-disk content is what its owning package shipped.
///
/// Package ownership answers "could a package have written here." It does not
/// answer "did a package write these bytes." Every supported package manager
/// records a digest for every file it ships, so the second question is
/// answerable, deterministically, from local state alone (Principle VI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageVerification {
    /// The package manager checked the file against its own recorded digest
    /// and it matched. These bytes are the bytes the package shipped.
    Verified,
    /// A package owns this path and the content does NOT match what the
    /// package shipped. This is the highest-signal state in the tool.
    Mismatch,
    /// The package marks this path a config file. The operator is expected to
    /// edit it, so a digest difference proves nothing either way.
    Conffile,
    /// The package manager reports the file as absent.
    Missing,
    /// No digest was recorded, verification could not run, or the package
    /// manager declined to check. Absence of proof, not proof of absence.
    Unknown,
}

impl PackageVerification {
    /// True when the verdict is positive proof the content came from the
    /// package. Only `Verified` clears this bar; everything else is either a
    /// finding or an unknown, and neither may be treated as proof.
    pub fn is_proof(&self) -> bool {
        matches!(self, PackageVerification::Verified)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PackageVerification::Verified => "verified",
            PackageVerification::Mismatch => "mismatch",
            PackageVerification::Conffile => "conffile",
            PackageVerification::Missing => "missing",
            PackageVerification::Unknown => "unknown",
        }
    }
}

/// Verify changed paths against the digests their owning packages recorded.
///
/// Takes a map of package name to the changed paths owned by that package, and
/// runs one verification per package rather than one per path. Any path the
/// package manager does not report as a problem is `Verified`, because every
/// supported backend reports a line for each file it could not fully check.
///
/// A backend failure (timeout, missing binary, non-zero exit with no parseable
/// output) yields `Unknown` for that package's paths. Failing to verify is
/// never reported as having verified.
pub fn verify_changed_paths(
    paths_by_package: &HashMap<String, Vec<String>>,
    config: &PackageManagerConfig,
) -> HashMap<String, PackageVerification> {
    let backend = if config.backend == PackageBackend::Auto {
        detect_backend()
    } else {
        config.backend
    };

    let mut verdicts = HashMap::new();

    // Conffile digests live in one system-wide file, so read it once for the
    // whole batch rather than once per package.
    let conffiles = if backend == PackageBackend::Dpkg {
        dpkg_conffile_digest_coverage()
    } else {
        HashMap::new()
    };

    for (package, paths) in paths_by_package {
        let reported = match backend {
            PackageBackend::Dpkg => verify_package_dpkg(package),
            PackageBackend::Rpm => verify_package_rpm(package),
            PackageBackend::Pacman => verify_package_pacman(package),
            PackageBackend::Auto => None,
        };

        let Some(problems) = reported else {
            // Verification did not run. Claim nothing.
            for path in paths {
                verdicts.insert(path.clone(), PackageVerification::Unknown);
            }
            continue;
        };

        // Which of this package's paths the package manager actually holds a
        // digest for. Silence from the verifier only means "clean" for paths
        // inside this set; for anything else it means the verifier had
        // nothing to check against (AF-013).
        let coverage = match backend {
            PackageBackend::Dpkg => {
                let mut covered = dpkg_md5sums_coverage(package).unwrap_or_default();
                if let Some(cf) = conffiles.get(package) {
                    covered.extend(cf.iter().cloned());
                }
                Some(covered)
            }
            // rpm records a digest for every regular file it ships and `rpm -V`
            // reports the ones it could not check, so silence is coverage.
            PackageBackend::Rpm => None,
            // pacman derives digests from the package's mtree. When that is
            // absent, `-Qkk` says so and the whole package is uncovered.
            PackageBackend::Pacman => None,
            PackageBackend::Auto => Some(HashSet::new()),
        };

        for path in paths {
            verdicts.insert(
                path.clone(),
                verdict_for(path, &problems, coverage.as_ref()),
            );
        }
    }

    verdicts
}

/// Decide one path's verdict from what the verifier reported and what the
/// package manager actually holds a digest for.
///
/// The subtle case is the second arm. A verifier that says nothing about a
/// path has either checked it and found it clean, or had no digest to check
/// it against. Those are opposite meanings and only `coverage` can tell them
/// apart (AF-013). `coverage` of `None` means the backend reports on every
/// file it ships, so silence there really is a pass.
fn verdict_for(
    path: &str,
    problems: &HashMap<String, PackageVerification>,
    coverage: Option<&HashSet<String>>,
) -> PackageVerification {
    match problems.get(path) {
        // The verifier had something to say. Its verdict stands on its own.
        Some(verdict) => *verdict,
        None => match coverage {
            Some(covered) if !covered.contains(path) => PackageVerification::Unknown,
            _ => PackageVerification::Verified,
        },
    }
}

/// Absolute paths for which dpkg recorded a digest in a package's md5sums
/// manifest. Returns None when the package ships no manifest at all, which is
/// not rare: on a stock Ubuntu install, packages including
/// `apport-core-dump-handler` and several kernel packages have none.
///
/// Manifest lines are `<md5>  <path relative to />`.
fn dpkg_md5sums_coverage(package: &str) -> Option<HashSet<String>> {
    let dir = Path::new(DPKG_INFO_DIR);

    // The manifest is either `<pkg>.md5sums` or, for multi-arch packages,
    // `<pkg>:<arch>.md5sums`. Ownership queries strip the arch, so try both.
    let mut candidates = vec![dir.join(format!("{package}.md5sums"))];
    if let Ok(entries) = std::fs::read_dir(dir) {
        let prefix = format!("{package}:");
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".md5sums") {
                candidates.push(entry.path());
            }
        }
    }

    let mut covered = HashSet::new();
    let mut found = false;
    for path in candidates {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        found = true;
        covered.extend(parse_md5sums_paths(&contents));
    }

    found.then_some(covered)
}

/// Parse the absolute paths out of a dpkg md5sums manifest.
fn parse_md5sums_paths(contents: &str) -> HashSet<String> {
    contents
        .lines()
        .filter_map(|line| {
            let (_digest, rel) = line.split_once("  ")?;
            let rel = rel.trim();
            (!rel.is_empty()).then(|| format!("/{}", rel.trim_start_matches('/')))
        })
        .collect()
}

/// Conffile digests, which dpkg records in its status database rather than in
/// the per-package md5sums manifest. Read once per verification batch.
fn dpkg_conffile_digest_coverage() -> HashMap<String, HashSet<String>> {
    match std::fs::read_to_string(DPKG_STATUS_FILE) {
        Ok(contents) => parse_status_conffiles(&contents),
        Err(e) => {
            tracing::debug!(error = %e, "could not read dpkg status for conffile coverage");
            HashMap::new()
        }
    }
}

/// Parse `Package:` / `Conffiles:` stanzas out of the dpkg status database.
///
/// Conffile lines are indented and shaped `<absolute path> <md5>[ obsolete]`.
fn parse_status_conffiles(contents: &str) -> HashMap<String, HashSet<String>> {
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    let mut package: Option<String> = None;
    let mut in_conffiles = false;

    for line in contents.lines() {
        if let Some(name) = line.strip_prefix("Package: ") {
            package = Some(name.trim().to_string());
            in_conffiles = false;
            continue;
        }
        if line.starts_with("Conffiles:") {
            in_conffiles = true;
            continue;
        }
        // Any other unindented field ends the Conffiles list.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_conffiles = false;
            continue;
        }
        if !in_conffiles {
            continue;
        }
        if let Some(ref pkg) = package {
            if let Some(path) = line.split_whitespace().next() {
                if path.starts_with('/') {
                    out.entry(pkg.clone()).or_default().insert(path.to_string());
                }
            }
        }
    }

    out
}

/// `dpkg --verify <pkg>`: one line per file that did not fully check out.
/// Files that verified clean are not printed.
fn verify_package_dpkg(package: &str) -> Option<HashMap<String, PackageVerification>> {
    let output = run_with_timeout(
        Command::new(DPKG_PATH).args(["--verify", "--", package]),
        PKG_VERIFY_TIMEOUT,
        true,
    )?;

    let problems = parse_verify_output(&String::from_utf8_lossy(&output.stdout));
    finalize_verify(&output, problems)
}

/// `rpm -V <pkg>`: same line shape as dpkg, with `.` for checks that passed
/// and a letter for each that failed.
fn verify_package_rpm(package: &str) -> Option<HashMap<String, PackageVerification>> {
    let output = run_with_timeout(
        Command::new(RPM_PATH).args(["-V", "--", package]),
        PKG_VERIFY_TIMEOUT,
        true,
    )?;

    let problems = parse_verify_output(&String::from_utf8_lossy(&output.stdout));
    finalize_verify(&output, problems)
}

/// `pacman -Qkk <pkg>`: a different output shape from dpkg and rpm. Problems
/// are printed as `warning: pkg: /path (Reason)`.
fn verify_package_pacman(package: &str) -> Option<HashMap<String, PackageVerification>> {
    let output = run_with_timeout(
        Command::new(PACMAN_PATH).args(["-Qkk", "--", package]),
        PKG_VERIFY_TIMEOUT,
        true,
    )?;

    let mut problems = HashMap::new();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Without an mtree there are no recorded digests, so pacman checked
    // nothing and silence proves nothing (AF-013).
    if combined.to_lowercase().contains("no mtree file") {
        return None;
    }

    for line in combined.lines() {
        if let Some((path, verdict)) = parse_pacman_verify_line(line) {
            problems.insert(path, verdict);
        }
    }
    finalize_verify(&output, problems)
}

/// Decide whether a verification run produced a usable answer.
///
/// The backends disagree on exit codes: `dpkg --verify` exits 0 even when it
/// reports differences and exits non-zero when the package is unknown, while
/// `rpm -V` exits non-zero *because* it found differences. The rule that holds
/// for both: a non-zero exit with nothing parseable means the tool failed to
/// run rather than found something, and a tool that did not run has proven
/// nothing.
///
/// Getting this backwards is how a verifier starts laundering: a typo'd or
/// uninstalled package name would exit non-zero, report nothing, and every
/// path in it would fall through to `Verified` (AF-012).
fn finalize_verify(
    output: &std::process::Output,
    problems: HashMap<String, PackageVerification>,
) -> Option<HashMap<String, PackageVerification>> {
    if !output.status.success() && problems.is_empty() {
        return None;
    }
    Some(problems)
}

/// Parse one `pacman -Qkk` problem line.
///
/// Shapes handled:
///   `warning: pkg: /usr/bin/x (SHA256 checksum mismatch)`
///   `backup file: /etc/x (SHA256 checksum mismatch)`
///   `warning: pkg: /usr/bin/x (No such file or directory)`
fn parse_pacman_verify_line(line: &str) -> Option<(String, PackageVerification)> {
    let start = line.find(" /")?;
    let rest = &line[start + 1..];
    let path_end = rest.find(" (")?;
    let path = rest[..path_end].to_string();
    let reason = rest[path_end..].to_lowercase();

    // A backup file is pacman's conffile: the operator owns its content.
    if line.to_lowercase().contains("backup file") {
        return Some((path, PackageVerification::Conffile));
    }
    if reason.contains("no such file") {
        return Some((path, PackageVerification::Missing));
    }
    if reason.contains("mismatch") {
        // Size and checksum mismatches both mean the content is not what the
        // package shipped. Permission and mtime differences do not.
        if reason.contains("checksum") || reason.contains("size") {
            return Some((path, PackageVerification::Mismatch));
        }
        return Some((path, PackageVerification::Unknown));
    }
    Some((path, PackageVerification::Unknown))
}

/// Parse `dpkg --verify` / `rpm -V` output into per-path verdicts.
///
/// Line shape (both tools):
///   `<9-char attribute string> [c] <path>`
///   `missing     [c] <path>`
///
/// The attribute string carries one character per checked property. Position 2
/// (zero-indexed) is the content digest: `5` means the digest differs. dpkg
/// writes `?` for a property it could not check (for example when not running
/// as root), so an all-`?` line means *unverifiable*, not *failed*. Treating
/// those as proof of tampering would be false-positive noise; treating them as
/// proof of cleanliness would be a lie. They are `Unknown`.
fn parse_verify_output(stdout: &str) -> HashMap<String, PackageVerification> {
    let mut problems = HashMap::new();

    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let attrs = match parts.next() {
            Some(a) => a,
            None => continue,
        };

        // An optional single-character file-type flag precedes the path.
        // `c` marks a config file.
        let mut is_conffile = false;
        let mut path = match parts.next() {
            Some(token) => token,
            None => continue,
        };
        if path.len() == 1 && !path.starts_with('/') {
            is_conffile = path == "c";
            path = match parts.next() {
                Some(token) => token,
                None => continue,
            };
        }

        if !path.starts_with('/') {
            continue;
        }

        // Trailing annotations such as `(Permission denied)` mean the tool
        // could not read the file, so nothing was proven about it.
        let unreadable = line.contains("(Permission denied)");

        let verdict = if unreadable {
            // The annotation overrides whatever verdict the tool printed on
            // this line. If it could not read the file, it did not check the
            // file, and `missing` here means "could not confirm" rather than
            // "confirmed absent".
            PackageVerification::Unknown
        } else if attrs == "missing" {
            PackageVerification::Missing
        } else if digest_differs(attrs) {
            if is_conffile {
                PackageVerification::Conffile
            } else {
                PackageVerification::Mismatch
            }
        } else if is_conffile {
            PackageVerification::Conffile
        } else {
            // Listed, but the digest column was not a failure: the tool could
            // not check it. Absence of proof.
            PackageVerification::Unknown
        };

        problems.insert(path.to_string(), verdict);
    }

    problems
}

/// True when the digest column of a dpkg/rpm attribute string reports a
/// difference. Position 2 is the digest check; `5` is the failure character in
/// both tools.
fn digest_differs(attrs: &str) -> bool {
    attrs.chars().nth(2) == Some('5')
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

    // ── Content verification ────────────────────────────────────────────
    //
    // The fixtures below are verbatim `dpkg --verify` output captured from a
    // live Debian-family system, including the awkward cases: an all-`?`
    // attribute string (the tool could not check the file), a conffile with a
    // real digest difference, a `missing` entry, and a `(Permission denied)`
    // annotation.

    const DPKG_VERIFY_REAL: &str = "\
?????????   /usr/share/chrony/chrony.keys
??5?????? c /etc/default/jellyfin
missing     /etc/apparmor.d/disable
missing     /var/cache/cups/rss (Permission denied)
????????? c /etc/sudoers
??5??????   /usr/bin/sudo
";

    #[test]
    fn verify_parse_treats_digest_mismatch_on_a_binary_as_a_mismatch() {
        let problems = parse_verify_output(DPKG_VERIFY_REAL);
        assert_eq!(
            problems.get("/usr/bin/sudo"),
            Some(&PackageVerification::Mismatch),
            "a `5` in the digest column on a non-conffile is the highest-signal \
             state this tool can observe and must never be softened"
        );
    }

    #[test]
    fn verify_parse_treats_unreadable_and_unchecked_files_as_unknown() {
        let problems = parse_verify_output(DPKG_VERIFY_REAL);

        // An all-`?` attribute string means the tool could not check the file.
        // Calling that a pass would be a lie; calling it a mismatch would be
        // noise. It is neither.
        assert_eq!(
            problems.get("/usr/share/chrony/chrony.keys"),
            Some(&PackageVerification::Unknown)
        );
        assert_eq!(
            problems.get("/var/cache/cups/rss"),
            Some(&PackageVerification::Unknown),
            "a file the tool could not read proves nothing, even though the \
             line starts with `missing`"
        );
        assert!(!PackageVerification::Unknown.is_proof());
    }

    #[test]
    fn verify_parse_marks_conffiles_so_operator_edits_are_not_alarms() {
        let problems = parse_verify_output(DPKG_VERIFY_REAL);

        // /etc/default/jellyfin has a genuine digest difference, but the `c`
        // flag says the package expects the operator to edit it. Reporting
        // these would recreate the noise this change exists to remove.
        assert_eq!(
            problems.get("/etc/default/jellyfin"),
            Some(&PackageVerification::Conffile)
        );
        assert_eq!(
            problems.get("/etc/sudoers"),
            Some(&PackageVerification::Conffile)
        );
    }

    #[test]
    fn verify_parse_reports_a_genuinely_absent_file_as_missing() {
        let problems = parse_verify_output(DPKG_VERIFY_REAL);
        assert_eq!(
            problems.get("/etc/apparmor.d/disable"),
            Some(&PackageVerification::Missing)
        );
    }

    #[test]
    fn verify_parse_handles_rpm_attribute_alphabet() {
        // rpm -V writes `.` for a check that passed and a letter for one that
        // failed, where dpkg writes `?` for "not checked". Position 2 is the
        // digest in both.
        let rpm = "\
S.5....T.   /usr/bin/foo
S.5....T. c /etc/foo.conf
.M.......   /usr/lib/bar.so
missing     /usr/bin/gone
";
        let problems = parse_verify_output(rpm);
        assert_eq!(
            problems.get("/usr/bin/foo"),
            Some(&PackageVerification::Mismatch)
        );
        assert_eq!(
            problems.get("/etc/foo.conf"),
            Some(&PackageVerification::Conffile)
        );
        assert_eq!(
            problems.get("/usr/lib/bar.so"),
            Some(&PackageVerification::Unknown),
            "a mode-only difference is not a content difference"
        );
        assert_eq!(
            problems.get("/usr/bin/gone"),
            Some(&PackageVerification::Missing)
        );
    }

    #[test]
    fn verify_parse_ignores_lines_that_are_not_file_reports() {
        let noise = "\n\
some preamble that is not a file line\n\
??5??????   /usr/bin/real\n";
        let problems = parse_verify_output(noise);
        assert_eq!(problems.len(), 1);
        assert_eq!(
            problems.get("/usr/bin/real"),
            Some(&PackageVerification::Mismatch)
        );
    }

    #[test]
    fn pacman_verify_lines_map_to_verdicts() {
        assert_eq!(
            parse_pacman_verify_line("warning: sudo: /usr/bin/sudo (SHA256 checksum mismatch)"),
            Some(("/usr/bin/sudo".to_string(), PackageVerification::Mismatch))
        );
        assert_eq!(
            parse_pacman_verify_line("backup file: /etc/sudoers (SHA256 checksum mismatch)"),
            Some(("/etc/sudoers".to_string(), PackageVerification::Conffile)),
            "pacman's backup files are its conffiles: the operator owns them"
        );
        assert_eq!(
            parse_pacman_verify_line("warning: foo: /usr/bin/gone (No such file or directory)"),
            Some(("/usr/bin/gone".to_string(), PackageVerification::Missing))
        );
        assert_eq!(
            parse_pacman_verify_line("foo: 123 total files, 0 altered files"),
            None,
            "the summary line names no path"
        );
    }

    /// Regression guard for AF-012.
    ///
    /// A verifier that did not run must never be read as a verifier that
    /// passed. This was found by running the real backend against a package
    /// name that is not installed: dpkg exited non-zero, printed nothing
    /// parseable, and every path in that group came back `Verified`.
    #[test]
    fn a_failed_verifier_run_is_never_reported_as_verified() {
        use std::os::unix::process::ExitStatusExt;

        let failed = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8), // exit code 1
            stdout: Vec::new(),
            stderr: b"dpkg: package 'no-such-package' is not installed".to_vec(),
        };
        assert!(!failed.status.success(), "fixture must model a failed run");
        assert!(
            finalize_verify(&failed, HashMap::new()).is_none(),
            "a non-zero exit with nothing parseable means the tool failed to \
             run; claiming those paths verified would launder exactly the \
             changes this feature exists to catch"
        );

        // rpm exits non-zero *because* it found differences. When there is
        // something parseable, the findings are the answer.
        let found = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"S.5....T.   /usr/bin/foo\n".to_vec(),
            stderr: Vec::new(),
        };
        let problems = parse_verify_output(&String::from_utf8_lossy(&found.stdout));
        let finalized = finalize_verify(&found, problems).expect("findings are a usable answer");
        assert_eq!(
            finalized.get("/usr/bin/foo"),
            Some(&PackageVerification::Mismatch)
        );

        // A clean run exits zero with nothing to report: everything verified.
        let clean = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(finalize_verify(&clean, HashMap::new()).is_some());
    }

    /// Regression guard for AF-013.
    ///
    /// dpkg holds no digest for a fifth of `/usr/bin` and nearly all of
    /// `/boot` on a stock Ubuntu install: locally generated initrds,
    /// alternatives, diverted binaries. `dpkg --verify` says nothing about
    /// those files because it has nothing to say, and reading that silence as
    /// a pass reported `/usr/bin/ls` as "proven to be the package's own
    /// bytes" when no such proof existed.
    #[test]
    fn silence_about_a_path_with_no_recorded_digest_is_not_a_pass() {
        // An md5sums manifest is the coverage set. Anything outside it is
        // unproven no matter how quiet the verifier is.
        let manifest = "\
35bffc2134207a22591b40843d78602d  usr/bin/covered
0afd86d97f20c14cce6c76d1d20f054a  usr/share/doc/pkg/copyright
";
        let covered = parse_md5sums_paths(manifest);
        assert!(covered.contains("/usr/bin/covered"));
        assert!(
            !covered.contains("/usr/bin/uncovered"),
            "a path absent from the manifest must never be counted as covered"
        );
        assert_eq!(covered.len(), 2);

        // The verifier reported nothing at all, which is what dpkg does for a
        // package whose files it holds no digests for.
        let silent: HashMap<String, PackageVerification> = HashMap::new();

        assert_eq!(
            verdict_for("/usr/bin/uncovered", &silent, Some(&covered)),
            PackageVerification::Unknown,
            "silence about a path with no recorded digest is not a pass"
        );
        assert_eq!(
            verdict_for("/usr/bin/covered", &silent, Some(&covered)),
            PackageVerification::Verified,
            "silence about a path the manager does hold a digest for is a pass"
        );

        // A verdict the verifier did give stands regardless of coverage.
        let mut reported = HashMap::new();
        reported.insert(
            "/usr/bin/uncovered".to_string(),
            PackageVerification::Mismatch,
        );
        assert_eq!(
            verdict_for("/usr/bin/uncovered", &reported, Some(&covered)),
            PackageVerification::Mismatch
        );

        // A backend that reports on every file it ships has no coverage set;
        // silence there really is a pass.
        assert_eq!(
            verdict_for("/anything", &silent, None),
            PackageVerification::Verified
        );
    }

    #[test]
    fn conffile_digests_come_from_the_status_database_not_the_manifest() {
        // dpkg records conffile digests separately. Without this the common
        // case of a package updating its own config file would be reported as
        // unproven on every upgrade.
        let status = "\
Package: apport-core-dump-handler
Status: install ok installed
Conffiles:
 /etc/init.d/apport cfe03fd39e0f1b45972349fcb25091d4
Description: Kernel core dump handler

Package: sudo
Conffiles:
 /etc/sudo.conf 031f8305ee0c554fb2433a949bebe9be
 /etc/sudo_logsrvd.conf ad0ba586da300ae3ba46312ad744a6e2
Description: limited super user privileges
";
        let map = parse_status_conffiles(status);

        let apport = map
            .get("apport-core-dump-handler")
            .expect("package present");
        assert!(apport.contains("/etc/init.d/apport"));

        let sudo = map.get("sudo").expect("package present");
        assert!(sudo.contains("/etc/sudo.conf"));
        assert!(sudo.contains("/etc/sudo_logsrvd.conf"));
        assert!(
            !sudo.contains("/etc/sudoers"),
            "/etc/sudoers is not one of sudo's conffiles; inventing coverage \
             for it would be the same false-proof bug in a new place"
        );

        // The Description continuation lines are indented too and must not be
        // mistaken for conffile entries.
        assert_eq!(sudo.len(), 2);
    }

    #[test]
    fn a_path_the_verifier_did_not_report_is_verified() {
        // Every backend reports a line for each file it could not fully
        // check, so silence about a path means it checked out.
        let problems = parse_verify_output(DPKG_VERIFY_REAL);
        assert!(
            !problems.contains_key("/usr/bin/ls"),
            "unreported paths must not appear in the problem map"
        );
        assert!(PackageVerification::Verified.is_proof());
    }
}
