pub mod hash;
pub mod metadata;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::Connection;

use crate::config::{expand_user_paths, Config, WatchGroup};
use crate::db::ops;
use crate::error::{Result, ScanWarning, VigilError, WarningSeverity};
use crate::types::{BaselineEntry, BaselineSource};

struct TxGuard<'a> {
    conn: &'a Connection,
    committed: bool,
}

impl<'a> TxGuard<'a> {
    fn new(conn: &'a Connection) -> Self {
        Self {
            conn,
            committed: false,
        }
    }

    fn mark_committed(&mut self) {
        self.committed = true;
    }
}

impl Drop for TxGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

/// Pre-compiled exclusion patterns for efficient matching.
pub struct CompiledExclusions {
    pub patterns: Vec<glob::Pattern>,
    pub system_prefixes: Vec<String>,
}

impl CompiledExclusions {
    pub fn from_config(config: &Config) -> Self {
        Self {
            patterns: config
                .exclusions
                .patterns
                .iter()
                .filter_map(|p| glob::Pattern::new(p).ok())
                .collect(),
            system_prefixes: config
                .exclusions
                .system_exclusions
                .iter()
                .map(|s| s.trim_end_matches('*').to_string())
                .collect(),
        }
    }
}

/// Initialize the baseline: scan all configured watch paths and populate the database.
pub fn init_baseline(
    conn: &Connection,
    config: &Config,
    quiet: bool,
) -> Result<(u64, Vec<ScanWarning>)> {
    let mut count: u64 = 0;
    let now = Utc::now().timestamp();
    let mut warnings = Vec::new();
    let exclusions = CompiledExclusions::from_config(config);

    conn.execute_batch("BEGIN DEFERRED")?;
    let mut tx_guard = TxGuard::new(conn);
    let mut batch_count: u64 = 0;

    for (group_name, group) in &config.watch {
        let expanded_paths = expand_user_paths(&group.paths);

        for path in &expanded_paths {
            match scan_path(
                conn,
                path,
                group_name,
                group,
                config,
                now,
                quiet,
                &exclusions,
            ) {
                Ok(n) => {
                    count += n;
                    batch_count += n;
                    // Commit every 1,000 inserts to avoid holding the write lock too long
                    if batch_count >= 1000 {
                        conn.execute_batch("COMMIT")?;
                        conn.execute_batch("BEGIN DEFERRED")?;
                        batch_count = 0;
                    }
                }
                Err(e) => {
                    // Transient error — log and continue
                    log::warn!("Skipping {}: {}", path.display(), e);
                    warnings.push(ScanWarning {
                        path: path.clone(),
                        detail: format!("Skipping: {}", e),
                        severity: WarningSeverity::Warning,
                    });
                }
            }
        }
    }

    conn.execute_batch("COMMIT")?;
    tx_guard.mark_committed();

    // Record baseline generation metadata
    ops::set_config_state(conn, "last_baseline_refresh", &now.to_string())?;
    ops::set_config_state(conn, "daemon_version", env!("CARGO_PKG_VERSION"))?;

    // Update database HMAC (Item 17)
    if config.security.hmac_signing {
        if let Ok(key) = crate::hmac::load_hmac_key(&config.security.hmac_key_path) {
            if let Ok(hmac_val) = ops::compute_baseline_hmac(conn, &key) {
                let _ = ops::set_config_state(conn, "database_hmac", &hmac_val);
            }
        }
    }

    if !quiet {
        log::info!("Baseline initialized: {} entries", count);
    }

    Ok((count, warnings))
}

/// Refresh the baseline: re-scan all configured paths and update existing entries.
pub fn refresh_baseline(
    conn: &Connection,
    config: &Config,
    filter_paths: Option<&[PathBuf]>,
    quiet: bool,
) -> Result<(u64, Vec<ScanWarning>)> {
    let mut count: u64 = 0;
    let now = Utc::now().timestamp();
    let mut warnings = Vec::new();
    let exclusions = CompiledExclusions::from_config(config);

    conn.execute_batch("BEGIN DEFERRED")?;
    let mut tx_guard = TxGuard::new(conn);
    let mut batch_count: u64 = 0;

    for (group_name, group) in &config.watch {
        let expanded_paths = expand_user_paths(&group.paths);

        for path in &expanded_paths {
            // If filter_paths is set, only refresh paths that match
            if let Some(filter) = filter_paths {
                let dominated = filter
                    .iter()
                    .any(|f| path.starts_with(f) || f.starts_with(path));
                if !dominated {
                    continue;
                }
            }

            match scan_path(
                conn,
                path,
                group_name,
                group,
                config,
                now,
                quiet,
                &exclusions,
            ) {
                Ok(n) => {
                    count += n;
                    batch_count += n;
                    if batch_count >= 1000 {
                        conn.execute_batch("COMMIT")?;
                        conn.execute_batch("BEGIN DEFERRED")?;
                        batch_count = 0;
                    }
                }
                Err(e) => {
                    log::warn!("Skipping {}: {}", path.display(), e);
                    warnings.push(ScanWarning {
                        path: path.clone(),
                        detail: format!("Skipping: {}", e),
                        severity: WarningSeverity::Warning,
                    });
                }
            }
        }
    }

    conn.execute_batch("COMMIT")?;
    tx_guard.mark_committed();

    ops::set_config_state(conn, "last_baseline_refresh", &now.to_string())?;

    // Update database HMAC (Item 17)
    if config.security.hmac_signing {
        if let Ok(key) = crate::hmac::load_hmac_key(&config.security.hmac_key_path) {
            if let Ok(hmac_val) = ops::compute_baseline_hmac(conn, &key) {
                let _ = ops::set_config_state(conn, "database_hmac", &hmac_val);
            }
        }
    }

    if !quiet {
        log::info!("Baseline refreshed: {} entries updated", count);
    }

    Ok((count, warnings))
}

/// Add a single file to the baseline.
pub fn add_file(conn: &Connection, path: &Path, config: &Config) -> Result<()> {
    let canonical = path
        .canonicalize()
        .map_err(|e| VigilError::Path(format!("cannot canonicalize {}: {}", path.display(), e)))?;

    let meta =
        metadata::collect_file_metadata(&canonical, config, Some(config.scanner.max_file_size))?;
    let now = Utc::now().timestamp();

    let pkg = crate::package::query_package_owner(&canonical, &config.package_manager);

    let entry = BaselineEntry {
        id: None,
        path: canonical,
        hash: meta.hash,
        size: meta.size,
        permissions: meta.permissions,
        owner_uid: meta.owner_uid,
        owner_gid: meta.owner_gid,
        mtime: meta.mtime,
        inode: meta.inode,
        device: meta.device,
        xattrs: meta.xattrs,
        security_context: meta.security_context,
        package: pkg,
        source: BaselineSource::Manual,
        added_at: now,
        updated_at: now,
        file_type: meta.file_type,
        symlink_target: meta.symlink_target,
        capabilities: meta.capabilities,
    };

    ops::upsert_baseline(conn, &entry)?;
    log::info!("Added to baseline: {}", entry.path.display());
    Ok(())
}

/// Remove a single file from the baseline.
pub fn remove_file(conn: &Connection, path: &Path) -> Result<()> {
    let path_str = path.to_string_lossy();
    let removed = ops::remove_baseline(conn, &path_str)?;
    if removed > 0 {
        log::info!("Removed from baseline: {}", path.display());
    } else {
        log::warn!("Path not found in baseline: {}", path.display());
    }
    Ok(())
}

/// Diff: compare current filesystem state against baseline without updating.
/// Returns a list of changes.
pub fn diff_baseline(
    conn: &Connection,
    config: &Config,
) -> Result<Vec<crate::types::ChangeResult>> {
    let entries = ops::get_all_baselines(conn)?;
    let mut changes = Vec::new();
    let exclusions = CompiledExclusions::from_config(config);

    // Build a lookup from path to (group_name, severity)
    let watch_lookup: Vec<(std::path::PathBuf, String, crate::types::Severity)> = config
        .watch
        .iter()
        .flat_map(|(group_name, group)| {
            let expanded = expand_user_paths(&group.paths);
            expanded
                .into_iter()
                .map(move |p| (p, group_name.clone(), group.severity))
        })
        .collect();

    for entry in &entries {
        // Find watch group for this entry's path
        let (severity, group_name) = watch_lookup
            .iter()
            .find(|(wp, _, _)| entry.path.starts_with(wp) || entry.path == *wp)
            .map(|(_, gn, sev)| (*sev, gn.as_str()))
            .unwrap_or((crate::types::Severity::Medium, "unknown"));

        match crate::compare::compare_entry(entry, config, severity, group_name, false) {
            Ok(Some(change)) => changes.push(change),
            Ok(None) => {} // no change
            Err(e) => {
                log::debug!("Error comparing {}: {}", entry.path.display(), e);
            }
        }
    }

    // Check for new files in monitored directories that aren't in the baseline
    let baseline_paths = ops::get_all_baseline_paths(conn)?;

    for (group_name, group) in &config.watch {
        let expanded = expand_user_paths(&group.paths);
        for path in &expanded {
            if path.is_dir() {
                if let Ok(walker) = walk_directory(path, &exclusions) {
                    for file_path in walker {
                        let path_str = file_path.to_string_lossy().into_owned();
                        if !baseline_paths.contains(&path_str) {
                            changes.push(crate::types::ChangeResult {
                                path: file_path,
                                change_types: vec![crate::types::ChangeType::Created],
                                severity: group.severity,
                                old_hash: None,
                                new_hash: None,
                                old_permissions: None,
                                new_permissions: None,
                                old_owner_uid: None,
                                new_owner_uid: None,
                                old_owner_gid: None,
                                new_owner_gid: None,
                                old_inode: None,
                                new_inode: None,
                                old_mtime: None,
                                new_mtime: None,
                                package: None,
                                package_update: false,
                                monitored_group: group_name.clone(),
                                responsible_pid: None,
                                responsible_exe: None,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(changes)
}

/// Baseline statistics.
pub fn baseline_stats(conn: &Connection) -> Result<BaselineStats> {
    let total = ops::baseline_count(conn)?;

    let by_source: HashMap<String, i64> = {
        let mut stmt = conn.prepare("SELECT source, COUNT(*) FROM baseline GROUP BY source")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.filter_map(|r| r.ok()).collect()
    };

    let last_refresh = ops::get_config_state(conn, "last_baseline_refresh")?;

    Ok(BaselineStats {
        total_entries: total,
        by_source,
        last_refresh,
    })
}

#[derive(Debug)]
pub struct BaselineStats {
    pub total_entries: i64,
    pub by_source: HashMap<String, i64>,
    pub last_refresh: Option<String>,
}

// ── Internal helpers ───────────────────────────────────────

/// Scan a single path (file or directory) and insert/upsert baseline entries.
#[allow(clippy::too_many_arguments)]
fn scan_path(
    conn: &Connection,
    path: &Path,
    group_name: &str,
    _group: &WatchGroup,
    config: &Config,
    now: i64,
    quiet: bool,
    exclusions: &CompiledExclusions,
) -> Result<u64> {
    let mut count = 0;

    if path.is_file() {
        count += scan_single_file(conn, path, group_name, config, now, exclusions, None)?;
    } else if path.is_dir() {
        let files = walk_directory(path, exclusions)?;
        // Batch query package ownership for all files at once
        let path_refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
        let pkg_map =
            crate::package::batch_query_package_owners(&path_refs, &config.package_manager);
        for file_path in &files {
            let pkg = pkg_map.get(file_path).cloned().flatten();
            match scan_single_file(
                conn,
                file_path,
                group_name,
                config,
                now,
                exclusions,
                Some(pkg),
            ) {
                Ok(n) => count += n,
                Err(e) => {
                    if !quiet {
                        log::debug!("Skipping {}: {}", file_path.display(), e);
                    }
                }
            }
        }
    } else if !path.exists() {
        log::warn!("Watch path does not exist: {}", path.display());
    } else {
        log::debug!("Skipping non-regular path: {}", path.display());
    }

    Ok(count)
}

fn scan_single_file(
    conn: &Connection,
    path: &Path,
    _group_name: &str,
    config: &Config,
    now: i64,
    exclusions: &CompiledExclusions,
    pre_resolved_pkg: Option<Option<String>>,
) -> Result<u64> {
    // Skip excluded patterns
    if is_excluded(path, exclusions) {
        return Ok(0);
    }

    let file_meta =
        match metadata::collect_file_metadata(path, config, Some(config.scanner.max_file_size)) {
            Ok(m) => m,
            Err(e) => {
                log::debug!("Skipping {}: {}", path.display(), e);
                return Ok(0);
            }
        };
    let pkg = match pre_resolved_pkg {
        Some(p) => p,
        None => crate::package::query_package_owner(path, &config.package_manager),
    };

    let entry = BaselineEntry {
        id: None,
        path: path.to_path_buf(),
        hash: file_meta.hash,
        size: file_meta.size,
        permissions: file_meta.permissions,
        owner_uid: file_meta.owner_uid,
        owner_gid: file_meta.owner_gid,
        mtime: file_meta.mtime,
        inode: file_meta.inode,
        device: file_meta.device,
        xattrs: file_meta.xattrs,
        security_context: file_meta.security_context,
        package: pkg,
        source: BaselineSource::AutoScan,
        added_at: now,
        updated_at: now,
        file_type: file_meta.file_type,
        symlink_target: file_meta.symlink_target,
        capabilities: file_meta.capabilities,
    };

    ops::upsert_baseline(conn, &entry)?;
    Ok(1)
}

/// Walk a directory recursively, yielding regular file paths.
/// Respects exclusion patterns.
fn walk_directory(dir: &Path, exclusions: &CompiledExclusions) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    walk_recursive(dir, exclusions, &mut files, 0, 20)?;
    Ok(files)
}

fn walk_recursive(
    dir: &Path,
    exclusions: &CompiledExclusions,
    files: &mut Vec<PathBuf>,
    depth: u32,
    max_depth: u32,
) -> Result<()> {
    if depth > max_depth {
        return Ok(());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            log::debug!("Cannot read directory {}: {}", dir.display(), e);
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();

        if is_excluded(&path, exclusions) {
            continue;
        }

        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if ft.is_file() {
            files.push(path);
        } else if ft.is_dir() {
            walk_recursive(&path, exclusions, files, depth + 1, max_depth)?;
        }
        // Skip symlinks, sockets, etc.
    }

    Ok(())
}

/// Check if a path matches any exclusion pattern.
fn is_excluded(path: &Path, exclusions: &CompiledExclusions) -> bool {
    let path_str = path.to_string_lossy();

    // System exclusions (absolute prefix match)
    for prefix in &exclusions.system_prefixes {
        if path_str.starts_with(prefix.as_str()) {
            return true;
        }
    }

    // Pattern exclusions (glob match against filename)
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or(std::borrow::Cow::Borrowed(""));

    for glob in &exclusions.patterns {
        if glob.matches(&file_name) || glob.matches(&path_str) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_exclusions_from_config() {
        let mut watch = HashMap::new();
        watch.insert(
            "test".into(),
            crate::config::WatchGroup {
                severity: crate::types::Severity::Medium,
                paths: vec!["/tmp/test".into()],
            },
        );
        let config = crate::config::Config {
            config_version: 2,
            daemon: crate::config::DaemonConfig::default(),
            scanner: crate::config::ScannerConfig::default(),
            alerts: crate::config::AlertsConfig::default(),
            exclusions: crate::config::ExclusionsConfig {
                patterns: vec!["*.swp".into(), "*.tmp".into()],
                system_exclusions: vec!["/proc/*".into(), "/sys/*".into()],
            },
            package_manager: crate::config::PackageManagerConfig::default(),
            hooks: crate::config::HooksConfig::default(),
            security: crate::config::SecurityConfig::default(),
            database: crate::config::DatabaseConfig::default(),
            watch,
        };

        let exclusions = CompiledExclusions::from_config(&config);
        assert!(!exclusions.patterns.is_empty());
        assert!(!exclusions.system_prefixes.is_empty());

        // Verify system prefixes have * stripped
        for prefix in &exclusions.system_prefixes {
            assert!(!prefix.ends_with('*'));
        }
    }

    #[test]
    fn compiled_exclusions_is_excluded() {
        let exclusions = CompiledExclusions {
            patterns: vec![
                glob::Pattern::new("*.swp").unwrap(),
                glob::Pattern::new("*.tmp").unwrap(),
            ],
            system_prefixes: vec!["/proc/".into(), "/sys/".into()],
        };

        assert!(is_excluded(Path::new("/proc/1/status"), &exclusions));
        assert!(is_excluded(Path::new("/sys/class/net"), &exclusions));
        assert!(is_excluded(Path::new("/home/user/.file.swp"), &exclusions));
        assert!(is_excluded(Path::new("/tmp/data.tmp"), &exclusions));
        assert!(!is_excluded(Path::new("/etc/passwd"), &exclusions));
        assert!(!is_excluded(Path::new("/usr/bin/ls"), &exclusions));
    }
}
