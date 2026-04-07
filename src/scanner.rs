use rusqlite::Connection;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::db::baseline_ops;
use crate::error::{Result, ScanWarning, WarningSeverity};
use crate::types::{CaptureOpts, ChangeResult, ScanMode, Severity, SnapshotOrDeleted};

#[derive(Debug, Default)]
pub struct ScanResult {
    pub total_checked: u64,
    pub changes_found: u64,
    pub errors: u64,
    pub warnings: Vec<ScanWarning>,
    pub changes: Vec<ChangeResult>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct GroupInitResult {
    pub name: String,
    pub paths: Vec<String>,
    pub file_count: u64,
    pub errors: u64,
}

#[derive(Debug, Clone)]
pub struct BaselineInitResult {
    pub total_count: u64,
    pub groups: Vec<GroupInitResult>,
    pub duration: Duration,
    pub db_size_bytes: u64,
}

/// Build a full initial baseline by walking all configured watch paths.
pub fn build_initial_baseline(conn: &Connection, config: &Config) -> Result<BaselineInitResult> {
    let started = Instant::now();
    let mut total_count = 0u64;
    let mut processed = 0u64;
    let now = chrono::Utc::now().timestamp();
    let exclusions = crate::filter::exclusion::ExclusionFilter::new(config);

    let skip_package_owner = std::env::var("VIGIL_SKIP_PACKAGE_OWNER")
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false);

    conn.execute_batch("BEGIN IMMEDIATE")?;

    // Build package ownership cache upfront (single command)
    // instead of per-file subprocess calls
    let package_cache = if !skip_package_owner {
        Some(crate::package::build_package_cache(&config.package_manager))
    } else {
        None
    };

    let result = (|| -> Result<Vec<GroupInitResult>> {
        let mut groups = Vec::with_capacity(config.watch.len());

        for (group_name, group) in &config.watch {
            let mut group_count = 0u64;
            let mut group_errors = 0u64;
            let roots = crate::config::expand_user_paths(&group.paths);
            for root in roots {
                walk_files(&root, &exclusions, &mut |path| {
                    processed += 1;
                    #[allow(clippy::manual_is_multiple_of)]
                    if processed % 5000 == 0 {
                        tracing::info!(
                            processed_files = processed,
                            inserted_entries = total_count,
                            "baseline init progress"
                        );
                    }

                    let opts = CaptureOpts {
                        force_hash: true,
                        max_file_size: config.scanner.max_file_size,
                        mmap_threshold: config.scanner.mmap_threshold,
                        baseline_mtime: None,
                        baseline_hash: None,
                    };

                    match crate::types::FileSnapshot::from_path(path, &opts) {
                        Ok(SnapshotOrDeleted::Snapshot(snapshot)) => {
                            let package = if skip_package_owner {
                                None
                            } else if let Some(ref cache) = package_cache {
                                cache.get(path).cloned()
                            } else {
                                crate::package::query_package_owner(path, &config.package_manager)
                            };

                            let entry = crate::types::BaselineEntry {
                                id: None,
                                path: path.to_path_buf(),
                                identity: snapshot.identity,
                                content: snapshot.content,
                                permissions: snapshot.permissions,
                                security: snapshot.security,
                                mtime: snapshot.mtime,
                                package,
                                source: crate::types::BaselineSource::AutoScan,
                                added_at: now,
                                updated_at: now,
                            };

                            baseline_ops::upsert(conn, &entry)?;
                            total_count += 1;
                            group_count += 1;
                        }
                        Ok(SnapshotOrDeleted::Deleted) => {}
                        Err(e) => {
                            group_errors += 1;
                            tracing::debug!(
                                path = %path.display(),
                                error = %e,
                                "baseline capture error"
                            );
                        }
                    }

                    Ok(())
                })?;
            }

            groups.push(GroupInitResult {
                name: group_name.clone(),
                paths: group.paths.clone(),
                file_count: group_count,
                errors: group_errors,
            });
        }

        Ok(groups)
    })();

    let groups = match result {
        Ok(groups) => {
            conn.execute_batch("COMMIT")?;
            groups
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    };

    baseline_ops::set_config_state(conn, "last_baseline_refresh", &now.to_string())?;
    let db_size_bytes = std::fs::metadata(&config.daemon.db_path)
        .map(|m| m.len())
        .unwrap_or(0);

    Ok(BaselineInitResult {
        total_count,
        groups,
        duration: started.elapsed(),
        db_size_bytes,
    })
}

/// Refresh baseline by rebuilding entries under watch paths.
pub fn refresh_baseline(conn: &Connection, config: &Config) -> Result<BaselineInitResult> {
    build_initial_baseline(conn, config)
}

/// Run a baseline comparison scan.
pub fn run_scan(conn: &Connection, config: &Config, mode: ScanMode) -> Result<ScanResult> {
    run_scan_with_progress(conn, config, mode, |_, _| {})
}

/// Run a baseline comparison scan with a progress callback.
///
/// The `progress` closure is called every 1,000 files with `(checked_so_far, total_entries)`.
pub fn run_scan_with_progress<F>(
    conn: &Connection,
    config: &Config,
    mode: ScanMode,
    progress: F,
) -> Result<ScanResult>
where
    F: Fn(u64, u64),
{
    let scan_start = std::time::Instant::now();
    let mut result = ScanResult::default();
    let total = baseline_ops::count(conn)?.max(0) as u64;

    baseline_ops::for_each_entry(conn, |entry| {
        result.total_checked += 1;

        if result.total_checked % 1000 == 0 {
            progress(result.total_checked, total);
        }

        let opts = CaptureOpts {
            force_hash: mode == ScanMode::Full,
            max_file_size: config.scanner.max_file_size,
            mmap_threshold: config.scanner.mmap_threshold,
            baseline_mtime: if mode != ScanMode::Full {
                Some(entry.mtime)
            } else {
                None
            },
            baseline_hash: if mode != ScanMode::Full {
                Some(entry.content.hash.clone())
            } else {
                None
            },
        };

        match crate::types::FileSnapshot::from_path(&entry.path, &opts) {
            Ok(SnapshotOrDeleted::Deleted) => {
                result.changes.push(ChangeResult::deletion(
                    &entry.path,
                    &entry,
                    Severity::High,
                    "scheduled_scan".into(),
                ));
                result.changes_found += 1;
            }
            Ok(SnapshotOrDeleted::Snapshot(snapshot)) => {
                let changes = snapshot.diff(&entry);
                if !changes.is_empty() {
                    result.changes.push(ChangeResult {
                        path: std::sync::Arc::new(entry.path.clone()),
                        changes,
                        severity: Severity::Medium,
                        monitored_group: "scheduled_scan".into(),
                        process: None,
                        package: entry.package.clone(),
                        package_update: false,
                    });
                    result.changes_found += 1;
                }
            }
            Err(e) => {
                result.errors += 1;
                result.warnings.push(ScanWarning {
                    path: entry.path.clone(),
                    detail: format!("scan error: {}", e),
                    severity: WarningSeverity::Error,
                });
            }
        }

        Ok(())
    })?;

    progress(total, total);

    result.duration_ms = scan_start.elapsed().as_millis() as u64;

    Ok(result)
}

/// Run a parallel baseline comparison scan (requires `parallel` feature).
#[cfg(feature = "parallel")]
pub fn run_scan_parallel(conn: &Connection, config: &Config, mode: ScanMode) -> Result<ScanResult> {
    use rayon::prelude::*;

    let scan_start = std::time::Instant::now();

    // Collect all entries first
    let entries = baseline_ops::get_all(conn)?;

    // Process in parallel
    let results: Vec<_> = entries
        .par_iter()
        .map(|entry| {
            let opts = CaptureOpts {
                force_hash: mode == ScanMode::Full,
                max_file_size: config.scanner.max_file_size,
                mmap_threshold: config.scanner.mmap_threshold,
                baseline_mtime: if mode != ScanMode::Full {
                    Some(entry.mtime)
                } else {
                    None
                },
                baseline_hash: if mode != ScanMode::Full {
                    Some(entry.content.hash.clone())
                } else {
                    None
                },
            };

            match crate::types::FileSnapshot::from_path(&entry.path, &opts) {
                Ok(SnapshotOrDeleted::Deleted) => Some((
                    true,
                    Some(ChangeResult::deletion(
                        &entry.path,
                        entry,
                        Severity::High,
                        "scheduled_scan".into(),
                    )),
                    None,
                )),
                Ok(SnapshotOrDeleted::Snapshot(snapshot)) => {
                    let changes = snapshot.diff(entry);
                    if !changes.is_empty() {
                        Some((
                            true,
                            Some(ChangeResult {
                                path: std::sync::Arc::new(entry.path.clone()),
                                changes,
                                severity: Severity::Medium,
                                monitored_group: "scheduled_scan".into(),
                                process: None,
                                package: entry.package.clone(),
                                package_update: false,
                            }),
                            None,
                        ))
                    } else {
                        Some((false, None, None))
                    }
                }
                Err(e) => Some((
                    false,
                    None,
                    Some(ScanWarning {
                        path: entry.path.clone(),
                        detail: format!("scan error: {}", e),
                        severity: WarningSeverity::Error,
                    }),
                )),
            }
        })
        .collect();

    let mut result = ScanResult {
        total_checked: entries.len() as u64,
        ..ScanResult::default()
    };

    for item in results.into_iter().flatten() {
        let (is_change, change, warning) = item;
        if let Some(cr) = change {
            result.changes.push(cr);
            result.changes_found += 1;
        } else if !is_change {
            if let Some(w) = warning {
                result.errors += 1;
                result.warnings.push(w);
            }
        }
    }

    result.duration_ms = scan_start.elapsed().as_millis() as u64;
    Ok(result)
}

/// Collect all file paths from watch groups for parallel processing.
#[cfg(feature = "parallel")]
pub fn collect_all_paths(config: &Config) -> Vec<std::path::PathBuf> {
    let exclusions = crate::filter::exclusion::ExclusionFilter::new(config);
    let mut all_paths = Vec::new();
    for group in config.watch.values() {
        let roots = crate::config::expand_user_paths(&group.paths);
        for root in roots {
            let _ = walk_files(&root, &exclusions, &mut |path| {
                all_paths.push(path.to_path_buf());
                Ok(())
            });
        }
    }
    all_paths
}

fn walk_files<F>(
    root: &Path,
    exclusions: &crate::filter::exclusion::ExclusionFilter,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(&Path) -> Result<()>,
{
    if !root.exists() {
        return Ok(());
    }

    let mut stack = vec![root.to_path_buf()];

    while let Some(path) = stack.pop() {
        let path_str = path.to_string_lossy();
        if exclusions.is_excluded(&path_str) {
            continue;
        }

        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "baseline walk metadata error");
                continue;
            }
        };

        let ft = meta.file_type();

        if ft.is_symlink() {
            // Follow symlinked files, but never descend into symlinked directories.
            // This avoids recursive loops in trees like /etc/systemd/system.
            match std::fs::metadata(&path) {
                Ok(target) if target.is_file() => {
                    visit(&path)?;
                }
                Ok(target) if target.is_dir() => {
                    tracing::debug!(
                        path = %path.display(),
                        "skipping symlinked directory during baseline walk"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "baseline walk symlink target error"
                    );
                }
            }
            continue;
        }

        if ft.is_file() {
            visit(&path)?;
            continue;
        }

        if ft.is_dir() {
            let entries = match std::fs::read_dir(&path) {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(path = %path.display(), error = %e, "baseline walk read_dir error");
                    continue;
                }
            };

            for entry in entries {
                match entry {
                    Ok(ent) => stack.push(ent.path()),
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "baseline walk dir entry error");
                    }
                }
            }
        }
    }

    Ok(())
}
