use rusqlite::Connection;
use std::path::Path;

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

/// Build a full initial baseline by walking all configured watch paths.
pub fn build_initial_baseline(conn: &Connection, config: &Config) -> Result<u64> {
    let mut count = 0u64;
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

    let result = (|| -> Result<()> {
        for group in config.watch.values() {
            let roots = crate::config::expand_user_paths(&group.paths);
            for root in roots {
                walk_files(&root, &exclusions, &mut |path| {
                    processed += 1;
                    if processed % 5000 == 0 {
                        tracing::info!(
                            processed_files = processed,
                            inserted_entries = count,
                            "baseline init progress"
                        );
                    }

                    let opts = CaptureOpts {
                        force_hash: true,
                        max_file_size: config.scanner.max_file_size,
                        mmap_threshold: config.scanner.mmap_threshold,
                    };

                    match crate::types::FileSnapshot::from_path(path, &opts) {
                        Ok(SnapshotOrDeleted::Snapshot(snapshot)) => {
                            let package = if skip_package_owner {
                                None
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
                            count += 1;
                        }
                        Ok(SnapshotOrDeleted::Deleted) => {}
                        Err(e) => {
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
        }

        Ok(())
    })();

    match result {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }

    Ok(count)
}

/// Refresh baseline by rebuilding entries under watch paths.
pub fn refresh_baseline(conn: &Connection, config: &Config) -> Result<u64> {
    build_initial_baseline(conn, config)
}

/// Run a baseline comparison scan.
pub fn run_scan(conn: &Connection, config: &Config, mode: ScanMode) -> Result<ScanResult> {
    let scan_start = std::time::Instant::now();
    let entries = baseline_ops::get_all(conn)?;
    let mut result = ScanResult::default();

    for entry in entries {
        result.total_checked += 1;

        let opts = CaptureOpts {
            force_hash: mode == ScanMode::Full,
            max_file_size: config.scanner.max_file_size,
            mmap_threshold: config.scanner.mmap_threshold,
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
                        path: entry.path.clone(),
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
    }

    result.duration_ms = scan_start.elapsed().as_millis() as u64;

    Ok(result)
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
