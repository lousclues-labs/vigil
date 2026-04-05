use rusqlite::Connection;

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
}

/// Build a full initial baseline by walking all configured watch paths.
pub fn build_initial_baseline(conn: &Connection, config: &Config) -> Result<u64> {
    let mut count = 0u64;
    let now = chrono::Utc::now().timestamp();

    for group in config.watch.values() {
        let roots = crate::config::expand_user_paths(&group.paths);
        for root in roots {
            let mut paths = Vec::new();
            collect_paths(&root, &mut paths);

            for path in paths {
                let opts = CaptureOpts {
                    force_hash: true,
                    max_file_size: config.scanner.max_file_size,
                    mmap_threshold: config.scanner.mmap_threshold,
                };

                match crate::types::FileSnapshot::from_path(&path, &opts) {
                    Ok(SnapshotOrDeleted::Snapshot(snapshot)) => {
                        let package =
                            crate::package::query_package_owner(&path, &config.package_manager);

                        let entry = crate::types::BaselineEntry {
                            id: None,
                            path: path.clone(),
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
                        tracing::debug!(path = %path.display(), error = %e, "baseline capture error");
                    }
                }
            }
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

    Ok(result)
}

fn collect_paths(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if !root.exists() {
        return;
    }

    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }

    if root.is_dir() {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    out.push(path);
                } else if path.is_dir() {
                    collect_paths(&path, out);
                }
            }
        }
    }
}
