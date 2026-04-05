use rusqlite::Connection;

use crate::alert::AlertEngine;
use crate::config::Config;
use crate::db::ops;
use crate::error::{Result, ScanWarning};
use crate::types::ScanMode;

/// Run a scheduled integrity scan.
///
/// - Incremental: only re-hash files with mtime newer than baseline entry
/// - Full: re-hash every file regardless of mtime
///
/// Runs at low I/O and CPU priority to avoid impacting desktop responsiveness.
pub fn run_scan(
    conn: &Connection,
    config: &Config,
    alert_engine: &AlertEngine,
    mode: ScanMode,
    progress: crate::ProgressCallback,
) -> Result<ScanResult> {
    // Set I/O scheduling class to idle (class 3) — only runs when disk is idle
    set_idle_io_priority();

    // Set CPU nice to 19 (lowest priority)
    set_low_cpu_priority();

    let entries = ops::get_all_baselines(conn)?;
    let mut result = ScanResult {
        total_checked: 0,
        changes_found: 0,
        errors: 0,
        warnings: Vec::new(),
    };

    let maintenance_window = is_maintenance_window(conn);

    // Build watch group index for severity/group resolution
    let watch_index = crate::watch_index::WatchGroupIndex::from_config(config);

    let total_entries = entries.len();

    // Parallel scanning path for Full mode when feature is enabled
    #[cfg(feature = "parallel")]
    if mode == ScanMode::Full {
        use rayon::prelude::*;

        // Note: progress callback is not used in parallel path because
        // Fn(&str) is not Sync. Progress is emitted after parallel collection.
        if progress.is_some() {
            log::debug!("Progress callback ignored in parallel scanning mode");
        }

        // Parallel: hash and compare all entries, collect results
        let compare_results: Vec<_> = entries
            .par_iter()
            .map(|entry| {
                let (severity, group_name) = watch_index
                    .lookup(&entry.path)
                    .map(|(gn, sev)| (sev, gn))
                    .unwrap_or((crate::types::Severity::Medium, "unknown"));

                (
                    entry,
                    crate::compare::compare_entry(entry, config, severity, group_name),
                )
            })
            .collect();

        // Dispatch alerts sequentially (DB connection is not Sync)
        for (entry, cmp_result) in compare_results {
            result.total_checked += 1;
            match cmp_result {
                Ok(Some(change)) => {
                    result.changes_found += 1;
                    if let Err(e) = alert_engine.dispatch(&change, maintenance_window, conn) {
                        log::error!("Alert dispatch error for {}: {}", entry.path.display(), e);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    result.errors += 1;
                    let detail = format!("Scan error: {}", e);
                    log::debug!("Scan error for {}: {}", entry.path.display(), e);
                    result.warnings.push(ScanWarning {
                        path: entry.path.clone(),
                        detail,
                        severity: crate::error::WarningSeverity::Error,
                    });
                }
            }
        }

        log::info!(
            "Scan complete ({} mode, parallel): {} checked, {} changes, {} errors",
            mode,
            result.total_checked,
            result.changes_found,
            result.errors,
        );

        return Ok(result);
    }

    // Sequential scanning path (default, also used for Incremental mode)
    for (idx, entry) in entries.iter().enumerate() {
        // Emit progress callback
        if let Some(ref cb) = progress {
            cb(&format!(
                "scanning {} ({}/{})",
                entry.path.display(),
                idx + 1,
                total_entries
            ));
        }

        // Incremental mode: skip files whose mtime hasn't changed
        if mode == ScanMode::Incremental {
            if let Ok(meta) = std::fs::metadata(&entry.path) {
                use std::os::unix::fs::MetadataExt;
                if meta.mtime() == entry.mtime {
                    continue; // mtime unchanged, skip hash computation
                }
            }
        }

        result.total_checked += 1;

        // Find watch group for this entry
        let (severity, group_name) = watch_index
            .lookup(&entry.path)
            .map(|(gn, sev)| (sev, gn))
            .unwrap_or((crate::types::Severity::Medium, "unknown"));

        match crate::compare::compare_entry(entry, config, severity, group_name) {
            Ok(Some(change)) => {
                result.changes_found += 1;
                if let Err(e) = alert_engine.dispatch(&change, maintenance_window, conn) {
                    log::error!("Alert dispatch error for {}: {}", entry.path.display(), e);
                }
            }
            Ok(None) => {} // no change
            Err(e) => {
                result.errors += 1;
                let detail = format!("Scan error: {}", e);
                log::debug!("Scan error for {}: {}", entry.path.display(), e);
                result.warnings.push(ScanWarning {
                    path: entry.path.clone(),
                    detail,
                    severity: crate::error::WarningSeverity::Error,
                });
            }
        }
    }

    log::info!(
        "Scan complete ({} mode): {} checked, {} changes, {} errors",
        mode,
        result.total_checked,
        result.changes_found,
        result.errors,
    );

    Ok(result)
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::Incremental => write!(f, "incremental"),
            ScanMode::Full => write!(f, "full"),
        }
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub total_checked: u64,
    pub changes_found: u64,
    pub errors: u64,
    pub warnings: Vec<ScanWarning>,
}

fn is_maintenance_window(conn: &Connection) -> bool {
    ops::get_config_state(conn, "maintenance_window_active")
        .ok()
        .flatten()
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Set I/O scheduling to idle class via direct syscall.
fn set_idle_io_priority() {
    const IOPRIO_WHO_PROCESS: i32 = 1;
    const IOPRIO_CLASS_IDLE: i32 = 3;

    // SAFETY: SYS_ioprio_set with IOPRIO_WHO_PROCESS and pid=0 (current process)
    // is a well-defined Linux syscall. No memory safety invariants to uphold.
    unsafe {
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0, // current process
            IOPRIO_CLASS_IDLE << 13,
        );
    }
}

/// Set CPU nice to 19 (lowest priority).
fn set_low_cpu_priority() {
    // SAFETY: setpriority with PRIO_PROCESS and who=0 (current process)
    // is a well-defined POSIX call. No memory safety invariants.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }
}
