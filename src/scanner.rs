use rusqlite::Connection;

use crate::alert::AlertEngine;
use crate::config::Config;
use crate::db::ops;
use crate::error::Result;
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
    };

    let maintenance_window = is_maintenance_window(conn);

    for entry in &entries {
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

        match crate::compare::compare_entry(entry, config) {
            Ok(Some(change)) => {
                result.changes_found += 1;
                if let Err(e) = alert_engine.dispatch(&change, maintenance_window, conn) {
                    log::error!("Alert dispatch error for {}: {}", entry.path.display(), e);
                }
            }
            Ok(None) => {} // no change
            Err(e) => {
                result.errors += 1;
                log::debug!("Scan error for {}: {}", entry.path.display(), e);
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
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }
}
