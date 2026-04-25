//! Display layer -- terminal rendering for Vigil CLI commands.
//!
//! Six focused files (Principle XI: complexity is a vulnerability):
//! - `mod.rs`    -- public API, shared report types, render dispatch
//! - `check.rs`  -- check/init report construction + command renderers
//! - `term.rs`   -- terminal detection (TermInfo)
//! - `format.rs` -- shared formatting: colors, numbers, paths, hashes
//! - `explain.rs`-- structural change explanations ("why" lines)
//! - `widgets.rs`-- histogram, comparison tables
//! - `time.rs`   -- time formatting helpers

mod check;
pub mod explain;
pub mod format;
pub mod term;
pub mod time;
pub mod widgets;

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::scanner::ScanResult;
use crate::types::{ChangeResult, OutputFormat, ScanMode, Severity};

use format::format_count;
use term::TermInfo;

// Re-export for external use (baseline_ops, main.rs, doctor.rs)
pub use format::{
    format_count as fmt_count, format_fingerprint, format_size as fmt_size, truncate_hash,
};

// ── Report Structs ─────────────────────────────────────────

/// Enriched report for `vigil check`. Built from ScanResult + baseline metadata.
pub struct CheckReport {
    // From ScanResult
    pub scan: ScanResult,

    // Baseline identity
    pub baseline_fingerprint: Option<String>,
    pub baseline_established: Option<i64>,
    pub hmac_signed: bool,

    // Scan metadata
    pub scan_mode: ScanMode,
    pub total_baseline_entries: u64,
    pub previous_check_at: Option<i64>,
    pub previous_check_changes: Option<u64>,

    // Baseline delta composition
    pub unchanged_count: u64,
    pub modified_count: u64,
    pub created_count: u64,
    pub deleted_count: u64,

    // Severity histogram
    pub severity_counts: BTreeMap<Severity, u64>,

    // Triage grouping
    pub investigate: Vec<ChangeResult>,
    pub attention: Vec<ChangeResult>,
    pub benign: Vec<PackageGroup>,
    pub benign_ungrouped: Vec<ChangeResult>,

    // DB info
    pub db_path: PathBuf,
}

/// A group of LOW-severity changes from the same package.
#[derive(Debug, Clone)]
pub struct PackageGroup {
    pub package_name: String,
    pub changes: Vec<ChangeResult>,
    pub paths_summary: String,
}

/// Enriched report for `vigil init` display.
pub struct InitReport {
    pub result: crate::scanner::BaselineInitResult,
    pub baseline_fingerprint: Option<String>,
    pub hmac_signed: bool,
    pub db_path: PathBuf,
    pub profile: Option<BaselineProfile>,
}

/// Classification of baselined files by property.
#[derive(Debug, Clone, Default)]
pub struct BaselineProfile {
    pub total: u64,
    pub executables: u64,
    pub setuid: u64,
    pub setgid: u64,
    pub config_files: u64,
    pub keys_certs: u64,
    pub package_owned: u64,
    pub unpackaged: u64,
}

/// Metadata used to enrich a `ScanResult` into a `CheckReport`.
pub struct CheckReportMeta {
    pub mode: ScanMode,
    pub baseline_fingerprint: Option<String>,
    pub baseline_established: Option<i64>,
    pub hmac_signed: bool,
    pub total_baseline_entries: u64,
    pub previous_check_at: Option<i64>,
    pub previous_check_changes: Option<u64>,
    pub db_path: PathBuf,
}

// ── CheckReport Builder ────────────────────────────────────

impl CheckReport {
    /// Build a CheckReport from scan results and baseline metadata.
    /// Encapsulates all enrichment: delta composition, severity histogram,
    /// triage grouping, and package grouping.
    pub fn from_scan(scan: ScanResult, meta: CheckReportMeta) -> Self {
        check::build_check_report(scan, meta)
    }

    /// Exit code based on highest severity detected.
    /// 0 = clean, 1 = low/medium, 2 = high, 3 = critical.
    pub fn exit_code(&self) -> i32 {
        check::exit_code(self)
    }
}

// ── Render Dispatch ────────────────────────────────────────

/// Render `vigil check` output. Single dispatch, no trait indirection.
pub fn render_check(
    report: &CheckReport,
    format: OutputFormat,
    term: &TermInfo,
    verbose: bool,
    brief: bool,
) -> String {
    if brief || format == OutputFormat::Brief {
        return check::render_brief(report, term);
    }
    match format {
        OutputFormat::Json => check::render_json(report),
        _ => check::render_human(report, term, verbose),
    }
}

/// Render `vigil init` output.
pub fn render_init(report: &InitReport, format: OutputFormat, term: &TermInfo) -> String {
    match format {
        OutputFormat::Json => check::render_init_json(report),
        OutputFormat::Brief => {
            format!(
                "● {} files baselined in {:.1}s\n",
                format_count(report.result.total_count),
                report.result.duration.as_secs_f64(),
            )
        }
        _ => check::render_init_human(report, term),
    }
}
