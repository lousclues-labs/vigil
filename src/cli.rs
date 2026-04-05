use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::types::OutputFormat;

#[derive(Parser)]
#[command(
    name = "vigil",
    about = "Lightweight File Integrity Monitor for Linux Desktops",
    version = env!("CARGO_PKG_VERSION"),
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Configuration file path (overrides default search)
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Output format
    #[arg(long, global = true, default_value = "human", value_enum)]
    pub format: OutputFormat,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize baseline database (first run)
    Init,

    /// Manage baselines
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Start real-time monitoring daemon
    Watch,

    /// Run immediate integrity check (one-shot)
    Check {
        /// Run a full scan instead of incremental
        #[arg(long)]
        full: bool,
    },

    /// Manage maintenance windows
    Maintenance {
        #[command(subcommand)]
        action: MaintenanceAction,
    },

    /// View alert history
    Log {
        #[command(subcommand)]
        action: LogAction,
    },

    /// Show daemon status and health
    Status,

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Run self-diagnostics
    Doctor,

    /// Print version information
    Version,
}

#[derive(Subcommand)]
pub enum BaselineAction {
    /// Create initial baseline (alias for top-level init)
    Init,

    /// Re-scan and update baseline
    Refresh {
        /// Only refresh paths under this directory
        #[arg(long)]
        paths: Option<PathBuf>,

        /// Suppress non-error output
        #[arg(long)]
        quiet: bool,
    },

    /// Show changes since last baseline
    Diff,

    /// Add single file to baseline
    Add {
        /// File path to add
        path: PathBuf,
    },

    /// Remove single file from baseline
    Remove {
        /// File path to remove
        path: PathBuf,
    },

    /// Show baseline statistics
    Stats,

    /// Export baseline as JSON
    Export,
}

#[derive(Subcommand)]
pub enum MaintenanceAction {
    /// Enter maintenance window (suppress alerts)
    Enter {
        /// Suppress non-error output
        #[arg(long)]
        quiet: bool,
    },

    /// Exit maintenance window (resume alerts)
    Exit {
        /// Suppress non-error output
        #[arg(long)]
        quiet: bool,
    },

    /// Show maintenance window state
    Status,
}

#[derive(Subcommand)]
pub enum LogAction {
    /// Show recent alerts
    Show {
        /// Filter by minimum severity
        #[arg(long)]
        severity: Option<String>,

        /// Number of most recent alerts to show
        #[arg(long, default_value = "20")]
        last: u32,
    },

    /// Search audit log
    Search {
        /// Search by path (substring match)
        #[arg(long)]
        path: Option<String>,

        /// Search by severity
        #[arg(long)]
        severity: Option<String>,
    },

    /// Show alert statistics
    Stats,

    /// Verify HMAC integrity of audit log
    Verify,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Display active configuration
    Show,

    /// Validate configuration file
    Validate,

    /// Deep-validate configuration file (checks filesystem access, permissions, etc.)
    Check,
}
