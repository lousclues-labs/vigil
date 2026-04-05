use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::types::OutputFormat;

#[derive(Parser)]
#[command(
    name = "vigil",
    about = "Linux file integrity monitor",
    version = env!("CARGO_PKG_VERSION"),
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
    /// Initialize baseline database
    Init,

    /// Run daemon in foreground
    Watch,

    /// Run one-shot integrity check
    Check {
        /// Run full scan instead of incremental
        #[arg(long)]
        full: bool,
    },

    /// Show daemon status
    Status,

    /// Audit log operations
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Configuration operations
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Print version
    Version,
}

#[derive(Subcommand)]
pub enum AuditAction {
    /// Show recent audit entries
    Show {
        /// Number of entries to show
        #[arg(long, default_value = "20")]
        last: u32,
    },

    /// Verify audit chain integrity
    Verify,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show active configuration as TOML
    Show,

    /// Validate configuration
    Validate,
}
