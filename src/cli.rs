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
    Init {
        /// Skip confirmation when overwriting existing baseline
        #[arg(long)]
        force: bool,
    },

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

    /// Run system health diagnostics
    Doctor {
        /// Output format
        #[arg(long, default_value = "human", value_enum)]
        format: Option<OutputFormat>,
    },

    /// Update Vigil from a local git repository
    Update {
        /// Path to the Vigil git repository (defaults to current directory)
        #[arg(long)]
        repo: Option<PathBuf>,
    },

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_force_flag_parses() {
        let cli = Cli::try_parse_from(["vigil", "init", "--force"]).expect("parse init --force");
        match cli.command {
            Command::Init { force } => assert!(force),
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn doctor_format_parses() {
        let cli = Cli::try_parse_from(["vigil", "doctor", "--format", "json"])
            .expect("parse doctor --format json");
        match cli.command {
            Command::Doctor { format } => assert_eq!(format, Some(OutputFormat::Json)),
            _ => panic!("expected doctor command"),
        }
    }

    #[test]
    fn update_repo_parses() {
        let cli = Cli::try_parse_from(["vigil", "update", "--repo", "/opt/vigil"])
            .expect("parse update --repo");
        match cli.command {
            Command::Update { repo } => {
                assert_eq!(repo, Some(PathBuf::from("/opt/vigil")));
            }
            _ => panic!("expected update command"),
        }
    }
}
