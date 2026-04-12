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

        /// Trigger scan on the running daemon via control socket instead of running inline
        #[arg(long)]
        now: bool,

        /// After showing changes, update baseline to accept current state
        #[arg(long)]
        accept: bool,

        /// Only accept changes matching this glob pattern (requires --accept)
        #[arg(long, requires = "accept")]
        path: Option<String>,
    },

    /// Compare a single file against its baseline entry
    Diff {
        /// Path to the file to check
        path: PathBuf,
    },

    /// Show daemon status
    Status,

    /// Run system health diagnostics
    Doctor {
        /// Output format
        #[arg(long, default_value = "human", value_enum)]
        format: Option<OutputFormat>,
    },

    /// Update VigilBaseline from a local git repository
    Update {
        /// Path to the VigilBaseline git repository (defaults to current directory)
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

    /// Setup operations (HMAC keys, socket configuration)
    Setup {
        #[command(subcommand)]
        action: SetupAction,
    },

    /// Show daemon log entries (errors, warnings, and operational messages)
    Log {
        #[command(subcommand)]
        action: LogAction,
    },

    /// Print version
    Version,
}

#[derive(Subcommand)]
pub enum AuditAction {
    /// Show audit log entries
    Show {
        /// Number of entries to show (default: 50)
        #[arg(long, short = 'n', default_value = "50")]
        last: u32,

        /// Filter by path (glob pattern, e.g. '/etc/*' or '/usr/bin/sudo')
        #[arg(long)]
        path: Option<String>,

        /// Filter by minimum severity: low, medium, high, critical
        #[arg(long)]
        severity: Option<String>,

        /// Filter by watch group name
        #[arg(long)]
        group: Option<String>,

        /// Show only entries after this time (ISO 8601, e.g. '2026-04-07' or '2026-04-07T14:00:00')
        #[arg(long)]
        since: Option<String>,

        /// Show only entries before this time (ISO 8601)
        #[arg(long)]
        until: Option<String>,

        /// Show only changes during maintenance windows
        #[arg(long)]
        maintenance: bool,

        /// Show only suppressed changes
        #[arg(long)]
        suppressed: bool,

        /// Show full change details for each entry (what specifically changed)
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// Show audit log statistics
    Stats {
        /// Time period: today, 24h, 7d, 30d, all (default: 7d)
        #[arg(long, default_value = "7d")]
        period: String,
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

#[derive(Subcommand)]
pub enum SetupAction {
    /// Generate and configure HMAC signing key
    Hmac {
        /// Path to write the HMAC key file
        #[arg(long, default_value = "/etc/vigil/hmac.key")]
        key_path: PathBuf,

        /// Overwrite existing key file without prompting
        #[arg(long)]
        force: bool,
    },

    /// Configure the alert socket path
    Socket {
        /// Path for the Unix domain socket
        #[arg(long, default_value = "/run/vigil/alert.sock")]
        path: PathBuf,

        /// Disable the socket sink
        #[arg(long)]
        disable: bool,
    },
}

#[derive(Subcommand)]
pub enum LogAction {
    /// Show recent daemon log entries from the journal
    Show {
        /// Number of lines to show (default: 100)
        #[arg(long, short = 'n', default_value = "100")]
        lines: u32,

        /// Filter by minimum level: error, warn, info, debug
        #[arg(long, short = 'l')]
        level: Option<String>,

        /// Follow log output in real time
        #[arg(long, short = 'f')]
        follow: bool,

        /// Show only entries after this time (e.g. '1h', '30m', '2026-04-07')
        #[arg(long)]
        since: Option<String>,

        /// Grep pattern to filter log lines
        #[arg(long, short = 'g')]
        grep: Option<String>,
    },

    /// Show only error and warning entries
    Errors {
        /// Number of lines to show (default: 50)
        #[arg(long, short = 'n', default_value = "50")]
        lines: u32,

        /// Show only entries after this time (e.g. '1h', '30m', '2026-04-07')
        #[arg(long)]
        since: Option<String>,
    },
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

    #[test]
    fn setup_hmac_parses_defaults() {
        let cli = Cli::try_parse_from(["vigil", "setup", "hmac"]).expect("parse setup hmac");
        match cli.command {
            Command::Setup {
                action: SetupAction::Hmac { key_path, force },
            } => {
                assert_eq!(key_path, PathBuf::from("/etc/vigil/hmac.key"));
                assert!(!force);
            }
            _ => panic!("expected setup hmac command"),
        }
    }

    #[test]
    fn setup_hmac_custom_path_and_force() {
        let cli = Cli::try_parse_from([
            "vigil",
            "setup",
            "hmac",
            "--key-path",
            "/custom/key",
            "--force",
        ])
        .expect("parse setup hmac with args");
        match cli.command {
            Command::Setup {
                action: SetupAction::Hmac { key_path, force },
            } => {
                assert_eq!(key_path, PathBuf::from("/custom/key"));
                assert!(force);
            }
            _ => panic!("expected setup hmac command"),
        }
    }

    #[test]
    fn setup_socket_parses_defaults() {
        let cli = Cli::try_parse_from(["vigil", "setup", "socket"]).expect("parse setup socket");
        match cli.command {
            Command::Setup {
                action: SetupAction::Socket { path, disable },
            } => {
                assert_eq!(path, PathBuf::from("/run/vigil/alert.sock"));
                assert!(!disable);
            }
            _ => panic!("expected setup socket command"),
        }
    }

    #[test]
    fn setup_socket_disable_flag() {
        let cli = Cli::try_parse_from(["vigil", "setup", "socket", "--disable"])
            .expect("parse setup socket --disable");
        match cli.command {
            Command::Setup {
                action: SetupAction::Socket { disable, .. },
            } => {
                assert!(disable);
            }
            _ => panic!("expected setup socket command"),
        }
    }

    #[test]
    fn check_accept_flag_parses() {
        let cli = Cli::try_parse_from(["vigil", "check", "--accept"]).expect("parse");
        match cli.command {
            Command::Check {
                accept,
                full,
                now,
                path,
            } => {
                assert!(accept);
                assert!(!full);
                assert!(!now);
                assert!(path.is_none());
            }
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn check_accept_and_full_parses() {
        let cli = Cli::try_parse_from(["vigil", "check", "--accept", "--full"]).expect("parse");
        match cli.command {
            Command::Check { accept, full, .. } => {
                assert!(accept);
                assert!(full);
            }
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn diff_command_parses() {
        let cli = Cli::try_parse_from(["vigil", "diff", "/etc/passwd"]).expect("parse diff");
        match cli.command {
            Command::Diff { path } => {
                assert_eq!(path, PathBuf::from("/etc/passwd"));
            }
            _ => panic!("expected diff command"),
        }
    }

    #[test]
    fn check_accept_path_requires_accept() {
        let result = Cli::try_parse_from(["vigil", "check", "--path", "/usr/bin/*"]);
        assert!(result.is_err(), "--path without --accept should fail");
    }

    #[test]
    fn check_accept_with_path_parses() {
        let cli = Cli::try_parse_from(["vigil", "check", "--accept", "--path", "/usr/bin/vigil*"])
            .expect("parse");
        match cli.command {
            Command::Check { accept, path, .. } => {
                assert!(accept);
                assert_eq!(path, Some("/usr/bin/vigil*".to_string()));
            }
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn audit_show_with_filters_parses() {
        let cli = Cli::try_parse_from([
            "vigil",
            "audit",
            "show",
            "--path",
            "/etc/*",
            "--severity",
            "high",
            "--since",
            "24h",
            "-v",
            "-n",
            "100",
        ])
        .expect("parse");
        match cli.command {
            Command::Audit {
                action:
                    AuditAction::Show {
                        last,
                        path,
                        severity,
                        since,
                        verbose,
                        ..
                    },
            } => {
                assert_eq!(last, 100);
                assert_eq!(path, Some("/etc/*".to_string()));
                assert_eq!(severity, Some("high".to_string()));
                assert_eq!(since, Some("24h".to_string()));
                assert!(verbose);
            }
            _ => panic!("expected audit show"),
        }
    }

    #[test]
    fn audit_show_defaults_parses() {
        let cli = Cli::try_parse_from(["vigil", "audit", "show"]).expect("parse");
        match cli.command {
            Command::Audit {
                action:
                    AuditAction::Show {
                        last,
                        path,
                        severity,
                        group,
                        since,
                        until,
                        maintenance,
                        suppressed,
                        verbose,
                    },
            } => {
                assert_eq!(last, 50);
                assert!(path.is_none());
                assert!(severity.is_none());
                assert!(group.is_none());
                assert!(since.is_none());
                assert!(until.is_none());
                assert!(!maintenance);
                assert!(!suppressed);
                assert!(!verbose);
            }
            _ => panic!("expected audit show"),
        }
    }

    #[test]
    fn audit_stats_parses() {
        let cli =
            Cli::try_parse_from(["vigil", "audit", "stats", "--period", "30d"]).expect("parse");
        match cli.command {
            Command::Audit {
                action: AuditAction::Stats { period },
            } => {
                assert_eq!(period, "30d");
            }
            _ => panic!("expected audit stats"),
        }
    }

    #[test]
    fn audit_stats_default_period() {
        let cli = Cli::try_parse_from(["vigil", "audit", "stats"]).expect("parse");
        match cli.command {
            Command::Audit {
                action: AuditAction::Stats { period },
            } => {
                assert_eq!(period, "7d");
            }
            _ => panic!("expected audit stats"),
        }
    }
}
