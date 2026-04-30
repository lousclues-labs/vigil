//! Clap-based CLI parser for the `vigil` binary.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::types::{OutputFormat, Severity};

#[derive(Parser)]
#[command(
    name = "vigil",
    about = "Linux file integrity monitor",
    version = env!("CARGO_PKG_VERSION"),
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Configuration file path (overrides default search)
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Output format
    #[arg(long, global = true, default_value = "human", value_enum)]
    pub format: OutputFormat,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize baseline database.
    #[command(
        long_about = "Initialize baseline database.\n\nWHEN TO USE THIS:\n  Run once on a clean, known-good system to establish the baseline.\n  Use --force to overwrite an existing baseline after a system rebuild.\n  For first-time setup, `vigil welcome` is easier."
    )]
    Init {
        /// Skip confirmation when overwriting existing baseline
        #[arg(long)]
        force: bool,
    },

    /// Run daemon in foreground
    Watch,

    /// Run one-shot integrity check.
    #[command(
        long_about = "Run one-shot integrity check.\n\nWHEN TO USE THIS:\n  After package updates, configuration changes, or to verify your system\n  is still in the expected state. Use --accept to update the baseline\n  after reviewing changes. Use --now to trigger on a running daemon."
    )]
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

        /// Preview what would be accepted without mutating baseline (requires --accept)
        #[arg(long, requires = "accept")]
        dry_run: bool,

        /// Accept only changes of this severity (requires --accept)
        #[arg(long = "accept-severity", requires = "accept")]
        accept_severity: Option<Severity>,

        /// Accept only changes from this watch group (requires --accept)
        #[arg(long = "accept-group", requires = "accept")]
        accept_group: Option<String>,

        /// Show expanded detail for all changes
        #[arg(short, long)]
        verbose: bool,

        /// Single-line summary output
        #[arg(long, conflicts_with = "verbose")]
        brief: bool,

        /// Disable automatic paging of output
        #[arg(long)]
        no_pager: bool,

        /// Show only current changes with audit evidence since this time (e.g. 24h, 7d, today, 2026-04-07)
        #[arg(long)]
        since: Option<String>,

        /// Record a verification receipt in the audit chain
        #[arg(long)]
        reason: bool,

        /// Forensically classify each detected content mismatch by re-reading
        /// the file after dropping its page cache (Linux). Adds ~one read per
        /// mismatch. For a clean scan there is no overhead. Distinguishes
        /// page-cache-only attacks (e.g. CVE-2026-31431) from disk-layer
        /// modifications. See docs/FORENSICS.md.
        #[arg(long = "disambiguate-cause")]
        disambiguate_cause: bool,
    },

    /// Compare a single file against its baseline entry
    Diff {
        /// Path to the file to check
        path: PathBuf,
    },

    /// Show daemon status.
    #[command(
        long_about = "Show daemon status.\n\nWHEN TO USE THIS:\n  To see if the daemon is running, what it's monitoring, and whether\n  the audit chain is intact. This is the default when you run `vigil`\n  with no arguments."
    )]
    Status,

    /// First-run configuration flow.
    #[command(
        long_about = "First-run configuration flow.\n\nWHEN TO USE THIS:\n  On a fresh install. Walks you through watch path selection, builds\n  the baseline, starts the daemon, and runs selftest. Idempotent.\n  Re-run to reconfigure."
    )]
    Welcome,

    /// Explain a change to a path
    Why {
        /// Path to explain (omit for most recent change)
        path: Option<PathBuf>,
    },

    /// End-to-end verification of vigil on the current machine
    Selftest,

    /// Query why a path is watched (or not)
    Explain {
        /// Path to explain
        path: PathBuf,

        /// Show full hash, xattr list, and audit history
        #[arg(long)]
        verbose: bool,
    },

    /// Query why Vigil is currently silent
    WhySilent,

    /// Inspect files against a baseline (offline forensic comparison)
    Inspect {
        /// Path to inspect (file or directory)
        path: PathBuf,

        /// Path to a baseline database file
        #[arg(long = "baseline-db")]
        baseline_db: Option<PathBuf>,

        /// Inspect directory recursively
        #[arg(long)]
        recursive: bool,

        /// Path prefix to strip when looking up baseline paths
        #[arg(long)]
        root: Option<String>,

        /// Single-line summary output
        #[arg(long)]
        brief: bool,
    },

    /// Test operations
    Test {
        #[command(subcommand)]
        action: TestAction,
    },

    /// Run system health diagnostics
    Doctor {
        /// Output format
        #[arg(long, default_value = "human", value_enum)]
        format: Option<OutputFormat>,

        /// Trigger a self-check on the running daemon via control socket
        #[arg(long)]
        now: bool,

        /// Show full diagnostic breakdown (default: compact summary)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Update Vigil Baseline from a local git repository
    Update {
        /// Path to the Vigil Baseline git repository (defaults to current directory)
        #[arg(long)]
        repo: Option<PathBuf>,

        /// Suppress all output except errors and final summary
        #[arg(short, long, conflicts_with_all = ["verbose", "no_progress"])]
        quiet: bool,

        /// Include debug-level output and per-step timing table
        #[arg(short, long, conflicts_with_all = ["quiet", "no_progress"])]
        verbose: bool,

        /// Force plain-text progress (no spinners) even on a TTY
        #[arg(long, conflicts_with_all = ["quiet", "verbose"])]
        no_progress: bool,
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

    /// Maintenance window operations (for package manager hooks)
    Maintenance {
        #[command(subcommand)]
        action: MaintenanceAction,
    },

    /// Baseline operations
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Create and verify portable attestations of baseline state
    Attest {
        #[command(subcommand)]
        action: AttestAction,
    },

    /// Recover from a degraded daemon state
    Recover {
        /// Degraded reason to recover from (e.g. baseline_db_replaced)
        #[arg(long)]
        reason: Option<String>,

        /// List all known degraded reasons and their recovery procedures
        #[arg(long)]
        list: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Alert sink operations
    Alerts {
        #[command(subcommand)]
        action: AlertsAction,
    },

    /// Package manager hook operations
    Hooks {
        #[command(subcommand)]
        action: HooksAction,
    },

    /// Acknowledge historical events in doctor output
    Ack {
        /// Event kind to acknowledge: hooks, baseline-refresh, chain-break, retention, degraded
        kind: Option<String>,

        /// Acknowledge a specific audit record by sequence number
        #[arg(long)]
        sequence: Option<i64>,

        /// Attach an operator note to the acknowledgment
        #[arg(long)]
        note: Option<String>,

        /// Additional ack operations
        #[command(subcommand)]
        action: Option<AckAction>,
    },

    /// Print version
    Version,

    /// Generate shell completions for bash, zsh, or fish.
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
pub enum TestAction {
    /// Send a synthetic alert through all configured delivery channels
    Alert {
        /// Severity of the test alert
        #[arg(long, default_value = "info")]
        severity: Severity,
    },
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

        /// Show only acknowledgment records
        #[arg(long)]
        acknowledgments_only: bool,

        /// Show associated acknowledgments alongside event records
        #[arg(long)]
        with_acknowledgments: bool,
    },

    /// Show audit log statistics
    Stats {
        /// Time period: today, 24h, 7d, 30d, all (default: 7d)
        #[arg(long, default_value = "7d")]
        period: String,
    },

    /// Verify audit chain integrity
    Verify,

    /// List sealed audit segments
    Segments,

    /// Manually prune old entries with a checkpoint
    Prune {
        /// Prune entries older than this date (ISO 8601, e.g. '2025-01-01')
        #[arg(long)]
        before: String,

        /// Actually execute the prune (default is dry-run)
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show active configuration as TOML
    Show,

    /// Validate configuration
    Validate,

    /// Watch group operations
    Watch {
        #[command(subcommand)]
        action: ConfigWatchAction,
    },

    /// Set a configuration value
    Set {
        /// Dotted key path (e.g. daemon.detection_wal_persistent)
        key: String,
        /// Value to set (TOML literal: true, false, 42, "string")
        value: String,
        /// Show the resulting diff without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Get a configuration value
    Get {
        /// Dotted key path (e.g. daemon.detection_wal_persistent)
        key: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigWatchAction {
    /// Add a path to a watch group
    Add {
        /// Path to add to the watch group
        path: String,
        /// Watch group name (default: system_critical)
        #[arg(long, default_value = "system_critical")]
        group: String,
    },
    /// Remove a path from a watch group
    Remove {
        /// Path to remove from the watch group
        path: String,
        /// Watch group name (default: system_critical)
        #[arg(long, default_value = "system_critical")]
        group: String,
    },
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

    /// Generate attestation signing key
    Attest {
        /// Path to write the attestation key file
        #[arg(long, default_value = "/etc/vigil/attest.key")]
        key_path: PathBuf,

        /// Overwrite existing key file without prompting
        #[arg(long)]
        force: bool,
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

#[derive(Subcommand)]
pub enum MaintenanceAction {
    /// Enter maintenance window (suppress low-severity package alerts)
    Enter {
        /// Suppress output
        #[arg(long)]
        quiet: bool,
    },
    /// Exit maintenance window
    Exit {
        /// Suppress output
        #[arg(long)]
        quiet: bool,
    },
    /// Show current maintenance window status
    Status,
}

#[derive(Subcommand)]
pub enum BaselineAction {
    /// Refresh baseline from configured watch paths
    Refresh {
        /// Suppress output
        #[arg(long)]
        quiet: bool,
    },
}

#[derive(Subcommand)]
pub enum AttestAction {
    /// Create a signed attestation of the current baseline and audit state
    Create {
        /// Attestation scope: full, baseline-only, or head-only
        #[arg(long, default_value = "full")]
        scope: String,

        /// Output file path (defaults to ./vigil-attest-{timestamp}-{host}.vatt)
        #[arg(long)]
        out: Option<PathBuf>,

        /// Path to attestation signing key
        #[arg(long)]
        key_path: Option<PathBuf>,

        /// Pin wall-clock time for deterministic output (RFC 3339, testing only)
        #[arg(long, hide = true)]
        deterministic_time: Option<String>,
    },

    /// Verify an attestation file
    Verify {
        /// Path to the attestation file
        file: PathBuf,

        /// Path to attestation signing key for signature verification
        #[arg(long)]
        key_path: Option<PathBuf>,
    },

    /// Compare an attestation against the current baseline or another attestation
    Diff {
        /// Path to the attestation file
        file: PathBuf,

        /// Compare against: "current" (live baseline) or path to another .vatt file
        #[arg(long, default_value = "current")]
        against: String,
    },

    /// Display attestation contents
    Show {
        /// Path to the attestation file
        file: PathBuf,

        /// Show full entry listing
        #[arg(long)]
        verbose: bool,
    },

    /// List attestation files in a directory
    List {
        /// Directory to search (defaults to current directory)
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AlertsAction {
    /// Alert socket operations
    Socket {
        #[command(subcommand)]
        action: AlertsSocketAction,
    },
}

#[derive(Subcommand)]
pub enum AlertsSocketAction {
    /// Show alert socket configuration and listener status
    Status,

    /// Enable the alert socket sink
    Enable {
        /// Path for the Unix domain socket
        path: String,
    },

    /// Disable the alert socket sink
    Disable,
}

#[derive(Subcommand)]
pub enum HooksAction {
    /// Compare installed hooks against canonical versions
    Verify,

    /// Reinstall canonical hook scripts
    Repair,

    /// Disable package manager hook integration
    Disable,

    /// Enable package manager hook integration (alias for repair)
    Enable,

    /// Show hook installation and enablement status
    Status,
}

#[derive(Subcommand)]
pub enum AckAction {
    /// List pending unacknowledged events and recent acknowledgments
    List,

    /// Revoke a previous acknowledgment
    Revoke {
        /// Event kind: hooks, baseline-refresh, chain-break, retention, degraded
        kind: String,

        /// Sequence number of the acknowledgment to revoke
        #[arg(long)]
        sequence: Option<i64>,
    },

    /// Show full details of a specific acknowledgment record
    Show {
        /// Audit record sequence number
        sequence: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_force_flag_parses() {
        let cli = Cli::try_parse_from(["vigil", "init", "--force"]).expect("parse init --force");
        match cli.command {
            Some(Command::Init { force }) => assert!(force),
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn doctor_format_parses() {
        let cli = Cli::try_parse_from(["vigil", "doctor", "--format", "json"])
            .expect("parse doctor --format json");
        match cli.command {
            Some(Command::Doctor { format, .. }) => assert_eq!(format, Some(OutputFormat::Json)),
            _ => panic!("expected doctor command"),
        }
    }

    #[test]
    fn update_repo_parses() {
        let cli = Cli::try_parse_from(["vigil", "update", "--repo", "/opt/vigil"])
            .expect("parse update --repo");
        match cli.command {
            Some(Command::Update { repo, .. }) => {
                assert_eq!(repo, Some(PathBuf::from("/opt/vigil")));
            }
            _ => panic!("expected update command"),
        }
    }

    #[test]
    fn update_quiet_flag() {
        let cli =
            Cli::try_parse_from(["vigil", "update", "--quiet"]).expect("parse update --quiet");
        match cli.command {
            Some(Command::Update {
                quiet,
                verbose,
                no_progress,
                ..
            }) => {
                assert!(quiet);
                assert!(!verbose);
                assert!(!no_progress);
            }
            _ => panic!("expected update command"),
        }
    }

    #[test]
    fn update_verbose_flag() {
        let cli = Cli::try_parse_from(["vigil", "update", "-v"]).expect("parse update -v");
        match cli.command {
            Some(Command::Update {
                quiet,
                verbose,
                no_progress,
                ..
            }) => {
                assert!(!quiet);
                assert!(verbose);
                assert!(!no_progress);
            }
            _ => panic!("expected update command"),
        }
    }

    #[test]
    fn update_no_progress_flag() {
        let cli = Cli::try_parse_from(["vigil", "update", "--no-progress"])
            .expect("parse update --no-progress");
        match cli.command {
            Some(Command::Update {
                quiet,
                verbose,
                no_progress,
                ..
            }) => {
                assert!(!quiet);
                assert!(!verbose);
                assert!(no_progress);
            }
            _ => panic!("expected update command"),
        }
    }

    #[test]
    fn update_quiet_verbose_conflict() {
        let result = Cli::try_parse_from(["vigil", "update", "--quiet", "--verbose"]);
        assert!(result.is_err(), "--quiet and --verbose should conflict");
    }

    #[test]
    fn update_json_format() {
        let cli = Cli::try_parse_from(["vigil", "--format", "json", "update"])
            .expect("parse --format json update");
        assert_eq!(cli.format, OutputFormat::Json);
    }

    #[test]
    fn setup_hmac_parses_defaults() {
        let cli = Cli::try_parse_from(["vigil", "setup", "hmac"]).expect("parse setup hmac");
        match cli.command {
            Some(Command::Setup {
                action: SetupAction::Hmac { key_path, force },
            }) => {
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
            Some(Command::Setup {
                action: SetupAction::Hmac { key_path, force },
            }) => {
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
            Some(Command::Setup {
                action: SetupAction::Socket { path, disable },
            }) => {
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
            Some(Command::Setup {
                action: SetupAction::Socket { disable, .. },
            }) => {
                assert!(disable);
            }
            _ => panic!("expected setup socket command"),
        }
    }

    #[test]
    fn check_accept_flag_parses() {
        let cli = Cli::try_parse_from(["vigil", "check", "--accept"]).expect("parse");
        match cli.command {
            Some(Command::Check {
                accept,
                full,
                now,
                path,
                ..
            }) => {
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
            Some(Command::Check { accept, full, .. }) => {
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
            Some(Command::Diff { path }) => {
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
    fn check_dry_run_requires_accept() {
        let result = Cli::try_parse_from(["vigil", "check", "--dry-run"]);
        assert!(result.is_err(), "--dry-run without --accept should fail");
    }

    #[test]
    fn check_accept_filters_parse() {
        let cli = Cli::try_parse_from([
            "vigil",
            "check",
            "--accept",
            "--dry-run",
            "--accept-severity",
            "low",
            "--accept-group",
            "user_config",
        ])
        .expect("parse accept filters");

        match cli.command {
            Some(Command::Check {
                accept,
                dry_run,
                accept_severity,
                accept_group,
                ..
            }) => {
                assert!(accept);
                assert!(dry_run);
                assert_eq!(accept_severity, Some(Severity::Low));
                assert_eq!(accept_group.as_deref(), Some("user_config"));
            }
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn check_accept_with_path_parses() {
        let cli = Cli::try_parse_from(["vigil", "check", "--accept", "--path", "/usr/bin/vigil*"])
            .expect("parse");
        match cli.command {
            Some(Command::Check { accept, path, .. }) => {
                assert!(accept);
                assert_eq!(path, Some("/usr/bin/vigil*".to_string()));
            }
            _ => panic!("expected check command"),
        }
    }

    #[test]
    fn check_since_parses() {
        let cli = Cli::try_parse_from(["vigil", "check", "--since", "24h"]).expect("parse");
        match cli.command {
            Some(Command::Check { since, .. }) => {
                assert_eq!(since.as_deref(), Some("24h"));
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
            Some(Command::Audit {
                action:
                    AuditAction::Show {
                        last,
                        path,
                        severity,
                        since,
                        verbose,
                        ..
                    },
            }) => {
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
            Some(Command::Audit {
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
                        acknowledgments_only,
                        with_acknowledgments,
                    },
            }) => {
                assert_eq!(last, 50);
                assert!(path.is_none());
                assert!(severity.is_none());
                assert!(group.is_none());
                assert!(since.is_none());
                assert!(until.is_none());
                assert!(!maintenance);
                assert!(!suppressed);
                assert!(!verbose);
                assert!(!acknowledgments_only);
                assert!(!with_acknowledgments);
            }
            _ => panic!("expected audit show"),
        }
    }

    #[test]
    fn audit_stats_parses() {
        let cli =
            Cli::try_parse_from(["vigil", "audit", "stats", "--period", "30d"]).expect("parse");
        match cli.command {
            Some(Command::Audit {
                action: AuditAction::Stats { period },
            }) => {
                assert_eq!(period, "30d");
            }
            _ => panic!("expected audit stats"),
        }
    }

    #[test]
    fn audit_stats_default_period() {
        let cli = Cli::try_parse_from(["vigil", "audit", "stats"]).expect("parse");
        match cli.command {
            Some(Command::Audit {
                action: AuditAction::Stats { period },
            }) => {
                assert_eq!(period, "7d");
            }
            _ => panic!("expected audit stats"),
        }
    }

    #[test]
    fn maintenance_enter_quiet_parses() {
        let cli = Cli::try_parse_from(["vigil", "maintenance", "enter", "--quiet"])
            .expect("parse maintenance enter --quiet");
        match cli.command {
            Some(Command::Maintenance {
                action: MaintenanceAction::Enter { quiet },
            }) => assert!(quiet),
            _ => panic!("expected maintenance enter"),
        }
    }

    #[test]
    fn maintenance_exit_parses() {
        let cli =
            Cli::try_parse_from(["vigil", "maintenance", "exit"]).expect("parse maintenance exit");
        match cli.command {
            Some(Command::Maintenance {
                action: MaintenanceAction::Exit { quiet },
            }) => assert!(!quiet),
            _ => panic!("expected maintenance exit"),
        }
    }

    #[test]
    fn maintenance_status_parses() {
        let cli = Cli::try_parse_from(["vigil", "maintenance", "status"])
            .expect("parse maintenance status");
        match cli.command {
            Some(Command::Maintenance {
                action: MaintenanceAction::Status,
            }) => {}
            _ => panic!("expected maintenance status"),
        }
    }

    #[test]
    fn baseline_refresh_quiet_parses() {
        let cli = Cli::try_parse_from(["vigil", "baseline", "refresh", "--quiet"])
            .expect("parse baseline refresh --quiet");
        match cli.command {
            Some(Command::Baseline {
                action: BaselineAction::Refresh { quiet },
            }) => assert!(quiet),
            _ => panic!("expected baseline refresh"),
        }
    }

    #[test]
    fn baseline_refresh_parses() {
        let cli =
            Cli::try_parse_from(["vigil", "baseline", "refresh"]).expect("parse baseline refresh");
        match cli.command {
            Some(Command::Baseline {
                action: BaselineAction::Refresh { quiet },
            }) => assert!(!quiet),
            _ => panic!("expected baseline refresh"),
        }
    }

    #[test]
    fn setup_attest_parses_defaults() {
        let cli = Cli::try_parse_from(["vigil", "setup", "attest"]).expect("parse setup attest");
        match cli.command {
            Some(Command::Setup {
                action: SetupAction::Attest { key_path, force },
            }) => {
                assert_eq!(key_path, PathBuf::from("/etc/vigil/attest.key"));
                assert!(!force);
            }
            _ => panic!("expected setup attest command"),
        }
    }

    #[test]
    fn attest_create_parses_defaults() {
        let cli = Cli::try_parse_from(["vigil", "attest", "create"]).expect("parse attest create");
        match cli.command {
            Some(Command::Attest {
                action:
                    AttestAction::Create {
                        scope,
                        out,
                        key_path,
                        deterministic_time,
                    },
            }) => {
                assert_eq!(scope, "full");
                assert!(out.is_none());
                assert!(key_path.is_none());
                assert!(deterministic_time.is_none());
            }
            _ => panic!("expected attest create"),
        }
    }

    #[test]
    fn attest_verify_parses_with_key_path() {
        let cli = Cli::try_parse_from([
            "vigil",
            "attest",
            "verify",
            "sample.vatt",
            "--key-path",
            "/tmp/attest.key",
        ])
        .expect("parse attest verify");

        match cli.command {
            Some(Command::Attest {
                action: AttestAction::Verify { file, key_path },
            }) => {
                assert_eq!(file, PathBuf::from("sample.vatt"));
                assert_eq!(key_path, Some(PathBuf::from("/tmp/attest.key")));
            }
            _ => panic!("expected attest verify"),
        }
    }

    #[test]
    fn attest_diff_defaults_to_current() {
        let cli =
            Cli::try_parse_from(["vigil", "attest", "diff", "a.vatt"]).expect("parse attest diff");
        match cli.command {
            Some(Command::Attest {
                action: AttestAction::Diff { file, against },
            }) => {
                assert_eq!(file, PathBuf::from("a.vatt"));
                assert_eq!(against, "current");
            }
            _ => panic!("expected attest diff"),
        }
    }

    #[test]
    fn attest_list_default_dir() {
        let cli = Cli::try_parse_from(["vigil", "attest", "list"]).expect("parse attest list");
        match cli.command {
            Some(Command::Attest {
                action: AttestAction::List { dir },
            }) => {
                assert_eq!(dir, PathBuf::from("."));
            }
            _ => panic!("expected attest list"),
        }
    }

    #[test]
    fn ack_kind_short_form_parses() {
        let cli = Cli::try_parse_from(["vigil", "ack", "hooks"]).expect("parse ack hooks");
        match cli.command {
            Some(Command::Ack {
                kind,
                sequence,
                note,
                action,
            }) => {
                assert_eq!(kind.as_deref(), Some("hooks"));
                assert!(sequence.is_none());
                assert!(note.is_none());
                assert!(action.is_none());
            }
            _ => panic!("expected ack command"),
        }
    }

    #[test]
    fn ack_list_subcommand_parses() {
        let cli = Cli::try_parse_from(["vigil", "ack", "list"]).expect("parse ack list");
        match cli.command {
            Some(Command::Ack {
                kind,
                action: Some(AckAction::List),
                ..
            }) => {
                assert!(kind.is_none());
            }
            _ => panic!("expected ack list"),
        }
    }

    #[test]
    fn no_cli_flag_exists_to_blanket_suppress_a_category() {
        let bad_flags = ["--suppress", "--silence", "--ignore", "--blanket"];
        for flag in bad_flags {
            let result = Cli::try_parse_from(["vigil", "ack", "hooks", flag]);
            assert!(
                result.is_err(),
                "unexpectedly accepted forbidden ack flag: {}",
                flag
            );
        }
    }

    #[test]
    fn hooks_disable_enable_status_parse() {
        let d = Cli::try_parse_from(["vigil", "hooks", "disable"]).expect("parse hooks disable");
        match d.command {
            Some(Command::Hooks {
                action: HooksAction::Disable,
            }) => {}
            _ => panic!("expected hooks disable"),
        }

        let e = Cli::try_parse_from(["vigil", "hooks", "enable"]).expect("parse hooks enable");
        match e.command {
            Some(Command::Hooks {
                action: HooksAction::Enable,
            }) => {}
            _ => panic!("expected hooks enable"),
        }

        let s = Cli::try_parse_from(["vigil", "hooks", "status"]).expect("parse hooks status");
        match s.command {
            Some(Command::Hooks {
                action: HooksAction::Status,
            }) => {}
            _ => panic!("expected hooks status"),
        }
    }
}
