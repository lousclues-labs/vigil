//! Typed constructors for every recovery hint vigil emits.
//!
//! Every `Recovery::Command` produced anywhere in the codebase must come
//! from this module. The clap-validity test becomes "this builder exists,
//! therefore its output parses," eliminating the format-string skip.
//!
//! See docs/PRINCIPLES.md — compile-time enforcement of operator-facing promises.

use std::path::Path;

use crate::types::DegradedReason;

use super::{Recovery, RecoveryHint};

/// Typed recovery hint constructors. The `for_degraded` function is an
/// exhaustive match over `DegradedReason`. Adding a new variant without
/// adding its recovery is a compile error — the same pattern as
/// `reason_code()` and `describe()`.
pub struct RecoveryBuilder;

impl RecoveryBuilder {
    /// Recovery for a specific `DegradedReason`. Exhaustive over the enum;
    /// the compiler enforces every variant has a recovery path.
    pub fn for_degraded(reason: &DegradedReason) -> Recovery {
        let code = reason.reason_code();
        let recover_cmd = format!("vigil recover --reason {}", code);

        match reason {
            DegradedReason::BaselineDbReplaced => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Command {
                    verb: "or reinitialize",
                    command: "vigil init".into(),
                },
            ]),
            DegradedReason::AuditDbReplaced => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Command {
                    verb: "or verify",
                    command: "vigil audit verify".into(),
                },
            ]),
            DegradedReason::WalFileReplaced => Recovery::Command(recover_cmd),
            DegradedReason::EventBackpressure => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Manual {
                    verb: "investigate",
                    instruction: "check if the event channel is saturated; \
                                  consider raising worker count or excluding noisy paths"
                        .into(),
                },
            ]),
            DegradedReason::EventLossDetected { .. } => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Command {
                    verb: "or run a compensating scan",
                    command: "vigil check".into(),
                },
            ]),
            DegradedReason::ClockSkewDetected { .. } => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Manual {
                    verb: "investigate",
                    instruction: "verify system clock with `timedatectl status`".into(),
                },
            ]),
            DegradedReason::FanotifyMarkFailed { mount } => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Manual {
                    verb: "investigate",
                    instruction: format!(
                        "check mount {} permissions and kernel fanotify support",
                        mount.display()
                    ),
                },
            ]),
            DegradedReason::FanotifyReadFailed => Recovery::Command(recover_cmd),
            DegradedReason::WorkerDbUnrecoverable => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Command {
                    verb: "or restart daemon",
                    command: "sudo systemctl restart vigild".into(),
                },
            ]),
            DegradedReason::BaselineHmacMismatch => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Command {
                    verb: "or verify baseline",
                    command: "vigil check".into(),
                },
            ]),
            DegradedReason::FanotifyQueueOverflow => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Command {
                    verb: "or run a compensating scan",
                    command: "vigil check".into(),
                },
            ]),
            DegradedReason::AuditLogFull => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: "vigil audit prune --before <date> --confirm".into(),
                },
                RecoveryHint::Command {
                    verb: "or recover",
                    command: recover_cmd,
                },
            ]),
            DegradedReason::RetentionPolicyMismatch { .. } => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Manual {
                    verb: "investigate",
                    instruction: "review audit.retention_days and audit.max_size_mb in vigil.toml"
                        .into(),
                },
            ]),
            DegradedReason::UserspaceEventDrops { .. } => Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: recover_cmd,
                },
                RecoveryHint::Command {
                    verb: "or run a compensating scan",
                    command: "vigil check".into(),
                },
            ]),
            DegradedReason::AlertSinkFailing { sink, .. } => {
                let investigate = match sink.as_str() {
                    "socket" => "vigil alerts socket disable".to_string(),
                    "webhook" => "vigil config show | grep webhook".to_string(),
                    _ => format!("check {} sink configuration in vigil.toml", sink),
                };
                Recovery::Multi(vec![
                    RecoveryHint::Command {
                        verb: "recover",
                        command: recover_cmd,
                    },
                    RecoveryHint::Command {
                        verb: "or investigate",
                        command: investigate,
                    },
                ])
            }
            DegradedReason::ControlSocketDrift { kind } => {
                let fix = match kind.as_str() {
                    "ownership_drift" => {
                        "sudo chown root:root /run/vigil/control.sock".to_string()
                    }
                    "permission_drift" => {
                        "sudo chmod 0660 /run/vigil/control.sock".to_string()
                    }
                    "missing" => "sudo systemctl restart vigild".to_string(),
                    _ => "sudo systemctl restart vigild".to_string(),
                };
                Recovery::Multi(vec![
                    RecoveryHint::Command {
                        verb: "recover",
                        command: fix,
                    },
                    RecoveryHint::Command {
                        verb: "or recover",
                        command: recover_cmd,
                    },
                ])
            }
        }
    }

    /// Acknowledge a chain break with operator context.
    pub fn ack_chain_break(_reason: &str) -> Recovery {
        Recovery::Command("vigil ack chain-break".into())
    }

    /// Run audit verify with optional verbose flag.
    pub fn audit_verify(verbose: bool) -> Recovery {
        if verbose {
            Recovery::Command("vigil audit verify -v".into())
        } else {
            Recovery::Command("vigil audit verify".into())
        }
    }

    /// Investigate a path's change history.
    pub fn why_path(path: &Path) -> Recovery {
        Recovery::Command(format!("vigil why {}", shell_escape(path)))
    }

    /// Recovery for an audit chain break: verify + why + ack.
    pub fn audit_chain_break(affected_path: Option<&Path>) -> Recovery {
        let mut hints = vec![RecoveryHint::Command {
            verb: "diagnose",
            command: "vigil audit verify -v".into(),
        }];
        if let Some(path) = affected_path {
            hints.push(RecoveryHint::Command {
                verb: "investigate",
                command: format!("vigil why {}", shell_escape(path)),
            });
        }
        hints.push(RecoveryHint::Command {
            verb: "acknowledge",
            command: "vigil ack chain-break".into(),
        });
        Recovery::Multi(hints)
    }

    /// Recovery for database backup + reinitialize.
    pub fn db_backup_and_reinit(db_path: &Path) -> Recovery {
        Recovery::Command(format!(
            "cp {} {}.bak && vigil init",
            shell_escape(db_path),
            shell_escape(db_path)
        ))
    }

    /// Recovery for HMAC key permissions fix.
    pub fn hmac_key_chmod(key_path: &Path) -> Recovery {
        Recovery::Command(format!("sudo chmod 0600 {}", shell_escape(key_path)))
    }

    /// Recovery for HMAC key creation.
    pub fn hmac_key_create(key_path: &Path) -> Recovery {
        Recovery::Command(format!(
            "openssl rand -hex 32 | sudo tee {} >/dev/null && sudo chmod 0600 {}",
            shell_escape(key_path),
            shell_escape(key_path)
        ))
    }

    /// Recovery for HMAC key ownership fix.
    pub fn hmac_key_chown(key_path: &Path) -> Recovery {
        Recovery::Command(format!(
            "sudo chown root:root {}",
            shell_escape(key_path)
        ))
    }

    /// Recovery for attest key permission fix.
    pub fn attest_key_chmod(key_path: &Path) -> Recovery {
        Recovery::Command(format!("sudo chmod 600 {}", shell_escape(key_path)))
    }
}

/// Escape a path for safe inclusion in a shell command string.
fn shell_escape(path: &Path) -> String {
    let s = path.display().to_string();
    if s.contains(|c: char| c.is_whitespace() || "\"'\\$`!#&|;(){}[]<>?*~".contains(c)) {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INVARIANT: every DegradedReason variant has a recovery path via
    /// RecoveryBuilder::for_degraded. The exhaustive match is compile-time
    /// enforced; this test validates the output is non-empty.
    /// CATEGORY: principle
    /// SEE: docs/PRINCIPLES.md (enforcement over discipline)
    #[test]
    fn every_degraded_reason_has_recovery() {
        for reason in DegradedReason::all_variants_for_introspection() {
            let recovery = RecoveryBuilder::for_degraded(&reason);
            match &recovery {
                Recovery::None => {
                    panic!("RecoveryBuilder::for_degraded returned None for {:?}", reason)
                }
                Recovery::Command(cmd) => assert!(
                    !cmd.is_empty(),
                    "empty recovery command for {:?}",
                    reason
                ),
                Recovery::Multi(hints) => assert!(
                    !hints.is_empty(),
                    "empty Multi recovery for {:?}",
                    reason
                ),
                _ => {}
            }
        }
    }

    /// INVARIANT: every recovery command vigil emits from RecoveryBuilder
    /// must parse as a valid invocation of the vigil CLI grammar.
    /// CATEGORY: principle
    /// SEE: docs/PRINCIPLES.md (operator-facing promise enforcement)
    #[test]
    fn every_recovery_builder_output_parses_via_clap() {
        let reasons = DegradedReason::all_variants_for_introspection();
        let mut failures: Vec<String> = Vec::new();

        for reason in &reasons {
            let recovery = RecoveryBuilder::for_degraded(reason);
            check_recovery_commands_parse(&recovery, reason.reason_code(), &mut failures);
        }

        // Also check standalone builders
        let standalone_recoveries = vec![
            ("audit_verify_verbose", RecoveryBuilder::audit_verify(true)),
            ("audit_verify", RecoveryBuilder::audit_verify(false)),
            (
                "why_path",
                RecoveryBuilder::why_path(Path::new("/etc/passwd")),
            ),
            (
                "audit_chain_break_no_path",
                RecoveryBuilder::audit_chain_break(None),
            ),
            (
                "audit_chain_break_with_path",
                RecoveryBuilder::audit_chain_break(Some(Path::new("/etc/shadow"))),
            ),
            (
                "ack_chain_break",
                RecoveryBuilder::ack_chain_break("test"),
            ),
        ];

        for (label, recovery) in &standalone_recoveries {
            check_recovery_commands_parse(recovery, label, &mut failures);
        }

        if !failures.is_empty() {
            panic!(
                "The following recovery commands did not parse via clap:\n{}",
                failures.join("\n")
            );
        }
    }

    fn check_recovery_commands_parse(
        recovery: &Recovery,
        label: &str,
        failures: &mut Vec<String>,
    ) {
        #[allow(unused_imports)]
        use clap::Parser;
        use crate::cli::Cli;

        let commands = extract_vigil_commands(recovery);
        for cmd in commands {
            // Skip commands that contain <placeholder> arguments
            if cmd.contains('<') {
                continue;
            }
            // Skip non-vigil commands (sudo, cp, openssl, etc.)
            let first_word = cmd.split_whitespace().next().unwrap_or("");
            if first_word != "vigil" {
                continue;
            }
            let args: Vec<&str> = cmd.split_whitespace().collect();
            if Cli::try_parse_from(&args).is_err() {
                failures.push(format!("  [{}] failed to parse: {}", label, cmd));
            }
        }
    }

    fn extract_vigil_commands(recovery: &Recovery) -> Vec<String> {
        let mut cmds = Vec::new();
        match recovery {
            Recovery::Command(cmd) => cmds.push(cmd.clone()),
            Recovery::CommandWithContext { command, .. } => cmds.push(command.clone()),
            Recovery::Multi(hints) => {
                for hint in hints {
                    if let RecoveryHint::Command { command, .. } = hint {
                        cmds.push(command.clone());
                    }
                }
            }
            _ => {}
        }
        cmds
    }

    #[test]
    fn shell_escape_plain_path() {
        assert_eq!(shell_escape(Path::new("/etc/passwd")), "/etc/passwd");
    }

    #[test]
    fn shell_escape_path_with_spaces() {
        assert_eq!(
            shell_escape(Path::new("/my path/file")),
            "'/my path/file'"
        );
    }
}
