//! Diagnostic check implementations.';3dffb6d3-a1e0-4a9a-a909-fd2e52a52f20]633;C//! Diagnostic check implementations.
//!
//! Each function returns a `DiagnosticCheck` with status, detail, and recovery.

use std::fs;
use std::path::Path;

use chrono::Utc;

use crate::config::Config;
use crate::db::{self, audit_ops, baseline_ops};
use crate::types::PackageBackend;

use super::recovery::{
    acknowledged_hook_recovery, audit_chain_break_ack_state, baseline_refresh_ack_state,
    baseline_refresh_acknowledged_recovery, baseline_refresh_unacked_recovery,
    chain_break_acknowledged_recovery, chain_break_unacked_recovery, daemon_degraded_ack_state,
    daemon_degraded_acknowledged_recovery, daemon_degraded_unacked_recovery,
    hook_failure_ack_state, hooks_disabled_by_operator, retention_failure_ack_state,
    retention_failure_acknowledged_recovery, retention_failure_unacked_recovery,
    unacked_hook_recovery,
};
use super::recovery_builder::RecoveryBuilder;
use super::{
    audit_check_from_snapshot, baseline_check_from_snapshot, command_exists,
    database_check_from_snapshot, detect_active_config_path, format_age, format_compact_duration,
    format_count, format_next_timer_relative, format_relative_duration_from_timestamp, format_size,
    has_sqlite_read_access, hook_last_trigger_parsed, metrics_file_timestamp,
    monitor_backend_label, open_existing_db, probe_daemon, read_metrics, read_state_json,
    systemctl_is_active, systemctl_show, walk_data_dir_usage, CheckStatus, DaemonProbe,
    DiagnosticCheck, HookTriggerResult, Recovery, RecoveryHint,
};

pub(super) fn check_daemon(config: &Config) -> (DiagnosticCheck, DaemonProbe) {
    let probe = probe_daemon(config);

    if probe.running {
        let detail = match (probe.pid, probe.uptime_seconds) {
            (Some(pid), Some(uptime)) => {
                format!(
                    "running (pid {}, uptime {})",
                    pid,
                    format_compact_duration(uptime)
                )
            }
            (Some(pid), None) => format!("running (pid {})", pid),
            (None, Some(uptime)) => format!("running (uptime {})", format_compact_duration(uptime)),
            (None, None) => "running".to_string(),
        };

        (
            DiagnosticCheck {
                name: "Daemon".to_string(),
                status: CheckStatus::Ok,
                detail,
                recovery: Recovery::None,
            },
            probe,
        )
    } else {
        (
            DiagnosticCheck {
                name: "Daemon".to_string(),
                status: CheckStatus::Failed,
                detail: "not running".to_string(),
                recovery: Recovery::Command("sudo systemctl start vigild.service".into()),
            },
            probe,
        )
    }
}

pub(super) fn check_backend(config: &Config, daemon_running: bool) -> DiagnosticCheck {
    if !daemon_running {
        return DiagnosticCheck {
            name: "Backend".to_string(),
            status: CheckStatus::Unknown,
            detail: "unknown (daemon not running)".to_string(),
            recovery: Recovery::None,
        };
    }

    let backend = monitor_backend_label(config);
    if backend == "fanotify" {
        DiagnosticCheck {
            name: "Backend".to_string(),
            status: CheckStatus::Ok,
            detail: "fanotify (mount-wide coverage)".to_string(),
            recovery: Recovery::None,
        }
    } else {
        DiagnosticCheck {
            name: "Backend".to_string(),
            status: CheckStatus::Warning,
            detail: "inotify fallback (reduced coverage)".to_string(),
            recovery: Recovery::Manual(
                "grant CAP_SYS_ADMIN to the daemon for full fanotify coverage".into(),
            ),
        }
    }
}

/// Check whether real-time event coverage is degraded due to mount-mark
/// limitations on this kernel. When `fanotify_mark_reduced_coverage > 0`,
/// some mounts accepted only the reduced event mask (`FAN_MODIFY |
/// FAN_CLOSE_WRITE`), meaning create/delete/move/attribute changes are
/// not delivered in real time and must wait for the next scheduled scan.
///
/// This is informational — the operator cannot change their kernel from
/// the CLI. On FID-capable kernels (tier Fid or FidDfidName), this
/// counter stays at zero because `FAN_MARK_FILESYSTEM` accepts the full
/// event mask.
pub(super) fn check_realtime_coverage(config: &Config, daemon_running: bool) -> DiagnosticCheck {
    if !daemon_running {
        return DiagnosticCheck {
            name: "Real-time coverage".to_string(),
            status: CheckStatus::Unknown,
            detail: "unknown (daemon not running)".to_string(),
            recovery: Recovery::None,
        };
    }

    let metrics = read_metrics(config);
    let reduced = metrics
        .as_ref()
        .map(|m| m.fanotify_mark_reduced_coverage)
        .unwrap_or(0);
    let tier = metrics.as_ref().map(|m| m.fanotify_tier).unwrap_or(0);

    if reduced == 0 {
        let tier_label = match tier {
            3 => "fid_dfid_name",
            2 => "fid",
            1 => "legacy_fd",
            _ => "unknown",
        };
        DiagnosticCheck {
            name: "Real-time coverage".to_string(),
            status: CheckStatus::Ok,
            detail: format!("full event coverage on all mounts (tier: {})", tier_label),
            recovery: Recovery::None,
        }
    } else {
        DiagnosticCheck {
            name: "Real-time coverage".to_string(),
            status: CheckStatus::Warning,
            detail: format!(
                "{} mount(s) accepted only a reduced event mask; \
                 create/delete/move/attribute changes are backstopped \
                 by scheduled scans, not real-time events. \
                 This kernel does not support FID-tier fanotify, which \
                 would restore full real-time coverage.",
                reduced
            ),
            recovery: Recovery::Documentation("docs/ARCHITECTURE.md § Fanotify tier system".into()),
        }
    }
}

pub(super) fn check_baseline(config: &Config) -> DiagnosticCheck {
    let db_path = &config.daemon.db_path;
    if !db_path.exists() {
        return DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Failed,
            detail: format!("database not found at {}", db_path.display()),
            recovery: Recovery::Command("vigil init".into()),
        };
    }

    if !has_sqlite_read_access(db_path) {
        if let Some(check) = baseline_check_from_snapshot(config) {
            return check;
        }

        return DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Unknown,
            detail: format!(
                "database present at {} (insufficient permissions for current user)",
                db_path.display()
            ),
            recovery: Recovery::Command("sudo vigil doctor".into()),
        };
    }

    let conn = match open_existing_db(db_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Baseline".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open baseline database: {}", e),
                recovery: Recovery::Command("vigil init".into()),
            };
        }
    };

    let count = match baseline_ops::count(&conn) {
        Ok(c) => c,
        Err(e) => {
            return DiagnosticCheck {
                name: "Baseline".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot read baseline: {}", e),
                recovery: Recovery::Command("vigil init".into()),
            };
        }
    };

    if count <= 0 {
        return DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Failed,
            detail: "no baseline found (database empty)".to_string(),
            recovery: Recovery::Command("vigil init".into()),
        };
    }

    let last_refresh = baseline_ops::get_config_state(&conn, "last_baseline_refresh")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok());

    let count_label = format_count(count as u64);
    match last_refresh {
        Some(ts) => {
            let age = (Utc::now().timestamp() - ts).max(0);
            if age > 86_400 {
                if let Some(ack_state) = baseline_refresh_ack_state(config, ts) {
                    return DiagnosticCheck {
                        name: "Baseline".to_string(),
                        status: CheckStatus::Unknown,
                        detail: format!(
                            "{} entries (last refresh: {})",
                            count_label,
                            format_age(age)
                        ),
                        recovery: baseline_refresh_acknowledged_recovery(
                            ack_state.ack_timestamp,
                            ack_state.operator_uid,
                            ack_state.note,
                        ),
                    };
                }

                DiagnosticCheck {
                    name: "Baseline".to_string(),
                    status: CheckStatus::Warning,
                    detail: format!(
                        "{} entries (last refresh: {})",
                        count_label,
                        format_age(age)
                    ),
                    recovery: baseline_refresh_unacked_recovery(),
                }
            } else {
                DiagnosticCheck {
                    name: "Baseline".to_string(),
                    status: CheckStatus::Ok,
                    detail: format!(
                        "{} entries (last refresh: {})",
                        count_label,
                        format_age(age)
                    ),
                    recovery: Recovery::None,
                }
            }
        }
        None => DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Ok,
            detail: format!("{} entries (last refresh: unknown)", count_label),
            recovery: Recovery::None,
        },
    }
}

pub(super) fn check_database_integrity(config: &Config) -> DiagnosticCheck {
    let baseline_path = &config.daemon.db_path;
    let audit_path = db::audit_db_path(config);

    if !baseline_path.exists() {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("baseline database not found at {}", baseline_path.display()),
            recovery: Recovery::Command("vigil init".into()),
        };
    }

    if !audit_path.exists() {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("audit database not found at {}", audit_path.display()),
            recovery: Recovery::Command("vigil init".into()),
        };
    }

    let mut unreadable = Vec::new();
    if !has_sqlite_read_access(baseline_path) {
        unreadable.push(baseline_path.display().to_string());
    }
    if !has_sqlite_read_access(&audit_path) {
        unreadable.push(audit_path.display().to_string());
    }
    if !unreadable.is_empty() {
        if let Some(check) = database_check_from_snapshot(config) {
            return check;
        }

        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Unknown,
            detail: format!(
                "integrity check unavailable for current user (cannot read: {})",
                unreadable.join(", ")
            ),
            recovery: Recovery::Command("sudo vigil doctor".into()),
        };
    }

    let baseline_conn = match open_existing_db(baseline_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Database".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open baseline database: {}", e),
                recovery: RecoveryBuilder::db_backup_and_reinit(baseline_path),
            };
        }
    };

    if let Err(e) = db::integrity_check(&baseline_conn) {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("integrity check failed: {}", e),
            recovery: RecoveryBuilder::db_backup_and_reinit(baseline_path),
        };
    }

    let audit_conn = match open_existing_db(&audit_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Database".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open audit database: {}", e),
                recovery: RecoveryBuilder::db_backup_and_reinit(&audit_path),
            };
        }
    };

    if let Err(e) = db::integrity_check(&audit_conn) {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("integrity check failed: {}", e),
            recovery: RecoveryBuilder::db_backup_and_reinit(baseline_path),
        };
    }

    let wal_mode = baseline_conn
        .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
        .unwrap_or_else(|_| "unknown".to_string())
        .to_uppercase();

    let baseline_size = fs::metadata(baseline_path).map(|m| m.len()).unwrap_or(0);
    let audit_size = fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);
    let total_size = baseline_size + audit_size;

    DiagnosticCheck {
        name: "Database".to_string(),
        status: CheckStatus::Ok,
        detail: format!(
            "integrity OK ({} mode, {})",
            wal_mode,
            format_size(total_size)
        ),
        recovery: Recovery::None,
    }
}

pub(super) fn check_audit_log(config: &Config) -> DiagnosticCheck {
    let audit_path = db::audit_db_path(config);
    if !audit_path.exists() {
        return DiagnosticCheck {
            name: "Audit log".to_string(),
            status: CheckStatus::Failed,
            detail: format!("audit database not found at {}", audit_path.display()),
            recovery: Recovery::Command("vigil init".into()),
        };
    }

    if !has_sqlite_read_access(&audit_path) {
        if let Some(check) = audit_check_from_snapshot(config) {
            return check;
        }

        return DiagnosticCheck {
            name: "Audit log".to_string(),
            status: CheckStatus::Unknown,
            detail: format!(
                "audit log present at {} (insufficient permissions for current user)",
                audit_path.display()
            ),
            recovery: Recovery::Command("sudo vigil doctor".into()),
        };
    }

    let conn = match open_existing_db(&audit_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Audit log".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open audit database: {}", e),
                recovery: Recovery::Command("vigil audit verify".into()),
            };
        }
    };

    let total = conn
        .query_row("SELECT COUNT(*) FROM audit_log", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0)
        .max(0) as u64;

    match audit_ops::verify_chain(&conn) {
        Ok((_t, _valid, breaks, missing)) => {
            if !breaks.is_empty() {
                let first_break = breaks.first().map(|b| b.0).unwrap_or(0);
                let ack_state = audit_chain_break_ack_state(config, first_break);
                DiagnosticCheck {
                    name: "Audit log".to_string(),
                    status: CheckStatus::Warning,
                    detail: format!(
                        "tampered at entry {}; {} entries total. Save a copy of the audit DB, then run `vigil audit verify -v`.",
                        first_break,
                        format_count(total),
                    ),
                    recovery: match ack_state {
                        Some(ack) => chain_break_acknowledged_recovery(
                            ack.ack_timestamp,
                            ack.operator_uid,
                            ack.note,
                        ),
                        None => chain_break_unacked_recovery(),
                    },
                }
            } else if missing > 0 {
                DiagnosticCheck {
                    name: "Audit log".to_string(),
                    status: CheckStatus::Warning,
                    detail: format!(
                        "{} entries, chain intact, {} missing hashes",
                        format_count(total),
                        missing
                    ),
                    recovery: Recovery::Command("vigil audit verify".into()),
                }
            } else {
                DiagnosticCheck {
                    name: "Audit log".to_string(),
                    status: CheckStatus::Ok,
                    detail: format!("{} entries, chain intact, 0 breaks", format_count(total)),
                    recovery: Recovery::None,
                }
            }
        }
        Err(e) => DiagnosticCheck {
            name: "Audit log".to_string(),
            status: CheckStatus::Failed,
            detail: format!("verification failed: {}", e),
            recovery: Recovery::Command("vigil audit verify".into()),
        },
    }
}

pub(super) fn check_audit_retention(config: &Config) -> DiagnosticCheck {
    let audit_path = crate::db::audit_db_path(config);
    let conn = match rusqlite::Connection::open_with_flags(
        &audit_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(_) => {
            return DiagnosticCheck {
                name: "Audit retention".to_string(),
                status: CheckStatus::Warning,
                detail: "cannot open audit DB".to_string(),
                recovery: Recovery::Command("vigil audit verify".into()),
            };
        }
    };

    let db_size_bytes = crate::db::audit_ops::db_file_size(&conn).unwrap_or(0);
    let max_bytes = config.audit.max_size_bytes();
    let pct = if max_bytes > 0 {
        (db_size_bytes as f64 / max_bytes as f64 * 100.0) as u32
    } else {
        0
    };

    let retention_days = config.audit.retention_days;

    if pct >= 100 {
        let ack_state = retention_failure_ack_state(config, config.audit.max_size_mb as u64);
        DiagnosticCheck {
            name: "Audit retention".to_string(),
            status: CheckStatus::Failed,
            detail: format!(
                "audit DB at {} MB ({:.0}% of {} MB cap)",
                db_size_bytes / 1_048_576,
                pct,
                config.audit.max_size_mb
            ),
            recovery: match ack_state {
                Some(ack) => retention_failure_acknowledged_recovery(
                    ack.ack_timestamp,
                    ack.operator_uid,
                    ack.note,
                ),
                None => retention_failure_unacked_recovery(),
            },
        }
    } else if pct >= 90 {
        DiagnosticCheck {
            name: "Audit retention".to_string(),
            status: CheckStatus::Warning,
            detail: format!(
                "{}d retention; {}% of {} MB cap; approaching limit",
                retention_days, pct, config.audit.max_size_mb
            ),
            recovery: Recovery::Manual(
                "consider lowering audit.retention_days or raising audit.max_size_mb".into(),
            ),
        }
    } else {
        DiagnosticCheck {
            name: "Audit retention".to_string(),
            status: CheckStatus::Ok,
            detail: format!(
                "{}d retention; {}% of {} MB cap",
                retention_days, pct, config.audit.max_size_mb
            ),
            recovery: Recovery::None,
        }
    }
}

/// Check audit DB cap trajectory: warn when projected days-to-cap is below
/// the configured threshold (default 30 days).
pub(super) fn check_audit_trajectory(config: &Config) -> DiagnosticCheck {
    let audit_path = crate::db::audit_db_path(config);
    let conn = match rusqlite::Connection::open_with_flags(
        &audit_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(_) => {
            return DiagnosticCheck {
                name: "Audit trajectory".to_string(),
                status: CheckStatus::Unknown,
                detail: "cannot open audit DB".to_string(),
                recovery: Recovery::None,
            };
        }
    };

    let db_size_bytes = crate::db::audit_ops::db_file_size(&conn).unwrap_or(0) as u64;
    let max_bytes = config.audit.max_size_bytes();

    if max_bytes == 0 || db_size_bytes == 0 {
        return DiagnosticCheck {
            name: "Audit trajectory".to_string(),
            status: CheckStatus::Ok,
            detail: "insufficient data for projection".to_string(),
            recovery: Recovery::None,
        };
    }

    let total_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
        .unwrap_or(0);

    let recent_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp > unixepoch() - 7 * 86400",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if total_rows == 0 || recent_rows == 0 {
        return DiagnosticCheck {
            name: "Audit trajectory".to_string(),
            status: CheckStatus::Ok,
            detail: "insufficient data for projection".to_string(),
            recovery: Recovery::None,
        };
    }

    let bytes_per_row = db_size_bytes as f64 / total_rows as f64;
    let rows_per_day = recent_rows as f64 / 7.0;
    let bytes_per_day = rows_per_day * bytes_per_row;

    if bytes_per_day <= 0.0 {
        return DiagnosticCheck {
            name: "Audit trajectory".to_string(),
            status: CheckStatus::Ok,
            detail: "no measurable growth".to_string(),
            recovery: Recovery::None,
        };
    }

    let remaining_bytes = max_bytes.saturating_sub(db_size_bytes) as f64;
    let days_to_cap = (remaining_bytes / bytes_per_day) as u32;
    let threshold = config.audit.trajectory_warning_days;

    let pct = (db_size_bytes as f64 / max_bytes as f64 * 100.0) as u32;
    let mb_per_day = (bytes_per_day / 1_048_576.0) as u32;

    if days_to_cap < threshold {
        DiagnosticCheck {
            name: "Audit trajectory".to_string(),
            status: CheckStatus::Warning,
            detail: format!(
                "{}% of {} MB cap; ~{} MB/day growth; projected to reach cap in ~{} days",
                pct, config.audit.max_size_mb, mb_per_day, days_to_cap
            ),
            recovery: Recovery::Multi(vec![
                RecoveryHint::Manual {
                    verb: "options",
                    instruction:
                        "raise audit.max_size_mb or lower audit.retention_days in vigil.toml".into(),
                },
                RecoveryHint::Command {
                    verb: "investigate",
                    command: "vigil audit stats --period 30d".into(),
                },
            ]),
        }
    } else {
        DiagnosticCheck {
            name: "Audit trajectory".to_string(),
            status: CheckStatus::Ok,
            detail: format!(
                "{}% of {} MB cap; ~{} MB/day growth; ~{} days to cap",
                pct, config.audit.max_size_mb, mb_per_day, days_to_cap
            ),
            recovery: Recovery::None,
        }
    }
}

pub(super) fn check_config(config: &Config) -> DiagnosticCheck {
    let config_path = detect_active_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/etc/vigil/vigil.toml".to_string());

    if let Err(e) = crate::config::validate_config(config) {
        return DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Failed,
            detail: format!("invalid: {}", e),
            recovery: Recovery::Command("vigil config validate".into()),
        };
    }

    match crate::config::validate_config_deep(config) {
        Ok(warnings) if warnings.is_empty() => DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Ok,
            detail: format!("valid ({})", config_path),
            recovery: Recovery::None,
        },
        Ok(warnings) => DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Warning,
            detail: format!("valid ({}) with {} warnings", config_path, warnings.len()),
            recovery: Recovery::Command("vigil config validate".into()),
        },
        Err(e) => DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Failed,
            detail: format!("invalid: {}", e),
            recovery: Recovery::Command("vigil config validate".into()),
        },
    }
}

pub(super) fn check_scan_timer(config: &Config) -> DiagnosticCheck {
    if !command_exists("systemctl") {
        return DiagnosticCheck {
            name: "Scan timer".to_string(),
            status: CheckStatus::Warning,
            detail: "timer not found".to_string(),
            recovery: Recovery::Command("sudo systemctl enable --now vigil-scan.timer".into()),
        };
    }

    let load_state = systemctl_show("vigil-scan.timer", "LoadState").unwrap_or_default();
    if load_state.trim() == "not-found" || load_state.trim().is_empty() {
        return DiagnosticCheck {
            name: "Scan timer".to_string(),
            status: CheckStatus::Warning,
            detail: "timer not found".to_string(),
            recovery: Recovery::Command("sudo systemctl enable --now vigil-scan.timer".into()),
        };
    }

    let active = systemctl_is_active("vigil-scan.timer") == Some(true);
    if !active {
        return DiagnosticCheck {
            name: "Scan timer".to_string(),
            status: CheckStatus::Warning,
            detail: "timer inactive".to_string(),
            recovery: Recovery::Command("sudo systemctl start vigil-scan.timer".into()),
        };
    }

    let next_raw = systemctl_show("vigil-scan.timer", "NextElapseUSecRealtime")
        .unwrap_or_else(|| "unknown".to_string());
    let next = format_next_timer_relative(&next_raw);
    let metrics = read_metrics(config);
    let last_scan_total = metrics.as_ref().map(|m| m.last_scan_total).unwrap_or(0);
    let last_scan = metrics_file_timestamp(config)
        .map(format_relative_duration_from_timestamp)
        .unwrap_or_else(|| "unknown".to_string());

    DiagnosticCheck {
        name: "Scan timer".to_string(),
        status: CheckStatus::Ok,
        detail: format!(
            "active (next scan {}; previous scan {} found {} changes)",
            next, last_scan, last_scan_total
        ),
        recovery: Recovery::None,
    }
}

pub(super) fn check_hmac_key(config: &Config) -> DiagnosticCheck {
    if !config.security.hmac_signing {
        return DiagnosticCheck {
            name: "HMAC signing".to_string(),
            status: CheckStatus::Warning,
            detail: "disabled — chain integrity verifiable but authenticity is not. \
                     An attacker with write access to audit.db could forge a \
                     self-consistent chain."
                .to_string(),
            recovery: Recovery::Command("sudo vigil setup hmac".to_string()),
        };
    }

    let key_path = &config.security.hmac_key_path;
    if !key_path.exists() {
        return DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Failed,
            detail: format!("not found at {}", key_path.display()),
            recovery: RecoveryBuilder::hmac_key_create(key_path),
        };
    }

    let issues = crate::hmac::validate_hmac_key_doctor(key_path);
    if issues.is_empty() {
        let meta = fs::metadata(key_path).ok();
        let (mode, owner) = match meta {
            Some(m) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let mode = m.permissions().mode() & 0o777;
                    let owner = if m.uid() == 0 {
                        "root-owned"
                    } else {
                        "non-root owner"
                    };
                    (format!("{:04o}", mode), owner.to_string())
                }
                #[cfg(not(unix))]
                {
                    ("unknown".to_string(), "owner unknown".to_string())
                }
            }
            None => ("unknown".to_string(), "owner unknown".to_string()),
        };

        return DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Ok,
            detail: format!("present, permissions {}, {}", mode, owner),
            recovery: Recovery::None,
        };
    }

    let joined = issues.join("; ");
    if joined.contains("permissions") {
        DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Warning,
            detail: joined,
            recovery: RecoveryBuilder::hmac_key_chmod(key_path),
        }
    } else if joined.contains("Cannot stat") {
        DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Failed,
            detail: joined,
            recovery: RecoveryBuilder::hmac_key_create(key_path),
        }
    } else {
        DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Warning,
            detail: joined,
            recovery: RecoveryBuilder::hmac_key_chown(key_path),
        }
    }
}

pub(super) fn check_attest_key() -> DiagnosticCheck {
    let search_paths = crate::attest::key::attest_key_search_paths();
    let found = search_paths.iter().find(|p| p.exists());

    match found {
        None => DiagnosticCheck {
            name: "Attest key".to_string(),
            status: CheckStatus::Unknown,
            detail: "not configured (optional; needed for `vigil attest`)".to_string(),
            recovery: Recovery::Command("sudo vigil setup attest".into()),
        },
        Some(key_path) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                match fs::metadata(key_path) {
                    Ok(meta) => {
                        let mode = meta.permissions().mode() & 0o777;
                        let mut issues = Vec::new();

                        if mode & 0o077 != 0 {
                            issues.push(format!("permissions {:04o} (should be 0600)", mode));
                        }

                        let key_in_etc = key_path.starts_with("/etc/");
                        if key_in_etc && meta.uid() != 0 {
                            issues.push(format!(
                                "owner uid {} (expected root for /etc key)",
                                meta.uid()
                            ));
                        }

                        let size = meta.len();
                        if size != 33 {
                            issues.push(format!("unexpected size {} bytes", size));
                        }

                        if issues.is_empty() {
                            let owner = if meta.uid() == 0 {
                                "root-owned"
                            } else {
                                "non-root owner"
                            };
                            DiagnosticCheck {
                                name: "Attest key".to_string(),
                                status: CheckStatus::Ok,
                                detail: format!(
                                    "present at {}, permissions {:04o}, {}",
                                    key_path.display(),
                                    mode,
                                    owner
                                ),
                                recovery: Recovery::None,
                            }
                        } else {
                            DiagnosticCheck {
                                name: "Attest key".to_string(),
                                status: CheckStatus::Warning,
                                detail: format!("{}: {}", key_path.display(), issues.join("; ")),
                                recovery: RecoveryBuilder::attest_key_chmod(key_path),
                            }
                        }
                    }
                    Err(e) => DiagnosticCheck {
                        name: "Attest key".to_string(),
                        status: CheckStatus::Failed,
                        detail: format!("cannot stat {}: {}", key_path.display(), e),
                        recovery: Recovery::Command("sudo vigil setup attest".into()),
                    },
                }
            }
            #[cfg(not(unix))]
            {
                DiagnosticCheck {
                    name: "Attest key".to_string(),
                    status: CheckStatus::Ok,
                    detail: format!("present at {}", key_path.display()),
                    recovery: Recovery::None,
                }
            }
        }
    }
}

pub(super) fn check_package_hooks(config: &Config) -> DiagnosticCheck {
    let hooks_disabled = hooks_disabled_by_operator(config);
    match crate::package::detect_backend() {
        PackageBackend::Pacman => {
            let pre = Path::new("/etc/pacman.d/hooks/vigil-pre.hook").exists();
            let post = Path::new("/etc/pacman.d/hooks/vigil-post.hook").exists();
            if pre && post {
                let trigger = hook_last_trigger_parsed("vigil-pacman");
                let (status, detail, recovery) = match trigger {
                    HookTriggerResult::NeverTriggered => (
                        CheckStatus::Ok,
                        "installed (pacman pre/post); never triggered".to_string(),
                        Recovery::None,
                    ),
                    HookTriggerResult::Success(ts) => (
                        CheckStatus::Ok,
                        format!("installed (pacman pre/post); last trigger {} ok", ts),
                        Recovery::None,
                    ),
                    HookTriggerResult::Failure(ts, _tag) => {
                        if let Some(ack_state) = hook_failure_ack_state(config, "pacman", &ts) {
                            (
                                CheckStatus::Unknown,
                                format!("installed (pacman pre/post); last trigger {} failed", ts,),
                                acknowledged_hook_recovery(
                                    ack_state.ack_timestamp,
                                    ack_state.operator_uid,
                                    ack_state.note,
                                    "journalctl -t vigil-pacman",
                                ),
                            )
                        } else {
                            (
                                CheckStatus::Warning,
                                format!("installed (pacman pre/post); last trigger {} failed", ts,),
                                unacked_hook_recovery("journalctl -t vigil-pacman"),
                            )
                        }
                    }
                    HookTriggerResult::Unknown => (
                        CheckStatus::Ok,
                        "installed (pacman pre/post)".to_string(),
                        Recovery::None,
                    ),
                };
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status,
                    detail,
                    recovery,
                }
            } else {
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status: CheckStatus::Unknown,
                    detail: if hooks_disabled {
                        "disabled (no hooks installed)".to_string()
                    } else {
                        "not installed".to_string()
                    },
                    recovery: if hooks_disabled {
                        Recovery::Command("vigil hooks enable".into())
                    } else {
                        Recovery::Command("vigil hooks repair".into())
                    },
                }
            }
        }
        PackageBackend::Dpkg => {
            let apt_hook = Path::new("/etc/apt/apt.conf.d/99vigil").exists();
            if apt_hook {
                let trigger = hook_last_trigger_parsed("vigil-apt");
                let (status, detail, recovery) = match trigger {
                    HookTriggerResult::NeverTriggered => (
                        CheckStatus::Ok,
                        "installed (apt hook); never triggered".to_string(),
                        Recovery::None,
                    ),
                    HookTriggerResult::Success(ts) => (
                        CheckStatus::Ok,
                        format!("installed (apt hook); last trigger {} ok", ts),
                        Recovery::None,
                    ),
                    HookTriggerResult::Failure(ts, _tag) => {
                        if let Some(ack_state) = hook_failure_ack_state(config, "apt", &ts) {
                            (
                                CheckStatus::Unknown,
                                format!("installed (apt hook); last trigger {} failed", ts,),
                                acknowledged_hook_recovery(
                                    ack_state.ack_timestamp,
                                    ack_state.operator_uid,
                                    ack_state.note,
                                    "journalctl -t vigil-apt",
                                ),
                            )
                        } else {
                            (
                                CheckStatus::Warning,
                                format!("installed (apt hook); last trigger {} failed", ts,),
                                unacked_hook_recovery("journalctl -t vigil-apt"),
                            )
                        }
                    }
                    HookTriggerResult::Unknown => (
                        CheckStatus::Ok,
                        "installed (apt hook)".to_string(),
                        Recovery::None,
                    ),
                };
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status,
                    detail,
                    recovery,
                }
            } else {
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status: CheckStatus::Unknown,
                    detail: if hooks_disabled {
                        "disabled (no hooks installed)".to_string()
                    } else {
                        "not installed".to_string()
                    },
                    recovery: if hooks_disabled {
                        Recovery::Command("vigil hooks enable".into())
                    } else {
                        Recovery::Command("vigil hooks repair".into())
                    },
                }
            }
        }
        PackageBackend::Rpm => DiagnosticCheck {
            name: "Hooks".to_string(),
            status: CheckStatus::Unknown,
            detail: "rpm detected (no native hook template bundled)".to_string(),
            recovery: Recovery::None,
        },
        PackageBackend::Auto => DiagnosticCheck {
            name: "Hooks".to_string(),
            status: CheckStatus::Unknown,
            detail: "no supported package manager detected".to_string(),
            recovery: Recovery::None,
        },
    }
}

pub(super) fn check_notify_send() -> DiagnosticCheck {
    if command_exists("notify-send") {
        DiagnosticCheck {
            name: "Notify".to_string(),
            status: CheckStatus::Ok,
            detail: "notify-send available".to_string(),
            recovery: Recovery::None,
        }
    } else {
        let (recovery, cmd_str) = match crate::package::detect_backend() {
            PackageBackend::Pacman => (true, "sudo pacman -S --needed libnotify"),
            PackageBackend::Dpkg => (true, "sudo apt-get install -y libnotify-bin"),
            PackageBackend::Rpm => (true, "sudo dnf install -y libnotify"),
            PackageBackend::Auto => (false, "install libnotify for your distribution"),
        };

        DiagnosticCheck {
            name: "Notify".to_string(),
            status: CheckStatus::Warning,
            detail: "notify-send not found (desktop notifications disabled)".to_string(),
            recovery: if recovery {
                Recovery::Command(cmd_str.into())
            } else {
                Recovery::Manual(cmd_str.into())
            },
        }
    }
}

pub(super) fn check_signal_socket(config: &Config) -> DiagnosticCheck {
    let socket_path = config.hooks.signal_socket.trim();
    if socket_path.is_empty() {
        return DiagnosticCheck {
            name: "Socket".to_string(),
            status: CheckStatus::Unknown,
            detail: "not configured (optional alert sink)".to_string(),
            recovery: Recovery::None,
        };
    }

    let path = Path::new(socket_path);
    if !path.exists() {
        return DiagnosticCheck {
            name: "Socket".to_string(),
            status: CheckStatus::Failed,
            detail: "configured but no listener; alerts to this sink are dropped".to_string(),
            recovery: Recovery::Multi(vec![
                RecoveryHint::Command {
                    verb: "recover",
                    command: "vigil alerts socket disable".into(),
                },
                RecoveryHint::Manual {
                    verb: "or attach",
                    instruction: format!("a listener at {}", socket_path),
                },
            ]),
        };
    }

    DiagnosticCheck {
        name: "Socket".to_string(),
        status: CheckStatus::Ok,
        detail: format!("configured at {}", path.display()),
        recovery: Recovery::None,
    }
}

pub(super) fn check_control_socket(config: &Config) -> DiagnosticCheck {
    if config.daemon.control_socket.as_os_str().is_empty() {
        return DiagnosticCheck {
            name: "Control".into(),
            status: CheckStatus::Unknown,
            detail: "not configured (optional)".into(),
            recovery: Recovery::None,
        };
    }

    let socket_path = &config.daemon.control_socket;
    if !socket_path.exists() {
        return DiagnosticCheck {
            name: "Control".into(),
            status: CheckStatus::Warning,
            detail: format!(
                "{} does not exist (daemon not running?)",
                socket_path.display()
            ),
            recovery: Recovery::Command("sudo systemctl start vigild".into()),
        };
    }

    match query_control_socket_quick(socket_path, &config.security) {
        Ok(_) => DiagnosticCheck {
            name: "Control".into(),
            status: CheckStatus::Ok,
            detail: format!("responding ({})", socket_path.display()),
            recovery: Recovery::None,
        },
        Err(e) => DiagnosticCheck {
            name: "Control".into(),
            status: CheckStatus::Warning,
            detail: format!("socket exists but not responding: {}", e),
            recovery: Recovery::Command("sudo systemctl restart vigild".into()),
        },
    }
}

/// Check internal daemon state (healthy/degraded) from state.json.
pub(super) fn check_daemon_state(config: &Config, daemon_running: bool) -> DiagnosticCheck {
    if !daemon_running {
        return DiagnosticCheck {
            name: "State".into(),
            status: CheckStatus::Unknown,
            detail: "unknown (daemon not running)".into(),
            recovery: Recovery::None,
        };
    }

    match read_state_json(config) {
        Some(state) => {
            let status_str = state
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            match status_str {
                "healthy" => DiagnosticCheck {
                    name: "State".into(),
                    status: CheckStatus::Ok,
                    detail: "healthy".into(),
                    recovery: Recovery::None,
                },
                "degraded" => {
                    let reason = state
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let since_raw = state
                        .get("since")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let since = state
                        .get("since")
                        .and_then(|v| v.as_str())
                        .map(|s| format!(" (since {})", s))
                        .unwrap_or_default();
                    let ack_state = daemon_degraded_ack_state(config, reason, since_raw);
                    DiagnosticCheck {
                        name: "State".into(),
                        status: CheckStatus::Failed,
                        detail: format!("degraded: {}{}", reason, since),
                        recovery: match ack_state {
                            Some(ack) => daemon_degraded_acknowledged_recovery(
                                reason,
                                ack.ack_timestamp,
                                ack.operator_uid,
                                ack.note,
                            ),
                            None => daemon_degraded_unacked_recovery(reason),
                        },
                    }
                }
                _ => DiagnosticCheck {
                    name: "State".into(),
                    status: CheckStatus::Warning,
                    detail: format!("unrecognized state: {}", status_str),
                    recovery: Recovery::None,
                },
            }
        }
        None => DiagnosticCheck {
            name: "State".into(),
            status: CheckStatus::Unknown,
            detail: "state.json not available".into(),
            recovery: Recovery::None,
        },
    }
}

/// Check WAL pipeline health from metrics.json.
pub(super) fn check_wal_pipeline(config: &Config, daemon_running: bool) -> DiagnosticCheck {
    if !daemon_running {
        return DiagnosticCheck {
            name: "WAL pipeline".into(),
            status: CheckStatus::Unknown,
            detail: "unknown (daemon not running)".into(),
            recovery: Recovery::None,
        };
    }

    if !config.daemon.detection_wal {
        return DiagnosticCheck {
            name: "WAL pipeline".into(),
            status: CheckStatus::Unknown,
            detail: "disabled".into(),
            recovery: Recovery::None,
        };
    }

    let metrics_path = config.daemon.runtime_dir.join("metrics.json");
    let raw = match fs::read_to_string(&metrics_path) {
        Ok(r) => r,
        Err(_) => {
            return DiagnosticCheck {
                name: "WAL pipeline".into(),
                status: CheckStatus::Unknown,
                detail: "metrics.json not available".into(),
                recovery: Recovery::None,
            };
        }
    };

    let snap: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            return DiagnosticCheck {
                name: "WAL pipeline".into(),
                status: CheckStatus::Warning,
                detail: "metrics.json unreadable".into(),
                recovery: Recovery::None,
            };
        }
    };

    let pending = snap
        .get("detections_wal_pending")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let bytes = snap
        .get("detections_wal_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let backpressure = snap
        .get("backpressure_events")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let detail = format!(
        "{} pending ({}), backpressure events: {}",
        pending,
        format_size(bytes),
        backpressure
    );

    if pending > 10_000 {
        DiagnosticCheck {
            name: "WAL pipeline".into(),
            status: CheckStatus::Failed,
            detail,
            recovery: Recovery::Command("vigil doctor --verbose".into()),
        }
    } else if pending > 1_000 {
        DiagnosticCheck {
            name: "WAL pipeline".into(),
            status: CheckStatus::Warning,
            detail,
            recovery: Recovery::None,
        }
    } else {
        DiagnosticCheck {
            name: "WAL pipeline".into(),
            status: CheckStatus::Ok,
            detail,
            recovery: Recovery::None,
        }
    }
}

/// Check data directory disk space.
pub(super) fn check_storage(config: &Config) -> DiagnosticCheck {
    let data_dir = config
        .daemon
        .db_path
        .parent()
        .unwrap_or(std::path::Path::new("/var/lib/vigil"));

    // Walk the data directory to compute vigil's actual usage.
    let usage = walk_data_dir_usage(data_dir);

    // Get filesystem capacity from statvfs.
    let fs_line = match nix::sys::statvfs::statvfs(data_dir) {
        Ok(stat) => {
            let total = stat.blocks() * stat.fragment_size();
            let free = stat.blocks_available() * stat.fragment_size();
            let pct_free = if total > 0 {
                (free as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            Some((free, total, pct_free))
        }
        Err(_) => None,
    };

    match (&usage, &fs_line) {
        (Ok(du), Some((free, total, pct_free))) => {
            let detail = format!(
                "{} used ({})\n    {:<14}   filesystem: {} free of {} ({:.1}% free)",
                format_size(du.total),
                du.breakdown_string(),
                "",
                format_size(*free),
                format_size(*total),
                pct_free,
            );

            if *pct_free < 5.0 {
                DiagnosticCheck {
                    name: "Data dir".into(),
                    status: CheckStatus::Failed,
                    detail,
                    recovery: Recovery::Manual("free space in the data directory; baseline refresh will be refused below 5% free".into()),
                }
            } else if *pct_free < 10.0 {
                DiagnosticCheck {
                    name: "Data dir".into(),
                    status: CheckStatus::Warning,
                    detail,
                    recovery: Recovery::None,
                }
            } else {
                DiagnosticCheck {
                    name: "Data dir".into(),
                    status: CheckStatus::Ok,
                    detail,
                    recovery: Recovery::None,
                }
            }
        }
        (Ok(du), None) => DiagnosticCheck {
            name: "Data dir".into(),
            status: CheckStatus::Ok,
            detail: format!(
                "{} used ({})\n    {:<14}   filesystem: cannot stat",
                format_size(du.total),
                du.breakdown_string(),
                "",
            ),
            recovery: Recovery::None,
        },
        (Err(walk_err), Some((free, total, pct_free))) => {
            let detail = format!(
                "usage unknown ({})\n    {:<14}   filesystem: {} free of {} ({:.1}% free)",
                walk_err,
                "",
                format_size(*free),
                format_size(*total),
                pct_free,
            );

            if *pct_free < 5.0 {
                DiagnosticCheck {
                    name: "Data dir".into(),
                    status: CheckStatus::Failed,
                    detail,
                    recovery: Recovery::Manual("free space in the data directory; baseline refresh will be refused below 5% free".into()),
                }
            } else {
                DiagnosticCheck {
                    name: "Data dir".into(),
                    status: CheckStatus::Warning,
                    detail,
                    recovery: Recovery::None,
                }
            }
        }
        (Err(walk_err), None) => DiagnosticCheck {
            name: "Data dir".into(),
            status: CheckStatus::Unknown,
            detail: format!("{} (cannot stat filesystem)", walk_err),
            recovery: Recovery::None,
        },
    }
}

pub(super) fn query_control_socket_quick(
    socket_path: &Path,
    security: &crate::config::SecurityConfig,
) -> std::result::Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path).map_err(|e| format!("connect failed: {}", e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set timeout: {}", e))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set timeout: {}", e))?;

    let auth_enabled = security.hmac_signing && security.control_socket_auth;

    if auth_enabled {
        // Authenticated mode: read challenge, compute HMAC, send authenticated request.
        let mut reader = BufReader::new(&stream);
        let mut challenge_line = String::new();
        reader
            .read_line(&mut challenge_line)
            .map_err(|e| format!("read challenge: {}", e))?;

        let challenge: serde_json::Value = serde_json::from_str(challenge_line.trim())
            .map_err(|e| format!("parse challenge: {}", e))?;
        let nonce = challenge
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or("server did not send a challenge nonce")?;

        let key = crate::hmac::load_hmac_key(&security.hmac_key_path)
            .map_err(|e| format!("load HMAC key: {}", e))?;
        let hmac_response = crate::hmac::compute_hmac(&key, nonce.as_bytes())
            .map_err(|e| format!("compute HMAC: {}", e))?;

        let auth_request = serde_json::json!({
            "method": "status",
            "response": hmac_response,
        });

        drop(reader);
        let mut req_str =
            serde_json::to_string(&auth_request).map_err(|e| format!("serialize: {}", e))?;
        req_str.push('\n');
        (&stream)
            .write_all(req_str.as_bytes())
            .map_err(|e| format!("write: {}", e))?;
        (&stream).flush().map_err(|e| format!("flush: {}", e))?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .map_err(|e| format!("read: {}", e))?;

        let value: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("parse: {}", e))?;
        if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            Ok(())
        } else {
            let err_msg = value
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error");
            Err(format!("status error: {}", err_msg))
        }
    } else {
        // Unauthenticated mode: send request, read response.
        writeln!(&stream, r#"{{"method":"status"}}"#).map_err(|e| format!("write: {}", e))?;
        (&stream).flush().map_err(|e| format!("flush: {}", e))?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .map_err(|e| format!("read: {}", e))?;

        let value: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("parse: {}", e))?;
        if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            Ok(())
        } else {
            Err("status returned ok=false".into())
        }
    }
}
