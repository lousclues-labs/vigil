use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;

use chrono::{Local, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::db::{self, audit_ops, baseline_ops};
use crate::types::PackageBackend;

const HEALTH_SNAPSHOT_MAX_AGE_SECS: i64 = 300;

/// Result of a single diagnostic check.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    pub fix: Option<String>,
}

/// Health status for a single diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warning,
    Failed,
    Unknown,
}

impl CheckStatus {
    /// Symbol used in human output.
    pub fn marker(self) -> &'static str {
        match self {
            CheckStatus::Ok => "●",
            CheckStatus::Warning => "⚠",
            CheckStatus::Failed => "✗",
            CheckStatus::Unknown => "○",
        }
    }
}

/// Runtime daemon probe information used by doctor and status commands.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DaemonProbe {
    pub running: bool,
    pub pid: Option<i32>,
    pub uptime_seconds: Option<i64>,
    pub systemd_active: Option<bool>,
}

/// Parsed metrics snapshot persisted by the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeMetrics {
    #[serde(default)]
    pub changes_detected: u64,
    #[serde(default)]
    pub last_scan_total: u64,
    #[serde(default)]
    pub scan_duration_ms: u64,
    #[serde(default)]
    pub uptime_start: i64,
}

/// Lightweight health snapshot produced by the privileged daemon.
/// This lets unprivileged CLI invocations report useful state without direct DB access.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeHealthSnapshot {
    #[serde(default)]
    pub generated_at: i64,
    #[serde(default)]
    pub baseline: BaselineHealthSnapshot,
    #[serde(default)]
    pub database: DatabaseHealthSnapshot,
    #[serde(default)]
    pub audit: AuditHealthSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BaselineHealthSnapshot {
    #[serde(default)]
    pub entry_count: Option<i64>,
    #[serde(default)]
    pub last_refresh: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DatabaseHealthSnapshot {
    #[serde(default)]
    pub baseline_open: bool,
    #[serde(default)]
    pub audit_open: bool,
    #[serde(default)]
    pub journal_mode: Option<String>,
    #[serde(default)]
    pub total_size_bytes: u64,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditHealthSnapshot {
    #[serde(default)]
    pub entry_count: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Read metrics snapshot from runtime dir.
pub fn read_metrics(config: &Config) -> Option<RuntimeMetrics> {
    let raw = fs::read_to_string(metrics_path(config)).ok()?;
    serde_json::from_str::<RuntimeMetrics>(&raw).ok()
}

/// Read daemon state json from runtime dir.
pub fn read_state_json(config: &Config) -> Option<serde_json::Value> {
    let raw = fs::read_to_string(state_path(config)).ok()?;
    serde_json::from_str::<serde_json::Value>(&raw).ok()
}

/// Read daemon health snapshot from runtime dir.
pub fn read_health_snapshot(config: &Config) -> Option<RuntimeHealthSnapshot> {
    let raw = fs::read_to_string(health_path(config)).ok()?;
    serde_json::from_str::<RuntimeHealthSnapshot>(&raw).ok()
}

/// Write daemon health snapshot to runtime dir.
pub fn write_health_snapshot(config: &Config) -> crate::Result<()> {
    let snapshot = collect_health_snapshot(config);
    fs::create_dir_all(&config.daemon.runtime_dir)?;
    crate::coordinator::atomic_write(&health_path(config), &serde_json::to_vec_pretty(&snapshot)?)?;
    Ok(())
}

/// Probe daemon process/systemd status.
pub fn probe_daemon(config: &Config) -> DaemonProbe {
    let pid = read_pid(&config.daemon.pid_file);
    let pid_alive = pid.map(is_pid_alive).unwrap_or(false);
    let systemd_active = systemctl_is_active("vigild.service");
    let running = pid_alive || matches!(systemd_active, Some(true));

    let uptime_seconds = if running {
        read_metrics(config)
            .and_then(|m| {
                if m.uptime_start > 0 {
                    Some(Utc::now().timestamp() - m.uptime_start)
                } else {
                    None
                }
            })
            .map(|s| s.max(0))
    } else {
        None
    };

    DaemonProbe {
        running,
        pid,
        uptime_seconds,
        systemd_active,
    }
}

/// Count baseline entries without creating a database if it does not exist.
pub fn baseline_count(config: &Config) -> Option<i64> {
    if !config.daemon.db_path.exists() {
        return None;
    }
    let conn = open_existing_db(&config.daemon.db_path).ok()?;
    baseline_ops::count(&conn).ok()
}

/// Count baseline entries and fall back to daemon health snapshot when direct DB access is not possible.
pub fn baseline_count_with_fallback(config: &Config) -> Option<i64> {
    baseline_count(config).or_else(|| {
        read_fresh_health_snapshot(config).and_then(|snapshot| snapshot.baseline.entry_count)
    })
}

/// Count audit entries newer than `since_unix`.
pub fn recent_audit_change_count(config: &Config, since_unix: i64) -> Option<u64> {
    let audit_path = db::audit_db_path(config);
    if !audit_path.exists() {
        return None;
    }
    let conn = open_existing_db(&audit_path).ok()?;
    conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1",
        [since_unix],
        |row| row.get::<_, i64>(0),
    )
    .ok()
    .map(|v| v.max(0) as u64)
}

/// Return the metrics snapshot file mtime as unix timestamp.
pub fn metrics_file_timestamp(config: &Config) -> Option<i64> {
    let modified = fs::metadata(metrics_path(config)).ok()?.modified().ok()?;
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    i64::try_from(secs).ok()
}

/// Return backend inferred from state json or config.
pub fn monitor_backend_label(config: &Config) -> String {
    if let Some(state) = read_state_json(config) {
        if let Some(backend) = state.get("backend").and_then(|v| v.as_str()) {
            return backend.to_string();
        }
    }
    config.daemon.monitor_backend.to_string()
}

/// Render compact uptime like "3d 14h".
pub fn format_compact_duration(seconds: i64) -> String {
    let s = seconds.max(0);
    let days = s / 86_400;
    let hours = (s % 86_400) / 3_600;
    let mins = (s % 3_600) / 60;

    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

/// Render timestamps as "HH:MM today", "HH:MM yesterday", or ISO-like date.
pub fn format_relative_timestamp(ts: i64) -> String {
    let Some(dt) = Local.timestamp_opt(ts, 0).single() else {
        return "unknown".to_string();
    };
    let now = Local::now();
    let today = now.date_naive();
    let yesterday = (now - chrono::Duration::days(1)).date_naive();

    if dt.date_naive() == today {
        format!("{} today", dt.format("%H:%M"))
    } else if dt.date_naive() == yesterday {
        format!("{} yesterday", dt.format("%H:%M"))
    } else {
        dt.format("%Y-%m-%d %H:%M").to_string()
    }
}

/// Format the final verdict sentence for diagnostic output.
pub fn diagnostics_verdict(checks: &[DiagnosticCheck]) -> String {
    let failures = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Failed)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warning)
        .count();

    if failures == 0 && warnings == 0 {
        "All systems nominal. Vigil Baseline is watching.".to_string()
    } else if failures == 0 {
        format!(
            "{} {}. Vigil Baseline is running with reduced coverage.",
            warnings,
            if warnings == 1 { "warning" } else { "warnings" }
        )
    } else {
        format!(
            "{} {} need{} attention. Run suggested commands above.",
            failures,
            if failures == 1 { "issue" } else { "issues" },
            if failures == 1 { "s" } else { "" }
        )
    }
}

/// Return doctor command exit code.
pub fn diagnostics_exit_code(checks: &[DiagnosticCheck]) -> i32 {
    let failures = checks.iter().any(|c| c.status == CheckStatus::Failed);
    if failures {
        return 2;
    }

    let warnings = checks.iter().any(|c| c.status == CheckStatus::Warning);
    if warnings {
        return 1;
    }

    0
}

/// Run all diagnostic checks and return results.
pub fn run_diagnostics(config: &Config) -> Vec<DiagnosticCheck> {
    let mut checks = Vec::with_capacity(11);

    let (daemon_check, daemon_probe) = check_daemon(config);
    checks.push(daemon_check);
    checks.push(check_backend(config, daemon_probe.running));
    checks.push(check_baseline(config));
    checks.push(check_database_integrity(config));
    checks.push(check_audit_log(config));
    checks.push(check_config(config));
    checks.push(check_scan_timer(config));
    checks.push(check_hmac_key(config));
    checks.push(check_package_hooks());
    checks.push(check_notify_send());
    checks.push(check_signal_socket(config));
    checks.push(check_control_socket(config));

    checks
}

fn check_daemon(config: &Config) -> (DiagnosticCheck, DaemonProbe) {
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
                fix: None,
            },
            probe,
        )
    } else {
        (
            DiagnosticCheck {
                name: "Daemon".to_string(),
                status: CheckStatus::Failed,
                detail: "not running".to_string(),
                fix: Some("sudo systemctl start vigild.service".to_string()),
            },
            probe,
        )
    }
}

fn check_backend(config: &Config, daemon_running: bool) -> DiagnosticCheck {
    if !daemon_running {
        return DiagnosticCheck {
            name: "Backend".to_string(),
            status: CheckStatus::Unknown,
            detail: "unknown (daemon not running)".to_string(),
            fix: None,
        };
    }

    let backend = monitor_backend_label(config);
    if backend == "fanotify" {
        DiagnosticCheck {
            name: "Backend".to_string(),
            status: CheckStatus::Ok,
            detail: "fanotify (mount-wide coverage)".to_string(),
            fix: None,
        }
    } else {
        DiagnosticCheck {
            name: "Backend".to_string(),
            status: CheckStatus::Warning,
            detail: "inotify fallback (reduced coverage)".to_string(),
            fix: Some("Run daemon with CAP_SYS_ADMIN for full fanotify coverage".to_string()),
        }
    }
}

fn check_baseline(config: &Config) -> DiagnosticCheck {
    let db_path = &config.daemon.db_path;
    if !db_path.exists() {
        return DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Failed,
            detail: format!("database not found at {}", db_path.display()),
            fix: Some("vigil init".to_string()),
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
            fix: Some("Run with elevated privileges: sudo vigil doctor".to_string()),
        };
    }

    let conn = match open_existing_db(db_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Baseline".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open baseline database: {}", e),
                fix: Some("vigil init".to_string()),
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
                fix: Some("vigil init".to_string()),
            };
        }
    };

    if count <= 0 {
        return DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Failed,
            detail: "no baseline found (database empty)".to_string(),
            fix: Some("vigil init".to_string()),
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
                DiagnosticCheck {
                    name: "Baseline".to_string(),
                    status: CheckStatus::Warning,
                    detail: format!(
                        "{} entries (last refresh: {})",
                        count_label,
                        format_age(age)
                    ),
                    fix: Some("vigil baseline refresh".to_string()),
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
                    fix: None,
                }
            }
        }
        None => DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Ok,
            detail: format!("{} entries (last refresh: unknown)", count_label),
            fix: None,
        },
    }
}

fn check_database_integrity(config: &Config) -> DiagnosticCheck {
    let baseline_path = &config.daemon.db_path;
    let audit_path = db::audit_db_path(config);

    if !baseline_path.exists() {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("baseline database not found at {}", baseline_path.display()),
            fix: Some("vigil init".to_string()),
        };
    }

    if !audit_path.exists() {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("audit database not found at {}", audit_path.display()),
            fix: Some("vigil init".to_string()),
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
            fix: Some("Run with elevated privileges: sudo vigil doctor".to_string()),
        };
    }

    let baseline_conn = match open_existing_db(baseline_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Database".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open baseline database: {}", e),
                fix: Some(format!(
                    "cp {} {}.bak && vigil init",
                    baseline_path.display(),
                    baseline_path.display()
                )),
            };
        }
    };

    if let Err(e) = db::integrity_check(&baseline_conn) {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("integrity check failed: {}", e),
            fix: Some(format!(
                "cp {} {}.bak && vigil init",
                baseline_path.display(),
                baseline_path.display()
            )),
        };
    }

    let audit_conn = match open_existing_db(&audit_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Database".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open audit database: {}", e),
                fix: Some(format!(
                    "cp {} {}.bak && vigil init",
                    audit_path.display(),
                    audit_path.display()
                )),
            };
        }
    };

    if let Err(e) = db::integrity_check(&audit_conn) {
        return DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!("integrity check failed: {}", e),
            fix: Some(format!(
                "cp {} {}.bak && vigil init",
                baseline_path.display(),
                baseline_path.display()
            )),
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
        fix: None,
    }
}

fn check_audit_log(config: &Config) -> DiagnosticCheck {
    let audit_path = db::audit_db_path(config);
    if !audit_path.exists() {
        return DiagnosticCheck {
            name: "Audit log".to_string(),
            status: CheckStatus::Failed,
            detail: format!("audit database not found at {}", audit_path.display()),
            fix: Some("vigil init".to_string()),
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
            fix: Some("Run with elevated privileges: sudo vigil doctor".to_string()),
        };
    }

    let conn = match open_existing_db(&audit_path) {
        Ok(conn) => conn,
        Err(e) => {
            return DiagnosticCheck {
                name: "Audit log".to_string(),
                status: CheckStatus::Failed,
                detail: format!("cannot open audit database: {}", e),
                fix: Some("vigil audit verify".to_string()),
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
                DiagnosticCheck {
                    name: "Audit log".to_string(),
                    status: CheckStatus::Warning,
                    detail: format!(
                        "{} entries, {} chain breaks detected",
                        format_count(total),
                        breaks.len()
                    ),
                    fix: Some("vigil audit verify".to_string()),
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
                    fix: Some("vigil audit verify".to_string()),
                }
            } else {
                DiagnosticCheck {
                    name: "Audit log".to_string(),
                    status: CheckStatus::Ok,
                    detail: format!("{} entries, chain intact, 0 breaks", format_count(total)),
                    fix: None,
                }
            }
        }
        Err(e) => DiagnosticCheck {
            name: "Audit log".to_string(),
            status: CheckStatus::Failed,
            detail: format!("verification failed: {}", e),
            fix: Some("vigil audit verify".to_string()),
        },
    }
}

fn check_config(config: &Config) -> DiagnosticCheck {
    let config_path = detect_active_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/etc/vigil/vigil.toml".to_string());

    if let Err(e) = crate::config::validate_config(config) {
        return DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Failed,
            detail: format!("invalid: {}", e),
            fix: Some("vigil config validate".to_string()),
        };
    }

    match crate::config::validate_config_deep(config) {
        Ok(warnings) if warnings.is_empty() => DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Ok,
            detail: format!("valid ({})", config_path),
            fix: None,
        },
        Ok(warnings) => DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Warning,
            detail: format!("valid ({}) with {} warnings", config_path, warnings.len()),
            fix: Some("vigil config validate".to_string()),
        },
        Err(e) => DiagnosticCheck {
            name: "Config".to_string(),
            status: CheckStatus::Failed,
            detail: format!("invalid: {}", e),
            fix: Some("vigil config validate".to_string()),
        },
    }
}

fn check_scan_timer(config: &Config) -> DiagnosticCheck {
    if !command_exists("systemctl") {
        return DiagnosticCheck {
            name: "Scan timer".to_string(),
            status: CheckStatus::Warning,
            detail: "timer not found".to_string(),
            fix: Some("sudo systemctl enable --now vigil-scan.timer".to_string()),
        };
    }

    let load_state = systemctl_show("vigil-scan.timer", "LoadState").unwrap_or_default();
    if load_state.trim() == "not-found" || load_state.trim().is_empty() {
        return DiagnosticCheck {
            name: "Scan timer".to_string(),
            status: CheckStatus::Warning,
            detail: "timer not found".to_string(),
            fix: Some("sudo systemctl enable --now vigil-scan.timer".to_string()),
        };
    }

    let active = systemctl_is_active("vigil-scan.timer") == Some(true);
    if !active {
        return DiagnosticCheck {
            name: "Scan timer".to_string(),
            status: CheckStatus::Warning,
            detail: "timer inactive".to_string(),
            fix: Some("sudo systemctl start vigil-scan.timer".to_string()),
        };
    }

    let next_raw = systemctl_show("vigil-scan.timer", "NextElapseUSecRealtime")
        .unwrap_or_else(|| "unknown".to_string());
    let next = shorten_next_timer(&next_raw);
    let metrics = read_metrics(config);
    let last_scan_total = metrics.as_ref().map(|m| m.last_scan_total).unwrap_or(0);
    let last_scan = metrics_file_timestamp(config)
        .map(format_relative_timestamp)
        .unwrap_or_else(|| "unknown".to_string());

    DiagnosticCheck {
        name: "Scan timer".to_string(),
        status: CheckStatus::Ok,
        detail: format!(
            "active (next: {}, last: {} — {} changes)",
            next, last_scan, last_scan_total
        ),
        fix: None,
    }
}

fn check_hmac_key(config: &Config) -> DiagnosticCheck {
    if !config.security.hmac_signing {
        return DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Unknown,
            detail: "not configured".to_string(),
            fix: None,
        };
    }

    let key_path = &config.security.hmac_key_path;
    if !key_path.exists() {
        return DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Failed,
            detail: format!("not found at {}", key_path.display()),
            fix: Some(format!(
                "openssl rand -hex 32 | sudo tee {} >/dev/null && sudo chmod 0600 {}",
                key_path.display(),
                key_path.display()
            )),
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
            fix: None,
        };
    }

    let joined = issues.join("; ");
    if joined.contains("permissions") {
        DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Warning,
            detail: joined,
            fix: Some(format!("sudo chmod 0600 {}", key_path.display())),
        }
    } else if joined.contains("Cannot stat") {
        DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Failed,
            detail: joined,
            fix: Some(format!(
                "openssl rand -hex 32 | sudo tee {} >/dev/null && sudo chmod 0600 {}",
                key_path.display(),
                key_path.display()
            )),
        }
    } else {
        DiagnosticCheck {
            name: "HMAC key".to_string(),
            status: CheckStatus::Warning,
            detail: joined,
            fix: Some(format!("sudo chown root:root {}", key_path.display())),
        }
    }
}

fn check_package_hooks() -> DiagnosticCheck {
    match crate::package::detect_backend() {
        PackageBackend::Pacman => {
            let pre = Path::new("/etc/pacman.d/hooks/vigil-pre.hook").exists();
            let post = Path::new("/etc/pacman.d/hooks/vigil-post.hook").exists();
            if pre && post {
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status: CheckStatus::Ok,
                    detail: "pacman pre/post installed".to_string(),
                    fix: None,
                }
            } else {
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status: CheckStatus::Warning,
                    detail: "pacman detected but hooks not installed".to_string(),
                    fix: Some(
                        "sudo install -Dm644 hooks/pacman/vigil-pre.hook /etc/pacman.d/hooks/vigil-pre.hook && sudo install -Dm644 hooks/pacman/vigil-post.hook /etc/pacman.d/hooks/vigil-post.hook".to_string(),
                    ),
                }
            }
        }
        PackageBackend::Dpkg => {
            let apt_hook = Path::new("/etc/apt/apt.conf.d/99vigil").exists();
            if apt_hook {
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status: CheckStatus::Ok,
                    detail: "apt hook installed".to_string(),
                    fix: None,
                }
            } else {
                DiagnosticCheck {
                    name: "Hooks".to_string(),
                    status: CheckStatus::Warning,
                    detail: "apt detected but hook not installed".to_string(),
                    fix: Some(
                        "sudo install -Dm644 hooks/apt/99vigil /etc/apt/apt.conf.d/99vigil"
                            .to_string(),
                    ),
                }
            }
        }
        PackageBackend::Rpm => DiagnosticCheck {
            name: "Hooks".to_string(),
            status: CheckStatus::Unknown,
            detail: "rpm detected (no native hook template bundled)".to_string(),
            fix: None,
        },
        PackageBackend::Auto => DiagnosticCheck {
            name: "Hooks".to_string(),
            status: CheckStatus::Unknown,
            detail: "no supported package manager detected".to_string(),
            fix: None,
        },
    }
}

fn check_notify_send() -> DiagnosticCheck {
    if command_exists("notify-send") {
        DiagnosticCheck {
            name: "Notify".to_string(),
            status: CheckStatus::Ok,
            detail: "notify-send available".to_string(),
            fix: None,
        }
    } else {
        let fix = match crate::package::detect_backend() {
            PackageBackend::Pacman => "sudo pacman -S --needed libnotify",
            PackageBackend::Dpkg => "sudo apt-get install -y libnotify-bin",
            PackageBackend::Rpm => "sudo dnf install -y libnotify",
            PackageBackend::Auto => "Install libnotify for your distribution",
        }
        .to_string();

        DiagnosticCheck {
            name: "Notify".to_string(),
            status: CheckStatus::Warning,
            detail: "notify-send not found (desktop notifications disabled)".to_string(),
            fix: Some(fix),
        }
    }
}

fn check_signal_socket(config: &Config) -> DiagnosticCheck {
    let socket_path = config.hooks.signal_socket.trim();
    if socket_path.is_empty() {
        return DiagnosticCheck {
            name: "Socket".to_string(),
            status: CheckStatus::Unknown,
            detail: "not configured (optional)".to_string(),
            fix: None,
        };
    }

    let path = Path::new(socket_path);
    if !path.exists() {
        return DiagnosticCheck {
            name: "Socket".to_string(),
            status: CheckStatus::Unknown,
            detail: "configured (no listener attached)".to_string(),
            fix: None,
        };
    }

    DiagnosticCheck {
        name: "Socket".to_string(),
        status: CheckStatus::Ok,
        detail: format!("configured at {}", path.display()),
        fix: None,
    }
}

fn check_control_socket(config: &Config) -> DiagnosticCheck {
    if config.daemon.control_socket.as_os_str().is_empty() {
        return DiagnosticCheck {
            name: "Control".into(),
            status: CheckStatus::Unknown,
            detail: "not configured (optional)".into(),
            fix: None,
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
            fix: Some("Start the daemon: sudo systemctl start vigild".into()),
        };
    }

    match query_control_socket_quick(socket_path, &config.security) {
        Ok(_) => DiagnosticCheck {
            name: "Control".into(),
            status: CheckStatus::Ok,
            detail: format!("responding ({})", socket_path.display()),
            fix: None,
        },
        Err(e) => DiagnosticCheck {
            name: "Control".into(),
            status: CheckStatus::Warning,
            detail: format!("socket exists but not responding: {}", e),
            fix: Some("Restart the daemon: sudo systemctl restart vigild".into()),
        },
    }
}

fn query_control_socket_quick(
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

fn baseline_check_from_snapshot(config: &Config) -> Option<DiagnosticCheck> {
    let snapshot = read_fresh_health_snapshot(config)?;
    let baseline = &snapshot.baseline;
    let snapshot_age = snapshot_age_label(snapshot.generated_at);

    if let Some(err) = baseline.error.as_ref() {
        return Some(DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Failed,
            detail: format!(
                "daemon snapshot reports baseline issue: {} ({})",
                err, snapshot_age
            ),
            fix: Some("sudo vigil doctor".to_string()),
        });
    }

    let count = baseline.entry_count?;
    if count <= 0 {
        return Some(DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Failed,
            detail: format!("no baseline found (daemon snapshot {})", snapshot_age),
            fix: Some("vigil init".to_string()),
        });
    }

    let count_label = format_count(count.max(0) as u64);
    match baseline.last_refresh {
        Some(ts) => {
            let age = (Utc::now().timestamp() - ts).max(0);
            if age > 86_400 {
                Some(DiagnosticCheck {
                    name: "Baseline".to_string(),
                    status: CheckStatus::Warning,
                    detail: format!(
                        "{} entries (last refresh: {}; daemon snapshot {})",
                        count_label,
                        format_age(age),
                        snapshot_age
                    ),
                    fix: Some("vigil baseline refresh".to_string()),
                })
            } else {
                Some(DiagnosticCheck {
                    name: "Baseline".to_string(),
                    status: CheckStatus::Ok,
                    detail: format!(
                        "{} entries (last refresh: {}; daemon snapshot {})",
                        count_label,
                        format_age(age),
                        snapshot_age
                    ),
                    fix: None,
                })
            }
        }
        None => Some(DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Ok,
            detail: format!(
                "{} entries (last refresh: unknown; daemon snapshot {})",
                count_label, snapshot_age
            ),
            fix: None,
        }),
    }
}

fn database_check_from_snapshot(config: &Config) -> Option<DiagnosticCheck> {
    let snapshot = read_fresh_health_snapshot(config)?;
    let database = &snapshot.database;
    let snapshot_age = snapshot_age_label(snapshot.generated_at);

    if let Some(err) = database.error.as_ref() {
        return Some(DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!(
                "daemon snapshot reports database issue: {} ({})",
                err, snapshot_age
            ),
            fix: Some("sudo vigil doctor".to_string()),
        });
    }

    if !database.baseline_open || !database.audit_open {
        let mut unavailable = Vec::new();
        if !database.baseline_open {
            unavailable.push("baseline");
        }
        if !database.audit_open {
            unavailable.push("audit");
        }

        return Some(DiagnosticCheck {
            name: "Database".to_string(),
            status: CheckStatus::Failed,
            detail: format!(
                "daemon snapshot cannot access {} database(s) ({})",
                unavailable.join("/"),
                snapshot_age
            ),
            fix: Some("sudo systemctl restart vigild.service && sudo vigil doctor".to_string()),
        });
    }

    let wal_mode = database
        .journal_mode
        .as_deref()
        .unwrap_or("unknown")
        .to_uppercase();

    Some(DiagnosticCheck {
        name: "Database".to_string(),
        status: CheckStatus::Warning,
        detail: format!(
            "daemon can access baseline/audit databases ({} mode, {}; {})",
            wal_mode,
            format_size(database.total_size_bytes),
            snapshot_age
        ),
        fix: Some("Run sudo vigil doctor for full integrity verification".to_string()),
    })
}

fn audit_check_from_snapshot(config: &Config) -> Option<DiagnosticCheck> {
    let snapshot = read_fresh_health_snapshot(config)?;
    let audit = &snapshot.audit;
    let snapshot_age = snapshot_age_label(snapshot.generated_at);

    if let Some(err) = audit.error.as_ref() {
        return Some(DiagnosticCheck {
            name: "Audit log".to_string(),
            status: CheckStatus::Failed,
            detail: format!(
                "daemon snapshot reports audit issue: {} ({})",
                err, snapshot_age
            ),
            fix: Some("sudo vigil doctor".to_string()),
        });
    }

    let total = audit.entry_count?;
    Some(DiagnosticCheck {
        name: "Audit log".to_string(),
        status: CheckStatus::Warning,
        detail: format!(
            "daemon reports {} entries ({}; chain verification requires sudo)",
            format_count(total),
            snapshot_age
        ),
        fix: Some("Run sudo vigil doctor to verify the audit chain".to_string()),
    })
}

fn read_fresh_health_snapshot(config: &Config) -> Option<RuntimeHealthSnapshot> {
    let snapshot = read_health_snapshot(config)?;
    let age_secs = snapshot_age_seconds(snapshot.generated_at)?;
    if age_secs > HEALTH_SNAPSHOT_MAX_AGE_SECS {
        return None;
    }
    Some(snapshot)
}

fn snapshot_age_seconds(generated_at: i64) -> Option<i64> {
    if generated_at <= 0 {
        return None;
    }

    Some((Utc::now().timestamp() - generated_at).max(0))
}

fn snapshot_age_label(generated_at: i64) -> String {
    snapshot_age_seconds(generated_at)
        .map(|age| format!("snapshot {}", format_age(age)))
        .unwrap_or_else(|| "snapshot age unknown".to_string())
}

fn collect_health_snapshot(config: &Config) -> RuntimeHealthSnapshot {
    let mut snapshot = RuntimeHealthSnapshot {
        generated_at: Utc::now().timestamp(),
        ..RuntimeHealthSnapshot::default()
    };

    let baseline_path = &config.daemon.db_path;
    let audit_path = db::audit_db_path(config);

    let baseline_size = fs::metadata(baseline_path).map(|m| m.len()).unwrap_or(0);
    let audit_size = fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);
    snapshot.database.total_size_bytes = baseline_size + audit_size;

    if !baseline_path.exists() {
        snapshot.baseline.error = Some(format!(
            "baseline database not found at {}",
            baseline_path.display()
        ));
    } else {
        match open_existing_db(baseline_path) {
            Ok(conn) => {
                snapshot.database.baseline_open = true;

                match baseline_ops::count(&conn) {
                    Ok(count) => snapshot.baseline.entry_count = Some(count),
                    Err(e) => {
                        snapshot.baseline.error = Some(format!("cannot read baseline: {}", e))
                    }
                }

                snapshot.baseline.last_refresh =
                    baseline_ops::get_config_state(&conn, "last_baseline_refresh")
                        .ok()
                        .flatten()
                        .and_then(|v| v.parse::<i64>().ok());

                snapshot.database.journal_mode = conn
                    .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                    .ok()
                    .map(|m| m.to_uppercase());
            }
            Err(e) => {
                snapshot.baseline.error = Some(format!("cannot open baseline database: {}", e));
            }
        }
    }

    if !audit_path.exists() {
        snapshot.audit.error = Some(format!(
            "audit database not found at {}",
            audit_path.display()
        ));
    } else {
        match open_existing_db(&audit_path) {
            Ok(conn) => {
                snapshot.database.audit_open = true;
                match conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| {
                    row.get::<_, i64>(0)
                }) {
                    Ok(total) => snapshot.audit.entry_count = Some(total.max(0) as u64),
                    Err(e) => {
                        snapshot.audit.error = Some(format!("cannot read audit log: {}", e));
                    }
                }
            }
            Err(e) => {
                snapshot.audit.error = Some(format!("cannot open audit database: {}", e));
            }
        }
    }

    snapshot.database.error = if !snapshot.database.baseline_open && !snapshot.database.audit_open {
        Some("cannot open baseline and audit databases".to_string())
    } else if !snapshot.database.baseline_open {
        Some("cannot open baseline database".to_string())
    } else if !snapshot.database.audit_open {
        Some("cannot open audit database".to_string())
    } else {
        None
    };

    snapshot
}

fn detect_active_config_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("VIGIL_CONFIG") {
        let p = PathBuf::from(explicit);
        if p.exists() {
            return Some(p);
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join(".config/vigil/vigil.toml");
        if p.exists() {
            return Some(p);
        }
    }

    let etc = PathBuf::from("/etc/vigil/vigil.toml");
    if etc.exists() {
        return Some(etc);
    }

    None
}

fn metrics_path(config: &Config) -> PathBuf {
    config.daemon.runtime_dir.join("metrics.json")
}

fn health_path(config: &Config) -> PathBuf {
    config.daemon.runtime_dir.join("health.json")
}

fn state_path(config: &Config) -> PathBuf {
    config.daemon.runtime_dir.join("state.json")
}

fn open_existing_db(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

fn has_sqlite_read_access(path: &Path) -> bool {
    if std::fs::File::open(path).is_err() {
        return false;
    }

    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar_path = PathBuf::from(sidecar);
        if sidecar_path.exists() && std::fs::File::open(&sidecar_path).is_err() {
            return false;
        }
    }

    true
}

fn read_pid(path: &Path) -> Option<i32> {
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse::<i32>().ok()
}

#[allow(unsafe_code)]
fn is_pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    if Path::new(&format!("/proc/{}/exe", pid)).exists() {
        return true;
    }

    // SAFETY: kill with signal 0 does not send a signal; it only probes process existence.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }

    let err = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default();
    err == libc::EPERM
}

fn command_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(cmd).is_file()))
        .unwrap_or(false)
}

fn systemctl_is_active(unit: &str) -> Option<bool> {
    if !command_exists("systemctl") {
        return None;
    }

    let status = Command::new("systemctl")
        .arg("is-active")
        .arg(unit)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    Some(status.success())
}

fn systemctl_show(unit: &str, property: &str) -> Option<String> {
    if !command_exists("systemctl") {
        return None;
    }

    let output = Command::new("systemctl")
        .arg("show")
        .arg(unit)
        .arg(format!("--property={}", property))
        .arg("--value")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn format_count(value: u64) -> String {
    let s = value.to_string();
    let mut out = String::with_capacity(s.len() + (s.len() / 3));

    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }

    out.chars().rev().collect()
}

fn format_size(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_048_576.0)
}

fn format_age(age_secs: i64) -> String {
    let secs = age_secs.max(0);
    let days = secs / 86_400;
    if days > 0 {
        return format!("{}d ago", days);
    }

    let hours = secs / 3_600;
    if hours > 0 {
        return format!("{}h ago", hours);
    }

    let mins = secs / 60;
    if mins > 0 {
        return format!("{}m ago", mins);
    }

    "just now".to_string()
}

fn shorten_next_timer(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "n/a" {
        return "unknown".to_string();
    }

    if let Some(time_part) = trimmed.split_whitespace().nth(2) {
        let hhmm = time_part.chars().take(5).collect::<String>();
        if hhmm.len() == 5 && hhmm.contains(':') {
            return hhmm;
        }
    }

    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn diagnostics_returns_expected_number_of_checks() {
        let cfg = crate::config::default_config();
        let checks = run_diagnostics(&cfg);
        assert_eq!(checks.len(), 12);
        for check in checks {
            assert!(!check.name.trim().is_empty());
            match check.status {
                CheckStatus::Ok
                | CheckStatus::Warning
                | CheckStatus::Failed
                | CheckStatus::Unknown => {}
            }
        }
    }

    #[test]
    fn compact_duration_formatting() {
        assert_eq!(format_compact_duration(65), "1m");
        assert_eq!(format_compact_duration(3_700), "1h 1m");
        assert_eq!(format_compact_duration(200_000), "2d 7h");
    }

    #[test]
    fn verdict_text_and_exit_code() {
        let ok = vec![DiagnosticCheck {
            name: "x".to_string(),
            status: CheckStatus::Ok,
            detail: "ok".to_string(),
            fix: None,
        }];
        assert_eq!(diagnostics_exit_code(&ok), 0);

        let warning = vec![DiagnosticCheck {
            name: "x".to_string(),
            status: CheckStatus::Warning,
            detail: "warn".to_string(),
            fix: None,
        }];
        assert_eq!(diagnostics_exit_code(&warning), 1);

        let failed = vec![DiagnosticCheck {
            name: "x".to_string(),
            status: CheckStatus::Failed,
            detail: "fail".to_string(),
            fix: None,
        }];
        assert_eq!(diagnostics_exit_code(&failed), 2);
    }

    #[test]
    #[cfg(unix)]
    fn sqlite_read_access_checks_respect_permissions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("baseline.db");
        std::fs::write(&db, b"not-a-db").expect("write file");

        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600))
            .expect("set readable perms");
        assert!(has_sqlite_read_access(&db));

        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000))
            .expect("set unreadable perms");
        assert!(!has_sqlite_read_access(&db));
    }

    #[test]
    #[cfg(unix)]
    fn baseline_check_reports_permission_limited_access() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("baseline.db");
        std::fs::write(&db, b"placeholder").expect("write file");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000))
            .expect("set unreadable perms");

        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = db;
        cfg.daemon.runtime_dir = dir.path().join("run");

        let check = check_baseline(&cfg);
        assert_eq!(check.status, CheckStatus::Unknown);
        assert!(
            check.detail.contains("insufficient permissions"),
            "unexpected detail: {}",
            check.detail
        );
        assert_eq!(
            check.fix,
            Some("Run with elevated privileges: sudo vigil doctor".to_string())
        );
    }

    #[test]
    #[cfg(unix)]
    fn database_and_audit_checks_report_permission_limited_access() {
        let dir = tempfile::tempdir().expect("temp dir");
        let baseline_db = dir.path().join("baseline.db");
        let audit_db = dir.path().join("audit.db");

        std::fs::write(&baseline_db, b"placeholder").expect("write baseline");
        std::fs::write(&audit_db, b"placeholder").expect("write audit");
        std::fs::set_permissions(&baseline_db, std::fs::Permissions::from_mode(0o000))
            .expect("set baseline unreadable perms");
        std::fs::set_permissions(&audit_db, std::fs::Permissions::from_mode(0o000))
            .expect("set audit unreadable perms");

        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = baseline_db;
        cfg.daemon.runtime_dir = dir.path().join("run");

        let db_check = check_database_integrity(&cfg);
        assert_eq!(db_check.status, CheckStatus::Unknown);
        assert!(
            db_check.detail.contains("integrity check unavailable"),
            "unexpected detail: {}",
            db_check.detail
        );

        let audit_check = check_audit_log(&cfg);
        assert_eq!(audit_check.status, CheckStatus::Unknown);
        assert!(
            audit_check.detail.contains("insufficient permissions"),
            "unexpected detail: {}",
            audit_check.detail
        );
    }

    #[test]
    #[cfg(unix)]
    fn baseline_check_uses_fresh_daemon_snapshot_when_unreadable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("baseline.db");
        let runtime_dir = dir.path().join("run");
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");

        std::fs::write(&db, b"placeholder").expect("write baseline file");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000))
            .expect("set unreadable perms");

        let now = Utc::now().timestamp();
        let snapshot = RuntimeHealthSnapshot {
            generated_at: now,
            baseline: BaselineHealthSnapshot {
                entry_count: Some(42),
                last_refresh: Some(now - 60),
                error: None,
            },
            ..RuntimeHealthSnapshot::default()
        };
        std::fs::write(
            runtime_dir.join("health.json"),
            serde_json::to_vec_pretty(&snapshot).expect("serialize health snapshot"),
        )
        .expect("write health snapshot");

        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = db;
        cfg.daemon.runtime_dir = runtime_dir;

        let check = check_baseline(&cfg);
        assert_eq!(check.status, CheckStatus::Ok);
        assert!(
            check.detail.contains("daemon snapshot"),
            "unexpected detail: {}",
            check.detail
        );
    }

    #[test]
    #[cfg(unix)]
    fn database_check_uses_snapshot_warning_when_unreadable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let baseline_db = dir.path().join("baseline.db");
        let audit_db = dir.path().join("audit.db");
        let runtime_dir = dir.path().join("run");
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");

        std::fs::write(&baseline_db, b"placeholder").expect("write baseline file");
        std::fs::write(&audit_db, b"placeholder").expect("write audit file");
        std::fs::set_permissions(&baseline_db, std::fs::Permissions::from_mode(0o000))
            .expect("set baseline unreadable perms");
        std::fs::set_permissions(&audit_db, std::fs::Permissions::from_mode(0o000))
            .expect("set audit unreadable perms");

        let snapshot = RuntimeHealthSnapshot {
            generated_at: Utc::now().timestamp(),
            database: DatabaseHealthSnapshot {
                baseline_open: true,
                audit_open: true,
                journal_mode: Some("WAL".to_string()),
                total_size_bytes: 2_097_152,
                error: None,
            },
            ..RuntimeHealthSnapshot::default()
        };
        std::fs::write(
            runtime_dir.join("health.json"),
            serde_json::to_vec_pretty(&snapshot).expect("serialize health snapshot"),
        )
        .expect("write health snapshot");

        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = baseline_db;
        cfg.daemon.runtime_dir = runtime_dir;

        let check = check_database_integrity(&cfg);
        assert_eq!(check.status, CheckStatus::Warning);
        assert!(
            check
                .detail
                .contains("daemon can access baseline/audit databases"),
            "unexpected detail: {}",
            check.detail
        );
    }

    #[test]
    #[cfg(unix)]
    fn stale_health_snapshot_is_not_used_for_permission_fallback() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = dir.path().join("baseline.db");
        let runtime_dir = dir.path().join("run");
        std::fs::create_dir_all(&runtime_dir).expect("create runtime dir");

        std::fs::write(&db, b"placeholder").expect("write baseline file");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000))
            .expect("set unreadable perms");

        let snapshot = RuntimeHealthSnapshot {
            generated_at: Utc::now().timestamp() - (HEALTH_SNAPSHOT_MAX_AGE_SECS + 60),
            baseline: BaselineHealthSnapshot {
                entry_count: Some(99),
                last_refresh: Some(Utc::now().timestamp()),
                error: None,
            },
            ..RuntimeHealthSnapshot::default()
        };
        std::fs::write(
            runtime_dir.join("health.json"),
            serde_json::to_vec_pretty(&snapshot).expect("serialize health snapshot"),
        )
        .expect("write health snapshot");

        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = db;
        cfg.daemon.runtime_dir = runtime_dir;

        let check = check_baseline(&cfg);
        assert_eq!(check.status, CheckStatus::Unknown);
        assert!(
            check.detail.contains("insufficient permissions"),
            "unexpected detail: {}",
            check.detail
        );
    }

    #[test]
    fn verdict_singular_warning() {
        let checks = vec![DiagnosticCheck {
            name: "x".to_string(),
            status: CheckStatus::Warning,
            detail: "warn".to_string(),
            fix: None,
        }];
        let verdict = diagnostics_verdict(&checks);
        assert!(verdict.contains("1 warning."), "got: {}", verdict);
        assert!(!verdict.contains("1 warnings"));
    }

    #[test]
    fn verdict_singular_failure() {
        let checks = vec![DiagnosticCheck {
            name: "x".to_string(),
            status: CheckStatus::Failed,
            detail: "fail".to_string(),
            fix: None,
        }];
        let verdict = diagnostics_verdict(&checks);
        assert!(verdict.contains("1 issue"), "got: {}", verdict);
        assert!(!verdict.contains("1 issues"));
    }
}
