//! System health diagnostics: 12+ checks covering config, databases,
//! permissions, daemon state, monitor backend, and audit chain integrity.

pub mod acknowledgment;
mod checks;
pub(crate) mod recovery;
pub mod recovery_builder;

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::db::{self, baseline_ops};

// --- Re-exports: moved helpers remain available at their original paths ---
pub use crate::db::access::{has_sqlite_read_access, open_existing_db as open_existing_db_pub};
pub use crate::display::format::format_age;
pub use crate::display::time::{
    format_absolute, format_compact_duration, format_iso, format_local, format_next_timer_relative,
    format_relative_duration_from_timestamp, format_relative_timestamp, shorten_next_timer,
};
pub use crate::util::fs_walk::{walk_data_dir_usage, DataDirUsage};
pub use crate::util::journald::{hook_last_trigger_parsed, HookTriggerResult};
pub use crate::util::process::{is_pid_alive, read_pid};
pub use crate::util::system::{
    command_exists, systemctl_binary, systemctl_is_active, systemctl_show,
};

const HEALTH_SNAPSHOT_MAX_AGE_SECS: i64 = 300;

/// A single recovery hint: a command, manual guidance, or documentation reference.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum RecoveryHint {
    /// A real, executable command.
    Command { verb: &'static str, command: String },
    /// Manual guidance that is not a single command.
    Manual {
        verb: &'static str,
        instruction: String,
    },
    /// A reference to documentation.
    Documentation { reference: String },
}

/// What the operator should do to resolve a doctor row's warning or failure.
///
/// The renderer formats each variant differently; rows must select the
/// variant that honestly describes the recovery, never wrapping prose
/// as a fake command.
///
/// For rows needing multiple hints, use `Recovery::Multi` with a list
/// of `RecoveryHint` values. The renderer composes them with appropriate
/// connectors (`recover with:`, `acknowledge with:`, `or investigate:`).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum Recovery {
    /// A real, executable command. Rendered as:
    ///   `recover with: <command>`
    Command(String),

    /// A real command followed by manual context the operator must
    /// understand to run it correctly. Rendered as:
    ///   `recover with: <command>`
    ///   `             <context>`
    CommandWithContext { command: String, context: String },

    /// Manual guidance that is not a single command. Rendered as:
    ///   `<guidance>`
    /// No "Run X when convenient" wrapper. The guidance stands alone
    /// as prose.
    Manual(String),

    /// A reference to documentation the operator should read before
    /// acting. Rendered as:
    ///   `see: <path or URL>`
    Documentation(String),

    /// No recovery action. Rendered as nothing.
    None,

    /// Multiple recovery hints with explicit connectors.
    /// Rendered with appropriate visual separation and `or`/`also`
    /// connectors based on the count and relationship between hints.
    Multi(Vec<RecoveryHint>),
}

impl Recovery {
    /// Return the operator-visible text for this recovery, if any.
    pub fn text(&self) -> Option<&str> {
        match self {
            Recovery::Command(s) => Some(s),
            Recovery::CommandWithContext { command, .. } => Some(command),
            Recovery::Manual(s) => Some(s),
            Recovery::Documentation(s) => Some(s),
            Recovery::None => None,
            Recovery::Multi(hints) => hints.first().map(|h| match h {
                RecoveryHint::Command { command, .. } => command.as_str(),
                RecoveryHint::Manual { instruction, .. } => instruction.as_str(),
                RecoveryHint::Documentation { reference } => reference.as_str(),
            }),
        }
    }
}

/// Result of a single diagnostic check.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    pub recovery: Recovery,
}

impl DiagnosticCheck {
    /// True when this check represents an optional feature that is not
    /// configured, as opposed to a genuine failure or unknown state.
    pub fn is_optional_not_configured(&self) -> bool {
        if self.status != CheckStatus::Unknown {
            return false;
        }
        // These checks are optional features; Unknown means "not configured."
        // Other checks use Unknown to mean "cannot determine" (e.g. daemon
        // not running), which is not the same as optional-not-configured.
        matches!(self.name.as_str(), "Attest key" | "Socket")
    }
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
    #[serde(default)]
    pub fanotify_mark_reduced_coverage: u64,
    #[serde(default)]
    pub fanotify_tier: u64,
}

/// Lightweight health snapshot produced by the privileged daemon.
/// Lets unprivileged CLI invocations report useful state without direct DB access.
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

/// Produce the summary line for doctor verbose output.
///
/// Distinguishes healthy checks, failures, warnings, and optional
/// features that are not configured.
pub fn format_doctor_summary(checks: &[DiagnosticCheck]) -> String {
    let healthy = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Ok)
        .count();
    let failures = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Failed)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warning)
        .count();
    let optional = checks
        .iter()
        .filter(|c| c.is_optional_not_configured())
        .count();

    let optional_suffix = if optional > 0 {
        format!(
            "; {}",
            crate::util::pluralize(
                optional as u64,
                "optional feature not configured",
                "optional features not configured"
            )
        )
    } else {
        String::new()
    };

    if failures == 0 && warnings == 0 {
        if optional > 0 {
            format!("all checks passed{}", optional_suffix)
        } else {
            "all checks passed".to_string()
        }
    } else if failures > 0 && warnings > 0 {
        format!(
            "{}; {}; {} healthy{}",
            crate::util::pluralize(failures as u64, "failure", "failures"),
            crate::util::pluralize(warnings as u64, "warning", "warnings"),
            healthy,
            optional_suffix,
        )
    } else if failures > 0 {
        format!(
            "{}; {} healthy{}",
            crate::util::pluralize(failures as u64, "failure", "failures"),
            healthy,
            optional_suffix,
        )
    } else {
        format!(
            "{}; {} healthy{}",
            crate::util::pluralize(warnings as u64, "warning", "warnings"),
            healthy,
            optional_suffix
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
    let mut checks_vec = Vec::with_capacity(16);

    let (daemon_check, daemon_probe) = checks::check_daemon(config);
    checks_vec.push(daemon_check);
    checks_vec.push(checks::check_daemon_state(config, daemon_probe.running));
    checks_vec.push(checks::check_backend(config, daemon_probe.running));
    checks_vec.push(checks::check_realtime_coverage(
        config,
        daemon_probe.running,
    ));
    checks_vec.push(checks::check_control_socket(config));
    checks_vec.push(checks::check_baseline(config));
    checks_vec.push(checks::check_database_integrity(config));
    checks_vec.push(checks::check_audit_log(config));
    checks_vec.push(checks::check_audit_retention(config));
    checks_vec.push(checks::check_audit_trajectory(config));
    checks_vec.push(checks::check_storage(config));
    checks_vec.push(checks::check_wal_pipeline(config, daemon_probe.running));
    checks_vec.push(checks::check_config(config));
    checks_vec.push(checks::check_scan_timer(config));
    checks_vec.push(checks::check_hmac_key(config));
    checks_vec.push(checks::check_attest_key());
    checks_vec.push(checks::check_package_hooks(config));
    checks_vec.push(checks::check_notify_send());
    checks_vec.push(checks::check_signal_socket(config));

    checks_vec
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
            recovery: Recovery::Command("sudo vigil doctor".into()),
        });
    }

    let count = baseline.entry_count?;
    if count <= 0 {
        return Some(DiagnosticCheck {
            name: "Baseline".to_string(),
            status: CheckStatus::Failed,
            detail: format!("no baseline found (daemon snapshot {})", snapshot_age),
            recovery: Recovery::Command("vigil init".into()),
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
                    recovery: Recovery::Command("vigil baseline refresh".into()),
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
                    recovery: Recovery::None,
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
            recovery: Recovery::None,
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
            recovery: Recovery::Command("sudo vigil doctor".into()),
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
            recovery: Recovery::Command(
                "sudo systemctl restart vigild.service && sudo vigil doctor".into(),
            ),
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
        recovery: Recovery::Command("sudo vigil doctor".into()),
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
            recovery: Recovery::Command("sudo vigil doctor".into()),
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
        recovery: Recovery::Command("sudo vigil doctor".into()),
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

/// Open a database read-only (private delegate to db::access).
fn open_existing_db(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    crate::db::access::open_existing_db(path)
}

fn format_count(value: u64) -> String {
    crate::display::fmt_count(value)
}

fn format_size(bytes: u64) -> String {
    crate::display::fmt_size(bytes)
}

#[cfg(test)]
mod tests {
    use super::checks::*;
    use super::recovery::*;
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn insert_hook_failure_event_for_test(
        cfg: &crate::config::Config,
        backend: &str,
        trigger_ts: &str,
    ) -> i64 {
        let conn = crate::db::open_audit_db(cfg).expect("open audit db");
        let payload = serde_json::json!({
            "event_kind": "hook_invocation_failure",
            "backend": backend,
            "trigger_timestamp": trigger_ts,
            "description": "hook invocation failure",
        });
        let payload_json = serde_json::to_string(&payload).expect("serialize payload");
        let previous_chain_hash = crate::db::audit_ops::get_last_chain_hash(&conn)
            .expect("read chain")
            .unwrap_or_else(|| {
                blake3::hash(b"vigil-audit-chain-genesis")
                    .to_hex()
                    .to_string()
            });
        let (_, seq) = crate::db::audit_ops::insert_doctor_event_entry(
            &conn,
            crate::db::audit_path::AuditEventPath::HookFailure.as_str(),
            &payload_json,
            &previous_chain_hash,
            None,
        )
        .expect("insert event");
        seq
    }

    fn insert_hook_ack_for_test(
        cfg: &crate::config::Config,
        event_sequence: i64,
        note: Option<String>,
    ) {
        insert_ack_for_test(
            cfg,
            crate::ack::DoctorEventKind::HookInvocationFailure,
            event_sequence,
            note,
        );
    }

    fn insert_ack_for_test(
        cfg: &crate::config::Config,
        kind: crate::ack::DoctorEventKind,
        event_sequence: i64,
        note: Option<String>,
    ) {
        let conn = crate::db::open_audit_db(cfg).expect("open audit db");
        let payload = crate::ack::build_operator_payload(
            kind,
            event_sequence,
            crate::ack::AcknowledgmentKind::Acknowledge,
            note,
        );
        let payload_json = serde_json::to_string(&payload).expect("serialize ack");
        let previous_chain_hash = crate::db::audit_ops::get_last_chain_hash(&conn)
            .expect("read chain")
            .unwrap_or_else(|| {
                blake3::hash(b"vigil-audit-chain-genesis")
                    .to_hex()
                    .to_string()
            });
        let _ = crate::db::audit_ops::insert_acknowledgment_entry(
            &conn,
            &payload_json,
            &previous_chain_hash,
            None,
        )
        .expect("insert ack");
    }

    fn latest_event_seq_for_path(cfg: &crate::config::Config, path: &str) -> i64 {
        let conn = crate::db::open_audit_db(cfg).expect("open audit db");
        conn.query_row(
            "SELECT id FROM audit_log WHERE path = ?1 ORDER BY id DESC LIMIT 1",
            rusqlite::params![path],
            |row| row.get::<_, i64>(0),
        )
        .expect("event sequence for path")
    }

    #[test]
    fn diagnostics_returns_expected_number_of_checks() {
        let cfg = crate::config::default_config();
        let checks = run_diagnostics(&cfg);
        assert_eq!(checks.len(), 19);
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
            recovery: Recovery::None,
        }];
        assert_eq!(diagnostics_exit_code(&ok), 0);

        let warning = vec![DiagnosticCheck {
            name: "x".to_string(),
            status: CheckStatus::Warning,
            detail: "warn".to_string(),
            recovery: Recovery::None,
        }];
        assert_eq!(diagnostics_exit_code(&warning), 1);

        let failed = vec![DiagnosticCheck {
            name: "x".to_string(),
            status: CheckStatus::Failed,
            detail: "fail".to_string(),
            recovery: Recovery::None,
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
        assert!(
            matches!(check.recovery, Recovery::Command(ref cmd) if cmd == "sudo vigil doctor"),
            "expected Recovery::Command for elevated privileges"
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
            recovery: Recovery::None,
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
            recovery: Recovery::None,
        }];
        let verdict = diagnostics_verdict(&checks);
        assert!(verdict.contains("1 issue"), "got: {}", verdict);
        assert!(!verdict.contains("1 issues"));
    }

    #[test]
    fn no_duplicate_check_names() {
        let cfg = crate::config::default_config();
        let checks = run_diagnostics(&cfg);
        let mut seen = std::collections::HashSet::new();
        for check in &checks {
            assert!(
                seen.insert(&check.name),
                "duplicate check name: {}",
                check.name
            );
        }
    }

    #[test]
    fn hooks_row_acknowledged_renders_with_circle_marker_and_metadata() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let event_seq = insert_hook_failure_event_for_test(&cfg, "pacman", "2026-04-24T10:00");
        insert_hook_ack_for_test(&cfg, event_seq, Some("investigated".to_string()));

        let ack_state = hook_failure_ack_state(&cfg, "pacman", "2026-04-24T10:00")
            .expect("ack state for existing event");

        let check = DiagnosticCheck {
            name: "Hooks".to_string(),
            status: CheckStatus::Unknown,
            detail: "installed (pacman pre/post); last trigger 2026-04-24T10:00 failed".to_string(),
            recovery: acknowledged_hook_recovery(
                ack_state.ack_timestamp,
                ack_state.operator_uid,
                ack_state.note,
                "journalctl -t vigil-pacman",
            ),
        };

        assert_eq!(check.status.marker(), "○");
        match check.recovery {
            Recovery::Multi(hints) => {
                assert!(hints.iter().any(|h| {
                    matches!(h, RecoveryHint::Manual { verb, instruction } if *verb == "acknowledged" && instruction.contains("uid"))
                }));
                assert!(hints.iter().any(|h| {
                    matches!(h, RecoveryHint::Manual { verb, instruction } if *verb == "note" && instruction.contains("investigated"))
                }));
            }
            _ => panic!("expected Recovery::Multi"),
        }
    }

    #[test]
    fn hooks_row_recurrence_after_ack_warns_with_fresh_event_data() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let old_event = insert_hook_failure_event_for_test(&cfg, "pacman", "2026-04-24T09:00");
        insert_hook_ack_for_test(&cfg, old_event, None);

        let old_state = hook_failure_ack_state(&cfg, "pacman", "2026-04-24T09:00");
        assert!(old_state.is_some(), "old event should be acknowledged");

        let fresh_state = hook_failure_ack_state(&cfg, "pacman", "2026-04-24T10:00");
        assert!(
            fresh_state.is_none(),
            "fresh event must not inherit prior ack"
        );

        let status = if fresh_state.is_some() {
            CheckStatus::Unknown
        } else {
            CheckStatus::Warning
        };
        assert_eq!(status, CheckStatus::Warning);
        assert_eq!(status.marker(), "⚠");
    }

    #[test]
    fn baseline_refresh_recurrence_after_ack_warns_with_fresh_last_refresh() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        let old_state = baseline_refresh_ack_state(&cfg, 1000);
        assert!(
            old_state.is_none(),
            "new stale-refresh event starts unacked"
        );

        let old_seq = latest_event_seq_for_path(
            &cfg,
            crate::db::audit_path::AuditEventPath::BaselineRefreshFailure.as_str(),
        );
        insert_ack_for_test(
            &cfg,
            crate::ack::DoctorEventKind::BaselineRefreshFailure,
            old_seq,
            Some("scheduled refresh window".to_string()),
        );

        assert!(
            baseline_refresh_ack_state(&cfg, 1000).is_some(),
            "same event should be acknowledged"
        );
        assert!(
            baseline_refresh_ack_state(&cfg, 2000).is_none(),
            "fresh stale-refresh episode must not inherit prior ack"
        );
    }

    #[test]
    fn chain_break_acknowledged_renders_metadata_but_keeps_warning_marker() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        assert!(
            audit_chain_break_ack_state(&cfg, 42).is_none(),
            "new chain-break event starts unacked"
        );
        let seq = latest_event_seq_for_path(
            &cfg,
            crate::db::audit_path::AuditEventPath::AuditChainBreak.as_str(),
        );
        insert_ack_for_test(
            &cfg,
            crate::ack::DoctorEventKind::AuditChainBreak,
            seq,
            Some("captured forensic copy".to_string()),
        );

        let ack_state =
            audit_chain_break_ack_state(&cfg, 42).expect("ack state for chain-break event");
        let check = DiagnosticCheck {
            name: "Audit log".to_string(),
            status: CheckStatus::Warning,
            detail: "tampered at entry 42".to_string(),
            recovery: chain_break_acknowledged_recovery(
                ack_state.ack_timestamp,
                ack_state.operator_uid,
                ack_state.note,
            ),
        };
        assert_eq!(check.status.marker(), "⚠");
        match check.recovery {
            Recovery::Multi(hints) => {
                assert!(hints.iter().any(|h| {
                    matches!(h, RecoveryHint::Manual { verb, instruction } if *verb == "acknowledged" && instruction.contains("uid"))
                }));
            }
            _ => panic!("expected Recovery::Multi"),
        }

        assert!(
            audit_chain_break_ack_state(&cfg, 43).is_none(),
            "new break id must warn afresh"
        );
    }

    #[test]
    fn degraded_acknowledgment_adds_context_but_keeps_failed_marker() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        assert!(
            daemon_degraded_ack_state(&cfg, "baseline_db_replaced", "2026-04-24T10:00").is_none(),
            "new degraded event starts unacked"
        );
        let seq = latest_event_seq_for_path(
            &cfg,
            crate::db::audit_path::AuditEventPath::DaemonDegraded.as_str(),
        );
        insert_ack_for_test(&cfg, crate::ack::DoctorEventKind::DaemonDegraded, seq, None);

        let ack_state = daemon_degraded_ack_state(&cfg, "baseline_db_replaced", "2026-04-24T10:00")
            .expect("ack state for degraded event");
        let check = DiagnosticCheck {
            name: "State".to_string(),
            status: CheckStatus::Failed,
            detail: "degraded: baseline_db_replaced".to_string(),
            recovery: daemon_degraded_acknowledged_recovery(
                "baseline_db_replaced",
                ack_state.ack_timestamp,
                ack_state.operator_uid,
                ack_state.note,
            ),
        };
        assert_eq!(check.status.marker(), "✗");
    }

    #[test]
    fn retention_failure_recurrence_after_ack_warns_with_fresh_cap() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cfg = crate::config::default_config();
        cfg.daemon.db_path = dir.path().join("baseline.db");

        assert!(
            retention_failure_ack_state(&cfg, 512).is_none(),
            "new retention event starts unacked"
        );
        let seq = latest_event_seq_for_path(
            &cfg,
            crate::db::audit_path::AuditEventPath::RetentionSweepFailure.as_str(),
        );
        insert_ack_for_test(
            &cfg,
            crate::ack::DoctorEventKind::RetentionSweepFailure,
            seq,
            None,
        );

        assert!(
            retention_failure_ack_state(&cfg, 512).is_some(),
            "same retention event should be acknowledged"
        );
        assert!(
            retention_failure_ack_state(&cfg, 1024).is_none(),
            "fresh cap episode should not inherit prior ack"
        );
    }
}
