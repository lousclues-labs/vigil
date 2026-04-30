//! `vigil why <path>` subcommand: explain a single change with facts only.

use std::path::Path;

use vigil::db;
use vigil::doctor;
use vigil::types::OutputFormat;

pub(crate) fn cmd_why(
    config_path: Option<&Path>,
    target: Option<&Path>,
    format: OutputFormat,
) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;

    let audit_path = db::audit_db_path(&cfg);
    if !audit_path.exists() {
        eprintln!("No audit log found at {}", audit_path.display());
        eprintln!();
        eprintln!("The daemon may not have started yet. Check: vigil status");
        return Ok(1);
    }

    let audit_conn = match doctor::open_existing_db_pub(&audit_path) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Cannot open audit log at {}: {}", audit_path.display(), e);
            return Ok(1);
        }
    };

    // If no path given, show the most recent change
    let entry = if let Some(path) = target {
        get_latest_for_path(&audit_conn, path)?
    } else {
        get_most_recent(&audit_conn)?
    };

    let entry = match entry {
        Some(e) => e,
        None => {
            if let Some(path) = target {
                eprintln!("No changes recorded for {}", path.display());
                eprintln!();
                eprintln!("This path may not be in any watch group. Check: vigil config show");
            } else {
                eprintln!("No changes recorded in the audit log.");
                eprintln!();
                eprintln!("The daemon may not have detected anything yet. Check: vigil status");
            }
            return Ok(0);
        }
    };

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(0);
    }

    print_why(&entry, &cfg);
    Ok(0)
}

#[derive(Debug, serde::Serialize)]
struct WhyEntry {
    path: String,
    timestamp: i64,
    timestamp_human: String,
    changes: Vec<WhyChange>,
    process_pid: Option<i32>,
    process_exe: Option<String>,
    attribution_method: Option<String>,
    maintenance_window: bool,
    group: Option<String>,
    severity: String,
    package_owner: Option<String>,
    history_count: Option<u64>,
    /// Forensic disambiguation result (v1.8.1+); `None` for older rows or
    /// when disambiguation was disabled at detection time.
    #[serde(skip_serializing_if = "Option::is_none")]
    disambiguation: Option<vigil::hash::DisambiguationResult>,
}

#[derive(Debug, serde::Serialize)]
struct WhyChange {
    field: String,
    detail: String,
}

fn print_why(entry: &WhyEntry, _cfg: &vigil::config::Config) {
    let path = &entry.path;
    eprintln!("{} changed at {}.", path, entry.timestamp_human);

    eprintln!();
    eprintln!("Changes:");
    for c in &entry.changes {
        eprintln!("  {:<14} {}", c.field, c.detail);
    }

    if entry.process_pid.is_some() || entry.process_exe.is_some() {
        eprintln!();
        eprintln!("Attribution:");
        if let (Some(pid), Some(ref exe)) = (entry.process_pid, &entry.process_exe) {
            eprintln!("  pid {}, {}", pid, exe);
        } else if let Some(pid) = entry.process_pid {
            eprintln!("  pid {}", pid);
        } else if let Some(ref exe) = entry.process_exe {
            eprintln!("  {}", exe);
        }
        if let Some(ref method) = entry.attribution_method {
            eprintln!("  method:    {}", method);
        }
    }

    eprintln!();
    eprintln!("Context:");
    if entry.maintenance_window {
        eprintln!("  A maintenance window was active.");
    } else {
        eprintln!("  No maintenance window was active.");
    }
    if let Some(ref group) = entry.group {
        eprintln!("  Group: [{}], severity: {}.", group, entry.severity);
    }
    if let Some(ref pkg) = entry.package_owner {
        eprintln!("  Package owner: {}.", pkg);
    }

    if let Some(ref disamb) = entry.disambiguation {
        eprintln!();
        eprintln!("Disambiguation: {}", disamb.label());
        eprintln!("  {}", disamb.description());
        if matches!(disamb, vigil::hash::DisambiguationResult::PageCacheOnly) {
            eprintln!();
            eprintln!("  The audit chain has preserved this detection. The live");
            eprintln!("  filesystem may have since reverted (page cache evicted by");
            eprintln!("  memory pressure or reboot).");
            eprintln!();
            eprintln!("  Suggested next steps:");
            eprintln!("    - Check kernel version: uname -r");
            eprintln!("    - Check for known page cache CVEs against your kernel");
            eprintln!("    - Review process attribution above");
        }
    }

    if let Some(count) = entry.history_count {
        eprintln!();
        eprintln!("Historical (informational, not a judgment):");
        eprintln!(
            "  This path appears in the audit log {} times in the last 30 days.",
            count
        );
        eprintln!(
            "  See `vigil audit show --path '{}' --since 30d` for the full record.",
            path
        );
    }
}

fn get_latest_for_path(
    conn: &rusqlite::Connection,
    path: &Path,
) -> vigil::Result<Option<WhyEntry>> {
    let path_str = path.to_string_lossy();

    let row = conn.query_row(
        "SELECT id, timestamp, path, change_type, severity, monitored_group, \
         responsible_pid, responsible_exe, package, maintenance_window, \
         changes_json, suppressed \
         FROM audit_log WHERE path = ?1 \
         ORDER BY timestamp DESC LIMIT 1",
        [path_str.as_ref()],
        |row| {
            Ok(AuditRow {
                _id: row.get(0)?,
                timestamp: row.get(1)?,
                path: row.get(2)?,
                change_type: row.get(3)?,
                severity: row.get(4)?,
                group: row.get(5)?,
                pid: row.get(6)?,
                exe: row.get(7)?,
                package: row.get(8)?,
                maintenance: row.get(9)?,
                changes_json: row.get(10)?,
                _suppressed: row.get(11)?,
            })
        },
    );

    match row {
        Ok(r) => Ok(Some(audit_row_to_why(conn, r)?)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(vigil::VigilError::Database(e)),
    }
}

fn get_most_recent(conn: &rusqlite::Connection) -> vigil::Result<Option<WhyEntry>> {
    let row = conn.query_row(
        "SELECT id, timestamp, path, change_type, severity, monitored_group, \
         responsible_pid, responsible_exe, package, maintenance_window, \
         changes_json, suppressed \
         FROM audit_log \
         ORDER BY timestamp DESC LIMIT 1",
        [],
        |row| {
            Ok(AuditRow {
                _id: row.get(0)?,
                timestamp: row.get(1)?,
                path: row.get(2)?,
                change_type: row.get(3)?,
                severity: row.get(4)?,
                group: row.get(5)?,
                pid: row.get(6)?,
                exe: row.get(7)?,
                package: row.get(8)?,
                maintenance: row.get(9)?,
                changes_json: row.get(10)?,
                _suppressed: row.get(11)?,
            })
        },
    );

    match row {
        Ok(r) => Ok(Some(audit_row_to_why(conn, r)?)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(vigil::VigilError::Database(e)),
    }
}

struct AuditRow {
    _id: i64,
    timestamp: i64,
    path: String,
    change_type: String,
    severity: String,
    group: Option<String>,
    pid: Option<i32>,
    exe: Option<String>,
    package: Option<String>,
    maintenance: bool,
    changes_json: Option<String>,
    _suppressed: bool,
}

fn audit_row_to_why(conn: &rusqlite::Connection, row: AuditRow) -> vigil::Result<WhyEntry> {
    let timestamp_human = doctor::format_relative_timestamp(row.timestamp);

    let changes = parse_changes(&row.change_type, row.changes_json.as_deref());

    // Count historical occurrences in last 30 days
    let thirty_days_ago = chrono::Utc::now().timestamp() - (30 * 86_400);
    let history_count: Option<u64> = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE path = ?1 AND timestamp >= ?2",
            rusqlite::params![&row.path, thirty_days_ago],
            |r| r.get::<_, i64>(0),
        )
        .ok()
        .map(|c| c.max(0) as u64);

    // Determine attribution method
    let attribution_method = if row.pid.is_some() {
        Some("pidfd (race-resistant)".to_string())
    } else {
        None
    };

    Ok(WhyEntry {
        path: row.path,
        timestamp: row.timestamp,
        timestamp_human,
        changes,
        process_pid: row.pid,
        process_exe: row.exe,
        attribution_method,
        maintenance_window: row.maintenance,
        group: row.group,
        severity: row.severity,
        package_owner: row.package,
        history_count,
        disambiguation: get_disambiguation(conn, row._id),
    })
}

/// Best-effort: fetch the disambiguation column for the given audit row.
/// Returns None on schema mismatch (column absent in older DBs), parse
/// failure, or missing row.
fn get_disambiguation(
    conn: &rusqlite::Connection,
    row_id: i64,
) -> Option<vigil::hash::DisambiguationResult> {
    let json: Option<String> = conn
        .query_row(
            "SELECT disambiguation FROM audit_log WHERE id = ?1",
            [row_id],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    json.and_then(|s| serde_json::from_str(&s).ok())
}

fn parse_changes(change_type: &str, changes_json: Option<&str>) -> Vec<WhyChange> {
    let mut out = Vec::new();

    if let Some(json) = changes_json {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json) {
            for item in &arr {
                if let Some(obj) = item.as_object() {
                    for (key, val) in obj {
                        let (field, detail) = match key.as_str() {
                            "ContentModified" => {
                                ("content".to_string(), "BLAKE3 hash differs".to_string())
                            }
                            "PermissionsChanged" => {
                                let old = val.get("old").and_then(|v| v.as_u64()).unwrap_or(0);
                                let new = val.get("new").and_then(|v| v.as_u64()).unwrap_or(0);
                                (
                                    "permissions".to_string(),
                                    format!("{:04o} -> {:04o}", old, new),
                                )
                            }
                            "OwnerChanged" => {
                                let old_uid =
                                    val.get("old_uid").and_then(|v| v.as_u64()).unwrap_or(0);
                                let new_uid =
                                    val.get("new_uid").and_then(|v| v.as_u64()).unwrap_or(0);
                                (
                                    "owner".to_string(),
                                    format!("uid {} -> {}", old_uid, new_uid),
                                )
                            }
                            "InodeChanged" => {
                                let old = val.get("old").and_then(|v| v.as_u64()).unwrap_or(0);
                                let new = val.get("new").and_then(|v| v.as_u64()).unwrap_or(0);
                                ("inode".to_string(), format!("{} -> {}", old, new))
                            }
                            "Deleted" => ("status".to_string(), "deleted".to_string()),
                            "Created" => ("status".to_string(), "created".to_string()),
                            _ => (
                                key.to_lowercase().replace("changed", ""),
                                "changed".to_string(),
                            ),
                        };
                        out.push(WhyChange { field, detail });
                    }
                }
            }
        }
    }

    if out.is_empty() {
        out.push(WhyChange {
            field: change_type.replace('_', " "),
            detail: "detected".to_string(),
        });
    }

    // Add unchanged fields for context
    let has_content = out.iter().any(|c| c.field == "content");
    let has_permissions = out.iter().any(|c| c.field == "permissions");
    let has_owner = out.iter().any(|c| c.field == "owner");
    if !has_permissions && has_content {
        out.push(WhyChange {
            field: "permissions".to_string(),
            detail: "unchanged".to_string(),
        });
    }
    if !has_owner && has_content {
        out.push(WhyChange {
            field: "owner".to_string(),
            detail: "unchanged".to_string(),
        });
    }

    out
}
