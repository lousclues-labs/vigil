use std::path::Path;

use vigil::db::{self, audit_ops};
use vigil::doctor;
use vigil::types::{OutputFormat, Severity};

/// Per-channel delivery result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelResult {
    pub channel: String,
    pub status: String,
    pub detail: Option<String>,
}

pub(crate) fn cmd_test_alert(
    config_path: Option<&Path>,
    severity: Severity,
    format: OutputFormat,
) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;

    let mut results: Vec<ChannelResult> = Vec::new();

    // Test desktop notification (D-Bus)
    if cfg.alerts.desktop_notifications {
        let result = test_dbus_notification(&severity);
        results.push(result);
    } else {
        results.push(ChannelResult {
            channel: "desktop_notification".to_string(),
            status: "unconfigured".to_string(),
            detail: None,
        });
    }

    // Test journald
    if cfg.alerts.syslog {
        let result = test_journald(&severity);
        results.push(result);
    } else {
        results.push(ChannelResult {
            channel: "journald".to_string(),
            status: "unconfigured".to_string(),
            detail: None,
        });
    }

    // Test JSON log
    if !cfg.alerts.log_file.as_os_str().is_empty() {
        let result = test_json_log(&cfg.alerts.log_file, &severity);
        results.push(result);
    } else {
        results.push(ChannelResult {
            channel: "json_log".to_string(),
            status: "unconfigured".to_string(),
            detail: None,
        });
    }

    // Test signal socket
    if !cfg.hooks.signal_socket.is_empty() {
        let result = test_signal_socket(&cfg.hooks.signal_socket);
        results.push(result);
    } else {
        results.push(ChannelResult {
            channel: "signal_socket".to_string(),
            status: "unconfigured".to_string(),
            detail: None,
        });
    }

    // Record test_alert audit entry
    let audit_path = db::audit_db_path(&cfg);
    if let Ok(conn) = doctor::open_existing_db_pub(&audit_path)
        .or_else(|_| rusqlite::Connection::open(&audit_path))
    {
        let _ = db::schema::create_audit_tables(&conn);
        let last_hash = audit_ops::get_last_chain_hash(&conn)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                blake3::hash(b"vigil-audit-chain-genesis")
                    .to_hex()
                    .to_string()
            });

        let payload = serde_json::json!({
            "test": true,
            "severity": severity.to_string(),
            "channels": results,
        });

        let _ = audit_ops::insert_test_alert_entry(
            &conn,
            &serde_json::to_string(&payload).unwrap_or_default(),
            &severity.to_string(),
            &last_hash,
            None,
        );
    }

    let configured_count = results
        .iter()
        .filter(|r| r.status != "unconfigured")
        .count();
    let failed_count = results.iter().filter(|r| r.status == "failed").count();

    if format == OutputFormat::Json {
        let json = serde_json::json!({
            "test": true,
            "severity": severity.to_string(),
            "channels": results,
            "configured": configured_count,
            "failed": failed_count,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("Testing alert delivery paths...");
        for r in &results {
            let status_display = match r.status.as_str() {
                "ok" => "delivered",
                "failed" => "FAILED",
                "no_listener" => "no listener",
                "unconfigured" => "not configured",
                other => other,
            };

            if let Some(ref detail) = r.detail {
                println!("  {:<34} {}", format!("{}:", r.channel), status_display);
                println!("  {:<34} {}", "", detail);
            } else {
                println!("  {:<34} {}", format!("{}:", r.channel), status_display);
            }
        }

        println!();
        if failed_count == 0 && configured_count > 0 {
            println!("All configured channels reachable.");
        } else if failed_count > 0 {
            println!(
                "{} channel{} failed. Real alerts may not reach you on the failed channels.",
                failed_count,
                if failed_count == 1 { "" } else { "s" }
            );
        } else {
            println!("No alert channels configured.");
        }
    }

    if failed_count > 0 {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn test_dbus_notification(severity: &Severity) -> ChannelResult {
    // Try to send a test notification via notify-send
    let summary = format!("[TEST] Vigil Baseline — {} alert test", severity);
    let body = "This is a test alert from `vigil test alert`. No action required.";

    match std::process::Command::new("notify-send")
        .arg("--app-name=vigil-baseline")
        .arg(&summary)
        .arg(body)
        .output()
    {
        Ok(output) if output.status.success() => ChannelResult {
            channel: "desktop_notification".to_string(),
            status: "ok".to_string(),
            detail: Some("delivered via notify-send".to_string()),
        },
        Ok(output) => ChannelResult {
            channel: "desktop_notification".to_string(),
            status: "failed".to_string(),
            detail: Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        },
        Err(e) => ChannelResult {
            channel: "desktop_notification".to_string(),
            status: "failed".to_string(),
            detail: Some(format!("notify-send not found: {}", e)),
        },
    }
}

fn test_journald(severity: &Severity) -> ChannelResult {
    // Write a test entry to the journal via logger
    let message = format!(
        "vigil test alert: severity={} test=true (from `vigil test alert`)",
        severity
    );

    match std::process::Command::new("logger")
        .arg("--tag")
        .arg("vigil-baseline")
        .arg(&message)
        .output()
    {
        Ok(output) if output.status.success() => ChannelResult {
            channel: "journald".to_string(),
            status: "ok".to_string(),
            detail: Some("delivered via logger".to_string()),
        },
        Ok(output) => ChannelResult {
            channel: "journald".to_string(),
            status: "failed".to_string(),
            detail: Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        },
        Err(e) => ChannelResult {
            channel: "journald".to_string(),
            status: "failed".to_string(),
            detail: Some(format!("logger not found: {}", e)),
        },
    }
}

fn test_json_log(log_file: &Path, severity: &Severity) -> ChannelResult {
    let entry = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "severity": severity.to_string(),
        "path": "vigil:test-alert",
        "test": true,
        "message": "Test alert from `vigil test alert`",
    });

    // Create parent directory if needed
    if let Some(parent) = log_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
    {
        Ok(mut file) => {
            use std::io::Write;
            match writeln!(
                file,
                "{}",
                serde_json::to_string(&entry).unwrap_or_default()
            ) {
                Ok(()) => ChannelResult {
                    channel: "json_log".to_string(),
                    status: "ok".to_string(),
                    detail: Some(format!("delivered to {}", log_file.display())),
                },
                Err(e) => ChannelResult {
                    channel: "json_log".to_string(),
                    status: "failed".to_string(),
                    detail: Some(format!("write error: {}", e)),
                },
            }
        }
        Err(e) => ChannelResult {
            channel: "json_log".to_string(),
            status: "failed".to_string(),
            detail: Some(format!("cannot open {}: {}", log_file.display(), e)),
        },
    }
}

fn test_signal_socket(socket_path: &str) -> ChannelResult {
    use std::os::unix::net::UnixStream;

    match UnixStream::connect(socket_path) {
        Ok(mut stream) => {
            use std::io::Write;
            let payload = serde_json::json!({
                "test": true,
                "severity": "info",
                "message": "Test alert from vigil test alert",
            });
            match writeln!(
                stream,
                "{}",
                serde_json::to_string(&payload).unwrap_or_default()
            ) {
                Ok(()) => ChannelResult {
                    channel: "signal_socket".to_string(),
                    status: "ok".to_string(),
                    detail: Some(format!("delivered to {}", socket_path)),
                },
                Err(e) => ChannelResult {
                    channel: "signal_socket".to_string(),
                    status: "failed".to_string(),
                    detail: Some(format!("write error: {}", e)),
                },
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => ChannelResult {
            channel: "signal_socket".to_string(),
            status: "no_listener".to_string(),
            detail: Some(format!("socket exists but no listener: {}", socket_path)),
        },
        Err(e) => ChannelResult {
            channel: "signal_socket".to_string(),
            status: "failed".to_string(),
            detail: Some(format!("cannot connect to {}: {}", socket_path, e)),
        },
    }
}
