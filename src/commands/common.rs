//! Shared CLI helpers: config resolution, control socket, timestamp parsing, pager.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use vigil::display;
use vigil::types::Change;

/// Print a section header with Unicode box-drawing separator.
pub(crate) fn print_header(title: &str) {
    println!();
    println!("{}", title);
    println!("{}", "═".repeat(title.len()));
    println!();
}

pub(crate) fn format_count(value: u64) -> String {
    display::fmt_count(value)
}

/// Truncate a hash to 16 hex chars for display.
pub(crate) fn truncate_hash(hash: &str) -> &str {
    display::truncate_hash(hash)
}

/// Print detail lines for a single Change variant.
pub(crate) fn print_change_detail(change: &Change) {
    match change {
        Change::ContentModified { old_hash, new_hash } => {
            println!(
                "    content: {} → {}",
                truncate_hash(old_hash),
                truncate_hash(new_hash)
            );
        }
        Change::PermissionsChanged { old, new } => {
            println!("    permissions: {:04o} → {:04o}", old, new);
        }
        Change::OwnerChanged {
            old_uid,
            new_uid,
            old_gid,
            new_gid,
        } => {
            println!(
                "    owner: {}:{} → {}:{}",
                old_uid, old_gid, new_uid, new_gid
            );
        }
        Change::InodeChanged { old, new } => {
            println!("    inode: {} → {}", old, new);
        }
        Change::TypeChanged { old, new } => {
            println!("    type: {} → {}", old, new);
        }
        Change::SymlinkTargetChanged { old, new } => {
            println!("    symlink: {} → {}", old.display(), new.display());
        }
        Change::CapabilitiesChanged { old, new } => {
            println!(
                "    capabilities: {} → {}",
                old.as_deref().unwrap_or("none"),
                new.as_deref().unwrap_or("none")
            );
        }
        Change::XattrChanged { key, old, new } => {
            println!(
                "    xattr {}: {} → {}",
                key,
                old.as_deref().unwrap_or("none"),
                new.as_deref().unwrap_or("none")
            );
        }
        Change::SecurityContextChanged { old, new } => {
            println!("    security context: {} → {}", old, new);
        }
        Change::SizeChanged { old, new } => {
            println!("    size: {} → {} bytes", old, new);
        }
        Change::DeviceChanged { old, new } => {
            println!("    device: {} → {}", old, new);
        }
        Change::Deleted => {
            println!("    file deleted from filesystem");
        }
        Change::Created => {
            println!("    new file not in baseline");
        }
    }
}

/// Pipe output through $PAGER (defaulting to `less -R`) for long output.
pub(crate) fn pipe_to_pager(output: &str) {
    if output.is_empty() {
        return;
    }

    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".into());
    let pager = pager.trim();
    if pager.is_empty() {
        print!("{}", output);
        return;
    }

    let mut parts: Vec<&str> = pager.split_whitespace().collect();
    if parts.is_empty() {
        print!("{}", output);
        return;
    }

    let cmd = parts.remove(0);
    let mut args = parts;

    // Add -R to preserve ANSI colors in less
    if cmd == "less" && !args.iter().any(|a| a.contains('R')) {
        args.push("-R");
    }

    match ProcessCommand::new(cmd)
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(output.as_bytes());
            }
            let _ = child.wait();
        }
        Err(_) => {
            // Pager failed; fall back to direct print
            print!("{}", output);
        }
    }
}

pub(crate) fn parse_time_filter_strict(input: &str, flag_name: &str) -> vigil::Result<Option<i64>> {
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok(None);
    }

    parse_time_filter(trimmed)
        .map(Some)
        .ok_or_else(|| {
            vigil::VigilError::Config(format!(
                "invalid {} value '{}'; expected 24h, 7d, today, YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS, or unix timestamp",
                flag_name, input
            ))
        })
}

pub(crate) fn parse_time_filter(input: &str) -> Option<i64> {
    let input = input.trim();
    let lower = input.to_ascii_lowercase();

    if let Some(hours) = lower.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        return Some(chrono::Utc::now().timestamp() - (hours * 3600));
    }
    if let Some(days) = lower.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        return Some(chrono::Utc::now().timestamp() - (days * 86400));
    }
    if lower == "today" {
        let today = chrono::Local::now().date_naive().and_hms_opt(0, 0, 0)?;
        return Some(today.and_local_timezone(chrono::Local).unwrap().timestamp());
    }
    if lower == "all" {
        return None;
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        let dt = date.and_hms_opt(0, 0, 0)?;
        return Some(dt.and_local_timezone(chrono::Local).unwrap().timestamp());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_local_timezone(chrono::Local).unwrap().timestamp());
    }
    input.parse::<i64>().ok()
}

/// Resolve the config file path that should be updated.
pub(crate) fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    if let Ok(env_path) = std::env::var("VIGIL_CONFIG") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    let etc = PathBuf::from("/etc/vigil/vigil.toml");
    if etc.exists() {
        return Some(etc);
    }
    // If no config file exists yet, create in /etc/vigil/
    Some(etc)
}

/// Update specific keys in a TOML config file. Creates the file and sections if needed.
pub(crate) fn update_config_toml(path: &Path, updates: &[(&str, &str, &str)]) -> vigil::Result<()> {
    let content = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .map_err(|e| vigil::VigilError::Config(format!("failed to parse TOML: {}", e)))?;

    for &(section, key, value) in updates {
        if doc.get(section).is_none() {
            doc[section] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let val: toml_edit::Value = value.parse().map_err(|e| {
            vigil::VigilError::Config(format!("invalid TOML value '{}': {}", value, e))
        })?;
        doc[section][key] = toml_edit::value(val);
    }

    std::fs::write(path, doc.to_string())?;
    Ok(())
}

pub(crate) fn format_audit_timestamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| {
            let local = dt.with_timezone(&chrono::Local);
            let now = chrono::Local::now();
            if local.date_naive() == now.date_naive() {
                local.format("today %H:%M:%S").to_string()
            } else if local.date_naive() == (now - chrono::Duration::days(1)).date_naive() {
                local.format("yesterday %H:%M:%S").to_string()
            } else if (now - local).num_days() < 7 {
                local.format("%A %H:%M:%S").to_string()
            } else {
                local.format("%Y-%m-%d %H:%M:%S").to_string()
            }
        })
        .unwrap_or_else(|| ts.to_string())
}

pub(crate) fn query_control_socket(
    socket_path: &Path,
    request: &str,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send request
    (&stream).write_all(request.as_bytes())?;
    (&stream).write_all(b"\n")?;
    (&stream).flush()?;

    let mut reader = BufReader::new(&stream);
    let mut first_line = String::new();
    reader.read_line(&mut first_line)?;

    let first_value: serde_json::Value = serde_json::from_str(first_line.trim())?;

    // If the server sent a challenge, reconnect with authenticated request
    if first_value
        .get("challenge")
        .and_then(|v| v.as_str())
        .is_some()
    {
        drop(reader);
        drop(stream);
        return query_control_socket_authenticated(socket_path, request);
    }

    // No challenge; use first_value as the response
    if first_value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(first_value)
    } else {
        Err(first_value
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error")
            .into())
    }
}

fn query_control_socket_authenticated(
    socket_path: &Path,
    request: &str,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Read challenge
    let mut reader = BufReader::new(&stream);
    let mut challenge_line = String::new();
    reader.read_line(&mut challenge_line)?;
    let challenge: serde_json::Value = serde_json::from_str(challenge_line.trim())?;
    let nonce = challenge
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or("missing challenge nonce")?;

    // Load HMAC key and compute response
    let hmac_key_path = std::path::PathBuf::from("/etc/vigil/hmac.key");
    let key = vigil::hmac::load_hmac_key(&hmac_key_path)?;
    let hmac_response = vigil::hmac::compute_hmac(&key, nonce.as_bytes())?;

    // Build authenticated request
    let mut req_value: serde_json::Value = serde_json::from_str(request)?;
    if let Some(obj) = req_value.as_object_mut() {
        obj.insert("response".into(), serde_json::Value::String(hmac_response));
    }
    let auth_request = serde_json::to_string(&req_value)?;

    // Need to drop reader to get mutable access to stream
    drop(reader);
    (&stream).write_all(auth_request.as_bytes())?;
    (&stream).write_all(b"\n")?;
    (&stream).flush()?;

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;
    let value: serde_json::Value = serde_json::from_str(&response)?;
    if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(value)
    } else {
        Err(value
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error")
            .into())
    }
}
