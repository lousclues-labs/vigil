//! `vigil baseline` subcommand: refresh via control socket.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use vigil::cli::BaselineAction;

use super::common::format_count;

pub(crate) fn cmd_baseline(
    config_path: Option<&Path>,
    action: BaselineAction,
) -> vigil::Result<()> {
    match action {
        BaselineAction::Refresh { quiet } => cmd_baseline_refresh(config_path, quiet),
    }
}

fn cmd_baseline_refresh(config_path: Option<&Path>, quiet: bool) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    if cfg.daemon.control_socket.as_os_str().is_empty() {
        return Err(vigil::VigilError::Config(
            "control_socket not configured in /etc/vigil/vigil.toml".into(),
        ));
    }

    // Connect to daemon control socket
    let stream = match UnixStream::connect(&cfg.daemon.control_socket) {
        Ok(s) => s,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::ConnectionRefused
            {
                return Err(vigil::VigilError::Daemon(
                    "vigild is not running. Start it first: sudo systemctl start vigild".into(),
                ));
            }
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(vigil::VigilError::PermissionDenied(
                    "cannot connect to vigild control socket. This command requires root.\n\
                     Run: sudo vigil baseline refresh"
                        .into(),
                ));
            }
            return Err(vigil::VigilError::Control(format!(
                "cannot connect to control socket at {}: {}",
                cfg.daemon.control_socket.display(),
                e
            )));
        }
    };

    // Long timeouts for refresh (can take minutes)
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Send request
    let request = r#"{"method":"baseline_refresh"}"#;
    (&stream).write_all(request.as_bytes())?;
    (&stream).write_all(b"\n")?;
    (&stream).flush()?;

    // Handle HMAC challenge if auth is enabled
    let mut reader = BufReader::new(&stream);
    let mut first_line = String::new();
    reader.read_line(&mut first_line)?;
    let first_value: serde_json::Value = match serde_json::from_str(first_line.trim()) {
        Ok(v) => v,
        Err(e) => {
            return Err(vigil::VigilError::Daemon(format!(
                "invalid response from vigild: {}",
                e
            )));
        }
    };

    // If we got a challenge, we need to re-connect with auth.
    // For now, handle the simple case where auth is disabled.
    if first_value.get("challenge").is_some() {
        // Auth is required; use the authenticated path
        drop(reader);
        drop(stream);
        return cmd_baseline_refresh_authenticated(config_path, quiet);
    }

    // Process the first event (might be progress, error, or complete)
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    if !quiet && !is_tty {
        let ts = chrono::Local::now().format("%H:%M:%S");
        eprintln!("[{}] refresh started", ts);
    } else if !quiet {
        eprintln!("Refreshing baseline.");
    }

    // Process the first line we already read
    process_event(&first_value, quiet, is_tty)?;
    if is_terminal_event(&first_value) {
        return finish_event(&first_value, quiet, is_tty);
    }

    // Read remaining streaming events
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(event) => {
                        process_event(&event, quiet, is_tty)?;
                        if is_terminal_event(&event) {
                            return finish_event(&event, quiet, is_tty);
                        }
                    }
                    Err(_) => continue,
                }
            }
            Err(e) => {
                return Err(vigil::VigilError::Control(format!(
                    "lost connection to vigild during refresh: {}",
                    e
                )));
            }
        }
    }

    Ok(())
}

fn is_terminal_event(event: &serde_json::Value) -> bool {
    let ev = event.get("event").and_then(|v| v.as_str()).unwrap_or("");
    ev == "complete" || ev == "error"
}

fn process_event(event: &serde_json::Value, quiet: bool, is_tty: bool) -> vigil::Result<()> {
    if quiet {
        return Ok(());
    }

    let ev = event.get("event").and_then(|v| v.as_str()).unwrap_or("");
    if ev == "progress" {
        let done = event.get("done").and_then(|v| v.as_u64()).unwrap_or(0);
        let total = event.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        let phase = event
            .get("phase")
            .and_then(|v| v.as_str())
            .unwrap_or("scanning");

        if is_tty && total > 0 {
            let pct = (done as f64 / total as f64 * 100.0).min(100.0) as u64;
            let bar_width = 20usize;
            let filled = (pct as usize * bar_width) / 100;
            let empty = bar_width - filled;
            eprint!(
                "\r[{}{}] {}% {}  ({} / {} files)  ",
                "\u{2588}".repeat(filled),
                "\u{2591}".repeat(empty),
                pct,
                phase,
                format_count(done),
                format_count(total),
            );
            let _ = std::io::stderr().flush();
        }
    }

    Ok(())
}

fn finish_event(event: &serde_json::Value, quiet: bool, is_tty: bool) -> vigil::Result<()> {
    let ev = event.get("event").and_then(|v| v.as_str()).unwrap_or("");

    if is_tty {
        // Clear the progress line
        eprint!("\r\x1b[2K");
        let _ = std::io::stderr().flush();
    }

    if ev == "error" {
        let error = event
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(vigil::VigilError::Daemon(error.to_string()));
    }

    if ev == "complete" && !quiet {
        let total = event.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        let duration_ms = event
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let duration_secs = duration_ms / 1000;

        if is_tty {
            eprintln!("Baseline refreshed in {} seconds.", duration_secs);
            eprintln!("  total:    {} files", format_count(total));
            eprintln!();
            eprintln!("Changes during refresh are recorded in the audit log.");
            eprintln!("Review them: vigil audit show --since 2m");
        } else {
            let ts = chrono::Local::now().format("%H:%M:%S");
            eprintln!("[{}] refresh complete: {} files", ts, format_count(total),);
        }
    }

    Ok(())
}

/// Authenticated baseline refresh via HMAC challenge-response.
fn cmd_baseline_refresh_authenticated(
    config_path: Option<&Path>,
    quiet: bool,
) -> vigil::Result<()> {
    let cfg = vigil::config::load_config(config_path)?;

    // Load HMAC key
    let key = vigil::hmac::load_hmac_key(&cfg.security.hmac_key_path)?;

    let stream = UnixStream::connect(&cfg.daemon.control_socket).map_err(|e| {
        vigil::VigilError::Daemon(format!("cannot connect to control socket: {}", e))
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Read challenge
    let mut reader = BufReader::new(&stream);
    let mut challenge_line = String::new();
    reader.read_line(&mut challenge_line)?;
    let challenge: serde_json::Value = serde_json::from_str(challenge_line.trim())
        .map_err(|e| vigil::VigilError::Daemon(format!("invalid challenge: {}", e)))?;

    let nonce = challenge
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| vigil::VigilError::Daemon("missing challenge nonce".into()))?;

    // Compute HMAC response
    let hmac_response = vigil::hmac::compute_hmac(&key, nonce.as_bytes())?;

    // Send authenticated request
    let auth_request = serde_json::json!({
        "method": "baseline_refresh",
        "response": hmac_response,
    });
    (&stream).write_all(serde_json::to_string(&auth_request)?.as_bytes())?;
    (&stream).write_all(b"\n")?;
    (&stream).flush()?;

    // Read streaming events
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    if !quiet {
        if is_tty {
            eprintln!("Refreshing baseline.");
        } else {
            let ts = chrono::Local::now().format("%H:%M:%S");
            eprintln!("[{}] refresh started", ts);
        }
    }

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    let _ = process_event(&event, quiet, is_tty);
                    if is_terminal_event(&event) {
                        return finish_event(&event, quiet, is_tty);
                    }
                }
            }
            Err(e) => {
                return Err(vigil::VigilError::Control(format!(
                    "lost connection to vigild during refresh: {}",
                    e
                )));
            }
        }
    }

    Ok(())
}
