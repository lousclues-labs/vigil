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
                // Discriminate: a non-root operator just needs sudo. A *root*
                // operator hitting EPERM means the socket is owned by another
                // uid -- a stale socket from a previous vigild run as a
                // different user, or worse, a hijack. Telling root to "use
                // sudo" would be operator-hostile and hide a real anomaly.
                if nix::unistd::geteuid().is_root() {
                    return Err(vigil::VigilError::PermissionDenied(format!(
                        "control socket at {} refused connection as root. \
                         The socket is owned by another uid -- this is either a \
                         stale socket from a previous run or a hijack. \
                         Inspect with: ls -l {}; lsof {}",
                        cfg.daemon.control_socket.display(),
                        cfg.daemon.control_socket.display(),
                        cfg.daemon.control_socket.display(),
                    )));
                }
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

/// Marker line the package-manager hooks grep for. Stable contract: changing
/// it breaks the post-transaction notification in hooks/{apt,pacman,dnf}.
///
/// Deliberately not prefixed `vigil:`; that prefix is reserved for audit path
/// discriminators and is enforced by an architecture invariant test.
pub(crate) const UNPROVEN_MARKER: &str = "VIGIL UNPROVEN CHANGES";

/// Report changes the refresh could not prove benign, on stderr, always.
///
/// A refresh absorbs the new on-disk state into the baseline. Everything it
/// absorbs silently becomes the new definition of "correct", so anything it
/// could not prove has to be said out loud exactly once, here, at the moment
/// it is absorbed. Two classes qualify:
///
///   - **mismatch**: a package owns the path and the content is not what that
///     package shipped. Nothing legitimate produces this.
///   - **unattributed**: no package owns the path at all.
///
/// Config files the package marks operator-editable are excluded: the operator
/// is supposed to edit those, so reporting them would be the noise this tool
/// exists to avoid (Principle II).
fn report_unproven_changes(event: &serde_json::Value) {
    let paths = |key: &str| -> Vec<String> {
        event
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };

    let mismatch = paths("pkg_mismatch_paths");
    let unattributed = paths("changed_unattributed_paths");

    if mismatch.is_empty() && unattributed.is_empty() {
        return;
    }

    eprintln!(
        "{}: {} ({} package mismatch, {} unattributed)",
        UNPROVEN_MARKER,
        mismatch.len() + unattributed.len(),
        mismatch.len(),
        unattributed.len()
    );

    // Never truncated (Principle V: Actionable).
    for path in &mismatch {
        eprintln!(
            "  {}    content does not match what its package shipped",
            path
        );
    }
    for path in &unattributed {
        eprintln!("  {}    content modified, no package owns this path", path);
    }
    eprintln!("  investigate: vigil audit show --since 5m");
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

    // Findings are reported regardless of --quiet. `--quiet` means "do not
    // narrate progress", never "hide evidence". The package-manager hooks run
    // this command quietly and non-interactively; before this block existed,
    // the refresh computed exactly the high-signal answer an operator needs
    // after an update and then threw it away (AF-011).
    if ev == "complete" {
        report_unproven_changes(event);
    }

    if ev == "complete" && !quiet {
        let total = event.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        let duration_ms = event
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let duration_secs = duration_ms / 1000;
        let diff_unavailable = event
            .get("diff_unavailable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let added = event.get("added").and_then(|v| v.as_u64()).unwrap_or(0);
        let removed = event.get("removed").and_then(|v| v.as_u64()).unwrap_or(0);
        let changed = event.get("changed").and_then(|v| v.as_u64()).unwrap_or(0);
        let changed_pkg = event
            .get("changed_pkg")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // changed_unattributed_paths: full list, never truncated (Principle V)
        let changed_unattributed_paths: Vec<String> = event
            .get("changed_unattributed_paths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let pkg_verified = event
            .get("pkg_verified")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let pkg_conffile = event
            .get("pkg_conffile")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let pkg_mismatch = event
            .get("pkg_mismatch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let pkg_unverifiable = event
            .get("pkg_unverifiable")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // added_paths_sample / removed_paths_sample: capped to 20
        let added_paths: Vec<String> = event
            .get("added_paths_sample")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let removed_paths: Vec<String> = event
            .get("removed_paths_sample")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        if is_tty {
            eprintln!("Baseline refreshed in {} seconds.", duration_secs);
            eprintln!("  total:    {} files", format_count(total));

            if diff_unavailable {
                let diff_error = event
                    .get("diff_error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                eprintln!("  diff:     unavailable ({})", diff_error);
            } else if added > 0 || removed > 0 || changed > 0 {
                eprintln!("  added:    {}", added);
                eprintln!("  removed:  {}", removed);
                if changed_pkg > 0 {
                    eprintln!(
                        "  changed:  {} ({} in package paths, {} unattributed)",
                        changed,
                        changed_pkg,
                        changed_unattributed_paths.len()
                    );
                    // Ownership is not proof. Show what the package manager
                    // was actually willing to vouch for.
                    eprintln!(
                        "  verified: {} match the digest their package recorded",
                        pkg_verified
                    );
                    if pkg_conffile > 0 {
                        eprintln!(
                            "  config:   {} operator-editable config files",
                            pkg_conffile
                        );
                    }
                    if pkg_unverifiable > 0 {
                        eprintln!(
                            "  unproven: {} the package manager could not verify",
                            pkg_unverifiable
                        );
                    }
                    if pkg_mismatch > 0 {
                        eprintln!(
                            "  MISMATCH: {} do NOT match what their package shipped",
                            pkg_mismatch
                        );
                    }
                } else {
                    eprintln!("  changed:  {}", changed);
                }

                // Unattributed changes: render every path, no cap (Principle V)
                if !changed_unattributed_paths.is_empty() {
                    eprintln!();
                    eprintln!("Unattributed changes:");
                    for path in &changed_unattributed_paths {
                        eprintln!("  {}    content modified", path);
                    }
                }

                if !added_paths.is_empty() {
                    eprintln!();
                    eprintln!("Added:");
                    for path in &added_paths {
                        eprintln!("  {}", path);
                    }
                    if added > added_paths.len() as u64 {
                        eprintln!("  ... and {} more", added - added_paths.len() as u64);
                    }
                }

                if !removed_paths.is_empty() {
                    eprintln!();
                    eprintln!("Removed:");
                    for path in &removed_paths {
                        eprintln!("  {}", path);
                    }
                    if removed > removed_paths.len() as u64 {
                        eprintln!("  ... and {} more", removed - removed_paths.len() as u64);
                    }
                }
            }
            eprintln!();
            eprintln!("Full record: vigil audit show --since 2m");

            // Audit log preservation line (Principle V: Unambiguous,
            // Principle XIII: Audit Trail Never Lies).
            if let Some(audit) = event.get("audit_log") {
                let entry_count = audit.get("entry_count").and_then(|v| v.as_u64());
                let chain_intact = audit.get("chain_intact").and_then(|v| v.as_bool());
                let preserved = audit.get("preserved_by_refresh").and_then(|v| v.as_bool());
                let error = audit.get("error").and_then(|v| v.as_str());

                if let Some(err) = error {
                    if chain_intact.is_none() && entry_count.is_none() {
                        eprintln!("audit log: status unavailable (see vigil doctor)");
                    } else {
                        eprintln!("audit log: {}", err);
                    }
                } else if preserved == Some(false) {
                    eprintln!(
                        "audit log: integrity check failed (refresh succeeded; investigate immediately)"
                    );
                } else if chain_intact == Some(false) {
                    let break_id = audit
                        .get("chain_break_at")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    eprintln!(
                        "audit log: chain broken at sequence {} (investigate: save a copy of audit.db then `vigil audit verify -v`; if not already acknowledged in `vigil doctor`: `vigil ack chain-break`)",
                        break_id
                    );
                } else if let (Some(count), Some(true)) = (entry_count, chain_intact) {
                    eprintln!(
                        "audit log: unchanged ({} entries, chain intact)",
                        format_count(count)
                    );
                }
            }
        } else {
            let ts = chrono::Local::now().format("%H:%M:%S");
            eprintln!(
                "[{}] refresh complete: {} files, {} added, {} removed, {} changed",
                ts,
                format_count(total),
                added,
                removed,
                changed,
            );

            // Non-TTY audit log line
            if let Some(audit) = event.get("audit_log") {
                let entry_count = audit.get("entry_count").and_then(|v| v.as_u64());
                let chain_intact = audit.get("chain_intact").and_then(|v| v.as_bool());
                let error = audit.get("error").and_then(|v| v.as_str());
                let preserved = audit.get("preserved_by_refresh").and_then(|v| v.as_bool());

                if error.is_some() || (chain_intact.is_none() && entry_count.is_none()) {
                    eprintln!("audit log: status unavailable (see vigil doctor)");
                } else if preserved == Some(false) {
                    eprintln!(
                        "audit log: integrity check failed (refresh succeeded; investigate immediately)"
                    );
                } else if chain_intact == Some(false) {
                    let break_id = audit
                        .get("chain_break_at")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    eprintln!("audit log: chain broken at sequence {}", break_id);
                } else if let (Some(count), Some(true)) = (entry_count, chain_intact) {
                    eprintln!(
                        "audit log: unchanged ({} entries, chain intact)",
                        format_count(count)
                    );
                }
            }
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
