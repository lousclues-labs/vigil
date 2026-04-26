//! `vigil ack` subcommand: acknowledge historical events in doctor output.

use std::path::Path;

use vigil::ack::{self, AcknowledgmentKind, AcknowledgmentPayload, DoctorEventKind};
use vigil::cli::AckAction;
use vigil::db::audit_ops;

pub(crate) fn cmd_ack(
    config_path: Option<&Path>,
    kind: Option<String>,
    sequence: Option<i64>,
    note: Option<String>,
    action: Option<AckAction>,
) -> vigil::Result<i32> {
    match action {
        Some(AckAction::List) => cmd_ack_list(config_path),
        Some(AckAction::Revoke { kind, sequence }) => cmd_ack_revoke(config_path, &kind, sequence),
        Some(AckAction::Show { sequence }) => cmd_ack_show(config_path, sequence),
        None => {
            let k = kind.ok_or_else(|| {
                vigil::VigilError::Config(
                    "missing ack kind. use `vigil ack <kind>` or `vigil ack list`".into(),
                )
            })?;
            cmd_ack_mark(config_path, &k, sequence, note)
        }
    }
}

fn cmd_ack_mark(
    config_path: Option<&Path>,
    kind_str: &str,
    explicit_sequence: Option<i64>,
    note: Option<String>,
) -> vigil::Result<i32> {
    let kind = DoctorEventKind::from_cli_name(kind_str).ok_or_else(|| {
        vigil::VigilError::Config(format!(
            "unknown event kind '{}'. valid kinds: {}",
            kind_str,
            DoctorEventKind::all()
                .iter()
                .map(|k| k.cli_name())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;

    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;
    let hmac_key = load_hmac_key_if_configured(&cfg);

    let cache = ack::build_cache_from_audit_log(&conn);

    let (event_seq, event_ts, event_desc) = if let Some(seq) = explicit_sequence {
        // Verify the sequence exists and is of the right kind
        let entry = conn
            .query_row(
                "SELECT id, timestamp, changes_json FROM audit_log WHERE id = ?1",
                rusqlite::params![seq],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|_| {
                vigil::VigilError::Config(format!("no audit record found with sequence {}", seq))
            })?;
        (entry.0, entry.1, kind.description().to_string())
    } else {
        ack::find_most_recent_unacknowledged(&conn, kind, &cache).ok_or_else(|| {
            vigil::VigilError::Config(format!(
                "no unacknowledged {} events found. run `vigil ack list` to see current state",
                kind.cli_name()
            ))
        })?
    };

    let payload = ack::build_operator_payload(
        kind,
        event_seq,
        AcknowledgmentKind::Acknowledge,
        note.clone(),
    );
    let payload_json = serde_json::to_string(&payload)?;

    let previous_chain_hash = audit_ops::get_last_chain_hash(&conn)?.unwrap_or_else(|| {
        blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string()
    });

    let (_new_hash, ack_seq) = audit_ops::insert_acknowledgment_entry(
        &conn,
        &payload_json,
        &previous_chain_hash,
        hmac_key.as_deref(),
    )?;

    let ts_str = format_timestamp(event_ts);

    println!(
        "acknowledged: {} at {} (sequence {})",
        event_desc, ts_str, event_seq
    );
    println!(
        "operator: uid {} (PID {})",
        payload.operator_uid, payload.operator_pid
    );
    println!("audit record: sequence {}", ack_seq);
    if let Some(n) = &note {
        println!("note: \"{}\"", n);
    }
    println!();
    println!("the event remains visible in doctor output with this acknowledgment");
    println!("attached. fresh occurrences will appear as new actionable events.");

    Ok(0)
}

fn cmd_ack_list(config_path: Option<&Path>) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;

    let cache = ack::build_cache_from_audit_log(&conn);

    // List unacknowledged events
    println!();
    let mut unacked_count = 0u32;
    let mut unacked_lines = Vec::new();
    for kind in DoctorEventKind::all() {
        let events = ack::find_unacknowledged_events(&conn, *kind, &cache);
        for (seq, ts, desc) in &events {
            unacked_count += 1;
            unacked_lines.push(format!(
                "  {:<18} sequence {:<10} {}    {}",
                kind.cli_name(),
                seq,
                format_timestamp(*ts),
                desc
            ));
        }
    }

    if unacked_count > 0 {
        println!("Unacknowledged events ({}):", unacked_count);
        for line in &unacked_lines {
            println!("{}", line);
        }
        // Print acknowledge hints
        for kind in DoctorEventKind::all() {
            let events = ack::find_unacknowledged_events(&conn, *kind, &cache);
            if !events.is_empty() {
                println!(
                    "  {:<18}                            (acknowledge with: vigil ack {})",
                    "",
                    kind.cli_name()
                );
            }
        }
    } else {
        println!("No unacknowledged events.");
    }

    // List recent acknowledgments
    let recent_acks = ack::list_recent_acknowledgments(&conn, 10);
    if !recent_acks.is_empty() {
        println!();
        println!("Recent acknowledgments ({}):", recent_acks.len());
        for (seq, ts, payload) in &recent_acks {
            let note_str = payload
                .note
                .as_deref()
                .map(|n| format!(" (note: \"{}\")", n))
                .unwrap_or_default();
            println!(
                "  {:<18} sequence {:<10} {}    by uid {}{}",
                payload.event_kind.cli_name(),
                seq,
                format_timestamp(*ts),
                payload.operator_uid,
                note_str,
            );
            println!(
                "  {:<18}                            acknowledging: sequence {} from {}",
                "",
                payload.event_sequence,
                format_timestamp(*ts),
            );
        }
    }

    println!();
    Ok(0)
}

fn cmd_ack_revoke(
    config_path: Option<&Path>,
    kind_str: &str,
    explicit_sequence: Option<i64>,
) -> vigil::Result<i32> {
    let kind = DoctorEventKind::from_cli_name(kind_str).ok_or_else(|| {
        vigil::VigilError::Config(format!(
            "unknown event kind '{}'. valid kinds: {}",
            kind_str,
            DoctorEventKind::all()
                .iter()
                .map(|k| k.cli_name())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;

    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;
    let hmac_key = load_hmac_key_if_configured(&cfg);

    // Find the acknowledgment to revoke
    let recent_acks = ack::list_recent_acknowledgments(&conn, 50);
    let target_ack = if let Some(seq) = explicit_sequence {
        recent_acks
            .iter()
            .find(|(s, _, p)| *s == seq && p.event_kind == kind)
            .ok_or_else(|| {
                vigil::VigilError::Config(format!(
                    "no acknowledgment of kind '{}' found at sequence {}",
                    kind.cli_name(),
                    seq
                ))
            })?
    } else {
        recent_acks
            .iter()
            .find(|(_, _, p)| {
                p.event_kind == kind && p.acknowledgment_kind == AcknowledgmentKind::Acknowledge
            })
            .ok_or_else(|| {
                vigil::VigilError::Config(format!(
                    "no acknowledgment of kind '{}' found to revoke",
                    kind.cli_name()
                ))
            })?
    };

    let (ack_seq, ack_ts, ack_payload) = target_ack;

    let payload = ack::build_operator_payload(
        kind,
        ack_payload.event_sequence,
        AcknowledgmentKind::Revoke,
        None,
    );
    let payload_json = serde_json::to_string(&payload)?;

    let previous_chain_hash = audit_ops::get_last_chain_hash(&conn)?.unwrap_or_else(|| {
        blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string()
    });

    let (_new_hash, revoke_seq) = audit_ops::insert_acknowledgment_entry(
        &conn,
        &payload_json,
        &previous_chain_hash,
        hmac_key.as_deref(),
    )?;

    println!(
        "revoked: acknowledgment of sequence {} ({} ack from {})",
        ack_seq,
        kind.description(),
        format_timestamp(*ack_ts),
    );
    println!(
        "operator: uid {} (PID {})",
        payload.operator_uid, payload.operator_pid
    );
    println!("audit record: sequence {}", revoke_seq);
    println!();
    println!(
        "the underlying event (sequence {}) is now unacknowledged.",
        ack_payload.event_sequence
    );
    println!("its doctor row will return to its natural severity.");

    Ok(0)
}

fn cmd_ack_show(config_path: Option<&Path>, sequence: i64) -> vigil::Result<i32> {
    let cfg = vigil::config::load_config(config_path)?;
    let conn = vigil::db::open_audit_db(&cfg)?;

    let (id, ts, path, changes_json, severity, chain_hash) = conn
        .query_row(
            "SELECT id, timestamp, path, changes_json, severity, chain_hash \
             FROM audit_log WHERE id = ?1",
            rusqlite::params![sequence],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(|_| {
            vigil::VigilError::Config(format!("no audit record found with sequence {}", sequence))
        })?;

    println!("Audit record: sequence {}", id);
    println!("  timestamp:  {}", format_timestamp(ts));
    println!("  path:       {}", path);
    println!("  severity:   {}", severity);
    println!("  chain_hash: {}", &chain_hash[..16]);

    if path == vigil::db::audit_path::AuditEventPath::OperatorAcknowledgment.as_str() {
        if let Ok(payload) = serde_json::from_str::<AcknowledgmentPayload>(&changes_json) {
            println!();
            println!("Acknowledgment details:");
            println!("  kind:       {:?}", payload.acknowledgment_kind);
            println!("  event_kind: {}", payload.event_kind.description());
            println!("  event_seq:  {}", payload.event_sequence);
            println!("  operator:   uid {}", payload.operator_uid);
            println!("  pid:        {}", payload.operator_pid);
            println!("  exe:        {}", payload.operator_exe);
            if let Some(note) = &payload.note {
                println!("  note:       \"{}\"", note);
            }
        }
    }

    Ok(0)
}

fn format_timestamp(ts: i64) -> String {
    vigil::display::time::format_local(ts)
}

fn load_hmac_key_if_configured(cfg: &vigil::config::Config) -> Option<Vec<u8>> {
    if !cfg.security.hmac_signing {
        return None;
    }
    std::fs::read(&cfg.security.hmac_key_path).ok()
}
