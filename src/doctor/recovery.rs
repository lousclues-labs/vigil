//! Recovery action builders and acknowledgment state lookups.';3dffb6d3-a1e0-4a9a-a909-fd2e52a52f20]633;C//! Recovery action builders and acknowledgment state lookups.
//!
//! Each doctor check that reports a historical event needs recovery actions
//! and acknowledgment integration. This module centralizes those helpers.

use crate::ack::DoctorEventKind;
use crate::config::Config;
use crate::db::audit_path::AuditEventPath;

use super::{Recovery, RecoveryHint};

pub(crate) fn hooks_disabled_by_operator(config: &Config) -> bool {
    let conn = match crate::db::open_audit_db(config) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let latest: std::result::Result<String, _> = conn.query_row(
        "SELECT path FROM audit_log \
         WHERE path IN ('vigil:hooks_disable', 'vigil:hooks_enable') \
         ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    );

    matches!(latest.ok().as_deref(), Some(s) if s == AuditEventPath::HooksDisable.as_str())
}

pub(crate) fn baseline_refresh_unacked_recovery() -> Recovery {
    Recovery::Multi(vec![
        RecoveryHint::Command {
            verb: "recover",
            command: "vigil baseline refresh".into(),
        },
        RecoveryHint::Command {
            verb: "acknowledge",
            command: "vigil ack baseline-refresh".into(),
        },
    ])
}

pub(crate) fn baseline_refresh_acknowledged_recovery(
    ack_ts: i64,
    uid: u32,
    note: Option<String>,
) -> Recovery {
    let mut hints = acknowledgment_metadata_hints(ack_ts, uid, note);
    hints.push(RecoveryHint::Command {
        verb: "recover",
        command: "vigil baseline refresh".into(),
    });
    hints.push(RecoveryHint::Manual {
        verb: "",
        instruction: "future stale-refresh episodes will warn afresh".into(),
    });
    hints.push(RecoveryHint::Command {
        verb: "acknowledge again on recurrence",
        command: "vigil ack baseline-refresh".into(),
    });
    Recovery::Multi(hints)
}

pub(crate) fn chain_break_unacked_recovery() -> Recovery {
    Recovery::Multi(vec![
        RecoveryHint::Command {
            verb: "recover",
            command: "vigil audit verify -v".into(),
        },
        RecoveryHint::Command {
            verb: "acknowledge",
            command: "vigil ack chain-break".into(),
        },
        RecoveryHint::Manual {
            verb: "or investigate",
            instruction: "save a copy of audit.db before remediation".into(),
        },
    ])
}

pub(crate) fn chain_break_acknowledged_recovery(
    ack_ts: i64,
    uid: u32,
    note: Option<String>,
) -> Recovery {
    let mut hints = acknowledgment_metadata_hints(ack_ts, uid, note);
    hints.push(RecoveryHint::Command {
        verb: "recover",
        command: "vigil audit verify -v".into(),
    });
    hints.push(RecoveryHint::Command {
        verb: "acknowledge again on recurrence",
        command: "vigil ack chain-break".into(),
    });
    hints.push(RecoveryHint::Manual {
        verb: "or investigate",
        instruction: "save a copy of audit.db before remediation".into(),
    });
    Recovery::Multi(hints)
}

pub(crate) fn retention_failure_unacked_recovery() -> Recovery {
    Recovery::Multi(vec![
        RecoveryHint::Command {
            verb: "recover",
            command: "vigil audit prune --before <date> --confirm".into(),
        },
        RecoveryHint::Command {
            verb: "or recover",
            command: "vigil daemon recover --reason audit_log_full".into(),
        },
        RecoveryHint::Command {
            verb: "acknowledge",
            command: "vigil ack retention".into(),
        },
    ])
}

pub(crate) fn retention_failure_acknowledged_recovery(
    ack_ts: i64,
    uid: u32,
    note: Option<String>,
) -> Recovery {
    let mut hints = acknowledgment_metadata_hints(ack_ts, uid, note);
    hints.push(RecoveryHint::Command {
        verb: "recover",
        command: "vigil audit prune --before <date> --confirm".into(),
    });
    hints.push(RecoveryHint::Command {
        verb: "or recover",
        command: "vigil daemon recover --reason audit_log_full".into(),
    });
    hints.push(RecoveryHint::Command {
        verb: "acknowledge again on recurrence",
        command: "vigil ack retention".into(),
    });
    Recovery::Multi(hints)
}

pub(crate) fn daemon_degraded_unacked_recovery(reason: &str) -> Recovery {
    Recovery::Multi(vec![
        RecoveryHint::Command {
            verb: "recover",
            command: format!(
                "vigil recover --reason {}",
                reason.split_whitespace().next().unwrap_or(reason)
            ),
        },
        RecoveryHint::Command {
            verb: "acknowledge",
            command: "vigil ack degraded".into(),
        },
    ])
}

pub(crate) fn daemon_degraded_acknowledged_recovery(
    reason: &str,
    ack_ts: i64,
    uid: u32,
    note: Option<String>,
) -> Recovery {
    let mut hints = acknowledgment_metadata_hints(ack_ts, uid, note);
    hints.push(RecoveryHint::Command {
        verb: "recover",
        command: format!(
            "vigil recover --reason {}",
            reason.split_whitespace().next().unwrap_or(reason)
        ),
    });
    hints.push(RecoveryHint::Command {
        verb: "acknowledge again on recurrence",
        command: "vigil ack degraded".into(),
    });
    Recovery::Multi(hints)
}

pub(crate) fn acknowledgment_metadata_hints(
    ack_ts: i64,
    uid: u32,
    note: Option<String>,
) -> Vec<RecoveryHint> {
    let mut hints = vec![RecoveryHint::Manual {
        verb: "acknowledged",
        instruction: format!("{} by uid {}", format_ack_timestamp(ack_ts), uid),
    }];
    if let Some(n) = note {
        hints.push(RecoveryHint::Manual {
            verb: "note",
            instruction: format!("\"{}\"", n),
        });
    }
    hints
}

pub(crate) fn unacked_hook_recovery(investigate_cmd: &str) -> Recovery {
    Recovery::Multi(vec![
        RecoveryHint::Command {
            verb: "recover",
            command: "vigil hooks verify".into(),
        },
        RecoveryHint::Command {
            verb: "acknowledge",
            command: "vigil ack hooks".into(),
        },
        RecoveryHint::Manual {
            verb: "or investigate",
            instruction: investigate_cmd.to_string(),
        },
    ])
}

pub(crate) fn acknowledged_hook_recovery(
    ack_ts: i64,
    uid: u32,
    note: Option<String>,
    investigate_cmd: &str,
) -> Recovery {
    let mut hints = acknowledgment_metadata_hints(ack_ts, uid, note);
    hints.push(RecoveryHint::Manual {
        verb: "",
        instruction: "fresh failures will appear as new actionable events".into(),
    });
    hints.push(RecoveryHint::Command {
        verb: "acknowledge again on recurrence",
        command: "vigil ack hooks".into(),
    });
    hints.push(RecoveryHint::Manual {
        verb: "or investigate",
        instruction: investigate_cmd.to_string(),
    });
    Recovery::Multi(hints)
}

pub(crate) fn format_ack_timestamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| {
            dt.with_timezone(&chrono::Local)
                .format("%Y-%m-%dT%H:%M")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_string())
}

pub(crate) fn hook_failure_ack_state(
    config: &Config,
    backend: &str,
    trigger_ts: &str,
) -> Option<crate::ack::AcknowledgmentState> {
    let payload = serde_json::json!({
        "event_kind": "hook_invocation_failure",
        "backend": backend,
        "trigger_timestamp": trigger_ts,
        "description": "hook invocation failure",
    });
    doctor_event_ack_state(
        config,
        DoctorEventKind::HookInvocationFailure,
        AuditEventPath::HookFailure.as_str(),
        payload,
        |v| {
            let b = v.get("backend").and_then(|x| x.as_str());
            let t = v.get("trigger_timestamp").and_then(|x| x.as_str());
            b == Some(backend) && t == Some(trigger_ts)
        },
    )
}

pub(crate) fn baseline_refresh_ack_state(
    config: &Config,
    last_refresh_ts: i64,
) -> Option<crate::ack::AcknowledgmentState> {
    let payload = serde_json::json!({
        "event_kind": "baseline_refresh_failure",
        "last_refresh_timestamp": last_refresh_ts,
        "description": "baseline refresh is stale",
    });
    doctor_event_ack_state(
        config,
        DoctorEventKind::BaselineRefreshFailure,
        AuditEventPath::BaselineRefreshFailure.as_str(),
        payload,
        |v| v.get("last_refresh_timestamp").and_then(|x| x.as_i64()) == Some(last_refresh_ts),
    )
}

pub(crate) fn audit_chain_break_ack_state(
    config: &Config,
    first_break_id: i64,
) -> Option<crate::ack::AcknowledgmentState> {
    let payload = serde_json::json!({
        "event_kind": "audit_chain_break",
        "first_break_id": first_break_id,
        "description": "audit chain break detected",
    });
    doctor_event_ack_state(
        config,
        DoctorEventKind::AuditChainBreak,
        AuditEventPath::AuditChainBreak.as_str(),
        payload,
        |v| v.get("first_break_id").and_then(|x| x.as_i64()) == Some(first_break_id),
    )
}

pub(crate) fn retention_failure_ack_state(
    config: &Config,
    cap_mb: u64,
) -> Option<crate::ack::AcknowledgmentState> {
    let payload = serde_json::json!({
        "event_kind": "retention_sweep_failure",
        "cap_mb": cap_mb,
        "condition": "audit_cap_reached",
        "description": "audit retention capacity reached",
    });
    doctor_event_ack_state(
        config,
        DoctorEventKind::RetentionSweepFailure,
        AuditEventPath::RetentionSweepFailure.as_str(),
        payload,
        |v| {
            v.get("condition").and_then(|x| x.as_str()) == Some("audit_cap_reached")
                && v.get("cap_mb").and_then(|x| x.as_u64()) == Some(cap_mb)
        },
    )
}

pub(crate) fn daemon_degraded_ack_state(
    config: &Config,
    reason: &str,
    since: &str,
) -> Option<crate::ack::AcknowledgmentState> {
    let payload = serde_json::json!({
        "event_kind": "daemon_degraded",
        "reason": reason,
        "since": since,
        "description": "daemon entered degraded state",
    });
    doctor_event_ack_state(
        config,
        DoctorEventKind::DaemonDegraded,
        AuditEventPath::DaemonDegraded.as_str(),
        payload,
        |v| {
            v.get("reason").and_then(|x| x.as_str()) == Some(reason)
                && v.get("since").and_then(|x| x.as_str()) == Some(since)
        },
    )
}

pub(crate) fn doctor_event_ack_state<F>(
    config: &Config,
    event_kind: DoctorEventKind,
    event_path: &str,
    payload: serde_json::Value,
    matcher: F,
) -> Option<crate::ack::AcknowledgmentState>
where
    F: Fn(&serde_json::Value) -> bool,
{
    let conn = crate::db::open_audit_db(config).ok()?;

    let mut event_seq: Option<i64> = None;
    let mut stmt = conn
        .prepare(
            "SELECT id, changes_json FROM audit_log \
             WHERE path = ?1 \
             ORDER BY id DESC LIMIT 200",
        )
        .ok()?;
    let rows = stmt
        .query_map(rusqlite::params![event_path], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .ok()?;
    for row in rows {
        let (id, json) = match row {
            Ok(v) => v,
            Err(_) => continue,
        };
        let value = match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if matcher(&value) {
            event_seq = Some(id);
            break;
        }
    }

    let seq = if let Some(s) = event_seq {
        s
    } else {
        let payload_json = serde_json::to_string(&payload).ok()?;
        let previous_chain_hash = crate::db::audit_ops::get_last_chain_hash(&conn)
            .ok()?
            .unwrap_or_else(|| {
                blake3::hash(b"vigil-audit-chain-genesis")
                    .to_hex()
                    .to_string()
            });
        let hmac_key = if config.security.hmac_signing {
            std::fs::read(&config.security.hmac_key_path).ok()
        } else {
            None
        };
        let (_, new_seq) = crate::db::audit_ops::insert_doctor_event_entry(
            &conn,
            event_path,
            &payload_json,
            &previous_chain_hash,
            hmac_key.as_deref(),
        )
        .ok()?;
        new_seq
    };

    let cache = crate::ack::build_cache_from_audit_log(&conn);
    cache.is_event_acknowledged(event_kind, seq).cloned()
}
