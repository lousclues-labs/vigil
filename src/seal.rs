//! Pre-transaction seals: recording what the filesystem looked like *before*
//! a change window opened.
//!
//! The operator question this exists for is "was my system already drifting
//! before I ran that update". Nothing else can answer it after the fact. A
//! deviation discovered once a transaction has finished looks identical
//! whether it arrived with the transaction or had been sitting there for a
//! week, and the baseline refresh that follows a transaction absorbs the new
//! state either way.
//!
//! So the verdict has to be taken at the boundary, before the package manager
//! writes anything, and written down where it cannot be quietly revised.
//! Deviations are appended to the detection WAL rather than inserted into the
//! audit table directly: the daemon owns the audit chain, and a second writer
//! racing it on `get_last_chain_hash` would break the chain this whole layer
//! depends on.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::wal::DetectionWal;

/// Where the attestation signing key lives. Matches the `vigil attest`
/// default, so a seal and a manual attestation speak with the same identity.
const ATTEST_KEY_PATH: &str = "/etc/vigil/attest.key";

/// Everything a seal needs from the running daemon.
pub struct SealContext<'a> {
    pub config: &'a Config,
    pub baseline_conn: &'a Arc<Mutex<rusqlite::Connection>>,
    pub wal: Option<&'a Arc<DetectionWal>>,
    pub metrics: &'a Arc<Metrics>,
    pub maintenance_active: bool,
}

/// Take a pre-transaction seal and return its verdict.
///
/// Never reports a clean system it did not verify. A scan that fails reports
/// the failure, because "we could not look" and "we looked and it was fine"
/// are opposite claims and only one of them is safe to act on.
pub fn take_seal(ctx: SealContext) -> serde_json::Value {
    let started = std::time::Instant::now();

    let scan = {
        let conn = ctx.baseline_conn.lock();
        crate::scanner::run_scan(&conn, ctx.config, crate::types::ScanMode::Incremental)
    };

    let scan = match scan {
        Ok(scan) => scan,
        Err(e) => {
            return serde_json::json!({
                "ok": false,
                "error": format!("pre-transaction scan failed: {}", e),
            });
        }
    };

    let deviation_paths: Vec<String> = scan
        .changes
        .iter()
        .map(|c| c.path.to_string_lossy().to_string())
        .collect();

    let recorded = match ctx.wal {
        Some(wal) => crate::baseline_diff::record_seal_deviations_to_wal(
            wal,
            &scan.changes,
            ctx.maintenance_active,
        ),
        None => 0,
    };

    ctx.metrics.seals_taken.fetch_add(1, Ordering::Relaxed);
    if !scan.changes.is_empty() {
        ctx.metrics
            .seals_with_deviations
            .fetch_add(1, Ordering::Relaxed);
    }

    let mut event = serde_json::json!({
        "ok": true,
        "files_checked": scan.total_checked,
        "deviations": deviation_paths.len(),
        "deviation_paths": deviation_paths,
        "scan_errors": scan.errors,
        "recorded": recorded,
        "sealed_at": chrono::Utc::now().to_rfc3339(),
        "duration_ms": started.elapsed().as_millis() as u64,
    });

    match write_seal_attestation(ctx.config) {
        Ok(Some(path)) => event["attestation"] = serde_json::json!(path),
        Ok(None) => {}
        Err(e) => event["attestation_error"] = serde_json::json!(e),
    }

    event
}

/// Write a head-only attestation sealing the audit chain head at this instant.
///
/// Returns `None` when no attestation key is configured, which is not a
/// failure: the seal is already recorded in the chain. The attestation adds a
/// portable, offline-verifiable receipt for operators who have set one up.
fn write_seal_attestation(config: &Config) -> std::result::Result<Option<String>, String> {
    let key_path = Path::new(ATTEST_KEY_PATH);
    if !key_path.exists() {
        return Ok(None);
    }

    let out_path = config.daemon.runtime_dir.join("pre-transaction.vatt");
    let opts = crate::attest::create::CreateOpts {
        scope: crate::attest::format::Scope::HeadOnly,
        out_path: Some(&out_path),
        key_path: Some(key_path),
        deterministic_time: None,
    };

    crate::attest::create::create_attestation(config, &opts)
        .map(|result| Some(result.path.display().to_string()))
        .map_err(|e| format!("{}", e))
}
