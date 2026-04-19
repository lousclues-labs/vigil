//! `vigil attest create` — build and write an attestation file.

use std::path::{Path, PathBuf};

use super::error::{AttestError, AttestResult};
use super::format::{
    AttestAuditEntry, AttestBaselineEntry, AttestWatchGroup, Attestation, Body, Footer, Header,
    Scope, SignatureScheme, FORMAT_VERSION, MAGIC,
};
use super::key;

/// Options for `attest create`.
pub struct CreateOpts<'a> {
    pub scope: Scope,
    pub out_path: Option<&'a Path>,
    pub key_path: Option<&'a Path>,
    /// If set, override wall-clock time for deterministic output (testing only).
    pub deterministic_time: Option<&'a str>,
}

/// Result of a successful attestation creation.
pub struct CreateResult {
    pub path: PathBuf,
    pub content_hash: [u8; 32],
    pub signing_key_id: [u8; 8],
    pub scope: Scope,
}

/// Create an attestation file.
///
/// Opens baseline and audit DBs read-only, verifies audit chain integrity,
/// builds the attestation, signs it, and writes it atomically.
pub fn create_attestation(
    config: &crate::config::Config,
    opts: &CreateOpts,
) -> AttestResult<CreateResult> {
    // 1. Open baseline DB read-only
    let baseline_path = &config.daemon.db_path;
    if !baseline_path.exists() {
        return Err(AttestError::Other(
            "no baseline found; run `vigil init` first".to_string(),
        ));
    }
    let baseline_conn = crate::db::open_baseline_db_readonly(baseline_path)
        .map_err(|e| AttestError::Other(format!("cannot open baseline DB: {}", e)))?;

    // 2. Open audit DB read-only
    let audit_path = crate::db::audit_db_path(config);
    let audit_conn = if audit_path.exists() {
        Some(
            crate::db::open_baseline_db_readonly(&audit_path)
                .map_err(|e| AttestError::Other(format!("cannot open audit DB: {}", e)))?,
        )
    } else {
        None
    };

    // 3. Verify audit chain integrity
    if let Some(ref audit_conn) = audit_conn {
        let (total, valid, breaks, _missing) = crate::db::audit_ops::verify_chain(audit_conn)
            .map_err(|e| AttestError::Other(format!("audit chain verification failed: {}", e)))?;
        if !breaks.is_empty() {
            return Err(AttestError::ChainBroken(format!(
                "audit chain has {} break(s) in {} entries (first break at entry IDs {}-{}); \
                 refusing to attest a broken chain",
                breaks.len(),
                total,
                breaks[0].0,
                breaks[0].1,
            )));
        }
        if valid < total {
            return Err(AttestError::ChainBroken(format!(
                "audit chain verification: only {}/{} entries valid",
                valid, total,
            )));
        }
    }

    // 4. Gather data
    let baseline_entries = crate::db::baseline_ops::get_all(&baseline_conn)
        .map_err(|e| AttestError::Other(format!("cannot read baseline entries: {}", e)))?;
    let baseline_count = baseline_entries.len() as u64;

    let audit_entries: Vec<crate::db::audit_ops::AuditEntry> = if let Some(ref ac) = audit_conn {
        // Get ALL audit entries in chronological order for attestation
        let mut stmt = ac
            .prepare(
                "SELECT id, timestamp, path, changes_json, severity,
                        monitored_group, process_json, package,
                        maintenance, suppressed, hmac, chain_hash
                 FROM audit_log ORDER BY id ASC",
            )
            .map_err(|e| AttestError::Other(format!("cannot query audit entries: {}", e)))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(crate::db::audit_ops::AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    path: row.get(2)?,
                    changes_json: row.get(3)?,
                    severity: row.get(4)?,
                    monitored_group: row.get(5)?,
                    process_json: row.get(6)?,
                    package: row.get(7)?,
                    maintenance: row.get::<_, i32>(8)? != 0,
                    suppressed: row.get::<_, i32>(9)? != 0,
                    hmac: row.get(10)?,
                    chain_hash: row.get(11)?,
                })
            })
            .map_err(|e| AttestError::Other(format!("cannot query audit entries: {}", e)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row.map_err(|e| AttestError::Other(format!("cannot read audit entry: {}", e)))?,
            );
        }
        out
    } else {
        Vec::new()
    };
    let audit_count = audit_entries.len() as u64;

    // Compute audit chain head
    let audit_chain_head: [u8; 32] = if let Some(last) = audit_entries.last() {
        *blake3::hash(last.chain_hash.as_bytes()).as_bytes()
    } else {
        [0u8; 32]
    };

    // Compute host ID (machine-id || hostname || install_uuid)
    let install_uuid = crate::db::baseline_ops::get_config_state(&baseline_conn, "install_uuid")
        .ok()
        .flatten();
    let (host_id, host_hint) = compute_host_id(install_uuid.as_deref());

    // Baseline epoch (from config_state if available)
    let baseline_epoch =
        crate::db::baseline_ops::get_config_state(&baseline_conn, "baseline_epoch")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

    // Wall clock time
    let wall_time = if let Some(dt) = opts.deterministic_time {
        dt.to_string()
    } else {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };

    let monotonic_ns = if opts.deterministic_time.is_some() {
        0
    } else {
        read_monotonic_ns()
    };

    // 5. Build header
    let header = Header {
        magic: *MAGIC,
        format_version: FORMAT_VERSION,
        created_at_wall: wall_time,
        created_at_monotonic: monotonic_ns,
        host_id,
        host_id_hint: host_hint,
        baseline_epoch,
        baseline_entry_count: baseline_count,
        audit_entry_count: audit_count,
        audit_chain_head,
        vigil_version: env!("CARGO_PKG_VERSION").to_string(),
        scope: opts.scope,
    };

    // 6. Build body according to scope
    let body = match opts.scope {
        Scope::HeadOnly => Body {
            baseline_entries: None,
            audit_entries: None,
            config_snapshot: None,
            watch_groups: None,
        },
        Scope::BaselineOnly => Body {
            baseline_entries: Some(
                baseline_entries
                    .iter()
                    .map(AttestBaselineEntry::from_baseline)
                    .collect(),
            ),
            audit_entries: None,
            config_snapshot: read_config_snapshot(config),
            watch_groups: Some(build_watch_groups(config)),
        },
        Scope::Full => Body {
            baseline_entries: Some(
                baseline_entries
                    .iter()
                    .map(AttestBaselineEntry::from_baseline)
                    .collect(),
            ),
            audit_entries: Some(
                audit_entries
                    .iter()
                    .map(AttestAuditEntry::from_audit)
                    .collect(),
            ),
            config_snapshot: read_config_snapshot(config),
            watch_groups: Some(build_watch_groups(config)),
        },
    };

    // 7. Compute content hash
    let content_hash =
        super::format::compute_content_hash(&header, &body).map_err(AttestError::Other)?;

    // 8. Load signing key
    let key_path = resolve_key_path(opts.key_path)?;
    let (sign_key, signing_key_id) = key::load_attest_key(&key_path)?;

    // 9. Compute signature
    let signature = key::sign_hmac_blake3(&sign_key, &content_hash);

    // 10. Build footer and assemble attestation
    let footer = Footer {
        content_hash,
        signature_scheme: SignatureScheme::HmacBlake3,
        signature,
        signing_key_id,
    };

    let attestation = Attestation {
        header,
        body,
        footer,
    };

    // Serialize and write atomically
    let cbor_bytes =
        super::format::serialize_attestation(&attestation).map_err(AttestError::Other)?;

    let out_path = resolve_out_path(opts.out_path, &attestation.header)?;
    atomic_write_file(&out_path, &cbor_bytes)?;

    Ok(CreateResult {
        path: out_path,
        content_hash,
        signing_key_id,
        scope: opts.scope,
    })
}

/// Compute host ID: BLAKE3(machine-id || hostname || install_uuid).
fn compute_host_id(install_uuid: Option<&str>) -> ([u8; 32], String) {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_string();
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();

    let mut hasher = blake3::Hasher::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(b"||");
    hasher.update(hostname.as_bytes());
    hasher.update(b"||");
    hasher.update(install_uuid.unwrap_or("").as_bytes());
    let hash = hasher.finalize();

    (*hash.as_bytes(), hostname)
}

/// Read monotonic nanoseconds from `/proc/uptime`.
/// Returns 0 if unavailable.
fn read_monotonic_ns() -> u64 {
    let uptime = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
    let secs = uptime
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    (secs * 1_000_000_000.0) as u64
}

/// Resolve key path: explicit > /etc/vigil/attest.key > ~/.config/vigil/attest.key.
fn resolve_key_path(explicit: Option<&Path>) -> AttestResult<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(AttestError::KeyNotFound(format!(
            "attestation signing key not found at {}. Run `vigil setup attest` to generate one.",
            p.display()
        )));
    }

    match key::find_attest_key() {
        Some(p) => Ok(p),
        None => Err(AttestError::KeyNotFound(
            "attestation signing key not found. \
             Provide --key-path or run `vigil setup attest` to generate one."
                .to_string(),
        )),
    }
}

/// Resolve output file path.
fn resolve_out_path(explicit: Option<&Path>, header: &Header) -> AttestResult<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }

    // Default: ./vigil-attest-<ISO8601-UTC>-<short-host-id>.vatt
    let ts: String = header
        .created_at_wall
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let short_host = hex::encode(&header.host_id[..4]);
    let name = format!("vigil-attest-{}-{}.vatt", ts, short_host);
    Ok(PathBuf::from(name))
}

/// Read config file content for the config snapshot.
fn read_config_snapshot(config: &crate::config::Config) -> Option<String> {
    let paths = crate::config::config_search_paths(None);
    for p in &paths {
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(p) {
                return Some(content);
            }
        }
    }
    // Fall back to serializing the in-memory config
    toml::to_string_pretty(config).ok()
}

/// Build watch groups from config.
fn build_watch_groups(config: &crate::config::Config) -> Vec<AttestWatchGroup> {
    config
        .watch
        .iter()
        .map(|(name, wg)| AttestWatchGroup {
            name: name.clone(),
            severity: wg.severity.to_string(),
            paths: wg.paths.clone(),
            mode: wg.mode.as_str().to_string(),
        })
        .collect()
}

/// Write a file atomically: write to .tmp, fsync, rename.
fn atomic_write_file(path: &Path, data: &[u8]) -> AttestResult<()> {
    use std::io::Write;

    let tmp_path = path.with_extension("vatt.tmp");
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header {
            magic: *MAGIC,
            format_version: FORMAT_VERSION,
            created_at_wall: "2026-04-18T14:22:01Z".to_string(),
            created_at_monotonic: 0,
            host_id: [0x11; 32],
            host_id_hint: "test-host".to_string(),
            baseline_epoch: 0,
            baseline_entry_count: 0,
            audit_entry_count: 0,
            audit_chain_head: [0; 32],
            vigil_version: "0.41.0".to_string(),
            scope: Scope::HeadOnly,
        }
    }

    #[test]
    fn default_out_path_has_vatt_extension() {
        let header = sample_header();
        let out = resolve_out_path(None, &header).unwrap();
        assert_eq!(out.extension().and_then(|s| s.to_str()), Some("vatt"));
        let out_str = out.to_string_lossy();
        assert!(out_str.starts_with("vigil-attest-"));
    }

    #[test]
    fn monotonic_reader_is_non_negative() {
        let _n = read_monotonic_ns();
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vatt");
        atomic_write_file(&path, b"abc").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, b"abc");
    }
}
