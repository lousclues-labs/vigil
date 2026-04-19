//! `vigil attest verify` — verify an attestation file.
//!
//! Security-critical path. This module is intentionally small and depends
//! only on `format`, `key`, and BLAKE3. It must work with no daemon,
//! no baseline DB, no config — only a Vigil binary, the attestation file,
//! and the signing key.

use std::path::Path;

use super::error::{AttestError, AttestResult};
use super::format::{Attestation, SignatureScheme, FORMAT_VERSION, MAGIC};
use super::key;

/// Verification step result.
#[derive(Debug, Clone)]
pub struct VerifyStep {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Full verification report.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub attestation_name: String,
    pub steps: Vec<VerifyStep>,
    pub valid: bool,
}

/// Verify an attestation file.
///
/// `key_path` is optional; if None, searches standard locations.
/// Returns a structured report and the parsed attestation if valid.
pub fn verify_attestation(
    path: &Path,
    key_path: Option<&Path>,
) -> AttestResult<(VerifyReport, Attestation)> {
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    let mut steps = Vec::new();
    let mut all_ok = true;

    // 1. Read file
    let data = std::fs::read(path)?;

    // 2. Deserialize
    let attestation: Attestation = match super::format::deserialize_attestation(&data) {
        Ok(a) => a,
        Err(e) => {
            return Err(AttestError::InvalidFormat(format!(
                "cannot parse attestation file: {}",
                e
            )));
        }
    };

    // 3. Check magic
    if attestation.header.magic == *MAGIC {
        steps.push(VerifyStep {
            name: "Magic".to_string(),
            passed: true,
            detail: "ok".to_string(),
        });
    } else {
        steps.push(VerifyStep {
            name: "Magic".to_string(),
            passed: false,
            detail: "not a Vigil attestation file (bad magic bytes)".to_string(),
        });
        all_ok = false;
    }

    // 4. Check format version
    if attestation.header.format_version <= FORMAT_VERSION {
        steps.push(VerifyStep {
            name: "Format version".to_string(),
            passed: true,
            detail: format!("{} (supported)", attestation.header.format_version),
        });
    } else {
        steps.push(VerifyStep {
            name: "Format version".to_string(),
            passed: false,
            detail: format!(
                "{} (unsupported; this binary supports up to version {})",
                attestation.header.format_version, FORMAT_VERSION
            ),
        });
        all_ok = false;
    }

    // 5. Recompute content hash
    let recomputed = super::format::compute_content_hash(&attestation.header, &attestation.body)
        .map_err(|e| AttestError::Other(format!("cannot recompute content hash: {}", e)))?;

    if recomputed == attestation.footer.content_hash {
        steps.push(VerifyStep {
            name: "Content hash".to_string(),
            passed: true,
            detail: "ok (matches recomputed BLAKE3)".to_string(),
        });
    } else {
        steps.push(VerifyStep {
            name: "Content hash".to_string(),
            passed: false,
            detail: format!(
                "MISMATCH\n                     declared:    {}\n                     recomputed:  {}\n                     The attestation has been modified after creation.",
                hex::encode(attestation.footer.content_hash),
                hex::encode(recomputed),
            ),
        });
        all_ok = false;
    }

    // 6. Verify signature
    match attestation.footer.signature_scheme {
        SignatureScheme::HmacBlake3 => {
            let resolved_key = resolve_verify_key(key_path);
            match resolved_key {
                Ok((sign_key, loaded_key_id)) => {
                    // Check key ID matches
                    if loaded_key_id != attestation.footer.signing_key_id {
                        steps.push(VerifyStep {
                            name: "Signature".to_string(),
                            passed: false,
                            detail: format!(
                                "key ID mismatch: attestation signed with {}, loaded key is {}",
                                key::format_key_id(&attestation.footer.signing_key_id),
                                key::format_key_id(&loaded_key_id),
                            ),
                        });
                        all_ok = false;
                    } else if key::verify_hmac_blake3(
                        &sign_key,
                        &attestation.footer.content_hash,
                        &attestation.footer.signature,
                    ) {
                        steps.push(VerifyStep {
                            name: "Signature".to_string(),
                            passed: true,
                            detail: format!(
                                "ok (key id {})",
                                key::format_key_id(&attestation.footer.signing_key_id)
                            ),
                        });
                    } else {
                        steps.push(VerifyStep {
                            name: "Signature".to_string(),
                            passed: false,
                            detail: "HMAC-BLAKE3 signature does not match".to_string(),
                        });
                        all_ok = false;
                    }
                }
                Err(e) => {
                    steps.push(VerifyStep {
                        name: "Signature".to_string(),
                        passed: false,
                        detail: format!("cannot verify: {}. Provide --key-path.", e),
                    });
                    all_ok = false;
                }
            }
        }
    }

    // 7. Verify internal audit chain links (if body contains audit entries)
    if let Some(ref entries) = attestation.body.audit_entries {
        if entries.is_empty() {
            steps.push(VerifyStep {
                name: "Audit chain links".to_string(),
                passed: true,
                detail: "ok (0 entries)".to_string(),
            });
        } else {
            let (chain_ok, chain_detail) = verify_embedded_chain(entries);
            steps.push(VerifyStep {
                name: "Audit chain links".to_string(),
                passed: chain_ok,
                detail: chain_detail,
            });
            if !chain_ok {
                all_ok = false;
            }
        }
    }

    Ok((
        VerifyReport {
            attestation_name: file_name,
            steps,
            valid: all_ok,
        },
        attestation,
    ))
}

/// Verify the embedded audit chain: check that each entry's chain_hash
/// matches the recomputed value from its predecessor.
fn verify_embedded_chain(entries: &[super::format::AttestAuditEntry]) -> (bool, String) {
    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();
    let mut prev = genesis;
    let mut broken_count = 0;

    for entry in entries {
        if entry.chain_hash.is_empty() {
            prev = entry.chain_hash.clone();
            continue;
        }

        let expected = crate::db::audit_ops::compute_chain_hash(
            &prev,
            entry.timestamp,
            &entry.path,
            &entry.changes_json,
            &entry.severity,
        );

        if expected != entry.chain_hash {
            broken_count += 1;
        }
        prev = entry.chain_hash.clone();
    }

    if broken_count == 0 {
        (
            true,
            format!(
                "ok ({} entries, all prev_hash references valid)",
                entries.len()
            ),
        )
    } else {
        (
            false,
            format!(
                "{} of {} entries have broken chain links",
                broken_count,
                entries.len()
            ),
        )
    }
}

/// Resolve signing key for verification.
fn resolve_verify_key(
    explicit: Option<&Path>,
) -> AttestResult<(zeroize::Zeroizing<Vec<u8>>, [u8; 8])> {
    if let Some(p) = explicit {
        return key::load_attest_key(p);
    }

    // Search standard locations
    match key::find_attest_key() {
        Some(p) => key::load_attest_key(&p),
        None => Err(AttestError::KeyNotFound(
            "signature cannot be verified without the attestation signing key. \
             Provide --key-path."
                .to_string(),
        )),
    }
}

/// Print a human-readable verification report to stderr.
pub fn print_report(report: &VerifyReport, attestation: &Attestation) {
    eprintln!("Attestation: {}", report.attestation_name);
    eprintln!(
        "  Created:           {}",
        attestation.header.created_at_wall
    );
    eprintln!("  Vigil version:     {}", attestation.header.vigil_version);
    eprintln!(
        "  Host ID:           {}  (hint: {})",
        &hex::encode(attestation.header.host_id)[..12],
        attestation.header.host_id_hint,
    );
    eprintln!("  Scope:             {}", attestation.header.scope);
    eprintln!("  Baseline epoch:    {}", attestation.header.baseline_epoch);
    eprintln!(
        "  Baseline entries:  {}",
        format_count(attestation.header.baseline_entry_count)
    );
    eprintln!(
        "  Audit entries:     {}",
        format_count(attestation.header.audit_entry_count)
    );
    eprintln!(
        "  Audit chain head:  {}",
        &hex::encode(attestation.header.audit_chain_head)[..12],
    );
    eprintln!();
    eprintln!("Verification:");

    for step in &report.steps {
        let marker = if step.passed { "ok" } else { "FAIL" };
        // Multi-line details: indent continuation lines
        let lines: Vec<&str> = step.detail.lines().collect();
        eprintln!("  {:18} {}", format!("{}:", step.name), lines[0]);
        for line in &lines[1..] {
            eprintln!("                     {}", line);
        }
        let _ = marker; // marker info is embedded in detail
    }

    eprintln!();
    if report.valid {
        eprintln!("Result: VALID");
    } else {
        eprintln!("Result: INVALID");
    }
}

fn format_count(n: u64) -> String {
    if n >= 1000 {
        let s = n.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect()
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_entry(
        prev: &str,
        ts: i64,
        path: &str,
        sev: &str,
    ) -> super::super::format::AttestAuditEntry {
        let chain_hash = crate::db::audit_ops::compute_chain_hash(prev, ts, path, "[]", sev);
        super::super::format::AttestAuditEntry {
            id: ts,
            timestamp: ts,
            path: path.to_string(),
            changes_json: "[]".to_string(),
            severity: sev.to_string(),
            monitored_group: None,
            process_json: None,
            package: None,
            maintenance: false,
            suppressed: false,
            chain_hash,
        }
    }

    #[test]
    fn embedded_chain_validates() {
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let e1 = mk_entry(&genesis, 1, "/etc/passwd", "high");
        let e2 = mk_entry(&e1.chain_hash, 2, "/etc/shadow", "critical");
        let (ok, detail) = verify_embedded_chain(&[e1, e2]);
        assert!(ok);
        assert!(detail.contains("all prev_hash references valid"));
    }

    #[test]
    fn embedded_chain_detects_break() {
        let genesis = blake3::hash(b"vigil-audit-chain-genesis")
            .to_hex()
            .to_string();
        let e1 = mk_entry(&genesis, 1, "/etc/passwd", "high");
        let mut e2 = mk_entry(&e1.chain_hash, 2, "/etc/shadow", "critical");
        e2.chain_hash = "tampered".to_string();
        let (ok, detail) = verify_embedded_chain(&[e1, e2]);
        assert!(!ok);
        assert!(detail.contains("broken chain links"));
    }

    #[test]
    fn count_formatting_uses_commas() {
        assert_eq!(format_count(1), "1");
        assert_eq!(format_count(1000), "1,000");
        assert_eq!(format_count(4217), "4,217");
    }
}
