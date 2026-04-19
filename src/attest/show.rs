//! `vigil attest show` — display attestation contents.

use std::path::Path;

use super::error::{AttestError, AttestResult};
use super::format::Attestation;

/// Show the contents of an attestation file.
pub fn show_attestation(path: &Path, verbose: bool) -> AttestResult<()> {
    let data = std::fs::read(path)?;
    let attestation: Attestation = super::format::deserialize_attestation(&data)
        .map_err(|e| AttestError::InvalidFormat(format!("cannot parse attestation: {}", e)))?;

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    eprintln!("Attestation: {}", file_name);
    eprintln!();
    eprintln!("  Header");
    eprintln!("  ──────");
    eprintln!(
        "  Created:           {}",
        attestation.header.created_at_wall
    );
    eprintln!("  Vigil version:     {}", attestation.header.vigil_version);
    eprintln!(
        "  Host ID:           {}  (hint: {})",
        hex::encode(attestation.header.host_id),
        attestation.header.host_id_hint,
    );
    eprintln!("  Scope:             {}", attestation.header.scope);
    eprintln!("  Format version:    {}", attestation.header.format_version);
    eprintln!("  Baseline epoch:    {}", attestation.header.baseline_epoch);
    eprintln!(
        "  Baseline entries:  {}",
        attestation.header.baseline_entry_count
    );
    eprintln!(
        "  Audit entries:     {}",
        attestation.header.audit_entry_count
    );
    eprintln!(
        "  Audit chain head:  {}",
        hex::encode(attestation.header.audit_chain_head),
    );

    eprintln!();
    eprintln!("  Footer");
    eprintln!("  ──────");
    eprintln!(
        "  Content hash:      {}",
        hex::encode(attestation.footer.content_hash),
    );
    eprintln!(
        "  Signature scheme:  {}",
        attestation.footer.signature_scheme,
    );
    eprintln!(
        "  Signing key ID:    {}",
        super::key::format_key_id(&attestation.footer.signing_key_id),
    );

    if verbose {
        if let Some(ref entries) = attestation.body.baseline_entries {
            eprintln!();
            eprintln!("  Baseline Entries ({})", entries.len());
            eprintln!("  ─────────────────");
            for e in entries {
                eprintln!(
                    "    {} {:04o} {}",
                    e.hash.get(..12).unwrap_or(&e.hash),
                    e.mode,
                    e.path
                );
            }
        }

        if let Some(ref entries) = attestation.body.audit_entries {
            eprintln!();
            eprintln!("  Audit Entries ({})", entries.len());
            eprintln!("  ──────────────");
            for e in entries {
                eprintln!(
                    "    {} {} {}",
                    chrono::DateTime::from_timestamp(e.timestamp, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| e.timestamp.to_string()),
                    e.severity.to_uppercase(),
                    e.path,
                );
            }
        }

        if let Some(ref groups) = attestation.body.watch_groups {
            eprintln!();
            eprintln!("  Watch Groups ({})", groups.len());
            eprintln!("  ────────────");
            for g in groups {
                eprintln!("    {} [{}] {} paths", g.name, g.severity, g.paths.len());
                for p in &g.paths {
                    eprintln!("      {}", p);
                }
            }
        }

        if let Some(ref config) = attestation.body.config_snapshot {
            eprintln!();
            eprintln!("  Config Snapshot");
            eprintln!("  ───────────────");
            for line in config.lines().take(20) {
                eprintln!("    {}", line);
            }
            let line_count = config.lines().count();
            if line_count > 20 {
                eprintln!("    ... ({} more lines)", line_count - 20);
            }
        }
    } else {
        eprintln!();
        eprintln!("  Use --verbose for full entry listing.");
    }

    Ok(())
}
