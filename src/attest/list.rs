//! `vigil attest list` -- list attestation files in a directory.

use std::path::Path;

use super::error::AttestResult;

/// List and summarize attestation files in a directory.
pub fn list_attestations(dir: &Path) -> AttestResult<()> {
    if !dir.is_dir() {
        return Err(super::error::AttestError::Other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "vatt")
                .unwrap_or(false)
        })
        .collect();

    if entries.is_empty() {
        eprintln!("No attestation files (.vatt) found in {}", dir.display());
        return Ok(());
    }

    entries.sort_by_key(|e| e.file_name());

    eprintln!(
        "Attestation files in {} ({} found):",
        dir.display(),
        entries.len()
    );
    eprintln!();

    for entry in &entries {
        let path = entry.path();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

        // Try to read and parse for summary info
        match std::fs::read(&path) {
            Ok(data) => match super::format::deserialize_attestation(&data) {
                Ok(att) => {
                    eprintln!(
                        "  {} ({}) -- {} scope, {} baseline, {} audit, {}",
                        name,
                        format_size(size),
                        att.header.scope,
                        att.header.baseline_entry_count,
                        att.header.audit_entry_count,
                        att.header.created_at_wall,
                    );
                }
                Err(_) => {
                    eprintln!("  {} ({}) -- parse error", name, format_size(size));
                }
            },
            Err(_) => {
                eprintln!("  {} -- unreadable", name);
            }
        }
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
