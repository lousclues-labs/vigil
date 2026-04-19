//! `vigil attest diff` -- compare an attestation against current state or another attestation.

use std::collections::BTreeMap;

use super::error::{AttestError, AttestResult};
use super::format::{AttestBaselineEntry, Attestation};

/// Diff result for a single path.
#[derive(Debug)]
pub enum EntryDiff {
    /// Present in left (attestation) but not in right
    OnlyLeft(AttestBaselineEntry),
    /// Present in right but not in left (attestation)
    OnlyRight(AttestBaselineEntry),
    /// Present in both with differences
    Changed {
        path: String,
        differences: Vec<FieldDiff>,
    },
}

/// A single field difference.
#[derive(Debug)]
pub struct FieldDiff {
    pub field: String,
    pub left: String,
    pub right: String,
}

/// Chain comparison result.
#[derive(Debug)]
pub enum ChainComparison {
    /// Current chain extends the attestation's chain
    Extends { additional_entries: u64 },
    /// Chains match exactly
    Identical,
    /// Chain has been forked or rewritten
    Forked,
    /// Cannot compare (no audit data in attestation or no current chain)
    Unavailable,
}

/// Full diff report.
#[derive(Debug)]
pub struct DiffReport {
    pub only_in_attestation: Vec<String>,
    pub only_in_current: Vec<String>,
    pub changed: Vec<EntryDiff>,
    pub chain_comparison: ChainComparison,
}

/// Compare an attestation against the live baseline DB.
pub fn diff_against_current(
    attestation: &Attestation,
    config: &crate::config::Config,
) -> AttestResult<DiffReport> {
    let baseline_path = &config.daemon.db_path;
    if !baseline_path.exists() {
        return Err(AttestError::Other(
            "no baseline found; cannot compare. Run `vigil init` first.".to_string(),
        ));
    }

    let conn = crate::db::open_baseline_db_readonly(baseline_path)
        .map_err(|e| AttestError::Other(format!("cannot open baseline DB: {}", e)))?;

    let current_entries = crate::db::baseline_ops::get_all(&conn)
        .map_err(|e| AttestError::Other(format!("cannot read baseline: {}", e)))?;

    // Convert current entries to attest format for comparison
    let current_map: BTreeMap<String, AttestBaselineEntry> = current_entries
        .iter()
        .map(|e| {
            let ae = super::format::AttestBaselineEntry::from_baseline(e);
            (ae.path.clone(), ae)
        })
        .collect();

    let attest_entries = attestation.body.baseline_entries.as_ref().ok_or_else(|| {
        AttestError::Other(
            "attestation has no baseline entries (scope may be head-only)".to_string(),
        )
    })?;

    let attest_map: BTreeMap<String, &AttestBaselineEntry> =
        attest_entries.iter().map(|e| (e.path.clone(), e)).collect();

    let mut only_in_attestation = Vec::new();
    let mut only_in_current = Vec::new();
    let mut changed = Vec::new();

    // Paths in attestation but not in current
    for (path, ae) in &attest_map {
        if !current_map.contains_key(path) {
            only_in_attestation.push(path.clone());
        } else {
            let ce = &current_map[path];
            let diffs = compare_entries(ae, ce);
            if !diffs.is_empty() {
                changed.push(EntryDiff::Changed {
                    path: path.clone(),
                    differences: diffs,
                });
            }
        }
    }

    // Paths in current but not in attestation
    for path in current_map.keys() {
        if !attest_map.contains_key(path) {
            only_in_current.push(path.clone());
        }
    }

    // Chain comparison
    let chain_comparison = compare_chain_against_current(attestation, config);

    Ok(DiffReport {
        only_in_attestation,
        only_in_current,
        changed,
        chain_comparison,
    })
}

/// Compare two attestation files.
pub fn diff_attestations(left: &Attestation, right: &Attestation) -> AttestResult<DiffReport> {
    let left_entries = left.body.baseline_entries.as_ref().ok_or_else(|| {
        AttestError::Other("left attestation has no baseline entries".to_string())
    })?;
    let right_entries = right.body.baseline_entries.as_ref().ok_or_else(|| {
        AttestError::Other("right attestation has no baseline entries".to_string())
    })?;

    let left_map: BTreeMap<String, &AttestBaselineEntry> =
        left_entries.iter().map(|e| (e.path.clone(), e)).collect();
    let right_map: BTreeMap<String, &AttestBaselineEntry> =
        right_entries.iter().map(|e| (e.path.clone(), e)).collect();

    let mut only_in_attestation = Vec::new();
    let mut only_in_current = Vec::new();
    let mut changed = Vec::new();

    for (path, le) in &left_map {
        if !right_map.contains_key(path) {
            only_in_attestation.push(path.clone());
        } else {
            let re = right_map[path];
            let diffs = compare_entries(le, re);
            if !diffs.is_empty() {
                changed.push(EntryDiff::Changed {
                    path: path.clone(),
                    differences: diffs,
                });
            }
        }
    }

    for path in right_map.keys() {
        if !left_map.contains_key(path) {
            only_in_current.push(path.clone());
        }
    }

    // Chain comparison between attestations
    let chain_comparison = if left.header.audit_chain_head == right.header.audit_chain_head {
        ChainComparison::Identical
    } else if left.header.audit_chain_head == [0u8; 32]
        || right.header.audit_chain_head == [0u8; 32]
    {
        ChainComparison::Unavailable
    } else {
        // Check if right chain extends left
        if let (Some(_left_audit), Some(right_audit)) =
            (&left.body.audit_entries, &right.body.audit_entries)
        {
            let left_head_hex = hex::encode(left.header.audit_chain_head);
            // Search for left's chain head in right's entries
            if let Some(pos) = right_audit.iter().position(|e| {
                hex::encode(blake3::hash(e.chain_hash.as_bytes()).as_bytes()) == left_head_hex
            }) {
                ChainComparison::Extends {
                    additional_entries: (right_audit.len() - pos - 1) as u64,
                }
            } else {
                ChainComparison::Forked
            }
        } else {
            ChainComparison::Forked
        }
    };

    Ok(DiffReport {
        only_in_attestation,
        only_in_current,
        changed,
        chain_comparison,
    })
}

/// Compare two baseline entries and return field differences.
fn compare_entries(left: &AttestBaselineEntry, right: &AttestBaselineEntry) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();

    if left.hash != right.hash {
        diffs.push(FieldDiff {
            field: "hash".to_string(),
            left: truncate_hash(&left.hash),
            right: truncate_hash(&right.hash),
        });
    }
    if left.size != right.size {
        diffs.push(FieldDiff {
            field: "size".to_string(),
            left: left.size.to_string(),
            right: right.size.to_string(),
        });
    }
    if left.mode != right.mode {
        diffs.push(FieldDiff {
            field: "mode".to_string(),
            left: format!("{:04o}", left.mode),
            right: format!("{:04o}", right.mode),
        });
    }
    if left.owner_uid != right.owner_uid {
        diffs.push(FieldDiff {
            field: "uid".to_string(),
            left: left.owner_uid.to_string(),
            right: right.owner_uid.to_string(),
        });
    }
    if left.owner_gid != right.owner_gid {
        diffs.push(FieldDiff {
            field: "gid".to_string(),
            left: left.owner_gid.to_string(),
            right: right.owner_gid.to_string(),
        });
    }
    if left.inode != right.inode {
        diffs.push(FieldDiff {
            field: "inode".to_string(),
            left: left.inode.to_string(),
            right: right.inode.to_string(),
        });
    }
    if left.file_type != right.file_type {
        diffs.push(FieldDiff {
            field: "type".to_string(),
            left: left.file_type.clone(),
            right: right.file_type.clone(),
        });
    }
    if left.symlink_target != right.symlink_target {
        diffs.push(FieldDiff {
            field: "symlink".to_string(),
            left: left.symlink_target.clone().unwrap_or_default(),
            right: right.symlink_target.clone().unwrap_or_default(),
        });
    }
    if left.security_context != right.security_context {
        diffs.push(FieldDiff {
            field: "security_context".to_string(),
            left: left.security_context.clone(),
            right: right.security_context.clone(),
        });
    }

    diffs
}

/// Compare audit chain head from attestation against current live DB.
fn compare_chain_against_current(
    attestation: &Attestation,
    config: &crate::config::Config,
) -> ChainComparison {
    if attestation.header.audit_chain_head == [0u8; 32] {
        return ChainComparison::Unavailable;
    }

    let audit_path = crate::db::audit_db_path(config);
    if !audit_path.exists() {
        return ChainComparison::Unavailable;
    }

    let conn = match crate::db::open_baseline_db_readonly(&audit_path) {
        Ok(c) => c,
        Err(_) => return ChainComparison::Unavailable,
    };

    // Get current chain head
    let current_head = match crate::db::audit_ops::get_last_chain_hash(&conn) {
        Ok(Some(h)) => h,
        _ => return ChainComparison::Unavailable,
    };

    let current_head_hash = *blake3::hash(current_head.as_bytes()).as_bytes();
    let attest_head = attestation.header.audit_chain_head;

    if current_head_hash == attest_head {
        return ChainComparison::Identical;
    }

    // Search for the attestation's chain head in the current chain
    let attest_head_hex = hex::encode(attest_head);

    // Walk the current chain looking for the attestation's head
    let search = conn.prepare("SELECT chain_hash FROM audit_log ORDER BY id ASC");
    if let Ok(mut stmt) = search {
        let rows = stmt.query_map([], |row| row.get::<_, String>(0));
        if let Ok(rows) = rows {
            let mut found = false;
            let mut after_count: u64 = 0;
            for hash in rows.flatten() {
                let hash_of_hash = hex::encode(blake3::hash(hash.as_bytes()).as_bytes());
                if found {
                    after_count += 1;
                } else if hash_of_hash == attest_head_hex {
                    found = true;
                }
            }
            if found {
                return ChainComparison::Extends {
                    additional_entries: after_count,
                };
            }
        }
    }

    ChainComparison::Forked
}

fn truncate_hash(h: &str) -> String {
    if h.len() > 12 {
        format!("{}...", &h[..12])
    } else {
        h.to_string()
    }
}

/// Print a human-readable diff report.
pub fn print_diff_report(report: &DiffReport, left_label: &str, right_label: &str) {
    let total_diffs =
        report.only_in_attestation.len() + report.only_in_current.len() + report.changed.len();

    if total_diffs == 0 {
        eprintln!("  No differences in baseline entries.");
    } else {
        if !report.only_in_attestation.is_empty() {
            eprintln!(
                "  {} path(s) in {} but not in {}:",
                report.only_in_attestation.len(),
                left_label,
                right_label,
            );
            for p in &report.only_in_attestation {
                eprintln!("    - {}", p);
            }
            eprintln!();
        }

        if !report.only_in_current.is_empty() {
            eprintln!(
                "  {} path(s) in {} but not in {}:",
                report.only_in_current.len(),
                right_label,
                left_label,
            );
            for p in &report.only_in_current {
                eprintln!("    + {}", p);
            }
            eprintln!();
        }

        if !report.changed.is_empty() {
            eprintln!("  {} path(s) differ:", report.changed.len(),);
            for entry in &report.changed {
                if let EntryDiff::Changed { path, differences } = entry {
                    eprintln!("    ~ {}", path);
                    for d in differences {
                        eprintln!("        {}: {} → {}", d.field, d.left, d.right);
                    }
                }
            }
            eprintln!();
        }
    }

    // Chain comparison
    match &report.chain_comparison {
        ChainComparison::Identical => {
            eprintln!("  Audit chain: identical");
        }
        ChainComparison::Extends { additional_entries } => {
            eprintln!(
                "  Audit chain: current chain extends attestation by {} entries",
                additional_entries
            );
        }
        ChainComparison::Forked => {
            eprintln!("  ✗ Audit chain: FORKED OR REWRITTEN since attestation");
            eprintln!("    The audit chain has been modified since this attestation was created.");
            eprintln!("    This is a HIGH-SEVERITY finding.");
        }
        ChainComparison::Unavailable => {
            eprintln!("  Audit chain: comparison unavailable (no audit data in attestation or current state)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::format::{
        Attestation, Body, Footer, Header, Scope, SignatureScheme, FORMAT_VERSION, MAGIC,
    };

    fn mk_baseline(path: &str, hash: &str) -> AttestBaselineEntry {
        AttestBaselineEntry {
            path: path.to_string(),
            hash: hash.to_string(),
            size: 1,
            file_type: "regular".to_string(),
            inode: 1,
            device: 1,
            mode: 0o644,
            owner_uid: 0,
            owner_gid: 0,
            mtime: 1,
            symlink_target: None,
            capabilities: None,
            xattrs: std::collections::BTreeMap::new(),
            security_context: String::new(),
            package: None,
            source: "manual".to_string(),
            added_at: 1,
            updated_at: 1,
        }
    }

    fn mk_attestation(entries: Vec<AttestBaselineEntry>, chain_head: [u8; 32]) -> Attestation {
        Attestation {
            header: Header {
                magic: *MAGIC,
                format_version: FORMAT_VERSION,
                created_at_wall: "2026-04-18T14:22:01Z".to_string(),
                created_at_monotonic: 0,
                host_id: [0; 32],
                host_id_hint: "host".to_string(),
                baseline_epoch: 0,
                baseline_entry_count: entries.len() as u64,
                audit_entry_count: 0,
                audit_chain_head: chain_head,
                vigil_version: "0.41.0".to_string(),
                scope: Scope::BaselineOnly,
            },
            body: Body {
                baseline_entries: Some(entries),
                audit_entries: None,
                config_snapshot: None,
                watch_groups: None,
            },
            footer: Footer {
                content_hash: [0; 32],
                signature_scheme: SignatureScheme::HmacBlake3,
                signature: Vec::new(),
                signing_key_id: [0; 8],
            },
        }
    }

    #[test]
    fn compare_entries_detects_hash_change() {
        let left = mk_baseline("/etc/passwd", "abc");
        let right = mk_baseline("/etc/passwd", "def");
        let diffs = compare_entries(&left, &right);
        assert!(diffs.iter().any(|d| d.field == "hash"));
    }

    #[test]
    fn diff_attestations_detects_added_removed_and_changed() {
        let left = mk_attestation(
            vec![mk_baseline("/a", "111"), mk_baseline("/b", "222")],
            [1; 32],
        );
        let right = mk_attestation(
            vec![mk_baseline("/b", "333"), mk_baseline("/c", "444")],
            [2; 32],
        );

        let report = diff_attestations(&left, &right).unwrap();
        assert!(report.only_in_attestation.contains(&"/a".to_string()));
        assert!(report.only_in_current.contains(&"/c".to_string()));
        assert_eq!(report.changed.len(), 1);
    }

    #[test]
    fn diff_attestations_chain_identical() {
        let left = mk_attestation(vec![mk_baseline("/a", "111")], [9; 32]);
        let right = mk_attestation(vec![mk_baseline("/a", "111")], [9; 32]);
        let report = diff_attestations(&left, &right).unwrap();
        assert!(matches!(
            report.chain_comparison,
            ChainComparison::Identical
        ));
    }
}
