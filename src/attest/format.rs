//! Attestation wire format types.
//!
//! All types here are CBOR-serializable via `serde` + `ciborium` with
//! deterministic encoding (RFC 8949 §4.2). Field order is fixed by the
//! struct definition order. The types are versioned — `format_version`
//! in the header gates parsing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Fixed 12-byte magic identifying a `.vatt` file.
pub const MAGIC: &[u8; 12] = b"VIGIL-ATTEST";

/// Current format version.
pub const FORMAT_VERSION: u16 = 1;

/// Top-level attestation structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub header: Header,
    pub body: Body,
    pub footer: Footer,
}

/// Attestation header — always present, contains summary metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// Fixed 12-byte magic: "VIGIL-ATTEST"
    #[serde(with = "magic_bytes")]
    pub magic: [u8; 12],
    /// Wire format version (start at 1)
    pub format_version: u16,
    /// RFC 3339 UTC timestamp string
    pub created_at_wall: String,
    /// Monotonic nanoseconds at creation (for cross-checking)
    pub created_at_monotonic: u64,
    /// BLAKE3 of machine-id || hostname || install_uuid
    pub host_id: [u8; 32],
    /// Human-readable hostname hint (advisory only)
    pub host_id_hint: String,
    /// Current baseline epoch (0 if not tracked)
    pub baseline_epoch: u64,
    /// Number of baseline entries
    pub baseline_entry_count: u64,
    /// Number of audit entries
    pub audit_entry_count: u64,
    /// BLAKE3 of last audit entry chain hash; zero if no entries
    pub audit_chain_head: [u8; 32],
    /// Vigil version that created this attestation
    pub vigil_version: String,
    /// Attestation scope
    pub scope: Scope,
}

/// Attestation body — contents depend on scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    pub baseline_entries: Option<Vec<AttestBaselineEntry>>,
    pub audit_entries: Option<Vec<AttestAuditEntry>>,
    pub config_snapshot: Option<String>,
    pub watch_groups: Option<Vec<AttestWatchGroup>>,
}

/// Attestation footer — integrity and signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Footer {
    /// BLAKE3 over deterministic CBOR of header || body
    pub content_hash: [u8; 32],
    /// Signature scheme used
    pub signature_scheme: SignatureScheme,
    /// Signature bytes (HMAC-BLAKE3 output or Ed25519 signature)
    pub signature: Vec<u8>,
    /// Short fingerprint of signing key (first 8 bytes of key ID)
    pub signing_key_id: [u8; 8],
}

/// Attestation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Full,
    BaselineOnly,
    HeadOnly,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Full => write!(f, "full"),
            Scope::BaselineOnly => write!(f, "baseline-only"),
            Scope::HeadOnly => write!(f, "head-only"),
        }
    }
}

impl std::str::FromStr for Scope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full" => Ok(Scope::Full),
            "baseline-only" => Ok(Scope::BaselineOnly),
            "head-only" => Ok(Scope::HeadOnly),
            _ => Err(format!("unknown scope: {}", s)),
        }
    }
}

/// Signature scheme identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureScheme {
    HmacBlake3,
    // Ed25519 — future. Stub kept for forward-compat.
    // Ed25519,
}

impl std::fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureScheme::HmacBlake3 => write!(f, "HMAC-BLAKE3"),
        }
    }
}

// ── Stable wire-format baseline entry ──

/// A baseline entry in the attestation wire format.
/// Mirrors `types::BaselineEntry` but with stable, portable field types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestBaselineEntry {
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub file_type: String,
    pub inode: u64,
    pub device: u64,
    pub mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mtime: i64,
    pub symlink_target: Option<String>,
    pub capabilities: Option<String>,
    pub xattrs: BTreeMap<String, String>,
    pub security_context: String,
    pub package: Option<String>,
    pub source: String,
    pub added_at: i64,
    pub updated_at: i64,
}

impl AttestBaselineEntry {
    /// Convert from the in-memory baseline entry type.
    pub fn from_baseline(entry: &crate::types::BaselineEntry) -> Self {
        Self {
            path: entry.path.to_string_lossy().to_string(),
            hash: entry.content.hash.clone(),
            size: entry.content.size,
            file_type: entry.identity.file_type.to_string(),
            inode: entry.identity.inode,
            device: entry.identity.device,
            mode: entry.permissions.mode,
            owner_uid: entry.permissions.owner_uid,
            owner_gid: entry.permissions.owner_gid,
            mtime: entry.mtime,
            symlink_target: entry
                .identity
                .symlink_target
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            capabilities: entry.permissions.capabilities.clone(),
            xattrs: entry.security.xattrs.clone(),
            security_context: entry.security.security_context.clone(),
            package: entry.package.clone(),
            source: entry.source.to_string(),
            added_at: entry.added_at,
            updated_at: entry.updated_at,
        }
    }
}

// ── Stable wire-format audit entry ──

/// An audit entry in the attestation wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestAuditEntry {
    pub id: i64,
    pub timestamp: i64,
    pub path: String,
    pub changes_json: String,
    pub severity: String,
    pub monitored_group: Option<String>,
    pub process_json: Option<String>,
    pub package: Option<String>,
    pub maintenance: bool,
    pub suppressed: bool,
    pub chain_hash: String,
}

impl AttestAuditEntry {
    pub fn from_audit(entry: &crate::db::audit_ops::AuditEntry) -> Self {
        Self {
            id: entry.id,
            timestamp: entry.timestamp,
            path: entry.path.clone(),
            changes_json: entry.changes_json.clone(),
            severity: entry.severity.clone(),
            monitored_group: entry.monitored_group.clone(),
            process_json: entry.process_json.clone(),
            package: entry.package.clone(),
            maintenance: entry.maintenance,
            suppressed: entry.suppressed,
            // Deliberately exclude HMAC — the chain HMAC key must never leave the host
            chain_hash: entry.chain_hash.clone(),
        }
    }
}

// ── Stable wire-format watch group ──

/// A resolved watch group in the attestation wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestWatchGroup {
    pub name: String,
    pub severity: String,
    pub paths: Vec<String>,
    pub mode: String,
}

// ── CBOR deterministic serialization helpers ──

/// Serialize header + body to deterministic CBOR bytes.
///
/// We serialize a two-element array `[header, body]` so the content hash
/// covers both in a single deterministic byte stream.
pub fn serialize_header_body(header: &Header, body: &Body) -> Result<Vec<u8>, String> {
    let pair: (&Header, &Body) = (header, body);
    let mut buf = Vec::new();
    ciborium::into_writer(&pair, &mut buf)
        .map_err(|e| format!("CBOR serialization failed: {}", e))?;
    Ok(buf)
}

/// Serialize a complete attestation to CBOR bytes.
pub fn serialize_attestation(attestation: &Attestation) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(attestation, &mut buf)
        .map_err(|e| format!("CBOR serialization failed: {}", e))?;
    Ok(buf)
}

/// Deserialize an attestation from CBOR bytes.
pub fn deserialize_attestation(data: &[u8]) -> Result<Attestation, String> {
    ciborium::from_reader(data).map_err(|e| format!("CBOR deserialization failed: {}", e))
}

/// Compute content hash (BLAKE3) over the deterministic CBOR encoding of header + body.
pub fn compute_content_hash(header: &Header, body: &Body) -> Result<[u8; 32], String> {
    let cbor_bytes = serialize_header_body(header, body)?;
    Ok(*blake3::hash(&cbor_bytes).as_bytes())
}

// ── Serde helper for magic bytes ──

mod magic_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&bytes[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let v: Vec<u8> = Deserialize::deserialize(d)?;
        if v.len() != 12 {
            return Err(serde::de::Error::custom(format!(
                "expected 12 magic bytes, got {}",
                v.len()
            )));
        }
        let mut arr = [0u8; 12];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_display_roundtrip() {
        for scope in &[Scope::Full, Scope::BaselineOnly, Scope::HeadOnly] {
            let s = scope.to_string();
            let parsed: Scope = s.parse().unwrap();
            assert_eq!(*scope, parsed);
        }
    }

    #[test]
    fn magic_constant_is_correct() {
        assert_eq!(MAGIC, b"VIGIL-ATTEST");
        assert_eq!(MAGIC.len(), 12);
    }

    #[test]
    fn header_body_cbor_roundtrip() {
        let header = Header {
            magic: *MAGIC,
            format_version: FORMAT_VERSION,
            created_at_wall: "2026-04-18T14:22:01Z".to_string(),
            created_at_monotonic: 123456789,
            host_id: [0xaa; 32],
            host_id_hint: "test-host".to_string(),
            baseline_epoch: 1,
            baseline_entry_count: 0,
            audit_entry_count: 0,
            audit_chain_head: [0; 32],
            vigil_version: "0.42.0".to_string(),
            scope: Scope::HeadOnly,
        };
        let body = Body {
            baseline_entries: None,
            audit_entries: None,
            config_snapshot: None,
            watch_groups: None,
        };

        let cbor = serialize_header_body(&header, &body).unwrap();
        // Deserialize back as a tuple
        let (h2, b2): (Header, Body) = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(h2.magic, *MAGIC);
        assert_eq!(h2.format_version, FORMAT_VERSION);
        assert_eq!(h2.scope, Scope::HeadOnly);
        assert!(b2.baseline_entries.is_none());
    }

    #[test]
    fn full_attestation_cbor_roundtrip() {
        let header = Header {
            magic: *MAGIC,
            format_version: FORMAT_VERSION,
            created_at_wall: "2026-04-18T14:22:01Z".to_string(),
            created_at_monotonic: 0,
            host_id: [0; 32],
            host_id_hint: String::new(),
            baseline_epoch: 0,
            baseline_entry_count: 0,
            audit_entry_count: 0,
            audit_chain_head: [0; 32],
            vigil_version: "0.42.0".to_string(),
            scope: Scope::Full,
        };
        let body = Body {
            baseline_entries: Some(Vec::new()),
            audit_entries: Some(Vec::new()),
            config_snapshot: Some("# empty".to_string()),
            watch_groups: Some(Vec::new()),
        };
        let footer = Footer {
            content_hash: [0x42; 32],
            signature_scheme: SignatureScheme::HmacBlake3,
            signature: vec![0xde, 0xad],
            signing_key_id: [0x01; 8],
        };

        let att = Attestation {
            header,
            body,
            footer,
        };

        let bytes = serialize_attestation(&att).unwrap();
        let att2 = deserialize_attestation(&bytes).unwrap();
        assert_eq!(att2.header.scope, Scope::Full);
        assert_eq!(att2.footer.content_hash, [0x42; 32]);
        assert_eq!(att2.footer.signature, vec![0xde, 0xad]);
    }

    #[test]
    fn content_hash_deterministic() {
        let header = Header {
            magic: *MAGIC,
            format_version: FORMAT_VERSION,
            created_at_wall: "2026-04-18T14:22:01Z".to_string(),
            created_at_monotonic: 0,
            host_id: [0; 32],
            host_id_hint: String::new(),
            baseline_epoch: 0,
            baseline_entry_count: 0,
            audit_entry_count: 0,
            audit_chain_head: [0; 32],
            vigil_version: "0.42.0".to_string(),
            scope: Scope::HeadOnly,
        };
        let body = Body {
            baseline_entries: None,
            audit_entries: None,
            config_snapshot: None,
            watch_groups: None,
        };

        let h1 = compute_content_hash(&header, &body).unwrap();
        let h2 = compute_content_hash(&header, &body).unwrap();
        assert_eq!(h1, h2);
    }
}
