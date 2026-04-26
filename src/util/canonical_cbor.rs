//! Deterministic CBOR encoding for audit HMAC data.
//!
//! RFC 8949 §4.2 deterministic encoding: definite-length, canonical key
//! ordering (lexicographic on encoded key bytes). Uses `ciborium` which
//! already produces definite-length encodings; we ensure canonical key
//! order by using a `BTreeMap` (sorted keys).
//!
//! VIGIL-VULN-076: replaces the pipe-delimited v1 format which was
//! vulnerable to delimiter collision on paths containing `|`.

use std::collections::BTreeMap;

/// Build deterministic CBOR bytes for audit HMAC v2 input.
///
/// Fields are encoded as a CBOR map with fixed string keys in canonical
/// (lexicographic) order. Path is encoded as a byte string to preserve
/// non-UTF-8 path bytes. Optional fields use CBOR `null`, not omission.
///
/// Keys (sorted): `"change"`, `"new"`, `"old"`, `"path"`, `"prev"`,
/// `"sev"`, `"ts"`.
pub(crate) fn build_audit_hmac_cbor(
    timestamp: i64,
    path: &[u8],
    change_type: &str,
    severity: &str,
    old_hash: Option<&str>,
    new_hash: Option<&str>,
    previous_chain_hash: &str,
) -> Vec<u8> {
    // BTreeMap<String, _> ensures lexicographic key ordering (RFC 8949 §4.2.1).
    // We build a BTreeMap of key→CborValue, then serialize as a CBOR map with
    // keys in insertion order (BTreeMap iterates in sorted order).
    let mut map = BTreeMap::new();
    map.insert(
        "change".to_string(),
        CborField::Text(change_type.to_string()),
    );
    map.insert(
        "new".to_string(),
        match new_hash {
            Some(h) => CborField::Text(h.to_string()),
            None => CborField::Null,
        },
    );
    map.insert(
        "old".to_string(),
        match old_hash {
            Some(h) => CborField::Text(h.to_string()),
            None => CborField::Null,
        },
    );
    // Path as CBOR byte string (not text) to preserve non-UTF-8 bytes.
    map.insert("path".to_string(), CborField::Bytes(path.to_vec()));
    map.insert(
        "prev".to_string(),
        CborField::Text(previous_chain_hash.to_string()),
    );
    map.insert("sev".to_string(), CborField::Text(severity.to_string()));
    map.insert("ts".to_string(), CborField::Integer(timestamp));

    // Convert to ciborium Value::Map with keys in sorted order.
    let cbor_entries: Vec<(ciborium::Value, ciborium::Value)> = map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Text(k), v.into_cbor()))
        .collect();

    let cbor_map = ciborium::Value::Map(cbor_entries);
    let mut buf = Vec::new();
    ciborium::into_writer(&cbor_map, &mut buf).expect("CBOR serialization of audit map");
    buf
}

/// Internal field type for building deterministic CBOR maps.
enum CborField {
    Text(String),
    Bytes(Vec<u8>),
    Integer(i64),
    Null,
}

impl CborField {
    fn into_cbor(self) -> ciborium::Value {
        match self {
            CborField::Text(s) => ciborium::Value::Text(s),
            CborField::Bytes(b) => ciborium::Value::Bytes(b),
            CborField::Integer(n) => ciborium::Value::Integer(n.into()),
            CborField::Null => ciborium::Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_roundtrip_deterministic() {
        let a = build_audit_hmac_cbor(
            1700000000,
            b"/etc/passwd",
            "modified",
            "critical",
            Some("oldhash"),
            Some("newhash"),
            "prev_chain",
        );
        let b = build_audit_hmac_cbor(
            1700000000,
            b"/etc/passwd",
            "modified",
            "critical",
            Some("oldhash"),
            Some("newhash"),
            "prev_chain",
        );
        assert_eq!(a, b, "identical inputs must produce identical CBOR bytes");
    }

    #[test]
    fn cbor_none_hashes_use_null() {
        let data = build_audit_hmac_cbor(
            1700000000,
            b"/etc/test",
            "deleted",
            "high",
            None,
            None,
            "genesis",
        );
        // Deserialize and verify nulls
        let val: ciborium::Value = ciborium::from_reader(&data[..]).unwrap();
        if let ciborium::Value::Map(entries) = &val {
            let old = entries
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("old".into()));
            let new = entries
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("new".into()));
            assert!(matches!(old, Some((_, ciborium::Value::Null))));
            assert!(matches!(new, Some((_, ciborium::Value::Null))));
        } else {
            panic!("expected CBOR map");
        }
    }

    /// VIGIL-VULN-076: The v1 pipe-delimited format collides when paths
    /// contain `|`. The v2 CBOR format must NOT collide.
    #[test]
    fn cbor_no_delimiter_collision() {
        // These two inputs produce identical v1 pipe-delimited strings:
        //   "1700000000|/etc/foo|bar|modified|high|||genesis"
        // but MUST produce different CBOR bytes.
        let a = build_audit_hmac_cbor(
            1700000000,
            b"/etc/foo|bar",
            "modified",
            "high",
            None,
            None,
            "genesis",
        );
        let b = build_audit_hmac_cbor(
            1700000000,
            b"/etc/foo",
            "bar|modified",
            "high",
            None,
            None,
            "genesis",
        );
        assert_ne!(a, b, "v2 CBOR must not collide on pipe-containing paths");
    }

    #[test]
    fn cbor_path_as_bytes_preserves_non_utf8() {
        let non_utf8_path: &[u8] = &[0x2F, 0x65, 0x74, 0x63, 0x2F, 0xFF, 0xFE];
        let data = build_audit_hmac_cbor(
            1700000000,
            non_utf8_path,
            "modified",
            "high",
            None,
            None,
            "genesis",
        );
        // Deserialize and verify path is byte string containing exact bytes
        let val: ciborium::Value = ciborium::from_reader(&data[..]).unwrap();
        if let ciborium::Value::Map(entries) = val {
            let path_val = entries
                .into_iter()
                .find(|(k, _)| k == &ciborium::Value::Text("path".into()))
                .map(|(_, v)| v);
            assert_eq!(
                path_val,
                Some(ciborium::Value::Bytes(non_utf8_path.to_vec())),
                "path must be CBOR byte string with exact bytes"
            );
        } else {
            panic!("expected CBOR map");
        }
    }

    #[test]
    fn cbor_keys_are_lexicographically_sorted() {
        let data = build_audit_hmac_cbor(
            1700000000,
            b"/etc/test",
            "modified",
            "high",
            Some("old"),
            Some("new"),
            "prev",
        );
        let val: ciborium::Value = ciborium::from_reader(&data[..]).unwrap();
        if let ciborium::Value::Map(entries) = val {
            let keys: Vec<String> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let ciborium::Value::Text(s) = k {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted, "keys must be in lexicographic order");
        } else {
            panic!("expected CBOR map");
        }
    }
}
