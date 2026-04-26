// tests/audit_chain_v1_v2_mixed.rs
//
// Regression test for VIGIL-VULN-076: a mixed v1+v2 audit chain must verify
// correctly. Existing deployments will have v1 entries below new v2 entries.
// verify_chain must dispatch to the correct HMAC builder per entry's
// encoding_version.

use vigil::db;

/// Populate a chain with v1 entries (legacy pipe format), then append v2
/// entries. verify_chain must return Ok with zero breaks.
#[test]
fn mixed_v1_v2_chain_verifies_without_breaks() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.db");

    let conn = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&conn).unwrap();

    let hmac_key = b"test-hmac-key-for-chain-verify";

    // Genesis hash
    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();

    // Insert v1 entries (legacy format)
    let mut prev = genesis.clone();
    for i in 0..3 {
        let ts = 1700000000 + i;
        let path = format!("/etc/test_{}", i);
        let changes = r#"[{"ContentModified":{"old_hash":"aaa","new_hash":"bbb"}}]"#;
        let severity = "high";

        let chain_hash = db::audit_ops::compute_chain_hash(&prev, ts, &path, changes, severity);

        // v1 HMAC
        let data = vigil::hmac::build_audit_hmac_data(
            ts,
            &path,
            "content_modified",
            severity,
            Some("aaa"),
            Some("bbb"),
            &prev,
        );
        let hmac = vigil::hmac::compute_hmac(hmac_key, &data).unwrap();

        conn.execute(
            "INSERT INTO audit_log (
                timestamp, path, changes_json, severity, hmac, chain_hash,
                maintenance, suppressed, encoding_version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 1)",
            rusqlite::params![ts, path, changes, severity, hmac, chain_hash],
        )
        .unwrap();

        prev = chain_hash;
    }

    // Insert v2 entries (CBOR format)
    for i in 3..6 {
        let ts = 1700000000 + i;
        let path = format!("/etc/test_{}", i);
        let changes = r#"[{"ContentModified":{"old_hash":"ccc","new_hash":"ddd"}}]"#;
        let severity = "medium";

        let chain_hash = db::audit_ops::compute_chain_hash(&prev, ts, &path, changes, severity);

        // v2 HMAC (CBOR)
        let data = vigil::hmac::build_audit_hmac_data_v2(
            ts,
            &path,
            "content_modified",
            severity,
            Some("ccc"),
            Some("ddd"),
            &prev,
        );
        let hmac = vigil::hmac::compute_hmac(hmac_key, &data).unwrap();

        conn.execute(
            "INSERT INTO audit_log (
                timestamp, path, changes_json, severity, hmac, chain_hash,
                maintenance, suppressed, encoding_version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 2)",
            rusqlite::params![ts, path, changes, severity, hmac, chain_hash],
        )
        .unwrap();

        prev = chain_hash;
    }

    // Verify the full mixed chain
    let result = db::audit_ops::verify_chain_with_hmac(&conn, Some(hmac_key)).unwrap();
    let (total, valid, breaks, _missing) = result;

    assert_eq!(total, 6, "should have 6 entries total");
    assert_eq!(valid, 6, "all 6 entries should verify");
    assert!(
        breaks.is_empty(),
        "no chain breaks in mixed v1+v2 chain: {:?}",
        breaks
    );
}

/// A v1 entry verified with v2 builder should fail (wrong encoding).
/// This confirms the dispatch logic is actually working.
#[test]
fn wrong_encoding_version_causes_break() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.db");

    let conn = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&conn).unwrap();

    let hmac_key = b"test-key";
    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();

    let ts = 1700000000i64;
    let path = "/etc/passwd";
    let changes = r#"[{"ContentModified":{"old_hash":"aaa","new_hash":"bbb"}}]"#;
    let severity = "high";

    let chain_hash = db::audit_ops::compute_chain_hash(&genesis, ts, path, changes, severity);

    // Compute HMAC with v1 builder but store as encoding_version = 2
    let data = vigil::hmac::build_audit_hmac_data(
        ts,
        path,
        "content_modified",
        severity,
        Some("aaa"),
        Some("bbb"),
        &genesis,
    );
    let hmac = vigil::hmac::compute_hmac(hmac_key, &data).unwrap();

    conn.execute(
        "INSERT INTO audit_log (
            timestamp, path, changes_json, severity, hmac, chain_hash,
            maintenance, suppressed, encoding_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 2)",
        rusqlite::params![ts, path, changes, severity, hmac, chain_hash],
    )
    .unwrap();

    // This should show a break because the HMAC was built with v1 but
    // stored as encoding_version=2 (so verifier uses v2 builder)
    let result = db::audit_ops::verify_chain_with_hmac(&conn, Some(hmac_key)).unwrap();
    let (_total, _valid, breaks, _missing) = result;

    assert!(
        !breaks.is_empty(),
        "mismatched encoding version should cause HMAC verification break"
    );
}
