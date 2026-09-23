use std::sync::Arc;
use vigil::types::{Change, ChangeResult, Severity};

fn sample_change(path: &str) -> ChangeResult {
    ChangeResult {
        path: Arc::new(path.into()),
        changes: vec![Change::Created],
        severity: Severity::Medium,
        monitored_group: "test".into(),
        process: None,
        package: None,
        package_update: false,
        disambiguation: None,
    }
}

#[test]
fn audit_chain_break_detected_after_deletion() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    vigil::db::schema::create_audit_tables(&conn).unwrap();

    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();

    let c1 = sample_change("/tmp/a");
    let h1 =
        vigil::db::audit_ops::insert_audit_entry(&conn, &c1, false, false, None, &genesis).unwrap();

    let c2 = sample_change("/tmp/b");
    let _h2 =
        vigil::db::audit_ops::insert_audit_entry(&conn, &c2, false, false, None, &h1).unwrap();

    let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn).unwrap();
    assert_eq!(total, 2);
    assert_eq!(valid, 2);
    assert!(breaks.is_empty());
    assert_eq!(missing, 0);

    conn.execute("DELETE FROM audit_log WHERE id = 1", [])
        .unwrap();

    let (total2, _valid2, breaks2, _missing2) = vigil::db::audit_ops::verify_chain(&conn).unwrap();
    assert_eq!(total2, 1);
    assert!(!breaks2.is_empty());
}

/// HMAC verification must succeed on entries serialized the way this build
/// actually serializes them.
///
/// `Change` is internally tagged, but every `changes_json` consumer parsed the
/// older externally-tagged shape by reading `obj.keys().next()` -- which on a
/// `BTreeMap` returns the alphabetically first *field* name (`"new_hash"`),
/// not a variant name. The writer builds its HMAC input from the typed enum
/// and the verifier rebuilt it from that JSON guess, so the two could never
/// agree: verification failed on entries that were never tampered with.
///
/// Nothing caught it because the only test exercising the keyed path fed the
/// verifier a hand-written legacy fixture -- the one format it still
/// understood. This test serializes a real `Change`, so the fixture cannot
/// drift away from what the producer emits.
#[test]
fn hmac_verification_succeeds_on_the_format_actually_written() {
    use vigil::db;
    use vigil::types::Change;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.db");
    let conn = db::open_db_at(&audit_path, false).unwrap();
    db::schema::create_audit_tables(&conn).unwrap();

    let hmac_key = b"test-hmac-key-for-chain-verify";
    let mut prev = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();

    for i in 0..3 {
        let ts = 1_700_000_000 + i;
        let path = format!("/etc/test_{i}");
        let severity = "critical";

        // The real serialization, not a hand-written fixture.
        let changes = serde_json::to_string(&vec![Change::ContentModified {
            old_hash: "aaa".to_string(),
            new_hash: "bbb".to_string(),
        }])
        .unwrap();
        assert!(
            changes.contains(r#""type":"content_modified""#),
            "sanity: Change must serialize internally tagged, got {changes}"
        );

        let chain_hash = db::audit_ops::compute_chain_hash(&prev, ts, &path, &changes, severity);
        let data = vigil::hmac::build_audit_hmac_data_v2(
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
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 2)",
            rusqlite::params![ts, path, changes, severity, hmac, chain_hash],
        )
        .unwrap();

        prev = chain_hash;
    }

    let detail = db::audit_ops::verify_chain_detail(&conn, Some(hmac_key)).unwrap();

    assert_eq!(detail.total, 3);
    assert!(
        detail.breaks.is_empty(),
        "untampered entries must verify; breaks at {:?}. A mismatch means the \
         verifier and the writer disagree about what was signed, so every audit \
         entry reads as tampered.",
        detail.breaks
    );
    assert_eq!(detail.valid, detail.total);
}
