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
    }
}

#[test]
fn test_hmac_verification_rejects_tampered_chain() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    vigil::db::schema::create_audit_tables(&conn).unwrap();

    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();

    // Insert two valid audit entries
    let c1 = sample_change("/tmp/a");
    let h1 =
        vigil::db::audit_ops::insert_audit_entry(&conn, &c1, false, false, None, &genesis).unwrap();

    let c2 = sample_change("/tmp/b");
    let _h2 =
        vigil::db::audit_ops::insert_audit_entry(&conn, &c2, false, false, None, &h1).unwrap();

    // Verify chain is valid before tampering
    let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn).unwrap();
    assert_eq!(total, 2);
    assert_eq!(valid, 2);
    assert!(breaks.is_empty());
    assert_eq!(missing, 0);

    // Tamper with the chain_hash of the first entry
    conn.execute(
        "UPDATE audit_log SET chain_hash = 'tampered_hash_value' WHERE id = 1",
        [],
    )
    .unwrap();

    // Verify chain now detects the tamper
    let (total2, valid2, breaks2, _missing2) = vigil::db::audit_ops::verify_chain(&conn).unwrap();
    assert_eq!(total2, 2);
    // At least one entry should be a break since the chain was tampered
    assert!(!breaks2.is_empty(), "should detect tampered chain hash");
    assert!(
        valid2 < 2,
        "not all entries should be valid after tampering"
    );
}
