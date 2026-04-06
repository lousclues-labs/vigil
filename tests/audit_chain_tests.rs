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
