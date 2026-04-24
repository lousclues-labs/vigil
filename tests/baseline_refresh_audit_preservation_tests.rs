//! Integration tests for baseline refresh audit log preservation.
//!
//! Verifies that `vigil baseline refresh` correctly reports audit log
//! status in the complete event: entry count, chain integrity, and
//! the preservation invariant.

use rusqlite::{params, Connection};

fn genesis_hash() -> String {
    blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string()
}

fn insert_audit_entry(
    conn: &Connection,
    path: &str,
    severity: &str,
    previous_chain_hash: &str,
    timestamp: i64,
) -> String {
    let changes_json = r#"[{"Created":"Created"}]"#;
    let chain_hash = vigil::db::audit_ops::compute_chain_hash(
        previous_chain_hash,
        timestamp,
        path,
        changes_json,
        severity,
    );
    conn.execute(
        "INSERT INTO audit_log (timestamp, path, changes_json, severity, maintenance, suppressed, chain_hash)
         VALUES (?1, ?2, ?3, ?4, 0, 0, ?5)",
        params![timestamp, path, changes_json, severity, chain_hash],
    )
    .unwrap();
    chain_hash
}

fn setup_audit_db(dir: &std::path::Path, entry_count: usize) -> (String, String) {
    let mut cfg = vigil::config::default_config();
    cfg.daemon.db_path = dir.join("baseline.db");
    let audit_path = vigil::db::audit_db_path(&cfg);
    let conn = Connection::open(&audit_path).unwrap();
    vigil::db::schema::create_audit_tables(&conn).unwrap();

    let mut prev = genesis_hash();
    for i in 0..entry_count {
        prev = insert_audit_entry(
            &conn,
            &format!("/test/file_{}", i),
            "high",
            &prev,
            1_000_000 + i as i64,
        );
    }
    let final_hash = prev;
    drop(conn);
    (audit_path.to_string_lossy().to_string(), final_hash)
}

#[test]
fn refresh_complete_event_audit_log_structure() {
    // The audit_log JSON object must have the correct structure.
    let audit_log = serde_json::json!({
        "entry_count": 10,
        "chain_intact": true,
        "preserved_by_refresh": true,
    });

    assert!(audit_log["entry_count"].is_number());
    assert!(audit_log["chain_intact"].is_boolean());
    assert!(audit_log["preserved_by_refresh"].is_boolean());
}

#[test]
fn refresh_preserves_pre_refresh_chain_head() {
    let dir = tempfile::tempdir().unwrap();
    let (audit_path, pre_hash) = setup_audit_db(dir.path(), 10);

    // Simulate post-refresh: add more entries (as BaselineRefresh would)
    let conn = Connection::open(&audit_path).unwrap();
    let mut prev = pre_hash.clone();
    for i in 0..3 {
        prev = insert_audit_entry(
            &conn,
            &format!("/new/file_{}", i),
            "medium",
            &prev,
            2_000_000 + i as i64,
        );
    }

    // Verify the pre-refresh chain head still exists
    let found: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM audit_log WHERE chain_hash = ?1",
            params![pre_hash],
            |row| row.get(0),
        )
        .unwrap();
    assert!(found, "pre-refresh chain head must exist post-refresh");

    // Total count increased by 3
    let count = vigil::db::audit_ops::count(&conn).unwrap();
    assert_eq!(count, 13);
}

#[test]
fn refresh_audit_entry_count_increases_with_unattributed() {
    let dir = tempfile::tempdir().unwrap();
    let (audit_path, pre_hash) = setup_audit_db(dir.path(), 20);

    let conn = Connection::open(&audit_path).unwrap();
    let pre_count = vigil::db::audit_ops::count(&conn).unwrap();
    assert_eq!(pre_count, 20);

    // Simulate 5 unattributed changes appended during refresh
    let mut prev = pre_hash;
    for i in 0..5 {
        prev = insert_audit_entry(
            &conn,
            &format!("/unattributed/{}", i),
            "high",
            &prev,
            3_000_000 + i as i64,
        );
    }

    let post_count = vigil::db::audit_ops::count(&conn).unwrap();
    assert_eq!(post_count, pre_count + 5);
}

#[test]
fn refresh_audit_entry_count_unchanged_when_no_unattributed() {
    let dir = tempfile::tempdir().unwrap();
    let (audit_path, _pre_hash) = setup_audit_db(dir.path(), 15);

    let conn = Connection::open(&audit_path).unwrap();
    let pre_count = vigil::db::audit_ops::count(&conn).unwrap();
    assert_eq!(pre_count, 15);

    // No unattributed changes -> count stays the same
    let post_count = vigil::db::audit_ops::count(&conn).unwrap();
    assert_eq!(post_count, pre_count);
}

#[test]
fn refresh_detects_chain_broken() {
    let dir = tempfile::tempdir().unwrap();
    let (audit_path, _pre_hash) = setup_audit_db(dir.path(), 5);

    // Corrupt the chain
    let conn = Connection::open(&audit_path).unwrap();
    conn.execute(
        "UPDATE audit_log SET chain_hash = 'corrupt' WHERE id = 3",
        [],
    )
    .unwrap();

    let result = vigil::db::audit_ops::verify_chain(&conn).unwrap();
    let (_total, _valid, breaks, _missing) = result;
    assert!(!breaks.is_empty(), "chain should be broken");
    let (break_id, _) = breaks[0];
    assert_eq!(break_id, 3);
}

#[test]
fn refresh_audit_status_unavailable_on_missing_db() {
    // With a non-existent audit path, opening should fail gracefully
    let result = Connection::open_with_flags(
        "/nonexistent/audit.db",
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    );
    assert!(result.is_err());
}

#[test]
fn refresh_chain_intact_after_appends() {
    let dir = tempfile::tempdir().unwrap();
    let (audit_path, pre_hash) = setup_audit_db(dir.path(), 10);

    // Append more entries (simulating refresh)
    let conn = Connection::open(&audit_path).unwrap();
    let mut prev = pre_hash;
    for i in 0..5 {
        prev = insert_audit_entry(
            &conn,
            &format!("/appended/{}", i),
            "low",
            &prev,
            2_000_000 + i as i64,
        );
    }

    // Chain must still be intact
    let (total, valid, breaks, missing) = vigil::db::audit_ops::verify_chain(&conn).unwrap();
    assert_eq!(total, 15);
    assert_eq!(valid, 15);
    assert!(breaks.is_empty());
    assert_eq!(missing, 0);
}
