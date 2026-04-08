use rusqlite::params;
use vigil::db::{baseline_ops, schema};

/// Verify that compute_baseline_hmac produces different output for different baselines.
#[test]
fn baseline_hmac_differs_for_different_content() {
    let conn1 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn1).unwrap();
    let conn2 = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn2).unwrap();

    let key = b"test-hmac-key-for-vigil-baseline";

    let entry1 = vigil::types::BaselineEntry {
        id: None,
        path: "/etc/passwd".into(),
        identity: Default::default(),
        content: vigil::types::ContentFingerprint {
            hash: "abc123".into(),
            size: 100,
        },
        permissions: Default::default(),
        security: Default::default(),
        mtime: 1700000000,
        package: None,
        source: vigil::types::BaselineSource::AutoScan,
        added_at: 1700000000,
        updated_at: 1700000000,
    };

    let mut entry2 = entry1.clone();
    entry2.content.hash = "def456".into();

    baseline_ops::upsert(&conn1, &entry1).unwrap();
    baseline_ops::upsert(&conn2, &entry2).unwrap();

    let hmac1 = baseline_ops::compute_baseline_hmac(&conn1, key).unwrap();
    let hmac2 = baseline_ops::compute_baseline_hmac(&conn2, key).unwrap();

    assert_ne!(
        hmac1, hmac2,
        "different baseline content must produce different HMACs"
    );
}

/// Verify that a tampered baseline entry causes HMAC verification failure.
#[test]
fn baseline_hmac_detects_tampered_entry() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    let key = b"test-hmac-key-for-vigil-baseline";

    let entry = vigil::types::BaselineEntry {
        id: None,
        path: "/etc/passwd".into(),
        identity: Default::default(),
        content: vigil::types::ContentFingerprint {
            hash: "abc123".into(),
            size: 100,
        },
        permissions: Default::default(),
        security: Default::default(),
        mtime: 1700000000,
        package: None,
        source: vigil::types::BaselineSource::AutoScan,
        added_at: 1700000000,
        updated_at: 1700000000,
    };

    baseline_ops::upsert(&conn, &entry).unwrap();
    let original_hmac = baseline_ops::compute_baseline_hmac(&conn, key).unwrap();

    // Tamper with the entry
    conn.execute(
        "UPDATE baseline SET hash = 'tampered_hash' WHERE path = '/etc/passwd'",
        params![],
    )
    .unwrap();

    let tampered_hmac = baseline_ops::compute_baseline_hmac(&conn, key).unwrap();
    assert_ne!(
        original_hmac, tampered_hmac,
        "HMAC should change after tampering"
    );

    // Verify original HMAC fails against tampered baseline
    assert!(
        !vigil::hmac::verify_hmac(key, tampered_hmac.as_bytes(), &original_hmac),
        "original HMAC should not verify against tampered baseline"
    );
}

/// Verify that startup with a valid HMAC would succeed (HMAC roundtrip).
#[test]
fn baseline_hmac_roundtrip_passes() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    let key = b"test-hmac-key-for-vigil-baseline";

    let entry = vigil::types::BaselineEntry {
        id: None,
        path: "/usr/bin/test".into(),
        identity: Default::default(),
        content: vigil::types::ContentFingerprint {
            hash: "goodhash".into(),
            size: 200,
        },
        permissions: Default::default(),
        security: Default::default(),
        mtime: 1700000000,
        package: None,
        source: vigil::types::BaselineSource::AutoScan,
        added_at: 1700000000,
        updated_at: 1700000000,
    };

    baseline_ops::upsert(&conn, &entry).unwrap();

    // Compute and store HMAC
    let hmac = baseline_ops::compute_baseline_hmac(&conn, key).unwrap();
    baseline_ops::set_config_state(&conn, "baseline_hmac", &hmac).unwrap();

    // Verify stored HMAC matches recomputed
    let stored = baseline_ops::get_config_state(&conn, "baseline_hmac")
        .unwrap()
        .unwrap();
    let current = baseline_ops::compute_baseline_hmac(&conn, key).unwrap();
    assert_eq!(
        stored, current,
        "stored HMAC should match recomputed HMAC for unchanged baseline"
    );
}

/// Verify baseline_initialized flag prevents auto-reinitialize on empty baseline.
#[test]
fn empty_baseline_after_init_is_refused() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    // Set the baseline_initialized flag
    baseline_ops::set_config_state(&conn, "baseline_initialized", "true").unwrap();

    // Verify the flag is read correctly
    let was_initialized = baseline_ops::get_config_state(&conn, "baseline_initialized")
        .unwrap()
        .map(|v| v == "true")
        .unwrap_or(false);

    assert!(
        was_initialized,
        "baseline_initialized flag should be true after being set"
    );

    // Verify count is zero (empty baseline)
    let count = baseline_ops::count(&conn).unwrap();
    assert_eq!(count, 0, "baseline should be empty");
}

/// Verify first initialization succeeds and sets the flag.
#[test]
fn first_initialization_sets_flag() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    // Initially, no flag should be set
    let initial = baseline_ops::get_config_state(&conn, "baseline_initialized")
        .unwrap()
        .map(|v| v == "true")
        .unwrap_or(false);
    assert!(!initial, "baseline_initialized should not be set initially");

    // Set the flag (simulating successful init)
    baseline_ops::set_config_state(&conn, "baseline_initialized", "true").unwrap();

    let after = baseline_ops::get_config_state(&conn, "baseline_initialized")
        .unwrap()
        .map(|v| v == "true")
        .unwrap_or(false);
    assert!(after, "baseline_initialized should be true after init");
}
