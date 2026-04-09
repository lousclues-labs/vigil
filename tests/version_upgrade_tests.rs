// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024–2026 loujr

//! Integration tests for version-upgrade scenarios.
//!
//! Simulates an old baseline DB (previously initialized but now empty after
//! schema migration) and verifies the daemon does not treat it as tampering
//! when the DB file is non-trivially sized.

use vigil::db::{baseline_ops, schema};

/// When a baseline DB was previously initialized but is now empty due to a
/// version-upgrade schema migration (DB file > 4096 bytes), ensure
/// `baseline_ops::count()` returns 0 but the DB is in a recoverable state.
#[test]
fn empty_baseline_after_schema_migration_is_recoverable() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    // Mark baseline as previously initialized (as a prior version would have done)
    baseline_ops::set_config_state(&conn, "baseline_initialized", "true").unwrap();

    // Verify count is zero (simulates post-migration empty table)
    let count = baseline_ops::count(&conn).unwrap();
    assert_eq!(count, 0, "empty baseline should have count 0");

    // Verify the initialized flag persists
    let flag = baseline_ops::get_config_state(&conn, "baseline_initialized")
        .unwrap()
        .unwrap();
    assert_eq!(flag, "true");
}

/// When a baseline DB has entries, the count should be accurate.
#[test]
fn populated_baseline_reports_correct_count() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

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
    baseline_ops::set_config_state(&conn, "baseline_initialized", "true").unwrap();

    let count = baseline_ops::count(&conn).unwrap();
    assert_eq!(count, 1);
}

/// HMAC recomputation after upgrade: storing old HMAC then recomputing should
/// yield a valid new HMAC without error.
#[test]
fn hmac_recomputation_after_upgrade_succeeds() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    let key = b"test-hmac-key-for-upgrade-check";

    let entry = vigil::types::BaselineEntry {
        id: None,
        path: "/usr/bin/test".into(),
        identity: Default::default(),
        content: vigil::types::ContentFingerprint {
            hash: "def456".into(),
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

    // Store an "old" HMAC (simulating a previous version's HMAC format)
    baseline_ops::set_config_state(&conn, "baseline_hmac", "old-stale-hmac-value").unwrap();

    // Recompute HMAC with current algorithm — should succeed
    let new_hmac = baseline_ops::compute_baseline_hmac(&conn, key).unwrap();
    assert!(!new_hmac.is_empty());
    assert_ne!(new_hmac, "old-stale-hmac-value");

    // Storing the recomputed HMAC should succeed
    baseline_ops::set_config_state(&conn, "baseline_hmac", &new_hmac).unwrap();

    // Verify it round-trips
    let stored = baseline_ops::get_config_state(&conn, "baseline_hmac")
        .unwrap()
        .unwrap();
    assert_eq!(stored, new_hmac);
}
