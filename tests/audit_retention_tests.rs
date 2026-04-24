//! Integration tests for bounded audit retention via cryptographic checkpoints.

use rusqlite::{params, Connection};

/// Create an in-memory audit DB with the current schema.
fn test_audit_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    vigil::db::schema::create_audit_tables(&conn).unwrap();
    conn
}

/// Genesis chain hash.
fn genesis_hash() -> String {
    blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string()
}

/// Insert a detection entry and return its chain_hash.
fn insert_detection(
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

    conn.prepare_cached(
        "INSERT INTO audit_log (
            timestamp, path, changes_json, severity,
            maintenance, suppressed, chain_hash, record_type
        ) VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, 'detection')",
    )
    .unwrap()
    .execute(params![timestamp, path, changes_json, severity, chain_hash])
    .unwrap();

    chain_hash
}

/// Insert N detection entries, chained. Returns the final chain_hash.
fn seed_entries(conn: &Connection, count: usize, base_timestamp: i64) -> String {
    let mut prev = genesis_hash();
    for i in 0..count {
        prev = insert_detection(
            conn,
            &format!("/test/file_{}", i),
            "high",
            &prev,
            base_timestamp + i as i64,
        );
    }
    prev
}

// ── Commit 1: AuditCheckpoint record type and verifier awareness ──

#[test]
fn audit_checkpoint_chain_hmac_round_trip() {
    let conn = test_audit_conn();

    // Write two detection entries, then a checkpoint
    let h1 = insert_detection(&conn, "/etc/passwd", "high", &genesis_hash(), 1000);
    let h2 = insert_detection(&conn, "/etc/shadow", "critical", &h1, 1001);

    // The checkpoint replaces the position of the last pruned entry.
    // Its chain_hash = bridge_chain_hash = h2 (the last pruned entry's hash).
    // Must delete originals first to free the id.
    let prev_before_range = genesis_hash();
    let checkpoint_ts = 2000i64;

    conn.execute("DELETE FROM audit_log WHERE id IN (1, 2)", [])
        .unwrap();

    let ckpt_hash = vigil::db::audit_ops::insert_checkpoint(
        &conn,
        2, // replace_id = last pruned entry's id
        checkpoint_ts,
        1,    // first_sequence
        2,    // last_sequence
        1000, // first_timestamp
        1001, // last_timestamp
        2,    // entry_count
        "fake_pruned_hmac_hex",
        &prev_before_range, // previous_chain_hash (before the pruned range)
        &h2,                // bridge_chain_hash (last pruned entry's chain_hash)
        None,               // no HMAC key
    )
    .unwrap();

    // The checkpoint's stored chain_hash is the bridge (= h2)
    assert_eq!(ckpt_hash, h2);
}

#[test]
fn audit_verify_with_checkpoint() {
    // Chain: [E1, E2, CHECKPOINT(replaces E1-E2), E3, E4] -- verify clean
    let conn = test_audit_conn();

    let h1 = insert_detection(&conn, "/file1", "high", &genesis_hash(), 1000);
    let h2 = insert_detection(&conn, "/file2", "medium", &h1, 1001);
    let h3 = insert_detection(&conn, "/file3", "low", &h2, 3000);
    let _h4 = insert_detection(&conn, "/file4", "high", &h3, 3001);

    // Now prune E1 and E2, replace with checkpoint at id=2
    // Checkpoint's bridge_chain_hash = h2 (last pruned entry's chain_hash)
    // E3's chain_hash was computed with prev=h2, so the bridge works.
    conn.execute("DELETE FROM audit_log WHERE id IN (1, 2)", [])
        .unwrap();

    vigil::db::audit_ops::insert_checkpoint(
        &conn,
        2,    // replace_id
        2000, // timestamp
        1,
        2, // first/last sequence
        1000,
        1001, // first/last timestamp
        2,    // entry_count
        "range_hmac_placeholder",
        &genesis_hash(), // previous_chain_hash (before range)
        &h2,             // bridge_chain_hash
        None,
    )
    .unwrap();

    let detail = vigil::db::audit_ops::verify_chain_detail(&conn, None).unwrap();
    assert_eq!(detail.total, 3); // checkpoint + E3 + E4
    assert_eq!(detail.valid, 3);
    assert!(detail.breaks.is_empty(), "breaks: {:?}", detail.breaks);
    assert_eq!(detail.checkpoint_count, 1);
    assert_eq!(detail.checkpoint_covered_entries, 2);
}

#[test]
fn audit_verify_detects_checkpoint_tampering() {
    let conn = test_audit_conn();

    let h1 = insert_detection(&conn, "/file1", "high", &genesis_hash(), 1000);
    let _h2 = insert_detection(&conn, "/file2", "low", &h1, 3000);

    // Prune E1, checkpoint at id=1
    conn.execute("DELETE FROM audit_log WHERE id = 1", [])
        .unwrap();

    vigil::db::audit_ops::insert_checkpoint(
        &conn,
        1, // replace_id
        2000,
        1,
        1,
        1000,
        1000,
        1,
        "original_range_hmac",
        &genesis_hash(),
        &h1, // bridge
        None,
    )
    .unwrap();

    // Tamper with the checkpoint's chain_hash (the bridge value)
    conn.execute(
        "UPDATE audit_log SET chain_hash = 'tampered_bridge' WHERE record_type = 'checkpoint'",
        [],
    )
    .unwrap();

    let detail = vigil::db::audit_ops::verify_chain_detail(&conn, None).unwrap();
    // E2's chain_hash was computed with h1 as prev, but now the checkpoint's
    // chain_hash is 'tampered_bridge', so E2 will fail verification.
    assert!(!detail.breaks.is_empty(), "tampering should be detected");
}

#[test]
fn audit_verify_detects_checkpoint_deletion() {
    let conn = test_audit_conn();

    let h1 = insert_detection(&conn, "/file1", "high", &genesis_hash(), 1000);
    let _h2 = insert_detection(&conn, "/file2", "low", &h1, 3000);

    // Prune E1, checkpoint at id=1
    conn.execute("DELETE FROM audit_log WHERE id = 1", [])
        .unwrap();

    vigil::db::audit_ops::insert_checkpoint(
        &conn,
        1,
        2000,
        1,
        1,
        1000,
        1000,
        1,
        "range_hmac",
        &genesis_hash(),
        &h1,
        None,
    )
    .unwrap();

    // Delete the checkpoint
    conn.execute("DELETE FROM audit_log WHERE record_type = 'checkpoint'", [])
        .unwrap();

    let detail = vigil::db::audit_ops::verify_chain_detail(&conn, None).unwrap();
    // E2's prev was h1, but now the only preceding entry is gone.
    // Verifier starts with genesis as prev, E2's chain_hash won't match.
    assert!(!detail.breaks.is_empty(), "deletion should break the chain");
}

#[test]
fn audit_db_migration_adds_checkpoint_columns() {
    // Simulate a v1.2.x DB that doesn't have the checkpoint columns
    let conn = Connection::open_in_memory().unwrap();

    // Create the old schema without checkpoint columns
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       INTEGER NOT NULL,
            path            TEXT NOT NULL,
            changes_json    TEXT NOT NULL,
            severity        TEXT NOT NULL,
            monitored_group TEXT,
            process_json    TEXT,
            package         TEXT,
            maintenance     INTEGER NOT NULL DEFAULT 0,
            suppressed      INTEGER NOT NULL DEFAULT 0,
            hmac            TEXT,
            chain_hash      TEXT NOT NULL
        );
        ",
    )
    .unwrap();

    // Insert an entry in the old schema
    let genesis = genesis_hash();
    let chain_hash =
        vigil::db::audit_ops::compute_chain_hash(&genesis, 1000, "/etc/test", "[]", "high");
    conn.execute(
        "INSERT INTO audit_log (timestamp, path, changes_json, severity, maintenance, suppressed, chain_hash)
         VALUES (1000, '/etc/test', '[]', 'high', 0, 0, ?1)",
        params![chain_hash],
    )
    .unwrap();

    // Now run the migration (via create_audit_tables)
    vigil::db::schema::create_audit_tables(&conn).unwrap();

    // Verify the old entry still verifies clean
    let detail = vigil::db::audit_ops::verify_chain_detail(&conn, None).unwrap();
    assert_eq!(detail.total, 1);
    assert_eq!(detail.valid, 1);
    assert!(detail.breaks.is_empty());

    // Verify we can now write a new entry after the old one
    let h2 = insert_detection(&conn, "/etc/new_file", "medium", &chain_hash, 2000);
    assert!(!h2.is_empty());

    // Chain still verifies
    let detail2 = vigil::db::audit_ops::verify_chain_detail(&conn, None).unwrap();
    assert_eq!(detail2.total, 2);
    assert_eq!(detail2.valid, 2);
    assert!(detail2.breaks.is_empty());
}

// ── Commit 2: Prune sweep tests ──

#[test]
fn prune_sweep_writes_checkpoint_and_deletes_originals() {
    let conn = test_audit_conn();

    // Seed 10 old entries and 5 recent entries
    let old_cutoff = 1_700_000_000i64; // old
    let recent_base = 2_000_000_000i64; // recent

    let mut prev = genesis_hash();
    for i in 0..10 {
        prev = insert_detection(
            &conn,
            &format!("/old/file_{}", i),
            "high",
            &prev,
            old_cutoff + i as i64,
        );
    }
    let _chain_before_recent = prev.clone();
    for i in 0..5 {
        prev = insert_detection(
            &conn,
            &format!("/recent/file_{}", i),
            "medium",
            &prev,
            recent_base + i as i64,
        );
    }

    // Identify prune range (anything before recent_base)
    let range = vigil::db::audit_ops::identify_prune_range(&conn, recent_base, 5).unwrap();
    assert!(range.is_some());
    let (first_id, last_id, count) = range.unwrap();
    assert_eq!(count, 10);

    // Get previous chain hash
    let prev_chain = vigil::db::audit_ops::get_previous_chain_hash(&conn, first_id).unwrap();

    // Read the entries to be pruned
    let entries = vigil::db::audit_ops::read_detection_range(&conn, first_id, last_id).unwrap();
    assert_eq!(entries.len(), 10);

    // Compute a pruned-range HMAC (simplified -- just hash the chain hashes)
    let mut range_data = prev_chain.clone();
    for e in &entries {
        range_data.push_str(&e.chain_hash);
    }
    let pruned_hmac = blake3::hash(range_data.as_bytes()).to_hex().to_string();

    // Execute the prune in a transaction
    let first_ts = entries.first().unwrap().timestamp;
    let last_ts = entries.last().unwrap().timestamp;
    let bridge = entries.last().unwrap().chain_hash.clone();

    conn.execute("BEGIN", []).unwrap();
    let deleted = vigil::db::audit_ops::delete_detection_range(&conn, first_id, last_id).unwrap();
    assert_eq!(deleted, 10);

    let _ckpt_hash = vigil::db::audit_ops::insert_checkpoint(
        &conn,
        last_id, // replace_id = last pruned entry's id
        chrono::Utc::now().timestamp(),
        first_id,
        last_id,
        first_ts,
        last_ts,
        count,
        &pruned_hmac,
        &prev_chain, // previous_chain_hash (before range)
        &bridge,     // bridge_chain_hash (last pruned entry's hash)
        None,
    )
    .unwrap();
    conn.execute("COMMIT", []).unwrap();

    // Verify: checkpoint exists, originals deleted
    let checkpoints = vigil::db::audit_ops::list_checkpoints(&conn).unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].entry_count, 10);

    let live = vigil::db::audit_ops::count_detection_entries(&conn).unwrap();
    assert_eq!(live, 5);
}

#[test]
fn prune_sweep_respects_min_entries_to_keep() {
    let conn = test_audit_conn();

    // Seed 50 old entries
    seed_entries(&conn, 50, 1_700_000_000);

    // With min_entries_to_keep = 100 and only 50 total, sweep refuses
    let range = vigil::db::audit_ops::identify_prune_range(&conn, 2_000_000_000, 100).unwrap();
    assert!(
        range.is_none(),
        "should refuse when remaining < min_entries_to_keep"
    );
}

#[test]
fn prune_sweep_no_op_when_no_old_entries() {
    let conn = test_audit_conn();

    // All entries are recent
    seed_entries(&conn, 10, 2_000_000_000);

    let range = vigil::db::audit_ops::identify_prune_range(
        &conn,
        1_999_999_999, // cutoff before all entries
        5,
    )
    .unwrap();
    // All entries are after cutoff, nothing to prune
    assert!(range.is_none());
}

#[test]
fn multiple_consecutive_sweeps_extend_chain() {
    let conn = test_audit_conn();

    // Three batches of entries
    let mut prev = genesis_hash();
    for i in 0..100 {
        prev = insert_detection(
            &conn,
            &format!("/batch1/{}", i),
            "low",
            &prev,
            1_000_000 + i as i64,
        );
    }
    for i in 0..100 {
        prev = insert_detection(
            &conn,
            &format!("/batch2/{}", i),
            "medium",
            &prev,
            2_000_000 + i as i64,
        );
    }
    for i in 0..100 {
        prev = insert_detection(
            &conn,
            &format!("/batch3/{}", i),
            "high",
            &prev,
            3_000_000 + i as i64,
        );
    }

    // Sweep 1: prune batch1
    let range1 = vigil::db::audit_ops::identify_prune_range(&conn, 2_000_000, 100).unwrap();
    assert!(range1.is_some());
    let (f1, l1, c1) = range1.unwrap();
    let entries1 = vigil::db::audit_ops::read_detection_range(&conn, f1, l1).unwrap();
    let prev1 = vigil::db::audit_ops::get_previous_chain_hash(&conn, f1).unwrap();
    let pruned_hmac1 = blake3::hash(format!("range1:{}", c1).as_bytes())
        .to_hex()
        .to_string();
    let bridge1 = entries1.last().unwrap().chain_hash.clone();

    conn.execute("BEGIN", []).unwrap();
    vigil::db::audit_ops::delete_detection_range(&conn, f1, l1).unwrap();
    let _ckpt1 = vigil::db::audit_ops::insert_checkpoint(
        &conn,
        l1,
        4_000_000,
        f1,
        l1,
        entries1.first().unwrap().timestamp,
        entries1.last().unwrap().timestamp,
        c1,
        &pruned_hmac1,
        &prev1,
        &bridge1,
        None,
    )
    .unwrap();
    conn.execute("COMMIT", []).unwrap();

    // Sweep 2: prune batch2
    let range2 = vigil::db::audit_ops::identify_prune_range(&conn, 3_000_000, 100).unwrap();
    assert!(range2.is_some());
    let (f2, l2, c2) = range2.unwrap();
    let entries2 = vigil::db::audit_ops::read_detection_range(&conn, f2, l2).unwrap();
    let prev2 = vigil::db::audit_ops::get_previous_chain_hash(&conn, f2).unwrap();
    let pruned_hmac2 = blake3::hash(format!("range2:{}", c2).as_bytes())
        .to_hex()
        .to_string();
    let bridge2 = entries2.last().unwrap().chain_hash.clone();

    conn.execute("BEGIN", []).unwrap();
    vigil::db::audit_ops::delete_detection_range(&conn, f2, l2).unwrap();
    let _ckpt2 = vigil::db::audit_ops::insert_checkpoint(
        &conn,
        l2,
        5_000_000,
        f2,
        l2,
        entries2.first().unwrap().timestamp,
        entries2.last().unwrap().timestamp,
        c2,
        &pruned_hmac2,
        &prev2,
        &bridge2,
        None,
    )
    .unwrap();
    conn.execute("COMMIT", []).unwrap();

    // Verify chain is intact across both checkpoints
    let detail = vigil::db::audit_ops::verify_chain_detail(&conn, None).unwrap();
    assert!(
        detail.breaks.is_empty(),
        "chain should be intact after two sweeps: {:?}",
        detail.breaks
    );
    assert_eq!(detail.checkpoint_count, 2);
    // 2 checkpoints + 100 remaining batch3 entries
    assert_eq!(detail.total, 102);
    assert_eq!(detail.valid, 102);
}

#[test]
fn audit_stats_helpers() {
    let conn = test_audit_conn();

    // Seed entries
    let mut prev = genesis_hash();
    for i in 0..20 {
        prev = insert_detection(&conn, &format!("/f/{}", i), "high", &prev, 1_000_000 + i);
    }

    // Insert a checkpoint covering a range
    let _ckpt = vigil::db::audit_ops::insert_checkpoint(
        &conn,
        21,
        2_000_000,
        1,
        5,
        1_000_000,
        1_000_004,
        5,
        "hmac_value",
        &genesis_hash(),
        &prev,
        None,
    )
    .unwrap();

    let live = vigil::db::audit_ops::count_detection_entries(&conn).unwrap();
    assert_eq!(live, 20);

    let covered = vigil::db::audit_ops::checkpoint_covered_entries(&conn).unwrap();
    assert_eq!(covered, 5);

    let oldest_ckpt = vigil::db::audit_ops::oldest_checkpoint_timestamp(&conn).unwrap();
    assert_eq!(oldest_ckpt, Some(1_000_000));

    let oldest_det = vigil::db::audit_ops::oldest_detection_timestamp(&conn).unwrap();
    assert!(oldest_det.is_some());
}

#[test]
fn audit_prune_dry_run_does_not_modify() {
    let conn = test_audit_conn();

    // 100 old entries + 50 recent entries
    let mut prev = genesis_hash();
    for i in 0..100 {
        prev = insert_detection(
            &conn,
            &format!("/old/{}", i),
            "high",
            &prev,
            1_000_000 + i as i64,
        );
    }
    for i in 0..50 {
        prev = insert_detection(
            &conn,
            &format!("/new/{}", i),
            "medium",
            &prev,
            2_000_000 + i as i64,
        );
    }

    let total_before = vigil::db::audit_ops::count_entries(&conn).unwrap();

    // identify_prune_range should find old entries
    let range = vigil::db::audit_ops::identify_prune_range(&conn, 2_000_000, 10).unwrap();
    assert!(range.is_some());

    // DB should be unchanged (identify doesn't modify)
    let total_after = vigil::db::audit_ops::count_entries(&conn).unwrap();
    assert_eq!(total_before, total_after);
}

#[test]
fn audit_prune_with_confirm_modifies() {
    let conn = test_audit_conn();

    let mut prev = genesis_hash();
    for i in 0..50 {
        prev = insert_detection(&conn, &format!("/old/{}", i), "high", &prev, 1_000_000 + i);
    }
    for i in 0..50 {
        prev = insert_detection(
            &conn,
            &format!("/new/{}", i),
            "medium",
            &prev,
            2_000_000 + i,
        );
    }

    let total_before = vigil::db::audit_ops::count_entries(&conn).unwrap();
    assert_eq!(total_before, 100);

    // Prune entries older than 2_000_000
    let (first_id, last_id, count) =
        vigil::db::audit_ops::identify_prune_range(&conn, 2_000_000, 10)
            .unwrap()
            .unwrap();
    assert_eq!(count, 50);

    let entries = vigil::db::audit_ops::read_detection_range(&conn, first_id, last_id).unwrap();
    let prev_chain = vigil::db::audit_ops::get_previous_chain_hash(&conn, first_id).unwrap();
    let bridge = entries.last().unwrap().chain_hash.clone();
    let pruned_hmac = blake3::hash(b"test-range-hmac").to_hex().to_string();

    conn.execute("BEGIN", []).unwrap();
    vigil::db::audit_ops::delete_detection_range(&conn, first_id, last_id).unwrap();
    vigil::db::audit_ops::insert_checkpoint(
        &conn,
        last_id,
        chrono::Utc::now().timestamp(),
        first_id,
        last_id,
        entries.first().unwrap().timestamp,
        entries.last().unwrap().timestamp,
        count,
        &pruned_hmac,
        &prev_chain,
        &bridge,
        None,
    )
    .unwrap();
    conn.execute("COMMIT", []).unwrap();

    // Verify: checkpoint written, originals deleted
    let checkpoints = vigil::db::audit_ops::list_checkpoints(&conn).unwrap();
    assert_eq!(checkpoints.len(), 1);

    let live = vigil::db::audit_ops::count_detection_entries(&conn).unwrap();
    assert_eq!(live, 50);

    // Chain integrity preserved
    let detail = vigil::db::audit_ops::verify_chain_detail(&conn, None).unwrap();
    assert!(
        detail.breaks.is_empty(),
        "chain should be intact after prune: {:?}",
        detail.breaks
    );
    assert_eq!(detail.checkpoint_count, 1);
    assert_eq!(detail.checkpoint_covered_entries, 50);
}

#[test]
fn audit_prune_refuses_below_min_entries() {
    let conn = test_audit_conn();
    seed_entries(&conn, 20, 1_000_000);

    // With min_entries_to_keep = 25, refuse since only 20 exist total
    let range = vigil::db::audit_ops::identify_prune_range(&conn, 2_000_000, 25).unwrap();
    assert!(range.is_none());
}

#[test]
fn audit_db_file_size() {
    let conn = test_audit_conn();
    let size = vigil::db::audit_ops::db_file_size(&conn).unwrap();
    // In-memory DB has a page size but effectively 0 data
    // In-memory DB: just verify no error
    let _ = size;
}

#[test]
fn config_audit_defaults() {
    let cfg = vigil::config::default_config();
    assert_eq!(cfg.audit.retention_days, 365);
    assert_eq!(cfg.audit.max_size_mb, 1024);
    assert_eq!(cfg.audit.min_entries_to_keep, 1000);
    assert_eq!(cfg.audit.retention_check_interval, "24h");

    let dur = cfg.audit.retention_check_duration();
    assert_eq!(dur, std::time::Duration::from_secs(86400));
}

#[test]
fn config_audit_validation_rejects_low_retention() {
    let toml_str = r#"
        [audit]
        retention_days = 3

        [watch.test]
        severity = "high"
        paths = ["/tmp/test"]
    "#;
    let config: vigil::config::Config = toml::from_str(toml_str).unwrap();
    let result = vigil::config::validate_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("retention_days"));
}

#[test]
fn config_audit_validation_rejects_low_cap() {
    let toml_str = r#"
        [audit]
        max_size_mb = 32

        [watch.test]
        severity = "high"
        paths = ["/tmp/test"]
    "#;
    let config: vigil::config::Config = toml::from_str(toml_str).unwrap();
    let result = vigil::config::validate_config(&config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("max_size_mb"));
}
