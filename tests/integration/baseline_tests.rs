// Integration tests: baseline engine — init, refresh, diff, add, remove.

use std::fs;

use vigil::baseline;
use vigil::db;
use vigil::db::ops;
use vigil::types::*;

use crate::common::assertions::*;
use crate::common::fixtures::*;

#[test]
fn init_baseline_scans_files() {
    let tmp = TempDir::new("bl-init");
    tmp.create_file("test1.txt", b"hello");
    tmp.create_file("test2.txt", b"world");
    tmp.create_file("subdir/test3.txt", b"nested");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();

    let (count, _warnings) = baseline::init_baseline(&conn, &config, true).unwrap();
    assert!(
        count >= 3,
        "Should have scanned at least 3 files, got {}",
        count
    );
}

#[test]
fn init_baseline_records_hashes() {
    let tmp = TempDir::new("bl-hash");
    let file_path = tmp.create_file("known.txt", b"known content");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    let entry = ops::get_baseline_by_path(&conn, &file_path.to_string_lossy()).unwrap();
    assert!(entry.is_some(), "File should be in baseline");

    let entry = entry.unwrap();
    let expected_hash = vigil::baseline::hash::blake3_hash_bytes(b"known content");
    assert_eq!(entry.hash, expected_hash);
}

#[test]
fn diff_detects_modified_file() {
    let tmp = TempDir::new("bl-diff-mod");
    let file_path = tmp.create_file("target.txt", b"original content");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    // Modify the file (use different length to ensure size change triggers hash comparison)
    fs::write(&file_path, b"modified content that is now longer").unwrap();

    let changes = baseline::diff_baseline(&conn, &config).unwrap();
    let modified: Vec<_> = changes
        .iter()
        .filter(|c| c.path == file_path && c.change_types.contains(&ChangeType::Modified))
        .collect();
    assert!(!modified.is_empty(), "Should detect modification");
}

#[test]
fn diff_detects_deleted_file() {
    let tmp = TempDir::new("bl-diff-del");
    let file_path = tmp.create_file("disappear.txt", b"going away");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    // Delete the file
    fs::remove_file(&file_path).unwrap();

    let changes = baseline::diff_baseline(&conn, &config).unwrap();
    let deleted: Vec<_> = changes
        .iter()
        .filter(|c| c.path == file_path && c.change_types.contains(&ChangeType::Deleted))
        .collect();
    assert!(!deleted.is_empty(), "Should detect deletion");
}

#[test]
fn diff_detects_new_file() {
    let tmp = TempDir::new("bl-diff-new");
    tmp.create_file("existing.txt", b"original");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    // Create a new file
    let new_path = tmp.create_file("intruder.txt", b"I am new");

    let changes = baseline::diff_baseline(&conn, &config).unwrap();
    let created: Vec<_> = changes
        .iter()
        .filter(|c| c.path == new_path && c.change_types.contains(&ChangeType::Created))
        .collect();
    assert!(!created.is_empty(), "Should detect new file");
}

#[test]
fn add_single_file_to_baseline() {
    let tmp = TempDir::new("bl-add");
    let file_path = tmp.create_file("manual.txt", b"manual add");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();

    baseline::add_file(&conn, &file_path, &config).unwrap();

    let entry = ops::get_baseline_by_path(&conn, &file_path.to_string_lossy()).unwrap();
    assert!(entry.is_some());
}

#[test]
fn remove_single_file_from_baseline() {
    let tmp = TempDir::new("bl-remove");
    let file_path = tmp.create_file("removeme.txt", b"remove me");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();

    baseline::add_file(&conn, &file_path, &config).unwrap();
    assert_baseline_count(&conn, 1);

    baseline::remove_file(&conn, &file_path).unwrap();
    assert_baseline_count(&conn, 0);
}

#[test]
fn refresh_updates_changed_files() {
    let tmp = TempDir::new("bl-refresh");
    let file_path = tmp.create_file("mutable.txt", b"version 1");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    let old = ops::get_baseline_by_path(&conn, &file_path.to_string_lossy())
        .unwrap()
        .unwrap();

    // Modify
    fs::write(&file_path, b"version 2").unwrap();

    // Refresh
    baseline::refresh_baseline(&conn, &config, None, true).unwrap();

    let new = ops::get_baseline_by_path(&conn, &file_path.to_string_lossy())
        .unwrap()
        .unwrap();
    assert_ne!(old.hash, new.hash, "Hash should change after refresh");
}

#[test]
fn baseline_stats_accurate() {
    let tmp = TempDir::new("bl-stats");
    tmp.create_file("a.txt", b"a");
    tmp.create_file("b.txt", b"b");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    let stats = baseline::baseline_stats(&conn).unwrap();
    assert!(stats.total_entries >= 2);
    assert!(stats.last_refresh.is_some());
}

#[test]
fn exclusion_patterns_respected() {
    let tmp = TempDir::new("bl-excl");
    tmp.create_file("keep.txt", b"keep me");
    tmp.create_file("ignore.swp", b"vim swap");
    tmp.create_file("ignore.tmp", b"temp file");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    // .swp and .tmp should be excluded by default patterns
    let swp =
        ops::get_baseline_by_path(&conn, &tmp.path.join("ignore.swp").to_string_lossy()).unwrap();
    assert!(swp.is_none(), ".swp files should be excluded");

    let tmp_file =
        ops::get_baseline_by_path(&conn, &tmp.path.join("ignore.tmp").to_string_lossy()).unwrap();
    assert!(tmp_file.is_none(), ".tmp files should be excluded");
}

#[test]
fn unchanged_file_produces_no_diff() {
    let tmp = TempDir::new("bl-unchanged");
    tmp.create_file("stable.txt", b"never changes");

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();
    baseline::init_baseline(&conn, &config, true).unwrap();

    // Don't change anything
    let changes = baseline::diff_baseline(&conn, &config).unwrap();
    let stable_changes: Vec<_> = changes
        .iter()
        .filter(|c| c.path.ends_with("stable.txt"))
        .collect();
    assert!(
        stable_changes.is_empty(),
        "Unchanged file should produce no diff"
    );
}
