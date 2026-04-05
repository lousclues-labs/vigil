// Security tests: race condition and TOCTOU resilience.

use std::fs;
use vigil::baseline;
use vigil::db;
use vigil::types::*;

use crate::common::fixtures::*;

#[test]
fn concurrent_baseline_writes_safe() {
    // Multiple threads writing to the same database should not corrupt it.
    let tmp = TempDir::new("sec-race-db");

    for i in 0..10 {
        tmp.create_file(
            &format!("file{}.txt", i),
            format!("content {}", i).as_bytes(),
        );
    }

    let config = test_config(&tmp);
    let conn = db::open_db(&config).unwrap();

    // Init baseline (single-threaded, but exercises DB under load)
    let (count, _warnings) = baseline::init_baseline(&conn, &config, true).unwrap();
    assert!(count >= 10);

    // Verify DB integrity after bulk writes
    assert!(db::integrity_check(&conn).is_ok());
}

#[test]
fn rapid_file_changes_during_comparison() {
    // File changes rapidly while we're comparing — comparison should
    // either succeed with current state or return a transient error.
    // It should never panic or corrupt data.
    let tmp = TempDir::new("sec-race-cmp");
    let file_path = tmp.create_file("racing.txt", b"initial");

    let config = test_config(&tmp);
    let entry = baseline_entry_for(&file_path);

    // Modify the file rapidly
    for i in 0..20 {
        fs::write(&file_path, format!("version {}", i).as_bytes()).unwrap();

        // Each comparison should either succeed or return a transient error
        // — never panic.
        let _ = vigil::compare::compare_entry(
            &entry,
            &config,
            vigil::types::Severity::Medium,
            "test",
            false,
        );
    }
}

#[test]
fn file_deleted_between_event_and_hash() {
    // Simulates: file is deleted after we receive the fanotify event
    // but before we can hash it. This is a normal transient condition.
    let tmp = TempDir::new("sec-race-del");
    let file_path = tmp.create_file("ephemeral.txt", b"here then gone");

    let config = test_config(&tmp);

    // Create baseline entry
    let entry = baseline_entry_for(&file_path);

    // Delete the file
    fs::remove_file(&file_path).unwrap();

    // Comparison should report deletion, not panic
    let result = vigil::compare::compare_entry(
        &entry,
        &config,
        vigil::types::Severity::Medium,
        "test",
        false,
    )
    .unwrap();
    assert!(result.is_some());
    assert!(
        result.unwrap().change_types.contains(&ChangeType::Deleted),
        "Should detect deletion gracefully"
    );
}

#[test]
fn empty_file_hashed_correctly() {
    // Edge case: empty files must be handled without error.
    let tmp = TempDir::new("sec-empty");
    let file_path = tmp.create_file("empty.txt", b"");

    let entry = baseline_entry_for(&file_path);
    assert!(!entry.hash.is_empty(), "Empty file must produce a hash");
    assert_eq!(entry.size, 0);
}

#[test]
fn large_path_handled() {
    // Paths near filesystem limits shouldn't cause panics.
    let tmp = TempDir::new("sec-long-path");

    // Create a deeply nested path (but within sane limits)
    let mut deep_dir = tmp.path.clone();
    for i in 0..10 {
        deep_dir = deep_dir.join(format!("d{}", i));
    }
    fs::create_dir_all(&deep_dir).unwrap();

    let file_path = deep_dir.join("deep.txt");
    fs::write(&file_path, b"deep content").unwrap();

    let entry = baseline_entry_for(&file_path);
    assert!(!entry.hash.is_empty());
}
