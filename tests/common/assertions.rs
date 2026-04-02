#![allow(dead_code)]
// Custom assertions for Vigil tests.

use vigil::types::{ChangeResult, ChangeType, Severity};

/// Assert that a ChangeResult contains a specific change type.
pub fn assert_has_change_type(result: &ChangeResult, expected: ChangeType) {
    assert!(
        result.change_types.contains(&expected),
        "Expected change type {:?} in {:?} for path {}",
        expected,
        result.change_types,
        result.path.display()
    );
}

/// Assert that a ChangeResult does NOT contain a specific change type.
pub fn assert_no_change_type(result: &ChangeResult, unexpected: ChangeType) {
    assert!(
        !result.change_types.contains(&unexpected),
        "Unexpected change type {:?} found in {:?} for path {}",
        unexpected,
        result.change_types,
        result.path.display()
    );
}

/// Assert a change result's severity matches expected.
pub fn assert_severity(result: &ChangeResult, expected: Severity) {
    assert_eq!(
        result.severity,
        expected,
        "Expected severity {:?} but got {:?} for path {}",
        expected,
        result.severity,
        result.path.display()
    );
}

/// Assert that the audit log has at least `min_count` entries.
pub fn assert_audit_count(conn: &rusqlite::Connection, min_count: i64) {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
        .expect("query audit count");
    assert!(
        count >= min_count,
        "Expected at least {} audit entries, found {}",
        min_count,
        count
    );
}

/// Assert that the baseline has exactly `expected` entries.
pub fn assert_baseline_count(conn: &rusqlite::Connection, expected: i64) {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM baseline", [], |row| row.get(0))
        .expect("query baseline count");
    assert_eq!(
        count, expected,
        "Expected {} baseline entries, found {}",
        expected, count
    );
}
