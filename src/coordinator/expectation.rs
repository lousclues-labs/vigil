//! Generalized file-change expectation, replacing the path-hardcoded
//! `SharedBaselineIdentity` for file modification coordination.
//!
//! Allows any operator-initiated command that modifies a watched file to
//! declare the modification in advance, suppressing the guardian's tamper
//! response within a deadline window.
//!
//! Fail-closed: deadline expiry re-engages normal tamper detection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

/// A single file-change expectation with an atomic deadline.
pub struct FileChangeExpectation {
    path: PathBuf,
    /// Epoch nanos of the authorized-change deadline. 0 = no expectation.
    expected_until: AtomicI64,
}

impl FileChangeExpectation {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            expected_until: AtomicI64::new(0),
        }
    }

    /// Declare that a change to this file is expected within `window`.
    pub fn expect_change_within(&self, window: Duration) {
        let deadline =
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) + window.as_nanos() as i64;
        self.expected_until.store(deadline, Ordering::Release);
    }

    /// Check whether we are inside an authorized change window.
    pub fn is_change_authorized(&self) -> bool {
        let deadline = self.expected_until.load(Ordering::Acquire);
        if deadline == 0 {
            return false;
        }
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) < deadline
    }

    /// Clear the expectation (re-engage tamper detection).
    pub fn clear(&self) {
        self.expected_until.store(0, Ordering::Release);
    }

    /// The path this expectation covers.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for FileChangeExpectation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileChangeExpectation")
            .field("path", &self.path)
            .field(
                "deadline_nanos",
                &self.expected_until.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// Registry of all active file-change expectations, keyed by path.
#[derive(Debug, Default)]
pub struct ExpectationRegistry {
    expectations: RwLock<HashMap<PathBuf, Arc<FileChangeExpectation>>>,
}

impl ExpectationRegistry {
    pub fn new() -> Self {
        Self {
            expectations: RwLock::new(HashMap::new()),
        }
    }

    /// Register (or retrieve) an expectation for the given path.
    pub fn register(&self, path: PathBuf) -> Arc<FileChangeExpectation> {
        let mut map = self.expectations.write();
        map.entry(path.clone())
            .or_insert_with(|| Arc::new(FileChangeExpectation::new(path)))
            .clone()
    }

    /// Look up an existing expectation for the given path.
    pub fn lookup(&self, path: &Path) -> Option<Arc<FileChangeExpectation>> {
        let map = self.expectations.read();
        map.get(path).cloned()
    }

    /// Check if a change to the given path is currently authorized.
    pub fn is_change_authorized(&self, path: &Path) -> bool {
        self.lookup(path)
            .map(|e| e.is_change_authorized())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expectation_not_authorized_by_default() {
        let exp = FileChangeExpectation::new(PathBuf::from("/test/path"));
        assert!(!exp.is_change_authorized());
    }

    #[test]
    fn expectation_authorized_within_window() {
        let exp = FileChangeExpectation::new(PathBuf::from("/test/path"));
        exp.expect_change_within(Duration::from_secs(30));
        assert!(exp.is_change_authorized());
    }

    #[test]
    fn expectation_cleared_after_clear() {
        let exp = FileChangeExpectation::new(PathBuf::from("/test/path"));
        exp.expect_change_within(Duration::from_secs(30));
        assert!(exp.is_change_authorized());
        exp.clear();
        assert!(!exp.is_change_authorized());
    }

    #[test]
    fn registry_registers_and_looks_up() {
        let registry = ExpectationRegistry::new();
        let path = PathBuf::from("/test/path");
        let exp = registry.register(path.clone());
        exp.expect_change_within(Duration::from_secs(30));

        assert!(registry.is_change_authorized(&path));
        assert!(!registry.is_change_authorized(Path::new("/other/path")));
    }

    #[test]
    fn registry_returns_same_expectation_for_same_path() {
        let registry = ExpectationRegistry::new();
        let path = PathBuf::from("/test/path");
        let exp1 = registry.register(path.clone());
        let exp2 = registry.register(path);

        exp1.expect_change_within(Duration::from_secs(30));
        assert!(exp2.is_change_authorized());
    }
}
