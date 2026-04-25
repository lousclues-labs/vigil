//! Database access helpers: read-only open and permission checks.

use std::path::{Path, PathBuf};

/// Open a database read-only (public for status/explain queries).
pub fn open_existing_db(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

/// Check whether we have read access to a SQLite database and its sidecar files.
pub fn has_sqlite_read_access(path: &Path) -> bool {
    if std::fs::File::open(path).is_err() {
        return false;
    }

    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar_path = PathBuf::from(sidecar);
        if sidecar_path.exists() && std::fs::File::open(&sidecar_path).is_err() {
            return false;
        }
    }

    true
}
