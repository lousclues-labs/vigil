use std::collections::HashSet;
use std::path::PathBuf;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::types::{
    BaselineEntry, BaselineSource, ContentFingerprint, FileIdentity, FileType, PermissionState,
    SecurityState,
};

/// Helper to parse a FileType from a string stored in the database.
fn parse_file_type(s: &str) -> FileType {
    match s {
        "symlink" => FileType::Symlink,
        "directory" => FileType::Directory,
        _ => FileType::Regular,
    }
}

/// Helper to parse a BaselineSource from a string stored in the database.
fn parse_source(s: &str) -> BaselineSource {
    match s {
        "package_manager" => BaselineSource::PackageManager,
        "manual" => BaselineSource::Manual,
        _ => BaselineSource::AutoScan,
    }
}

/// Helper to parse xattrs JSON into a BTreeMap.
fn parse_xattrs(json: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(json).unwrap_or_default()
}

/// Construct a BaselineEntry from a v2 native-column row.
fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<BaselineEntry> {
    let file_type_str: String = row.get(4)?;
    let source_str: String = row.get(16)?;
    let xattrs_json: String = row.get(12)?;

    Ok(BaselineEntry {
        id: Some(row.get(0)?),
        path: PathBuf::from(row.get::<_, String>(1)?),
        identity: FileIdentity {
            inode: row.get::<_, i64>(2)? as u64,
            device: row.get::<_, i64>(3)? as u64,
            file_type: parse_file_type(&file_type_str),
            symlink_target: row.get::<_, Option<String>>(5)?.map(PathBuf::from),
        },
        content: ContentFingerprint {
            hash: row.get(6)?,
            size: row.get::<_, i64>(7)? as u64,
        },
        permissions: PermissionState {
            mode: row.get::<_, i64>(8)? as u32,
            owner_uid: row.get::<_, i64>(9)? as u32,
            owner_gid: row.get::<_, i64>(10)? as u32,
            capabilities: row.get(11)?,
        },
        security: SecurityState {
            xattrs: parse_xattrs(&xattrs_json),
            security_context: row.get(13)?,
        },
        mtime: row.get(14)?,
        package: row.get(15)?,
        source: parse_source(&source_str),
        added_at: row.get(17)?,
        updated_at: row.get(18)?,
    })
}

const SELECT_COLS: &str = "id, path, inode, device, file_type, symlink_target,
     hash, size, mode, owner_uid, owner_gid, capabilities,
     xattrs_json, security_context, mtime, package,
     source, added_at, updated_at";

/// Insert or update a baseline entry by path.
pub fn upsert(conn: &Connection, entry: &BaselineEntry) -> Result<()> {
    let xattrs_json = serde_json::to_string(&entry.security.xattrs)?;

    conn.prepare_cached(
        "INSERT INTO baseline (path, inode, device, file_type, symlink_target,
                               hash, size, mode, owner_uid, owner_gid, capabilities,
                               xattrs_json, security_context, mtime, package, source,
                               added_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
         ON CONFLICT(path) DO UPDATE SET
             inode = excluded.inode,
             device = excluded.device,
             file_type = excluded.file_type,
             symlink_target = excluded.symlink_target,
             hash = excluded.hash,
             size = excluded.size,
             mode = excluded.mode,
             owner_uid = excluded.owner_uid,
             owner_gid = excluded.owner_gid,
             capabilities = excluded.capabilities,
             xattrs_json = excluded.xattrs_json,
             security_context = excluded.security_context,
             mtime = excluded.mtime,
             package = excluded.package,
             source = excluded.source,
             updated_at = excluded.updated_at",
    )?
    .execute(params![
        entry.path.to_string_lossy().as_ref(),
        entry.identity.inode as i64,
        entry.identity.device as i64,
        entry.identity.file_type.to_string(),
        entry
            .identity
            .symlink_target
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        entry.content.hash,
        entry.content.size as i64,
        entry.permissions.mode as i64,
        entry.permissions.owner_uid as i64,
        entry.permissions.owner_gid as i64,
        entry.permissions.capabilities,
        xattrs_json,
        entry.security.security_context,
        entry.mtime,
        entry.package,
        entry.source.to_string(),
        entry.added_at,
        entry.updated_at,
    ])?;

    Ok(())
}

/// Insert many baseline entries in a single transaction.
pub fn batch_upsert(conn: &Connection, entries: &[BaselineEntry]) -> Result<u64> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let mut count = 0u64;
    for entry in entries {
        if let Err(e) = upsert(conn, entry) {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
        count += 1;
    }
    conn.execute_batch("COMMIT")?;
    Ok(count)
}

/// Get baseline entry by absolute path.
pub fn get_by_path(conn: &Connection, path: &str) -> Result<Option<BaselineEntry>> {
    let query = format!("SELECT {} FROM baseline WHERE path = ?1", SELECT_COLS);
    conn.prepare_cached(&query)?
        .query_row(params![path], row_to_entry)
        .optional()
        .map_err(Into::into)
}

/// Iterate over all baseline entries, calling the provided closure for each.
/// This streams rows from SQLite without collecting them into a Vec.
pub fn for_each_entry<F>(conn: &Connection, mut f: F) -> Result<()>
where
    F: FnMut(BaselineEntry) -> Result<()>,
{
    let query = format!("SELECT {} FROM baseline ORDER BY path", SELECT_COLS);
    let mut stmt = conn.prepare_cached(&query)?;
    let rows = stmt.query_map([], row_to_entry)?;

    for row in rows {
        f(row?)?;
    }

    Ok(())
}

/// Get all baseline entries ordered by path.
pub fn get_all(conn: &Connection) -> Result<Vec<BaselineEntry>> {
    let query = format!("SELECT {} FROM baseline ORDER BY path", SELECT_COLS);
    let mut stmt = conn.prepare_cached(&query)?;
    let mut out = Vec::new();
    let rows = stmt.query_map([], row_to_entry)?;

    for row in rows {
        out.push(row?);
    }

    Ok(out)
}

pub fn remove_by_path(conn: &Connection, path: &str) -> Result<usize> {
    let rows = conn.execute("DELETE FROM baseline WHERE path = ?1", params![path])?;
    Ok(rows)
}

pub fn count(conn: &Connection) -> Result<i64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM baseline", [], |row| row.get(0))?;
    Ok(count)
}

pub fn get_all_paths(conn: &Connection) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare_cached("SELECT path FROM baseline")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

pub fn set_config_state(conn: &Connection, key: &str, value: &str) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO config_state (key, value, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value, now],
    )?;
    Ok(())
}

pub fn get_config_state(conn: &Connection, key: &str) -> Result<Option<String>> {
    let value = conn
        .query_row(
            "SELECT value FROM config_state WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value)
}

/// Compute HMAC over the baseline table for at-rest tamper evidence.
/// Covers all 13 security-relevant fields for comprehensive integrity.
pub fn compute_baseline_hmac(conn: &Connection, key: &[u8]) -> Result<String> {
    let entries = get_all(conn)?;
    let mut canonical = String::new();

    for entry in entries {
        let symlink_str = entry
            .identity
            .symlink_target
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let caps_str = entry.permissions.capabilities.as_deref().unwrap_or("");
        let xattrs_json = serde_json::to_string(&entry.security.xattrs).unwrap_or_default();

        canonical.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            entry.path.display(),
            entry.content.hash,
            entry.content.size,
            entry.permissions.mode,
            entry.permissions.owner_uid,
            entry.permissions.owner_gid,
            entry.identity.inode,
            entry.identity.device,
            entry.identity.file_type,
            symlink_str,
            caps_str,
            xattrs_json,
            entry.security.security_context,
        ));
    }

    crate::hmac::compute_hmac(key, canonical.as_bytes())
}

/// Get the baseline fingerprint formatted as xxxx·xxxx·xxxx·xxxx.
/// Reads the baseline_hmac from config_state.
pub fn get_baseline_fingerprint(conn: &Connection) -> Option<String> {
    let hmac = get_config_state(conn, "baseline_hmac").ok()??;
    Some(crate::display::format_fingerprint(&hmac))
}

/// Get the baseline established timestamp from config_state.
pub fn get_baseline_established(conn: &Connection) -> Option<i64> {
    conn.query_row(
        "SELECT updated_at FROM config_state WHERE key = 'baseline_hmac'",
        [],
        |row| row.get::<_, i64>(0),
    )
    .ok()
}

/// Classification of baselined files by property.
pub fn compute_baseline_profile(conn: &Connection) -> Result<crate::display::BaselineProfile> {
    let row = conn.query_row(
        "SELECT
            COUNT(*) as total,
            SUM(CASE WHEN (mode & 73) != 0 THEN 1 ELSE 0 END) as executables,
            SUM(CASE WHEN (mode & 2048) != 0 THEN 1 ELSE 0 END) as setuid,
            SUM(CASE WHEN (mode & 1024) != 0 THEN 1 ELSE 0 END) as setgid,
            SUM(CASE WHEN path LIKE '/etc/%' THEN 1 ELSE 0 END) as config_files,
            SUM(CASE WHEN path LIKE '%/.ssh/%' OR path LIKE '%/.gnupg/%' THEN 1 ELSE 0 END) as keys_certs,
            SUM(CASE WHEN package IS NOT NULL THEN 1 ELSE 0 END) as package_owned,
            SUM(CASE WHEN package IS NULL THEN 1 ELSE 0 END) as unpackaged
         FROM baseline",
        [],
        |row| {
            Ok(crate::display::BaselineProfile {
                total: row.get::<_, i64>(0)? as u64,
                executables: row.get::<_, i64>(1)? as u64,
                setuid: row.get::<_, i64>(2)? as u64,
                setgid: row.get::<_, i64>(3)? as u64,
                config_files: row.get::<_, i64>(4)? as u64,
                keys_certs: row.get::<_, i64>(5)? as u64,
                package_owned: row.get::<_, i64>(6)? as u64,
                unpackaged: row.get::<_, i64>(7)? as u64,
            })
        },
    )?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema;
    use crate::types::{
        BaselineEntry, BaselineSource, ContentFingerprint, FileIdentity, FileType, PermissionState,
        SecurityState,
    };

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        schema::create_baseline_tables(&conn).unwrap();
        conn
    }

    fn sample_entry(path: &str) -> BaselineEntry {
        BaselineEntry {
            id: None,
            path: PathBuf::from(path),
            identity: FileIdentity {
                inode: 99999,
                device: 1,
                file_type: FileType::Regular,
                symlink_target: None,
            },
            content: ContentFingerprint {
                hash: "abc123def456".into(),
                size: 1024,
            },
            permissions: PermissionState {
                mode: 0o100644,
                owner_uid: 1000,
                owner_gid: 1000,
                capabilities: None,
            },
            security: SecurityState::default(),
            mtime: 1700000000,
            package: None,
            source: BaselineSource::AutoScan,
            added_at: 1700000000,
            updated_at: 1700000000,
        }
    }

    #[test]
    fn upsert_and_get_roundtrip() {
        let conn = test_conn();
        let entry = sample_entry("/etc/passwd");

        upsert(&conn, &entry).unwrap();
        let retrieved = get_by_path(&conn, "/etc/passwd").unwrap().unwrap();
        assert_eq!(retrieved.content.hash, "abc123def456");
        assert_eq!(retrieved.permissions.mode, 0o100644);
    }

    #[test]
    fn upsert_updates_existing_path() {
        let conn = test_conn();
        let mut entry = sample_entry("/etc/passwd");

        upsert(&conn, &entry).unwrap();
        entry.content.hash = "new_hash".into();
        entry.content.size = 2048;
        upsert(&conn, &entry).unwrap();

        assert_eq!(count(&conn).unwrap(), 1);
        let r = get_by_path(&conn, "/etc/passwd").unwrap().unwrap();
        assert_eq!(r.content.hash, "new_hash");
        assert_eq!(r.content.size, 2048);
    }

    #[test]
    fn native_columns_roundtrip() {
        let conn = test_conn();
        let mut entry = sample_entry("/etc/test");
        entry.identity.file_type = FileType::Symlink;
        entry.identity.symlink_target = Some(PathBuf::from("/etc/real"));
        entry.permissions.capabilities = Some("cap_net_admin".into());
        entry
            .security
            .xattrs
            .insert("user.test".into(), "val".into());
        entry.security.security_context = "system_u:object_r:etc_t:s0".into();

        upsert(&conn, &entry).unwrap();
        let r = get_by_path(&conn, "/etc/test").unwrap().unwrap();
        assert_eq!(r.identity.file_type, FileType::Symlink);
        assert_eq!(r.identity.symlink_target, Some(PathBuf::from("/etc/real")));
        assert_eq!(r.permissions.capabilities, Some("cap_net_admin".into()));
        assert_eq!(r.security.xattrs.get("user.test").unwrap(), "val");
        assert_eq!(r.security.security_context, "system_u:object_r:etc_t:s0");
    }

    #[test]
    fn for_each_entry_streams_all_rows() {
        let conn = test_conn();

        // Insert 5 entries
        for i in 0..5 {
            let entry = sample_entry(&format!("/test/file_{}", i));
            upsert(&conn, &entry).unwrap();
        }

        let mut count = 0u32;
        let mut paths = Vec::new();
        for_each_entry(&conn, |entry| {
            count += 1;
            paths.push(entry.path.to_string_lossy().to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 5);
        // Should be ordered by path
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }
}
