use std::collections::HashSet;
use std::path::PathBuf;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::types::{
    BaselineEntry, BaselineSource, ContentFingerprint, FileIdentity, PermissionState, SecurityState,
};

/// Insert or update a baseline entry by path.
pub fn upsert(conn: &Connection, entry: &BaselineEntry) -> Result<()> {
    let identity_json = serde_json::to_string(&entry.identity)?;
    let content_json = serde_json::to_string(&entry.content)?;
    let perms_json = serde_json::to_string(&entry.permissions)?;
    let security_json = serde_json::to_string(&entry.security)?;

    conn.prepare_cached(
        "INSERT INTO baseline (path, identity_json, content_json, perms_json, security_json,
                               mtime, package, source, added_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(path) DO UPDATE SET
             identity_json = excluded.identity_json,
             content_json = excluded.content_json,
             perms_json = excluded.perms_json,
             security_json = excluded.security_json,
             mtime = excluded.mtime,
             package = excluded.package,
             source = excluded.source,
             updated_at = excluded.updated_at",
    )?
    .execute(params![
        entry.path.to_string_lossy().as_ref(),
        identity_json,
        content_json,
        perms_json,
        security_json,
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
    conn.prepare_cached(
        "SELECT id, path, identity_json, content_json, perms_json, security_json,
                mtime, package, source, added_at, updated_at
         FROM baseline WHERE path = ?1",
    )?
    .query_row(params![path], |row| {
        let identity_json: String = row.get(2)?;
        let content_json: String = row.get(3)?;
        let perms_json: String = row.get(4)?;
        let security_json: String = row.get(5)?;

        let identity: FileIdentity = serde_json::from_str(&identity_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let content: ContentFingerprint = serde_json::from_str(&content_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let perms: PermissionState = serde_json::from_str(&perms_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let security: SecurityState = serde_json::from_str(&security_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;

        let source_str: String = row.get(8)?;
        let source = match source_str.as_str() {
            "package_manager" => BaselineSource::PackageManager,
            "manual" => BaselineSource::Manual,
            _ => BaselineSource::AutoScan,
        };

        Ok(BaselineEntry {
            id: Some(row.get(0)?),
            path: PathBuf::from(row.get::<_, String>(1)?),
            identity,
            content,
            permissions: perms,
            security,
            mtime: row.get(6)?,
            package: row.get(7)?,
            source,
            added_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    })
    .optional()
    .map_err(Into::into)
}

/// Get all baseline entries ordered by path.
pub fn get_all(conn: &Connection) -> Result<Vec<BaselineEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, path, identity_json, content_json, perms_json, security_json,
                mtime, package, source, added_at, updated_at
         FROM baseline ORDER BY path",
    )?;

    let mut out = Vec::new();
    let rows = stmt.query_map([], |row| {
        let identity_json: String = row.get(2)?;
        let content_json: String = row.get(3)?;
        let perms_json: String = row.get(4)?;
        let security_json: String = row.get(5)?;

        let identity: FileIdentity = serde_json::from_str(&identity_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let content: ContentFingerprint = serde_json::from_str(&content_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let perms: PermissionState = serde_json::from_str(&perms_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let security: SecurityState = serde_json::from_str(&security_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;

        let source_str: String = row.get(8)?;
        let source = match source_str.as_str() {
            "package_manager" => BaselineSource::PackageManager,
            "manual" => BaselineSource::Manual,
            _ => BaselineSource::AutoScan,
        };

        Ok(BaselineEntry {
            id: Some(row.get(0)?),
            path: PathBuf::from(row.get::<_, String>(1)?),
            identity,
            content,
            permissions: perms,
            security,
            mtime: row.get(6)?,
            package: row.get(7)?,
            source,
            added_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    })?;

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
pub fn compute_baseline_hmac(conn: &Connection, key: &[u8]) -> Result<String> {
    let entries = get_all(conn)?;
    let mut canonical = String::new();

    for entry in entries {
        canonical.push_str(&format!(
            "{}|{}|{}|{}|{}\n",
            entry.path.display(),
            entry.content.hash,
            entry.permissions.mode,
            entry.permissions.owner_uid,
            entry.permissions.owner_gid,
        ));
    }

    crate::hmac::compute_hmac(key, canonical.as_bytes())
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
    fn json_blob_backward_compat_default_field() {
        let conn = test_conn();

        let old_identity_json =
            r#"{"inode":1,"device":1,"file_type":"regular","symlink_target":null}"#;
        let content_json = r#"{"hash":"h","size":1}"#;
        let perms_json = r#"{"mode":420,"owner_uid":0,"owner_gid":0}"#;
        let security_json = r#"{"xattrs":{},"security_context":""}"#;

        conn.execute(
            "INSERT INTO baseline (path, identity_json, content_json, perms_json, security_json, mtime, package, source, added_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'auto_scan', ?7, ?8)",
            params!["/old", old_identity_json, content_json, perms_json, security_json, 1i64, 1i64, 1i64],
        )
        .unwrap();

        let r = get_by_path(&conn, "/old").unwrap().unwrap();
        assert_eq!(r.identity.inode, 1);
        assert_eq!(r.permissions.capabilities, None);
    }
}
