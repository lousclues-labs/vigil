use rusqlite::Connection;

use crate::error::Result;

/// Run schema creation/migrations for baseline and audit databases.
pub fn migrate_all(baseline_conn: &Connection, audit_conn: &Connection) -> Result<()> {
    crate::db::schema::create_baseline_tables(baseline_conn)?;
    crate::db::schema::create_audit_tables(audit_conn)?;
    Ok(())
}

/// Check if the baseline table uses the v1 JSON blob schema.
fn is_v1_schema(conn: &Connection) -> bool {
    // Check if the old identity_json column exists
    let has_identity_json: bool = conn
        .prepare("SELECT identity_json FROM baseline LIMIT 0")
        .is_ok();
    has_identity_json
}

/// Migrate baseline from v1 (JSON blobs) to v2 (native columns).
pub fn migrate_v1_to_v2(conn: &Connection) -> Result<()> {
    if !is_v1_schema(conn) {
        return Ok(());
    }

    tracing::info!("migrating baseline schema from v1 (JSON blobs) to v2 (native columns)");

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS baseline_v2 (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            path            TEXT NOT NULL UNIQUE,
            inode           INTEGER NOT NULL,
            device          INTEGER NOT NULL,
            file_type       TEXT NOT NULL DEFAULT 'regular',
            symlink_target  TEXT,
            hash            TEXT NOT NULL,
            size            INTEGER NOT NULL,
            mode            INTEGER NOT NULL,
            owner_uid       INTEGER NOT NULL,
            owner_gid       INTEGER NOT NULL,
            capabilities    TEXT,
            xattrs_json     TEXT NOT NULL DEFAULT '{}',
            security_context TEXT NOT NULL DEFAULT '',
            mtime           INTEGER NOT NULL,
            package         TEXT,
            source          TEXT NOT NULL DEFAULT 'auto_scan',
            added_at        INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL,
            CHECK(source IN ('package_manager', 'manual', 'auto_scan'))
        );
        ",
    )?;

    // Copy all rows, extracting JSON fields into native columns
    let mut stmt = conn.prepare(
        "SELECT id, path, identity_json, content_json, perms_json, security_json,
                mtime, package, source, added_at, updated_at
         FROM baseline ORDER BY id",
    )?;

    let mut insert_stmt = conn.prepare(
        "INSERT INTO baseline_v2 (path, inode, device, file_type, symlink_target,
                                   hash, size, mode, owner_uid, owner_gid, capabilities,
                                   xattrs_json, security_context, mtime, package, source,
                                   added_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
    )?;

    let mut migrated = 0u64;
    let mut errors = 0u64;

    let rows: Vec<_> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,         // path
                row.get::<_, String>(2)?,         // identity_json
                row.get::<_, String>(3)?,         // content_json
                row.get::<_, String>(4)?,         // perms_json
                row.get::<_, String>(5)?,         // security_json
                row.get::<_, i64>(6)?,            // mtime
                row.get::<_, Option<String>>(7)?, // package
                row.get::<_, String>(8)?,         // source
                row.get::<_, i64>(9)?,            // added_at
                row.get::<_, i64>(10)?,           // updated_at
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    for (
        path,
        identity_json,
        content_json,
        perms_json,
        security_json,
        mtime,
        package,
        source,
        added_at,
        updated_at,
    ) in &rows
    {
        let identity: serde_json::Value = match serde_json::from_str(identity_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "skipping row with invalid identity_json");
                errors += 1;
                continue;
            }
        };
        let content: serde_json::Value = match serde_json::from_str(content_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "skipping row with invalid content_json");
                errors += 1;
                continue;
            }
        };
        let perms: serde_json::Value = match serde_json::from_str(perms_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "skipping row with invalid perms_json");
                errors += 1;
                continue;
            }
        };
        let security: serde_json::Value = match serde_json::from_str(security_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "skipping row with invalid security_json");
                errors += 1;
                continue;
            }
        };

        let inode = identity["inode"].as_u64().unwrap_or(0) as i64;
        let device = identity["device"].as_u64().unwrap_or(0) as i64;
        let file_type = identity["file_type"].as_str().unwrap_or("regular");
        let symlink_target = identity["symlink_target"].as_str().map(|s| s.to_string());

        let hash = content["hash"].as_str().unwrap_or("");
        let size = content["size"].as_u64().unwrap_or(0) as i64;

        let mode = perms["mode"].as_u64().unwrap_or(0o644) as i64;
        let owner_uid = perms["owner_uid"].as_u64().unwrap_or(0) as i64;
        let owner_gid = perms["owner_gid"].as_u64().unwrap_or(0) as i64;
        let capabilities = perms["capabilities"].as_str().map(|s| s.to_string());

        let xattrs = security
            .get("xattrs")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let xattrs_json_str = serde_json::to_string(&xattrs).unwrap_or_else(|_| "{}".to_string());
        let security_context = security["security_context"].as_str().unwrap_or("");

        if let Err(e) = insert_stmt.execute(rusqlite::params![
            path,
            inode,
            device,
            file_type,
            symlink_target,
            hash,
            size,
            mode,
            owner_uid,
            owner_gid,
            capabilities,
            xattrs_json_str,
            security_context,
            mtime,
            package,
            source,
            added_at,
            updated_at,
        ]) {
            tracing::warn!(path = %path, error = %e, "failed to migrate row");
            errors += 1;
            continue;
        }
        migrated += 1;
    }

    drop(insert_stmt);
    drop(stmt);

    // Replace old table with new one
    conn.execute_batch(
        "
        DROP TABLE baseline;
        ALTER TABLE baseline_v2 RENAME TO baseline;
        CREATE INDEX IF NOT EXISTS idx_baseline_path ON baseline(path);
        ",
    )?;

    // Record migration version
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT OR REPLACE INTO config_state (key, value, updated_at) VALUES ('schema_version', '2', ?1)",
        rusqlite::params![now],
    )?;

    tracing::info!(
        migrated = migrated,
        errors = errors,
        "baseline schema migration v1→v2 complete"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_v1_to_v2_preserves_data() {
        let conn = Connection::open_in_memory().unwrap();

        // Create v1 schema
        crate::db::schema::create_baseline_v1_tables(&conn).unwrap();

        // Insert v1 data
        conn.execute(
            "INSERT INTO baseline (path, identity_json, content_json, perms_json, security_json,
                                   mtime, package, source, added_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                "/etc/passwd",
                r#"{"inode":12345,"device":1,"file_type":"regular","symlink_target":null}"#,
                r#"{"hash":"abc123","size":1024}"#,
                r#"{"mode":420,"owner_uid":0,"owner_gid":0,"capabilities":null}"#,
                r#"{"xattrs":{},"security_context":""}"#,
                1700000000i64,
                "base",
                "package_manager",
                1700000000i64,
                1700000000i64,
            ],
        )
        .unwrap();

        // Run migration
        migrate_v1_to_v2(&conn).unwrap();

        // Verify data
        let (inode, hash, mode, owner_uid): (i64, String, i64, i64) = conn
            .query_row(
                "SELECT inode, hash, mode, owner_uid FROM baseline WHERE path = '/etc/passwd'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(inode, 12345);
        assert_eq!(hash, "abc123");
        assert_eq!(mode, 420);
        assert_eq!(owner_uid, 0);

        // Verify schema version was recorded
        let version: String = conn
            .query_row(
                "SELECT value FROM config_state WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "2");
    }

    #[test]
    fn migrate_noop_on_v2_schema() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();

        // Should be a no-op since no identity_json column exists
        migrate_v1_to_v2(&conn).unwrap();
    }
}
