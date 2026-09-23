//! Schema migration for baseline and audit databases.
//!
//! Runs CREATE TABLE IF NOT EXISTS on open, so new tables are added
//! transparently. Future version upgrades will add ALTER TABLE steps here.

use rusqlite::Connection;

use crate::error::Result;

/// Baseline schema version written to `config_state` after a successful
/// migration. v1 stored JSON blobs; v2 flattened them into native columns;
/// v3 added the symlink object identity columns;
/// v3 added the symlink object columns (`link_text`, `link_inode`,
/// `link_device`).
pub const BASELINE_SCHEMA_VERSION: u32 = 3;

/// Columns added by the v2 to v3 migration live in `schema.rs` alongside the
/// table definition, so a fresh database and a migrated one cannot drift.
///
/// Run schema creation/migrations for baseline and audit databases.
pub fn migrate_all(baseline_conn: &Connection, audit_conn: &Connection) -> Result<()> {
    crate::db::schema::create_baseline_tables(baseline_conn)?;
    crate::db::schema::create_audit_tables(audit_conn)?;
    Ok(())
}

/// Migrate an existing v2 baseline to v3 by adding the symlink object columns.
///
/// Additive only. No existing value is rewritten, no row is deleted, and the
/// baseline HMAC is deliberately left alone: it covers the same 13 fields it
/// always has, so a baseline signed before this migration still verifies after
/// it, and nothing is silently resigned. See `docs/ARCHITECTURE.md` for why
/// the new columns sit outside that signature.
pub fn migrate_v2_to_v3(conn: &Connection) -> Result<()> {
    // A database without a baseline table has nothing to migrate.
    if conn.prepare("SELECT 1 FROM baseline LIMIT 0").is_err() {
        return Ok(());
    }

    let added = crate::db::schema::ensure_baseline_v3_columns(conn)?;
    if !added.is_empty() {
        tracing::info!(
            columns = ?added,
            "baseline migrated to schema v3: symlink object columns added; \
             existing entries carry NULL until their next scan and are \
             compared with pre-v3 semantics in the meantime"
        );
    }

    record_schema_version(conn, BASELINE_SCHEMA_VERSION)?;
    Ok(())
}

/// Persist the baseline schema version in `config_state`.
fn record_schema_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO config_state (key, value, updated_at) VALUES ('schema_version', ?1, ?2)",
        rusqlite::params![version.to_string(), chrono::Utc::now().timestamp()],
    )?;
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

    tracing::info!(
        migrated = migrated,
        errors = errors,
        "baseline schema migration v1→v2 complete"
    );

    // Continue to the current schema. A migration must always land on the
    // version this build reads, whichever entry point invoked it, so that no
    // caller can be left holding a half-migrated table.
    migrate_v2_to_v3(conn)?;

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

        // Verify the schema version was recorded. A v1 database migrates all
        // the way to the current version, not just to the next one.
        let version: String = conn
            .query_row(
                "SELECT value FROM config_state WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, BASELINE_SCHEMA_VERSION.to_string());

        // And the v3 symlink object columns exist, so a subsequent read of the
        // migrated table does not fail on a missing column.
        assert!(conn
            .prepare("SELECT link_text, link_inode, link_device FROM baseline LIMIT 0")
            .is_ok());
    }

    #[test]
    fn migrate_v2_to_v3_is_additive_and_idempotent() {
        let conn = Connection::open_in_memory().unwrap();

        // Build a v2 table by hand: the shape that shipped before v3.
        conn.execute_batch(
            "CREATE TABLE baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                inode INTEGER NOT NULL,
                device INTEGER NOT NULL,
                file_type TEXT NOT NULL DEFAULT 'regular',
                symlink_target TEXT,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                mode INTEGER NOT NULL,
                owner_uid INTEGER NOT NULL,
                owner_gid INTEGER NOT NULL,
                capabilities TEXT,
                xattrs_json TEXT NOT NULL DEFAULT '{}',
                security_context TEXT NOT NULL DEFAULT '',
                mtime INTEGER NOT NULL,
                package TEXT,
                source TEXT NOT NULL DEFAULT 'auto_scan',
                added_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE config_state (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
            );
            INSERT INTO baseline (path, inode, device, hash, size, mode, owner_uid,
                                  owner_gid, mtime, added_at, updated_at)
            VALUES ('/etc/passwd', 7, 1, 'keepme', 99, 420, 0, 0, 5, 5, 5);",
        )
        .unwrap();

        migrate_v2_to_v3(&conn).unwrap();
        // Idempotent: running it again must not error or duplicate columns.
        migrate_v2_to_v3(&conn).unwrap();

        // The pre-existing row is untouched, and the new columns read as NULL.
        let (hash, size, link_text): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT hash, size, link_text FROM baseline WHERE path = '/etc/passwd'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(hash, "keepme", "existing data must survive byte for byte");
        assert_eq!(size, 99);
        assert_eq!(link_text, None, "pre-v3 rows carry no link data");
    }

    #[test]
    fn migrate_noop_on_v2_schema() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::schema::create_baseline_tables(&conn).unwrap();

        // Should be a no-op since no identity_json column exists
        migrate_v1_to_v2(&conn).unwrap();
    }
}
