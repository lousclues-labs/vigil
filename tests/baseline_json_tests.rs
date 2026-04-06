use rusqlite::params;

#[test]
fn baseline_native_columns_roundtrip() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    vigil::db::schema::create_baseline_tables(&conn).unwrap();

    conn.execute(
        "INSERT INTO baseline (path, inode, device, file_type, symlink_target,
                               hash, size, mode, owner_uid, owner_gid, capabilities,
                               xattrs_json, security_context, mtime, package, source,
                               added_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9, NULL, '{}', '', ?10, NULL, 'auto_scan', ?11, ?12)",
        params!["/etc/test", 1i64, 1i64, "regular", "h", 1i64, 420i64, 0i64, 0i64, 1i64, 1i64, 1i64],
    )
    .unwrap();

    let entry = vigil::db::baseline_ops::get_by_path(&conn, "/etc/test")
        .unwrap()
        .expect("entry should exist");

    assert_eq!(entry.identity.inode, 1);
    assert_eq!(entry.content.hash, "h");
    assert_eq!(entry.permissions.capabilities, None);
}

#[test]
fn baseline_v1_to_v2_migration_preserves_data() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    vigil::db::schema::create_baseline_v1_tables(&conn).unwrap();

    let old_identity_json =
        r#"{"inode":42,"device":1,"file_type":"regular","symlink_target":null}"#;
    let content_json = r#"{"hash":"abc123","size":1024}"#;
    let perms_json = r#"{"mode":420,"owner_uid":0,"owner_gid":0}"#;
    let security_json = r#"{"xattrs":{},"security_context":""}"#;

    conn.execute(
        "INSERT INTO baseline (path, identity_json, content_json, perms_json, security_json, mtime, package, source, added_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'auto_scan', ?7, ?8)",
        params!["/old", old_identity_json, content_json, perms_json, security_json, 1i64, 1i64, 1i64],
    )
    .unwrap();

    // Run migration
    vigil::db::migrate::migrate_v1_to_v2(&conn).unwrap();

    // Now query with the new native columns
    let entry = vigil::db::baseline_ops::get_by_path(&conn, "/old")
        .unwrap()
        .expect("entry should exist after migration");

    assert_eq!(entry.identity.inode, 42);
    assert_eq!(entry.content.hash, "abc123");
    assert_eq!(entry.content.size, 1024);
    assert_eq!(entry.permissions.capabilities, None);
}
