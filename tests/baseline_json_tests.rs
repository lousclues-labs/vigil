use rusqlite::params;

#[test]
fn baseline_json_blobs_deserialize_with_defaults() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    vigil::db::schema::create_baseline_tables(&conn).unwrap();

    let old_identity_json = r#"{"inode":1,"device":1,"file_type":"regular","symlink_target":null}"#;
    let content_json = r#"{"hash":"h","size":1}"#;
    let perms_json = r#"{"mode":420,"owner_uid":0,"owner_gid":0}"#;
    let security_json = r#"{"xattrs":{},"security_context":""}"#;

    conn.execute(
        "INSERT INTO baseline (path, identity_json, content_json, perms_json, security_json, mtime, package, source, added_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'auto_scan', ?7, ?8)",
        params!["/old", old_identity_json, content_json, perms_json, security_json, 1i64, 1i64, 1i64],
    )
    .unwrap();

    let entry = vigil::db::baseline_ops::get_by_path(&conn, "/old")
        .unwrap()
        .expect("entry should exist");

    assert_eq!(entry.identity.inode, 1);
    assert_eq!(entry.content.hash, "h");
    assert_eq!(entry.permissions.capabilities, None);
}
