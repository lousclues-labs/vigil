#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use vigil::db;
use vigil::types::{BaselineEntry, BaselineSource};

#[derive(Arbitrary, Debug)]
struct FuzzEntry {
    path: String,
    hash: String,
    size: u64,
    permissions: u32,
    owner_uid: u32,
    owner_gid: u32,
    mtime: i64,
    inode: u64,
    device: u64,
    xattrs: String,
}

fuzz_target!(|input: FuzzEntry| {
    // Create an in-memory SQLite DB
    let conn = match rusqlite::Connection::open_in_memory() {
        Ok(c) => c,
        Err(_) => return,
    };
    if db::schema::create_tables(&conn).is_err() {
        return;
    }

    let entry = BaselineEntry {
        id: None,
        path: std::path::PathBuf::from(&input.path),
        hash: input.hash.clone(),
        size: input.size,
        permissions: input.permissions,
        owner_uid: input.owner_uid,
        owner_gid: input.owner_gid,
        mtime: input.mtime,
        inode: input.inode,
        device: input.device,
        xattrs: input.xattrs.clone(),
        security_context: String::new(),
        package: None,
        source: BaselineSource::AutoScan,
        added_at: 1700000000,
        updated_at: 1700000000,
        file_type: "file".into(),
        symlink_target: None,
        capabilities: None,
    };

    // Insert must not panic
    if db::ops::upsert_baseline(&conn, &entry).is_ok() {
        // Read back must not panic or lose data
        let path_str = entry.path.to_string_lossy().into_owned();
        if let Ok(Some(retrieved)) = db::ops::get_baseline_by_path(&conn, &path_str) {
            assert_eq!(retrieved.hash, input.hash);
            assert_eq!(retrieved.size, input.size);
        }
    }
});
