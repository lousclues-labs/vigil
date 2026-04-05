#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use vigil::db;
use vigil::types::{
    BaselineEntry, BaselineSource, ContentFingerprint, FileIdentity, FileType, PermissionState,
    SecurityState,
};

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
}

fuzz_target!(|input: FuzzEntry| {
    let conn = match rusqlite::Connection::open_in_memory() {
        Ok(c) => c,
        Err(_) => return,
    };
    if db::schema::create_baseline_tables(&conn).is_err() {
        return;
    }

    let entry = BaselineEntry {
        id: None,
        path: std::path::PathBuf::from(&input.path),
        identity: FileIdentity {
            inode: input.inode,
            device: input.device,
            file_type: FileType::Regular,
            symlink_target: None,
        },
        content: ContentFingerprint {
            hash: input.hash.clone(),
            size: input.size,
        },
        permissions: PermissionState {
            mode: input.permissions,
            owner_uid: input.owner_uid,
            owner_gid: input.owner_gid,
            capabilities: None,
        },
        security: SecurityState::default(),
        mtime: input.mtime,
        package: None,
        source: BaselineSource::AutoScan,
        added_at: 1700000000,
        updated_at: 1700000000,
    };

    if db::baseline_ops::upsert(&conn, &entry).is_ok() {
        let path_str = entry.path.to_string_lossy().into_owned();
        if let Ok(Some(retrieved)) = db::baseline_ops::get_by_path(&conn, &path_str) {
            assert_eq!(retrieved.content.hash, input.hash);
            assert_eq!(retrieved.content.size, input.size);
        }
    }
});
