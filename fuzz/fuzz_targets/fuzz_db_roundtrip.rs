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
    // Schema v3 symlink object identity, stored in columns distinct from
    // symlink_target. These ride the same upsert/get roundtrip, so the
    // fuzzer covers them rather than pinning them to None.
    is_symlink: bool,
    symlink_target: Option<String>,
    link_text: Option<String>,
    link_inode: Option<u64>,
    link_device: Option<u64>,
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
            file_type: if input.is_symlink {
                FileType::Symlink
            } else {
                FileType::Regular
            },
            symlink_target: input
                .symlink_target
                .as_deref()
                .map(std::path::PathBuf::from),
            link_text: input.link_text.as_deref().map(std::path::PathBuf::from),
            link_inode: input.link_inode,
            link_device: input.link_device,
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
            // The v3 columns must survive the roundtrip intact. Integer
            // fields are asserted directly; they carry no text-encoding
            // ambiguity, so a mismatch is a real storage defect.
            assert_eq!(retrieved.identity.link_inode, input.link_inode);
            assert_eq!(retrieved.identity.link_device, input.link_device);
        }
    }
});
