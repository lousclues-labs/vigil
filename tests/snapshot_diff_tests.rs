use std::collections::BTreeMap;
use std::path::PathBuf;

use vigil::types::{
    BaselineEntry, BaselineSource, Change, ContentFingerprint, FileIdentity, FileSnapshot,
    FileType, PermissionState, SecurityState,
};

fn baseline_entry() -> BaselineEntry {
    BaselineEntry {
        id: None,
        path: PathBuf::from("/etc/passwd"),
        identity: FileIdentity {
            inode: 100,
            device: 1,
            file_type: FileType::Regular,
            symlink_target: None,
        },
        content: ContentFingerprint {
            hash: "old_hash".into(),
            size: 128,
        },
        permissions: PermissionState {
            mode: 0o644,
            owner_uid: 0,
            owner_gid: 0,
            capabilities: None,
        },
        security: SecurityState {
            xattrs: BTreeMap::new(),
            security_context: "system_u:object_r:etc_t:s0".into(),
        },
        mtime: 1,
        package: Some("base-files".into()),
        source: BaselineSource::AutoScan,
        added_at: 1,
        updated_at: 1,
    }
}

#[test]
fn diff_detects_multiple_dimensions() {
    let baseline = baseline_entry();
    let mut xattrs = BTreeMap::new();
    xattrs.insert("user.test".into(), "value".into());

    let snapshot = FileSnapshot {
        path: baseline.path.clone(),
        identity: FileIdentity {
            inode: 200,
            device: 1,
            file_type: FileType::Regular,
            symlink_target: None,
        },
        content: ContentFingerprint {
            hash: "new_hash".into(),
            size: 128,
        },
        permissions: PermissionState {
            mode: 0o600,
            owner_uid: 1000,
            owner_gid: 1000,
            // Real VFS v2 capability blob with CAP_SETUID (bit 7) set
            capabilities: Some(hex::encode([
                0x02, 0x00, 0x00, 0x02, // magic: VFS_CAP_REVISION_2 + effective
                0x80, 0x00, 0x00, 0x00, // permitted[0]: bit 7 = CAP_SETUID
                0x80, 0x00, 0x00, 0x00, // inheritable[0]
                0x00, 0x00, 0x00, 0x00, // permitted[1]
                0x00, 0x00, 0x00, 0x00, // inheritable[1]
            ])),
        },
        security: SecurityState {
            xattrs,
            security_context: "unconfined_u:object_r:user_home_t:s0".into(),
        },
        mtime: 2,
    };

    let changes = snapshot.diff(&baseline);

    assert!(changes
        .iter()
        .any(|c| matches!(c, Change::ContentModified { .. })));
    assert!(changes
        .iter()
        .any(|c| matches!(c, Change::PermissionsChanged { .. })));
    assert!(changes
        .iter()
        .any(|c| matches!(c, Change::OwnerChanged { .. })));
    assert!(changes
        .iter()
        .any(|c| matches!(c, Change::InodeChanged { .. })));
    assert!(changes
        .iter()
        .any(|c| matches!(c, Change::XattrChanged { .. })));
    assert!(changes
        .iter()
        .any(|c| matches!(c, Change::SecurityContextChanged { .. })));
}
