use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::baseline::hash::blake3_hash_file;
use crate::config::Config;
use crate::error::Result;
use crate::types::{BaselineEntry, ChangeResult, ChangeType, Severity};

/// Compare a baseline entry against the current state of the file on disk.
/// Uses the open-first TOCTOU-hardened pattern.
///
/// Returns:
/// - Ok(Some(change)) if something changed
/// - Ok(None) if the file matches its baseline
/// - Err if the file cannot be read (transient error)
pub fn compare_entry(baseline: &BaselineEntry, _config: &Config) -> Result<Option<ChangeResult>> {
    let path = &baseline.path;

    // File deleted?
    if !path.exists() {
        return Ok(Some(ChangeResult {
            path: path.clone(),
            change_types: vec![ChangeType::Deleted],
            severity: Severity::Medium, // overridden by caller from watch group
            old_hash: Some(baseline.hash.clone()),
            new_hash: None,
            old_permissions: Some(baseline.permissions),
            new_permissions: None,
            old_owner_uid: Some(baseline.owner_uid),
            new_owner_uid: None,
            old_owner_gid: Some(baseline.owner_gid),
            new_owner_gid: None,
            old_inode: Some(baseline.inode),
            new_inode: None,
            package: baseline.package.clone(),
            package_update: false,
            monitored_group: String::new(),
        }));
    }

    // 1. Open file — pin inode
    let file = File::open(path)?;

    // 2. fstat on the open fd
    let meta = file.metadata()?;

    // 3. Collect change types
    let mut change_types = Vec::new();

    // Inode changed? (file replaced, not modified in place)
    if meta.ino() != baseline.inode || meta.dev() != baseline.device {
        change_types.push(ChangeType::InodeChanged);
    }

    // Permissions changed?
    if meta.mode() != baseline.permissions {
        change_types.push(ChangeType::PermissionsChanged);
    }

    // Owner changed?
    if meta.uid() != baseline.owner_uid {
        change_types.push(ChangeType::OwnerChanged);
    }
    if meta.gid() != baseline.owner_gid {
        change_types.push(ChangeType::OwnerChanged);
    }

    // Hash via open fd (content check)
    let current_hash = blake3_hash_file(&file)?;
    if current_hash != baseline.hash {
        change_types.push(ChangeType::Modified);
    }

    // xattr check
    let current_xattrs = read_xattrs_json(path);
    if current_xattrs != baseline.xattrs {
        change_types.push(ChangeType::XattrChanged);
    }

    // Deduplicate change_types
    change_types.sort_by_key(|c| format!("{:?}", c));
    change_types.dedup();

    if change_types.is_empty() {
        return Ok(None);
    }

    Ok(Some(ChangeResult {
        path: path.clone(),
        change_types,
        severity: Severity::Medium, // caller should override from watch group
        old_hash: Some(baseline.hash.clone()),
        new_hash: Some(current_hash),
        old_permissions: Some(baseline.permissions),
        new_permissions: Some(meta.mode()),
        old_owner_uid: Some(baseline.owner_uid),
        new_owner_uid: Some(meta.uid()),
        old_owner_gid: Some(baseline.owner_gid),
        new_owner_gid: Some(meta.gid()),
        old_inode: Some(baseline.inode),
        new_inode: Some(meta.ino()),
        package: baseline.package.clone(),
        package_update: false,
        monitored_group: String::new(),
    }))
}

/// Compare a filesystem event against the baseline for a specific path.
/// Used by the real-time monitor.
pub fn compare_event(
    path: &Path,
    baseline: &BaselineEntry,
    group_name: &str,
    group_severity: Severity,
) -> Result<Option<ChangeResult>> {
    if !path.exists() {
        return Ok(Some(ChangeResult {
            path: path.to_path_buf(),
            change_types: vec![ChangeType::Deleted],
            severity: group_severity,
            old_hash: Some(baseline.hash.clone()),
            new_hash: None,
            old_permissions: Some(baseline.permissions),
            new_permissions: None,
            old_owner_uid: Some(baseline.owner_uid),
            new_owner_uid: None,
            old_owner_gid: Some(baseline.owner_gid),
            new_owner_gid: None,
            old_inode: Some(baseline.inode),
            new_inode: None,
            package: baseline.package.clone(),
            package_update: false,
            monitored_group: group_name.to_string(),
        }));
    }

    let file = File::open(path)?;
    let meta = file.metadata()?;

    let mut change_types = Vec::new();

    if meta.ino() != baseline.inode || meta.dev() != baseline.device {
        change_types.push(ChangeType::InodeChanged);
    }

    if meta.mode() != baseline.permissions {
        change_types.push(ChangeType::PermissionsChanged);
    }

    if meta.uid() != baseline.owner_uid {
        change_types.push(ChangeType::OwnerChanged);
    }
    if meta.gid() != baseline.owner_gid && !change_types.contains(&ChangeType::OwnerChanged) {
        change_types.push(ChangeType::OwnerChanged);
    }

    let current_hash = blake3_hash_file(&file)?;
    if current_hash != baseline.hash {
        change_types.push(ChangeType::Modified);
    }

    if change_types.is_empty() {
        return Ok(None);
    }

    Ok(Some(ChangeResult {
        path: path.to_path_buf(),
        change_types,
        severity: group_severity,
        old_hash: Some(baseline.hash.clone()),
        new_hash: Some(current_hash),
        old_permissions: Some(baseline.permissions),
        new_permissions: Some(meta.mode()),
        old_owner_uid: Some(baseline.owner_uid),
        new_owner_uid: Some(meta.uid()),
        old_owner_gid: Some(baseline.owner_gid),
        new_owner_gid: Some(meta.gid()),
        old_inode: Some(baseline.inode),
        new_inode: Some(meta.ino()),
        package: baseline.package.clone(),
        package_update: false,
        monitored_group: group_name.to_string(),
    }))
}

fn read_xattrs_json(path: &Path) -> String {
    let mut attrs = std::collections::HashMap::new();
    if let Ok(names) = xattr::list(path) {
        for name in names {
            let key = name.to_string_lossy().into_owned();
            if let Ok(Some(value)) = xattr::get(path, &name) {
                attrs.insert(key, hex::encode(&value));
            }
        }
    }
    serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".to_string())
}
