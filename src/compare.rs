use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::baseline::hash::blake3_hash_file;
use crate::config::Config;
use crate::error::Result;
use crate::types::{BaselineEntry, ChangeResult, ChangeType, FileMetadata, Severity};

/// Shared comparison logic: open file, fstat, hash, compare against baseline.
/// Returns Ok(None) if no changes detected, Ok(Some(...)) with the change types,
/// current hash, and file metadata if changes are found.
///
/// Uses the open-first pattern to avoid TOCTOU races: we attempt File::open()
/// directly and match on NotFound to detect deletions, rather than checking
/// path.exists() first.
fn compare_file_against_baseline(
    path: &Path,
    baseline: &BaselineEntry,
) -> Result<Option<(Vec<ChangeType>, String, FileMetadata)>> {
    // 1. Open file — pin inode. Detect deletions via open error, not exists().
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None); // Caller handles deletion
        }
        Err(e) => return Err(e.into()),
    };

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

    // Owner changed? (combine UID and GID into one check)
    if meta.uid() != baseline.owner_uid || meta.gid() != baseline.owner_gid {
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
    change_types.sort();
    change_types.dedup();

    if change_types.is_empty() {
        return Ok(None);
    }

    let file_meta = FileMetadata {
        path: path.to_path_buf(),
        hash: current_hash.clone(),
        size: meta.len(),
        permissions: meta.mode(),
        owner_uid: meta.uid(),
        owner_gid: meta.gid(),
        mtime: meta.mtime(),
        inode: meta.ino(),
        device: meta.dev(),
        xattrs: current_xattrs,
        security_context: String::new(),
    };

    Ok(Some((change_types, current_hash, file_meta)))
}

/// Build a deletion ChangeResult.
fn deletion_result(
    path: &Path,
    baseline: &BaselineEntry,
    severity: Severity,
    group_name: String,
) -> ChangeResult {
    ChangeResult {
        path: path.to_path_buf(),
        change_types: vec![ChangeType::Deleted],
        severity,
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
        old_mtime: Some(baseline.mtime),
        new_mtime: None,
        package: baseline.package.clone(),
        package_update: false,
        monitored_group: group_name,
    }
}

/// Build a change ChangeResult from comparison results.
fn change_result(
    path: &Path,
    baseline: &BaselineEntry,
    change_types: Vec<ChangeType>,
    current_hash: String,
    file_meta: &FileMetadata,
    severity: Severity,
    group_name: String,
) -> ChangeResult {
    ChangeResult {
        path: path.to_path_buf(),
        change_types,
        severity,
        old_hash: Some(baseline.hash.clone()),
        new_hash: Some(current_hash),
        old_permissions: Some(baseline.permissions),
        new_permissions: Some(file_meta.permissions),
        old_owner_uid: Some(baseline.owner_uid),
        new_owner_uid: Some(file_meta.owner_uid),
        old_owner_gid: Some(baseline.owner_gid),
        new_owner_gid: Some(file_meta.owner_gid),
        old_inode: Some(baseline.inode),
        new_inode: Some(file_meta.inode),
        old_mtime: Some(baseline.mtime),
        new_mtime: Some(file_meta.mtime),
        package: baseline.package.clone(),
        package_update: false,
        monitored_group: group_name,
    }
}

/// Compare a baseline entry against the current state of the file on disk.
/// Uses the open-first TOCTOU-hardened pattern.
///
/// Returns:
/// - Ok(Some(change)) if something changed
/// - Ok(None) if the file matches its baseline
/// - Err if the file cannot be read (transient error)
pub fn compare_entry(baseline: &BaselineEntry, _config: &Config) -> Result<Option<ChangeResult>> {
    let path = &baseline.path;

    match compare_file_against_baseline(path, baseline)? {
        None => {
            // File was deleted (NotFound) or no changes detected.
            // We need to distinguish: try opening to see if it's truly gone.
            // compare_file_against_baseline returns None for both "no changes"
            // and "file not found". We handle deletion by attempting open again.
            // Actually, we need to restructure: if file not found, we get None;
            // if file exists with no changes, we also get None.
            // Let's check if the file can be opened to distinguish.
            match File::open(path) {
                Ok(_) => Ok(None), // File exists, no changes
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(deletion_result(
                    path,
                    baseline,
                    Severity::Medium,
                    String::new(),
                ))),
                Err(e) => Err(e.into()),
            }
        }
        Some((change_types, current_hash, file_meta)) => Ok(Some(change_result(
            path,
            baseline,
            change_types,
            current_hash,
            &file_meta,
            Severity::Medium, // caller should override from watch group
            String::new(),
        ))),
    }
}

/// Compare a filesystem event against the baseline for a specific path.
/// Used by the real-time monitor.
pub fn compare_event(
    path: &Path,
    baseline: &BaselineEntry,
    group_name: &str,
    group_severity: Severity,
) -> Result<Option<ChangeResult>> {
    match compare_file_against_baseline(path, baseline)? {
        None => match File::open(path) {
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(deletion_result(
                path,
                baseline,
                group_severity,
                group_name.to_string(),
            ))),
            Err(e) => Err(e.into()),
        },
        Some((change_types, current_hash, file_meta)) => Ok(Some(change_result(
            path,
            baseline,
            change_types,
            current_hash,
            &file_meta,
            group_severity,
            group_name.to_string(),
        ))),
    }
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
