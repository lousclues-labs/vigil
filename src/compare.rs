use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::baseline::hash::blake3_hash_file;
use crate::config::Config;
use crate::error::Result;
use crate::types::{BaselineEntry, ChangeResult, ChangeType, FileMetadata, Severity};

/// Three-state outcome from comparing a file against its baseline.
/// Eliminates the TOCTOU double-open that occurred when the caller had
/// to re-open the file to distinguish "no changes" from "deleted."
pub enum CompareOutcome {
    /// File exists and matches its baseline — no changes detected.
    NoChange,
    /// File has been deleted (open returned NotFound).
    Deleted,
    /// File exists but differs from baseline.
    Changed(Vec<ChangeType>, String, FileMetadata),
}

/// Shared comparison logic: open file, fstat, hash, compare against baseline.
/// Returns a three-state CompareOutcome — no second open is ever needed.
///
/// If `max_file_size` is Some, files larger than the limit are skipped
/// (returns NoChange) to prevent blocking on large file hashing.
fn compare_file_against_baseline(
    path: &Path,
    baseline: &BaselineEntry,
    max_file_size: Option<u64>,
) -> Result<CompareOutcome> {
    // 1. Open file — pin inode. Detect deletions via open error, not exists().
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CompareOutcome::Deleted);
        }
        Err(e) => return Err(e.into()),
    };

    // 2. fstat on the open fd
    let meta = file.metadata()?;

    // 3. Skip files exceeding max_file_size (avoid blocking the event thread)
    if let Some(max_size) = max_file_size {
        if meta.len() > max_size {
            log::debug!(
                "Skipping {} (size {} > max {})",
                path.display(),
                meta.len(),
                max_size
            );
            return Ok(CompareOutcome::NoChange);
        }
    }

    // 4. Fast path: if ALL metadata matches baseline, skip expensive hash
    let metadata_unchanged = meta.mtime() == baseline.mtime
        && meta.len() == baseline.size
        && meta.ino() == baseline.inode
        && meta.dev() == baseline.device
        && meta.mode() == baseline.permissions
        && meta.uid() == baseline.owner_uid
        && meta.gid() == baseline.owner_gid;

    if metadata_unchanged {
        // Only check xattrs (cheap compared to full file hash)
        let current_xattrs = read_xattrs_json_fd(&file);
        if current_xattrs == baseline.xattrs {
            return Ok(CompareOutcome::NoChange);
        }
        // xattr changed — build result with baseline hash since content is unchanged
        let file_meta = FileMetadata {
            path: path.to_path_buf(),
            hash: baseline.hash.clone(),
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
        return Ok(CompareOutcome::Changed(
            vec![ChangeType::XattrChanged],
            baseline.hash.clone(),
            file_meta,
        ));
    }

    // Slow path: metadata differs, compute full comparison
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

    // xattr check via fd (avoids TOCTOU — uses flistxattr/fgetxattr)
    let current_xattrs = read_xattrs_json_fd(&file);
    if current_xattrs != baseline.xattrs {
        change_types.push(ChangeType::XattrChanged);
    }

    // Deduplicate change_types
    change_types.sort();
    change_types.dedup();

    if change_types.is_empty() {
        return Ok(CompareOutcome::NoChange);
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

    Ok(CompareOutcome::Changed(
        change_types,
        current_hash,
        file_meta,
    ))
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
/// Uses the open-first TOCTOU-hardened pattern with three-state CompareOutcome.
///
/// Returns:
/// - Ok(Some(change)) if something changed (including deletion)
/// - Ok(None) if the file matches its baseline
/// - Err if the file cannot be read (transient error)
pub fn compare_entry(
    baseline: &BaselineEntry,
    _config: &Config,
    severity: Severity,
    group_name: &str,
) -> Result<Option<ChangeResult>> {
    let path = &baseline.path;

    match compare_file_against_baseline(path, baseline, Some(_config.scanner.max_file_size))? {
        CompareOutcome::NoChange => Ok(None),
        CompareOutcome::Deleted => Ok(Some(deletion_result(
            path,
            baseline,
            severity,
            group_name.to_string(),
        ))),
        CompareOutcome::Changed(change_types, current_hash, file_meta) => Ok(Some(change_result(
            path,
            baseline,
            change_types,
            current_hash,
            &file_meta,
            severity,
            group_name.to_string(),
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
    max_file_size: u64,
) -> Result<Option<ChangeResult>> {
    match compare_file_against_baseline(path, baseline, Some(max_file_size))? {
        CompareOutcome::NoChange => Ok(None),
        CompareOutcome::Deleted => Ok(Some(deletion_result(
            path,
            baseline,
            group_severity,
            group_name.to_string(),
        ))),
        CompareOutcome::Changed(change_types, current_hash, file_meta) => Ok(Some(change_result(
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

/// Read extended attributes via file descriptor (flistxattr/fgetxattr).
/// This avoids TOCTOU by using the already-open fd instead of the path.
fn read_xattrs_json_fd(file: &File) -> String {
    let mut attrs = std::collections::BTreeMap::new();
    let fd = file.as_raw_fd();
    // Use /proc/self/fd/<fd> path for the xattr crate, which internally
    // uses the fd-based path and avoids path-based races.
    let fd_path = format!("/proc/self/fd/{}", fd);
    let fd_path = Path::new(&fd_path);
    if let Ok(names) = xattr::list(fd_path) {
        for name in names {
            let key = name.to_string_lossy().into_owned();
            if let Ok(Some(value)) = xattr::get(fd_path, &name) {
                attrs.insert(key, hex::encode(&value));
            }
        }
    }
    serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_baseline(path: &Path) -> BaselineEntry {
        let file = File::open(path).unwrap();
        let meta = file.metadata().unwrap();
        use std::os::unix::fs::MetadataExt;
        let hash = crate::baseline::hash::blake3_hash_file(&file).unwrap();
        BaselineEntry {
            id: None,
            path: path.to_path_buf(),
            hash,
            size: meta.len(),
            permissions: meta.mode(),
            owner_uid: meta.uid(),
            owner_gid: meta.gid(),
            mtime: meta.mtime(),
            inode: meta.ino(),
            device: meta.dev(),
            xattrs: "{}".into(),
            security_context: String::new(),
            package: None,
            source: crate::types::BaselineSource::AutoScan,
            added_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn fast_reject_skips_hash_when_metadata_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("stable.txt");
        fs::write(&file_path, b"stable content").unwrap();

        let baseline = make_baseline(&file_path);
        // File hasn't changed — should return NoChange via fast-reject
        let outcome = compare_file_against_baseline(&file_path, &baseline, None).unwrap();
        assert!(matches!(outcome, CompareOutcome::NoChange));
    }

    #[test]
    fn fast_reject_detects_size_change() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("grow.txt");
        fs::write(&file_path, b"short").unwrap();

        let baseline = make_baseline(&file_path);
        // Change content with different length
        fs::write(&file_path, b"much longer content now").unwrap();

        let outcome = compare_file_against_baseline(&file_path, &baseline, None).unwrap();
        assert!(matches!(outcome, CompareOutcome::Changed(..)));
    }
}
