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
///
/// # Security parameters
///
/// - `force_hash`: When true, always compute the BLAKE3 hash even if metadata
///   is unchanged. This defeats mtime-spoofing attacks where an attacker modifies
///   file contents and resets mtime via `touch -t` / `utimensat()` while preserving
///   file size through padding. Should be `true` for real-time event paths (the
///   event already fired — something changed) and `false` for batch/incremental
///   scans where the mtime optimization is an explicitly accepted tradeoff.
///
/// - `skip_unchanged`: When true AND all metadata matches the baseline, return
///   NoChange without hashing. This is the incremental scan mtime optimization,
///   now performed *inside* the TOCTOU-hardened open-first pattern (fstat on the
///   pinned fd) rather than via a racy stat-by-path before open. Only effective
///   when `force_hash` is false.
fn compare_file_against_baseline(
    path: &Path,
    baseline: &BaselineEntry,
    max_file_size: Option<u64>,
    force_hash: bool,
    skip_unchanged: bool,
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

    // 4. Check metadata invariants
    let metadata_unchanged = meta.mtime() == baseline.mtime
        && meta.len() == baseline.size
        && meta.ino() == baseline.inode
        && meta.dev() == baseline.device
        && meta.mode() == baseline.permissions
        && meta.uid() == baseline.owner_uid
        && meta.gid() == baseline.owner_gid;

    // Read security context via fd (SELinux/AppArmor)
    let current_security_context = read_security_context_fd(&file);

    // Read xattrs via fd
    let current_xattrs = read_xattrs_json_fd(&file);

    // Fast path: if ALL metadata, xattrs, and security context match baseline,
    // and we are not forced to hash, skip the expensive BLAKE3 computation.
    // When skip_unchanged is true (incremental scan), this is the mtime
    // optimization — now using fstat on the pinned fd, not a racy stat-by-path.
    if metadata_unchanged && !force_hash {
        let security_context_unchanged = current_security_context == baseline.security_context;
        let xattrs_unchanged = current_xattrs == baseline.xattrs;

        if skip_unchanged && security_context_unchanged && xattrs_unchanged {
            return Ok(CompareOutcome::NoChange);
        }

        if security_context_unchanged && xattrs_unchanged {
            return Ok(CompareOutcome::NoChange);
        }

        // xattr or security context changed — build result with baseline hash
        // since content is unchanged
        let mut change_types = Vec::new();
        if !xattrs_unchanged {
            change_types.push(ChangeType::XattrChanged);
        }
        if !security_context_unchanged {
            change_types.push(ChangeType::SecurityContextChanged);
        }
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
            security_context: current_security_context,
        };
        return Ok(CompareOutcome::Changed(
            change_types,
            baseline.hash.clone(),
            file_meta,
        ));
    }

    // Slow path: metadata differs or force_hash is true — compute full comparison
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

    // xattr check (already read above)
    if current_xattrs != baseline.xattrs {
        change_types.push(ChangeType::XattrChanged);
    }

    // Security context check (already read above)
    if current_security_context != baseline.security_context {
        change_types.push(ChangeType::SecurityContextChanged);
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
        security_context: current_security_context,
    };

    Ok(CompareOutcome::Changed(
        change_types,
        current_hash,
        file_meta,
    ))
}

/// Read SELinux or AppArmor security context via /proc/self/fd/<fd>.
fn read_security_context_fd(file: &File) -> String {
    let fd = file.as_raw_fd();
    let fd_path = format!("/proc/self/fd/{}", fd);
    let fd_path = Path::new(&fd_path);

    if let Ok(Some(val)) = xattr::get(fd_path, "security.selinux") {
        return String::from_utf8_lossy(&val)
            .trim_end_matches('\0')
            .to_string();
    }

    if let Ok(Some(val)) = xattr::get(fd_path, "security.apparmor") {
        return String::from_utf8_lossy(&val)
            .trim_end_matches('\0')
            .to_string();
    }

    String::new()
}

/// Build a deletion ChangeResult.
fn deletion_result(
    path: &Path,
    baseline: &BaselineEntry,
    severity: Severity,
    group_name: String,
    package_update: bool,
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
        package_update,
        monitored_group: group_name,
    }
}

/// Build a change ChangeResult from comparison results.
fn change_result(
    baseline: &BaselineEntry,
    change_types: Vec<ChangeType>,
    current_hash: String,
    file_meta: &FileMetadata,
    severity: Severity,
    group_name: String,
    package_update: bool,
) -> ChangeResult {
    ChangeResult {
        path: baseline.path.clone(),
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
        package_update,
        monitored_group: group_name,
    }
}

/// Compare a baseline entry against the current state of the file on disk.
/// Uses the open-first TOCTOU-hardened pattern with three-state CompareOutcome.
///
/// The `skip_unchanged` parameter enables the incremental scan mtime optimization
/// *inside* the TOCTOU-hardened open-first pattern (using fstat on the pinned fd)
/// rather than via a racy stat-by-path before open.
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
    skip_unchanged: bool,
) -> Result<Option<ChangeResult>> {
    let path = &baseline.path;

    match compare_file_against_baseline(
        path,
        baseline,
        Some(_config.scanner.max_file_size),
        false,
        skip_unchanged,
    )? {
        CompareOutcome::NoChange => Ok(None),
        CompareOutcome::Deleted => Ok(Some(deletion_result(
            path,
            baseline,
            severity,
            group_name.to_string(),
            false,
        ))),
        CompareOutcome::Changed(change_types, current_hash, file_meta) => Ok(Some(change_result(
            baseline,
            change_types,
            current_hash,
            &file_meta,
            severity,
            group_name.to_string(),
            false,
        ))),
    }
}

/// Compare a filesystem event against the baseline for a specific path.
/// Used by the real-time monitor. Always forces BLAKE3 hashing because
/// the event already fired — something changed — so the mtime fast-reject
/// must be bypassed to prevent attackers from spoofing mtime.
pub fn compare_event(
    path: &Path,
    baseline: &BaselineEntry,
    group_name: &str,
    group_severity: Severity,
    max_file_size: u64,
) -> Result<Option<ChangeResult>> {
    match compare_file_against_baseline(path, baseline, Some(max_file_size), true, false)? {
        CompareOutcome::NoChange => Ok(None),
        CompareOutcome::Deleted => Ok(Some(deletion_result(
            path,
            baseline,
            group_severity,
            group_name.to_string(),
            false,
        ))),
        CompareOutcome::Changed(change_types, current_hash, file_meta) => Ok(Some(change_result(
            baseline,
            change_types,
            current_hash,
            &file_meta,
            group_severity,
            group_name.to_string(),
            false,
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
        let outcome =
            compare_file_against_baseline(&file_path, &baseline, None, false, false).unwrap();
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

        let outcome =
            compare_file_against_baseline(&file_path, &baseline, None, false, false).unwrap();
        assert!(matches!(outcome, CompareOutcome::Changed(..)));
    }

    #[test]
    fn force_hash_detects_content_change_despite_matching_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("sneaky.txt");
        fs::write(&file_path, b"original text").unwrap();

        let baseline = make_baseline(&file_path);

        // Overwrite with same-length content to keep size unchanged
        fs::write(&file_path, b"tampered text").unwrap();

        // Restore original mtime via filetime
        let mtime = filetime::FileTime::from_unix_time(baseline.mtime, 0);
        filetime::set_file_mtime(&file_path, mtime).unwrap();

        // Without force_hash, fast-reject returns NoChange
        let outcome =
            compare_file_against_baseline(&file_path, &baseline, None, false, false).unwrap();
        assert!(matches!(outcome, CompareOutcome::NoChange));

        // With force_hash, the content change is detected
        let outcome =
            compare_file_against_baseline(&file_path, &baseline, None, true, false).unwrap();
        assert!(matches!(outcome, CompareOutcome::Changed(..)));
        if let CompareOutcome::Changed(change_types, _, _) = outcome {
            assert!(change_types.contains(&ChangeType::Modified));
        }
    }
}
