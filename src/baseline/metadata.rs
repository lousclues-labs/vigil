use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::config::Config;
use crate::error::{Result, VigilError};
use crate::types::FileMetadata;

/// Collect complete metadata for a file using the open-first TOCTOU-hardened pattern:
/// 1. Open file (pin inode)
/// 2. fstat on the open fd
/// 3. Hash via the open fd
/// 4. Read xattrs via the open fd
///
/// If `max_file_size` is `Some`, files larger than the limit return `FileTooLarge`.
pub fn collect_file_metadata(
    path: &Path,
    _config: &Config,
    max_file_size: Option<u64>,
) -> Result<FileMetadata> {
    // 1. Open file — pins the inode
    let file = File::open(path)
        .map_err(|e| VigilError::Baseline(format!("cannot open {}: {}", path.display(), e)))?;

    // 2. Stat the open fd (not the path) to avoid TOCTOU
    let meta = file
        .metadata()
        .map_err(|e| VigilError::Baseline(format!("cannot stat {}: {}", path.display(), e)))?;

    // Skip non-regular files
    if !meta.is_file() {
        return Err(VigilError::Baseline(format!(
            "not a regular file: {}",
            path.display()
        )));
    }

    // Check file size limit
    if let Some(max_size) = max_file_size {
        if meta.len() > max_size {
            return Err(VigilError::Baseline(format!(
                "file too large: {} ({} > {})",
                path.display(),
                meta.len(),
                max_size
            )));
        }
    }

    // 3. BLAKE3 hash via the open fd
    let hash = super::hash::blake3_hash_file(&file)?;

    // 4. Extended attributes via fd (avoids TOCTOU)
    let xattrs = read_xattrs_fd(&file);

    // 5. Security context via fd (SELinux/AppArmor)
    let security_context = read_security_context_fd(&file);

    // 6. Capabilities via security.capability xattr
    let capabilities = read_capabilities_fd(&file);

    Ok(FileMetadata {
        path: path.to_path_buf(),
        hash,
        size: meta.len(),
        permissions: meta.mode(),
        owner_uid: meta.uid(),
        owner_gid: meta.gid(),
        mtime: meta.mtime(),
        inode: meta.ino(),
        device: meta.dev(),
        xattrs,
        security_context,
        file_type: "file".to_string(),
        symlink_target: None,
        capabilities,
    })
}

/// Read extended attributes via /proc/self/fd/<fd> to avoid TOCTOU.
fn read_xattrs_fd(file: &File) -> String {
    let mut attrs = BTreeMap::new();
    let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let fd_path = Path::new(&fd_path);

    if let Ok(names) = xattr::list(fd_path) {
        for name in names {
            let key = name.to_string_lossy().into_owned();
            match xattr::get(fd_path, &name) {
                Ok(Some(value)) => {
                    attrs.insert(key, hex::encode(&value));
                }
                Ok(None) => {
                    attrs.insert(key, String::new());
                }
                Err(_) => {}
            }
        }
    }

    serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".to_string())
}

/// Read SELinux or AppArmor security context via /proc/self/fd/<fd>.
fn read_security_context_fd(file: &File) -> String {
    let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
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

/// Read Linux file capabilities via the security.capability xattr.
fn read_capabilities_fd(file: &File) -> Option<String> {
    let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let fd_path = Path::new(&fd_path);

    match xattr::get(fd_path, "security.capability") {
        Ok(Some(val)) => Some(hex::encode(&val)),
        _ => None,
    }
}
