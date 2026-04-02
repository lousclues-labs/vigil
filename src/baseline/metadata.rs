use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::config::Config;
use crate::error::{Result, VigilError};
use crate::types::FileMetadata;

/// Collect complete metadata for a file using the open-first TOCTOU-hardened pattern:
/// 1. Open file (pin inode)
/// 2. fstat on the open fd
/// 3. Hash via the open fd
/// 4. Read xattrs
pub fn collect_file_metadata(path: &Path, _config: &Config) -> Result<FileMetadata> {
    // 1. Open file — pins the inode
    let file = File::open(path).map_err(|e| {
        VigilError::Baseline(format!("cannot open {}: {}", path.display(), e))
    })?;

    // 2. Stat the open fd (not the path) to avoid TOCTOU
    let meta = file.metadata().map_err(|e| {
        VigilError::Baseline(format!("cannot stat {}: {}", path.display(), e))
    })?;

    // Skip non-regular files
    if !meta.is_file() {
        return Err(VigilError::Baseline(format!(
            "not a regular file: {}",
            path.display()
        )));
    }

    // 3. BLAKE3 hash via the open fd
    let hash = super::hash::blake3_hash_file(&file)?;

    // 4. Extended attributes
    let xattrs = read_xattrs(path);

    // 5. Security context (SELinux/AppArmor)
    let security_context = read_security_context(path);

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
    })
}

/// Read extended attributes and return as JSON string.
fn read_xattrs(path: &Path) -> String {
    let mut attrs = HashMap::new();

    match xattr::list(path) {
        Ok(names) => {
            for name in names {
                let key = name.to_string_lossy().into_owned();
                match xattr::get(path, &name) {
                    Ok(Some(value)) => {
                        // Store as hex for binary-safe representation
                        attrs.insert(key, hex::encode(&value));
                    }
                    Ok(None) => {
                        attrs.insert(key, String::new());
                    }
                    Err(_) => {
                        // Skip unreadable attributes
                    }
                }
            }
        }
        Err(_) => {
            // xattrs not supported or not readable — return empty
        }
    }

    serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".to_string())
}

/// Read SELinux or AppArmor security context.
fn read_security_context(path: &Path) -> String {
    // Try SELinux context first
    if let Ok(Some(val)) = xattr::get(path, "security.selinux") {
        return String::from_utf8_lossy(&val).trim_end_matches('\0').to_string();
    }

    // Try AppArmor
    if let Ok(Some(val)) = xattr::get(path, "security.apparmor") {
        return String::from_utf8_lossy(&val).trim_end_matches('\0').to_string();
    }

    String::new()
}
