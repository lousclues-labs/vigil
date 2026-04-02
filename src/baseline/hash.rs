use std::fs::File;
use std::io::Read;

use crate::error::{Result, VigilError};

/// Compute BLAKE3 hash of an already-opened file descriptor.
/// This avoids TOCTOU by never re-opening the path.
pub fn blake3_hash_file(file: &File) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 65536]; // 64 KB buffer

    // Clone the file handle so we can read without consuming the caller's fd
    let mut reader = file
        .try_clone()
        .map_err(|e| VigilError::Hash(format!("cannot clone file handle: {}", e)))?;

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| VigilError::Hash(format!("read error during hashing: {}", e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Compute BLAKE3 hash of raw bytes.
pub fn blake3_hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}
