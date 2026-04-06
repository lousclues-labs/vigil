use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};

use crate::error::{Result, VigilError};

/// Compute BLAKE3 hash of an open file descriptor. Tiered strategy:
/// - Files >= mmap_threshold: memory-mapped I/O (kernel-optimal paging, SIMD)
/// - Smaller files: buffered reader with 128KB buffer (16x default)
///
/// The fd is NOT closed. The caller retains ownership.
pub fn blake3_hash_fd(file: &File, size: u64, mmap_threshold: u64) -> Result<String> {
    let mut hasher = blake3::Hasher::new();

    if size >= mmap_threshold && size > 0 {
        // Memory-mapped I/O via /proc/self/fd/<fd> (TOCTOU-safe — no path re-open)
        use std::os::unix::io::AsRawFd;
        let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        if std::path::Path::new(&fd_path).exists() {
            hasher
                .update_mmap(&fd_path)
                .map_err(|e| VigilError::Hash(format!("mmap hash error: {}", e)))?;
        } else {
            // /proc unavailable — fall back to buffered reader
            let mut reader = file
                .try_clone()
                .map_err(|e| VigilError::Hash(format!("cannot clone file handle: {}", e)))?;
            reader
                .seek(SeekFrom::Start(0))
                .map_err(|e| VigilError::Hash(format!("seek error: {}", e)))?;
            let buf_reader = BufReader::with_capacity(131_072, &mut reader);
            hasher
                .update_reader(buf_reader)
                .map_err(|e| VigilError::Hash(format!("read hash error: {}", e)))?;
        }
    } else {
        // Buffered reader with 128KB buffer
        let mut reader = file
            .try_clone()
            .map_err(|e| VigilError::Hash(format!("cannot clone file handle: {}", e)))?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| VigilError::Hash(format!("seek error: {}", e)))?;
        let buf_reader = BufReader::with_capacity(131_072, &mut reader);
        hasher
            .update_reader(buf_reader)
            .map_err(|e| VigilError::Hash(format!("read hash error: {}", e)))?;
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Compute BLAKE3 hash of raw bytes.
pub fn blake3_hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_empty_file() {
        let tmp = make_temp_file("empty", b"");
        let hash = blake3_hash_fd(&tmp, 0, 1_048_576).unwrap();
        let expected = blake3::hash(b"").to_hex().to_string();
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_known_content() {
        let tmp = make_temp_file("known", b"hello vigil");
        let hash = blake3_hash_fd(&tmp, 11, 1_048_576).unwrap();
        let expected = blake3::hash(b"hello vigil").to_hex().to_string();
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_bytes_deterministic() {
        let h1 = blake3_hash_bytes(b"test data");
        let h2 = blake3_hash_bytes(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_bytes_different_input() {
        let h1 = blake3_hash_bytes(b"file A");
        let h2 = blake3_hash_bytes(b"file B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_fd_matches_hash_bytes() {
        let content = b"the filesystem is the source of truth";
        let tmp = make_temp_file("match", content);
        let file_hash = blake3_hash_fd(&tmp, content.len() as u64, 1_048_576).unwrap();
        let bytes_hash = blake3_hash_bytes(content);
        assert_eq!(file_hash, bytes_hash);
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let hash = blake3_hash_bytes(b"some content");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn make_temp_file(suffix: &str, content: &[u8]) -> File {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vigil-hash-test-{}-{}-{}",
            std::process::id(),
            suffix,
            n,
        ));
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f
    }
}
