use std::fs::File;
use std::io::{BufReader, Seek};

use crate::error::{Result, VigilError};

/// Compute BLAKE3 hash of an already-opened file descriptor.
/// This avoids TOCTOU by never re-opening the path.
///
/// If `mmap_threshold` is provided and the file size >= threshold,
/// uses memory-mapped I/O for better performance on large files (Item 19).
/// Otherwise uses buffered read with a 128KB buffer.
pub fn blake3_hash_file(file: &File) -> Result<String> {
    blake3_hash_file_with_threshold(file, None)
}

/// Compute BLAKE3 hash with configurable mmap threshold.
pub fn blake3_hash_file_with_threshold(file: &File, mmap_threshold: Option<u64>) -> Result<String> {
    // Clone the file handle so we can read without consuming the caller's fd
    let mut reader = file
        .try_clone()
        .map_err(|e| VigilError::Hash(format!("cannot clone file handle: {}", e)))?;

    // Seek to the start to ensure we hash the entire file
    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| VigilError::Hash(format!("seek error during hashing: {}", e)))?;

    let file_size = reader.metadata().map(|m| m.len()).unwrap_or(0);

    let threshold = mmap_threshold.unwrap_or(u64::MAX);

    if file_size >= threshold && file_size > 0 {
        // Use memory-mapped I/O for large files
        // blake3::Hasher::update_mmap takes a path, so we use /proc/self/fd/<fd>
        // to reference the open fd without re-opening the path (TOCTOU-safe).
        use std::os::unix::io::AsRawFd;
        let fd_path = format!("/proc/self/fd/{}", reader.as_raw_fd());
        let mut hasher = blake3::Hasher::new();
        hasher
            .update_mmap(&fd_path)
            .map_err(|e| VigilError::Hash(format!("mmap hash error: {}", e)))?;
        Ok(hasher.finalize().to_hex().to_string())
    } else {
        // Use buffered read with 128KB buffer (up from default 8KB)
        let mut hasher = blake3::Hasher::new();
        let buf_reader = BufReader::with_capacity(131_072, &mut reader);
        hasher
            .update_reader(buf_reader)
            .map_err(|e| VigilError::Hash(format!("read error during hashing: {}", e)))?;
        Ok(hasher.finalize().to_hex().to_string())
    }
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
        let tmp = tempfile("empty");
        // empty file — read from start
        let hash = blake3_hash_file(&tmp).unwrap();
        let expected = blake3::hash(b"").to_hex().to_string();
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_known_content() {
        let mut tmp = tempfile("known");
        tmp.write_all(b"hello vigil").unwrap();
        tmp.flush().unwrap();

        // Re-open to read from start
        let reader = reopen(&tmp);
        let hash = blake3_hash_file(&reader).unwrap();
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
    fn hash_file_matches_hash_bytes() {
        let content = b"the filesystem is the source of truth";
        let mut tmp = tempfile("match");
        tmp.write_all(content).unwrap();
        tmp.flush().unwrap();

        let reader = reopen(&tmp);
        let file_hash = blake3_hash_file(&reader).unwrap();
        let bytes_hash = blake3_hash_bytes(content);
        assert_eq!(file_hash, bytes_hash);
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let hash = blake3_hash_bytes(b"some content");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn tempfile(suffix: &str) -> File {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vigil-hash-test-{}-{}-{}",
            std::process::id(),
            suffix,
            n,
        ));
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(&path)
            .unwrap()
    }

    fn reopen(f: &File) -> File {
        use std::os::unix::io::AsRawFd;
        let path = format!("/proc/self/fd/{}", f.as_raw_fd());
        File::open(&path).unwrap()
    }
}
