//! BLAKE3 file hashing with mmap fast path and buffered fallback.
//!
//! `blake3_hash_fd` hashes from an open fd (TOCTOU-safe). Falls back to
//! buffered I/O for special files where mmap fails. `hash_buffered` provides
//! a path-based entry point for CLI commands.

use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;

use crate::error::{Result, VigilError};

/// RAII guard for memory-mapped regions. Calls munmap on drop.
#[allow(unsafe_code)]
struct MmapGuard {
    ptr: *mut libc::c_void,
    len: usize,
}

#[allow(unsafe_code)]
impl MmapGuard {
    /// Create a read-only mmap of the given fd.
    ///
    /// # Safety
    /// The fd must be a valid open descriptor with read permission.
    /// The mapping is MAP_PRIVATE + PROT_READ, so no writes reach the file.
    /// The caller must keep the fd open for the lifetime of this guard.
    unsafe fn new(fd: std::os::unix::io::RawFd, len: usize) -> std::io::Result<Self> {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { ptr, len })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for len bytes from the mmap call. The region
        // is PROT_READ, so reading through from_raw_parts is sound.
        // The guard keeps the mapping alive for the slice's lifetime.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

#[allow(unsafe_code)]
impl Drop for MmapGuard {
    fn drop(&mut self) {
        // SAFETY: ptr and len are from a successful mmap call. munmap
        // releases the mapping. After drop, no references to the region
        // exist because the guard owned the only slice.
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

/// Compute BLAKE3 hash of an open file descriptor. Tiered strategy:
/// - Files >= mmap_threshold: direct mmap on the fd (no path re-open, TOCTOU-safe)
/// - Smaller files: buffered reader with 128KB buffer (16x default)
///
/// The fd is NOT closed. The caller retains ownership.
#[allow(unsafe_code)]
pub fn blake3_hash_fd(file: &File, size: u64, mmap_threshold: u64) -> Result<String> {
    let mut hasher = blake3::Hasher::new();

    if size >= mmap_threshold && size > 0 {
        // Direct mmap on the fd; no path re-open, eliminating the TOCTOU window
        // that existed when using update_mmap() with /proc/self/fd/N paths.
        let raw_fd = file.as_raw_fd();
        match unsafe { MmapGuard::new(raw_fd, size as usize) } {
            Ok(guard) => {
                hasher.update(guard.as_slice());
            }
            Err(_) => {
                // mmap failed (e.g., special files, /proc entries); fall back to buffered reader
                hash_buffered(file, &mut hasher)?;
            }
        }
    } else {
        hash_buffered(file, &mut hasher)?;
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Hash a file using a buffered reader with a 128KB buffer.
fn hash_buffered(file: &File, hasher: &mut blake3::Hasher) -> Result<()> {
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
    Ok(())
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
        let tmp = make_temp_file(b"");
        let hash = blake3_hash_fd(tmp.as_file(), 0, 1_048_576).unwrap();
        let expected = blake3::hash(b"").to_hex().to_string();
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_known_content() {
        let tmp = make_temp_file(b"hello vigil");
        let hash = blake3_hash_fd(tmp.as_file(), 11, 1_048_576).unwrap();
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
        let tmp = make_temp_file(content);
        let file_hash = blake3_hash_fd(tmp.as_file(), content.len() as u64, 1_048_576).unwrap();
        let bytes_hash = blake3_hash_bytes(content);
        assert_eq!(file_hash, bytes_hash);
    }

    #[test]
    fn hash_mmap_matches_buffered() {
        // Create a file > 0 bytes and hash it via both mmap (threshold=1) and buffered (threshold=MAX)
        let content = b"mmap vs buffered consistency check with enough data to test";
        let tmp_mmap = make_temp_file(content);
        let tmp_buf = make_temp_file(content);
        let hash_mmap = blake3_hash_fd(tmp_mmap.as_file(), content.len() as u64, 1).unwrap(); // threshold=1 forces mmap
        let hash_buf = blake3_hash_fd(tmp_buf.as_file(), content.len() as u64, u64::MAX).unwrap(); // threshold=MAX forces buffered
        assert_eq!(hash_mmap, hash_buf);
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let hash = blake3_hash_bytes(b"some content");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn make_temp_file(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f
    }
}
