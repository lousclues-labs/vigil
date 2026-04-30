//! BLAKE3 file hashing with mmap fast path and buffered fallback.
//!
//! `blake3_hash_fd` hashes from an open fd (TOCTOU-safe). Falls back to
//! buffered I/O for special files where mmap fails. `hash_buffered` provides
//! a path-based entry point for CLI commands.

use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;

use crate::error::{Result, VigilError};

// Thread-local 128KB read buffer reused across hash operations to avoid
// per-file heap allocation churn.
thread_local! {
    static HASH_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 131_072]);
}

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

/// Hash a file using a thread-local reusable buffer. Reads via `&File`
/// (which implements `Read` on Unix) to avoid a `dup(2)` syscall from
/// `try_clone()`. The 128KB buffer is allocated once per thread.
fn hash_buffered(file: &File, hasher: &mut blake3::Hasher) -> Result<()> {
    (&*file)
        .seek(SeekFrom::Start(0))
        .map_err(|e| VigilError::Hash(format!("seek error: {}", e)))?;
    HASH_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        let mut reader: &File = file;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buf[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(VigilError::Hash(format!("read hash error: {}", e))),
            }
        }
        Ok(())
    })
}

/// Compute BLAKE3 hash of raw bytes.
pub fn blake3_hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

// =============================================================================
// Forensic disambiguation (v1.8.1)
//
// When a content mismatch is detected, the operator may want to know whether
// the modification exists on disk or only in the kernel page cache. This is
// directly relevant to page-cache-layer attacks (e.g. CVE-2026-31431 /
// copy.fail) where on-disk bytes are unchanged but the kernel's cached view
// of the file differs.
//
// The disambiguation is pure comparison: drop the cache, re-read, classify.
// No inference, no behavioral analysis. See docs/FORENSICS.md.
// =============================================================================

/// Result of comparing a file's hash before and after dropping its page cache.
///
/// Stable wire format: variant names are serialized as snake_case strings via
/// serde, and stored in the audit chain's `disambiguation` column. Renaming a
/// variant is a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum DisambiguationResult {
    /// Initial hash matched baseline. No mismatch to disambiguate.
    /// (Should not normally be returned; defensive.)
    NotApplicable,

    /// Cached read differed from baseline; post-drop read matched baseline.
    /// The on-disk file is intact. The modification exists only in the page
    /// cache. Signature consistent with a kernel-level page cache attack
    /// such as CVE-2026-31431 (copy.fail).
    PageCacheOnly,

    /// Cached read and post-drop read both differed from baseline with the
    /// same hash. The file has been modified on disk (or dirty cached pages
    /// will be written through).
    DiskModification,

    /// Cached read and post-drop read differed from each other AND from
    /// baseline. The file is being actively written during the scan.
    /// Re-scan recommended.
    ActiveModification,

    /// fadvise(DONTNEED) failed or had no effect (e.g., dirty pages were not
    /// dropped). Cannot disambiguate; treat as DiskModification for safety.
    Inconclusive { reason: String },
}

impl DisambiguationResult {
    /// Stable string label for display, audit storage, and JSON output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::PageCacheOnly => "page_cache_only",
            Self::DiskModification => "disk_modification",
            Self::ActiveModification => "active_modification",
            Self::Inconclusive { .. } => "inconclusive",
        }
    }

    /// Operator-grade one-line description.
    pub fn description(&self) -> String {
        match self {
            Self::NotApplicable => "no content mismatch to disambiguate".to_string(),
            Self::PageCacheOnly => {
                "on-disk hash matches baseline; modification exists only in the page cache. \
                 signature consistent with a kernel-level page cache attack \
                 (e.g. CVE-2026-31431)."
                    .to_string()
            }
            Self::DiskModification => {
                "post-drop hash matches observed; the on-disk file is modified \
                 (or dirty cached pages will be written through)."
                    .to_string()
            }
            Self::ActiveModification => "post-drop hash differs from both observed and baseline; \
                 the file is being actively written. re-scan recommended."
                .to_string(),
            Self::Inconclusive { reason } => {
                format!(
                    "could not disambiguate: {}; treat as disk modification.",
                    reason
                )
            }
        }
    }
}

/// Pure classification logic, factored out for testability. Given the hashes
/// observed before and after dropping the page cache, plus the baseline hash,
/// classify the modification.
///
/// `reread` is invoked exactly once and may fail; the failure is propagated.
pub fn disambiguate_with_reader<R>(
    observed_hash: &str,
    baseline_hash: &str,
    reread: R,
) -> Result<DisambiguationResult>
where
    R: FnOnce() -> Result<String>,
{
    if observed_hash == baseline_hash {
        // Defensive: caller should only invoke disambiguation on actual mismatches.
        return Ok(DisambiguationResult::NotApplicable);
    }
    let post_drop = reread()?;
    Ok(classify(observed_hash, baseline_hash, &post_drop))
}

fn classify(observed: &str, baseline: &str, post_drop: &str) -> DisambiguationResult {
    if post_drop == baseline {
        DisambiguationResult::PageCacheOnly
    } else if post_drop == observed {
        DisambiguationResult::DiskModification
    } else {
        // Differs from both: file changed between the two reads.
        DisambiguationResult::ActiveModification
    }
}

/// Re-hash a file after dropping its page cache, and classify the result
/// against the originally observed hash and the baseline.
///
/// This is a pure comparison operation. It performs:
///   1. `posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED)`
///   2. Verify that pages were actually evicted via `mincore(2)`. If they
///      were not (e.g., dirty pages), return `Inconclusive` rather than
///      misclassifying.
///   3. Re-read the file via the same code path used for initial hashing.
///   4. Classify based on the relationship between observed_hash,
///      baseline_hash, and the new hash.
///
/// The fd is NOT closed; the caller retains ownership. The file's seek
/// position may be reset to 0.
pub fn disambiguate_via_cache_drop(
    file: &File,
    file_size: u64,
    mmap_threshold: u64,
    observed_hash: &str,
    baseline_hash: &str,
) -> Result<DisambiguationResult> {
    if observed_hash == baseline_hash {
        return Ok(DisambiguationResult::NotApplicable);
    }

    let raw_fd = file.as_raw_fd();

    // Empty files: no pages to drop, nothing to compare.
    if file_size == 0 {
        let post = blake3_hash_fd(file, file_size, mmap_threshold)?;
        return Ok(classify(observed_hash, baseline_hash, &post));
    }

    let cached_before = count_cached_pages(raw_fd, file_size as usize).unwrap_or(0);
    posix_fadvise_dontneed(raw_fd, file_size as usize)?;
    let cached_after = count_cached_pages(raw_fd, file_size as usize).unwrap_or(0);

    // If the kernel did not actually evict pages, we cannot trust the
    // re-read: it may still be served from cache. Bail out with a clear
    // reason rather than misclassify.
    if cached_before > 0 && cached_after >= cached_before {
        return Ok(DisambiguationResult::Inconclusive {
            reason: "pages not evicted from cache".to_string(),
        });
    }

    let post = blake3_hash_fd(file, file_size, mmap_threshold)?;
    Ok(classify(observed_hash, baseline_hash, &post))
}

/// Wrapper for `posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED)`. Returns Ok
/// even if fadvise reports `EINVAL`/`ENOSYS` on this kernel (best-effort).
#[allow(unsafe_code)]
fn posix_fadvise_dontneed(fd: std::os::unix::io::RawFd, _len: usize) -> Result<()> {
    // SAFETY: fd is a valid open descriptor (caller owns the File). The
    // syscall takes scalar args only and writes nothing through pointers.
    // POSIX_FADV_DONTNEED with offset=0,len=0 means "the entire file".
    let rc = unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED) };
    if rc != 0 && rc != libc::EINVAL && rc != libc::ENOSYS {
        return Err(VigilError::Hash(format!(
            "posix_fadvise(DONTNEED) failed: errno {}",
            rc
        )));
    }
    Ok(())
}

/// Count the number of pages of `len` bytes starting at offset 0 that are
/// currently resident in the page cache, via `mincore(2)`.
///
/// Returns `None` if mincore is unavailable on this fd (e.g. special files
/// or `EINVAL`); the caller should treat that as "unknown" and proceed.
#[allow(unsafe_code)]
fn count_cached_pages(fd: std::os::unix::io::RawFd, len: usize) -> Option<usize> {
    if len == 0 {
        return Some(0);
    }
    // mincore needs a memory mapping. Map PROT_READ MAP_SHARED and query.
    // SAFETY: fd is a valid open descriptor with read access. mmap may fail
    // (returns MAP_FAILED) which we handle. The mapping is read-only and
    // shared so it observes the live page cache state.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return None;
    }

    let page_size = page_size();
    let n_pages = len.div_ceil(page_size);
    let mut vec = vec![0u8; n_pages];

    // SAFETY: ptr is from a successful mmap of len bytes. vec.as_mut_ptr is
    // valid for n_pages bytes. mincore writes one byte per page.
    let rc = unsafe { libc::mincore(ptr, len, vec.as_mut_ptr()) };

    // SAFETY: ptr/len from successful mmap above; no outstanding references.
    unsafe {
        libc::munmap(ptr, len);
    }

    if rc != 0 {
        return None;
    }
    // Bit 0 of each byte is the "in cache" indicator.
    Some(vec.iter().filter(|b| **b & 1 != 0).count())
}

#[allow(unsafe_code)]
fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) is async-signal-safe and never fails
    // for this query on Linux. A negative return would be impossible.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v <= 0 {
        4096
    } else {
        v as usize
    }
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

    // -------------------------------------------------------------------
    // Forensic disambiguation tests (v1.8.1)
    // -------------------------------------------------------------------

    #[test]
    fn disambiguate_classifies_page_cache_only() {
        // observed != baseline; post-drop matches baseline -> page cache only.
        let r = disambiguate_with_reader("aaaa", "bbbb", || Ok("bbbb".to_string())).unwrap();
        assert_eq!(r, DisambiguationResult::PageCacheOnly);
    }

    #[test]
    fn disambiguate_classifies_disk_modification() {
        // observed != baseline; post-drop matches observed -> disk modification.
        let r = disambiguate_with_reader("aaaa", "bbbb", || Ok("aaaa".to_string())).unwrap();
        assert_eq!(r, DisambiguationResult::DiskModification);
    }

    #[test]
    fn disambiguate_classifies_active_modification() {
        // observed != baseline; post-drop matches neither -> active modification.
        let r = disambiguate_with_reader("aaaa", "bbbb", || Ok("cccc".to_string())).unwrap();
        assert_eq!(r, DisambiguationResult::ActiveModification);
    }

    #[test]
    fn disambiguate_returns_not_applicable_when_observed_matches_baseline() {
        // Defensive: caller invokes disambiguation only on actual mismatches,
        // but if observed == baseline, return NotApplicable without re-reading.
        let called = std::cell::Cell::new(false);
        let r = disambiguate_with_reader("aaaa", "aaaa", || {
            called.set(true);
            Ok("aaaa".to_string())
        })
        .unwrap();
        assert_eq!(r, DisambiguationResult::NotApplicable);
        assert!(
            !called.get(),
            "reread must not be invoked when observed == baseline"
        );
    }

    #[test]
    fn disambiguate_propagates_reread_error() {
        let r = disambiguate_with_reader("aaaa", "bbbb", || {
            Err(VigilError::Hash("simulated read failure".into()))
        });
        assert!(r.is_err());
    }

    #[test]
    fn disambiguation_result_labels_are_stable() {
        assert_eq!(
            DisambiguationResult::NotApplicable.label(),
            "not_applicable"
        );
        assert_eq!(
            DisambiguationResult::PageCacheOnly.label(),
            "page_cache_only"
        );
        assert_eq!(
            DisambiguationResult::DiskModification.label(),
            "disk_modification"
        );
        assert_eq!(
            DisambiguationResult::ActiveModification.label(),
            "active_modification"
        );
        assert_eq!(
            DisambiguationResult::Inconclusive {
                reason: "x".to_string()
            }
            .label(),
            "inconclusive"
        );
    }

    #[test]
    fn disambiguation_result_serde_roundtrip() {
        let cases = [
            DisambiguationResult::NotApplicable,
            DisambiguationResult::PageCacheOnly,
            DisambiguationResult::DiskModification,
            DisambiguationResult::ActiveModification,
            DisambiguationResult::Inconclusive {
                reason: "pages not evicted from cache".to_string(),
            },
        ];
        for case in cases {
            let json = serde_json::to_string(&case).unwrap();
            let back: DisambiguationResult = serde_json::from_str(&json).unwrap();
            assert_eq!(case, back, "json: {}", json);
        }
    }

    #[test]
    fn disambiguate_via_cache_drop_real_file_disk_modification() {
        // End-to-end smoke test against a real fd: observed_hash and
        // baseline_hash differ; the file's actual content matches observed_hash.
        // Whether or not fadvise drops the cache here, the post-drop re-read
        // returns the same bytes as the observed hash, so the result must be
        // either DiskModification or Inconclusive (both are correct answers).
        let content = b"vigil disambiguation real-file test content";
        let tmp = make_temp_file(content);
        let actual_hash = blake3_hash_bytes(content);
        let fake_baseline = blake3_hash_bytes(b"different baseline");
        let r = disambiguate_via_cache_drop(
            tmp.as_file(),
            content.len() as u64,
            1_048_576,
            &actual_hash,
            &fake_baseline,
        )
        .unwrap();
        assert!(
            matches!(
                r,
                DisambiguationResult::DiskModification | DisambiguationResult::Inconclusive { .. }
            ),
            "expected DiskModification or Inconclusive; got {:?}",
            r
        );
    }

    #[test]
    fn disambiguate_via_cache_drop_empty_file() {
        let tmp = make_temp_file(b"");
        let empty_hash = blake3_hash_bytes(b"");
        let r = disambiguate_via_cache_drop(tmp.as_file(), 0, 1_048_576, &empty_hash, &empty_hash)
            .unwrap();
        assert_eq!(r, DisambiguationResult::NotApplicable);
    }
}
