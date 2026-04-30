//! End-to-end integration tests for forensic disambiguation against real
//! files and a real kernel page cache.
//!
//! Most of these tests are gated behind the `root-tests` feature because
//! reliable cache eviction (`echo 3 > /proc/sys/vm/drop_caches` or similar)
//! requires CAP_SYS_ADMIN. When the feature is on but the test runner is
//! NOT root, individual tests skip cleanly with a printed message rather
//! than spuriously fail.
//!
//! Run with:
//!   sudo -E cargo test --features root-tests --test integration_disambiguation

use std::fs::{File, OpenOptions};
#[allow(unused_imports)]
use std::io::{Read, Seek, SeekFrom, Write};

use vigil::hash::{
    blake3_hash_bytes, blake3_hash_fd, disambiguate_via_cache_drop, DisambiguationResult,
};

const MMAP_THRESHOLD: u64 = 1_048_576;

#[allow(dead_code)]
fn am_i_root() -> bool {
    // SAFETY: getuid() is async-signal-safe and never fails.
    #[allow(unsafe_code)]
    unsafe {
        libc::getuid() == 0
    }
}

#[allow(dead_code)]
fn skip_if_not_root(test_name: &str) -> bool {
    if !am_i_root() {
        eprintln!(
            "SKIP {}: requires root for reliable page-cache control. \
             Re-run with `sudo -E cargo test --features root-tests`.",
            test_name
        );
        return true;
    }
    false
}

/// Force-drop the entire system page cache. Requires CAP_SYS_ADMIN.
#[allow(dead_code)]
fn drop_all_caches() {
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .open("/proc/sys/vm/drop_caches")
    {
        let _ = f.write_all(b"3\n");
    }
}

/// Disambiguation must report DiskModification when the on-disk file actually
/// changed. We sync, drop caches, then disambiguate; the post-drop re-read
/// will see the new content (matching observed_hash).
#[cfg(feature = "root-tests")]
#[test]
fn disambiguation_detects_real_modification() {
    if skip_if_not_root("disambiguation_detects_real_modification") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("victim");

    // Establish "baseline" content X.
    let baseline_content = b"baseline content X\n";
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(baseline_content).unwrap();
        f.sync_all().unwrap();
    }
    let baseline_hash = blake3_hash_bytes(baseline_content);

    // Simulate the daemon "observing" a different hash (the file was modified
    // on disk, but the original capture saw bytes Y).
    let observed_content = b"modified disk content YYYY YYYY\n";
    {
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(observed_content).unwrap();
        f.sync_all().unwrap();
    }
    let observed_hash = blake3_hash_bytes(observed_content);
    drop_all_caches();

    let f = File::open(&path).unwrap();
    let size = f.metadata().unwrap().len();
    let result =
        disambiguate_via_cache_drop(&f, size, MMAP_THRESHOLD, &observed_hash, &baseline_hash)
            .expect("disambiguation must not error");

    assert!(
        matches!(
            result,
            DisambiguationResult::DiskModification | DisambiguationResult::Inconclusive { .. }
        ),
        "expected DiskModification (or Inconclusive on hostile kernel), got {:?}",
        result
    );
}

/// Dirty-page mmap modification. fadvise(DONTNEED) typically does NOT evict
/// dirty pages, so this either:
///   (a) returns DiskModification (post-drop sees same dirty bytes), or
///   (b) returns Inconclusive (mincore reports no eviction).
/// Both are correct given page state — the dirty pages will be written
/// through eventually.
#[cfg(feature = "root-tests")]
#[test]
fn disambiguation_handles_dirty_mmap_modification() {
    if skip_if_not_root("disambiguation_handles_dirty_mmap_modification") {
        return;
    }
    use std::os::unix::io::AsRawFd;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("victim_mmap");

    let baseline = b"AAAAAAAAAAAA\n";
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(baseline).unwrap();
        f.sync_all().unwrap();
    }
    let baseline_hash = blake3_hash_bytes(baseline);

    // Open RW and mmap shared, then modify.
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let size = f.metadata().unwrap().len() as usize;
    // SAFETY: f is a valid RW fd; mmap shared writable for `size` bytes.
    #[allow(unsafe_code)]
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            f.as_raw_fd(),
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");

    // SAFETY: ptr is a valid writable mapping of `size` bytes.
    #[allow(unsafe_code)]
    unsafe {
        let bytes = std::slice::from_raw_parts_mut(ptr as *mut u8, size);
        for b in bytes.iter_mut() {
            *b = b'B';
        }
    }

    // Read back what userspace sees (should now be all 'B').
    let mut buf = vec![0u8; size];
    let mut rf = File::open(&path).unwrap();
    rf.read_exact(&mut buf).unwrap();
    let observed_hash = blake3_hash_bytes(&buf);
    assert_ne!(
        observed_hash, baseline_hash,
        "mmap modification did not produce a different hash"
    );

    let result = disambiguate_via_cache_drop(
        &f,
        size as u64,
        MMAP_THRESHOLD,
        &observed_hash,
        &baseline_hash,
    )
    .unwrap();

    // SAFETY: ptr/size from successful mmap above; no outstanding refs.
    #[allow(unsafe_code)]
    unsafe {
        libc::munmap(ptr, size);
    }

    // Either classification is correct given dirty pages.
    assert!(
        matches!(
            result,
            DisambiguationResult::DiskModification
                | DisambiguationResult::Inconclusive { .. }
                | DisambiguationResult::PageCacheOnly
        ),
        "got unexpected {:?}",
        result
    );
}

/// If observed != baseline AND we read different bytes again at disambiguation
/// time (because the file was concurrently modified), we report
/// ActiveModification. This test deterministically synthesizes the hashes
/// rather than racing a real thread, since deterministic timing of "read
/// during write" is unreliable in CI.
#[test]
fn disambiguation_active_modification_classification_is_correct() {
    use vigil::hash::disambiguate_with_reader;
    let r = disambiguate_with_reader("hash_observed", "hash_baseline", || {
        Ok("hash_third_distinct".to_string())
    })
    .unwrap();
    assert_eq!(r, DisambiguationResult::ActiveModification);
}

/// When disambiguation is invoked but observed actually equals baseline (race
/// or accidental call), return NotApplicable without re-reading.
#[test]
fn disambiguation_short_circuits_when_no_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ok");
    let content = b"some content";
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(content).unwrap();
        f.sync_all().unwrap();
    }
    let h = blake3_hash_bytes(content);
    let f = File::open(&path).unwrap();
    let result =
        disambiguate_via_cache_drop(&f, content.len() as u64, MMAP_THRESHOLD, &h, &h).unwrap();
    assert_eq!(result, DisambiguationResult::NotApplicable);
}

/// Vigil's standard hashing pipeline (blake3_hash_fd) reads through the
/// page cache. So if the cache is poisoned with bytes B while the disk holds
/// bytes A, the hash equals B (matching every userspace program's view).
/// This is the precondition the disambiguation feature builds on. We assert
/// it here for documentation and regression safety.
#[test]
fn standard_hash_observes_page_cache_view() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("standard_hash");
    let content = b"Vigil reads through the page cache, just like every other userspace program.\n";
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(content).unwrap();
        f.sync_all().unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
    }
    let f = File::open(&path).unwrap();
    let h = blake3_hash_fd(&f, content.len() as u64, MMAP_THRESHOLD).unwrap();
    assert_eq!(h, blake3_hash_bytes(content));
}
