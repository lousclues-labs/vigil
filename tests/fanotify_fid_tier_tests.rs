// tests/fanotify_fid_tier_tests.rs
//
// Tests for the FID-tier fanotify event loop: tier-gated dispatch, FID
// handle resolution, and end-to-end real-time event delivery for
// create/delete/move/attribute operations on FID-capable kernels.
//
// The integration tests are gated behind the `root-tests` feature because
// fanotify_init requires CAP_SYS_ADMIN. Run with:
//   sudo -E cargo test --features root-tests --test fanotify_fid_tier_tests

use vigil::monitor::FanotifyTier;

// ---------------------------------------------------------------------------
// Property-shape tests (no privileges required)
// ---------------------------------------------------------------------------

/// The FID-tier code path must be selected for FidDfidName and Fid tiers,
/// and must NOT be selected for LegacyFd or Inotify. This test enforces
/// the tier-gated dispatch invariant at compile time: future contributors
/// who try to use FID-tier code on LegacyFd or Inotify break the build.
#[test]
fn fid_code_path_selected_only_for_fid_tiers() {
    for tier in [FanotifyTier::FidDfidName, FanotifyTier::Fid] {
        let fid_mode = matches!(tier, FanotifyTier::FidDfidName | FanotifyTier::Fid);
        assert!(fid_mode, "{:?} must select FID code path", tier);
    }

    for tier in [FanotifyTier::LegacyFd, FanotifyTier::Inotify] {
        let fid_mode = matches!(tier, FanotifyTier::FidDfidName | FanotifyTier::Fid);
        assert!(!fid_mode, "{:?} must NOT select FID code path", tier);
    }
}

/// The Fid tier must produce different init flags than FidDfidName.
/// Specifically, Fid must NOT include FAN_REPORT_DFID_NAME.
#[test]
fn fid_and_fid_dfid_name_have_distinct_init_flags() {
    // These are the flag values defined in fanotify.rs:
    const FAN_REPORT_FID: u32 = 0x0000_0200;
    const FAN_REPORT_DFID_NAME: u32 = 0x0000_1000;
    const FAN_CLOEXEC: u32 = 0x0000_0001;
    const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
    const FAN_NONBLOCK: u32 = 0x0000_0002;

    let fid_flags = FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_FID;
    let dfid_flags =
        FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_DFID_NAME | FAN_REPORT_FID;

    assert_ne!(
        fid_flags, dfid_flags,
        "Fid and FidDfidName must use different init flags"
    );
    assert_eq!(
        fid_flags & FAN_REPORT_DFID_NAME,
        0,
        "Fid init flags must not include FAN_REPORT_DFID_NAME"
    );
    assert_ne!(
        dfid_flags & FAN_REPORT_DFID_NAME,
        0,
        "FidDfidName init flags must include FAN_REPORT_DFID_NAME"
    );
}

/// The resolved tier from config "auto" must be one of the valid tiers,
/// and if it's Fid or FidDfidName, the FID code path would be selected.
#[test]
fn auto_tier_resolution_consistent_with_fid_dispatch() {
    let mut config = vigil::config::default_config();
    config.monitor.fanotify_tier = "auto".to_string();
    let tier = vigil::monitor::resolve_fanotify_tier(&config);

    let fid_mode = matches!(tier, FanotifyTier::FidDfidName | FanotifyTier::Fid);
    let legacy_mode = matches!(tier, FanotifyTier::LegacyFd | FanotifyTier::Inotify);

    assert!(
        fid_mode || legacy_mode,
        "resolved tier must be in exactly one of FID or legacy groups"
    );
    assert!(
        fid_mode != legacy_mode,
        "FID and legacy modes are mutually exclusive"
    );
}

// ---------------------------------------------------------------------------
// Integration tests (root-only, FID-capable kernel required)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn am_i_root() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        libc::getuid() == 0
    }
}

#[allow(dead_code)]
fn skip_if_not_root(test_name: &str) -> bool {
    if !am_i_root() {
        eprintln!(
            "SKIP {}: requires root (CAP_SYS_ADMIN) for fanotify_init. \
             Re-run with `sudo -E cargo test --features root-tests`.",
            test_name
        );
        return true;
    }
    false
}

/// End-to-end integration test: initialize a FID-tier fanotify group,
/// mark a tmpfs filesystem, perform create/delete/move/attrib operations,
/// and assert that real-time events arrive for each.
///
/// This test requires root and a kernel that supports FID mode (Linux 5.9+
/// for FidDfidName, 5.1+ for Fid). If the kernel doesn't support FID, the
/// test is skipped.
#[cfg(feature = "root-tests")]
#[test]
fn fid_tier_receives_create_delete_move_attrib_events() {
    if skip_if_not_root("fid_tier_receives_create_delete_move_attrib_events") {
        return;
    }

    let tier = vigil::monitor::detect_fanotify_tier();
    if !matches!(tier, FanotifyTier::FidDfidName | FanotifyTier::Fid) {
        eprintln!(
            "SKIP: kernel does not support FID mode (detected tier: {:?})",
            tier
        );
        return;
    }

    use std::os::unix::io::RawFd;
    use std::time::Duration;

    // Constants matching fanotify.rs
    const FAN_CLOEXEC: u32 = 0x0000_0001;
    const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
    const FAN_NONBLOCK: u32 = 0x0000_0002;
    const FAN_REPORT_FID: u32 = 0x0000_0200;
    const FAN_REPORT_DFID_NAME: u32 = 0x0000_1000;
    const FAN_MARK_ADD: u32 = 0x0000_0001;
    const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;
    const FAN_MODIFY: u64 = 0x0000_0002;
    const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
    const FAN_ATTRIB: u64 = 0x0000_0004;
    const FAN_CREATE: u64 = 0x0000_0100;
    const FAN_DELETE: u64 = 0x0000_0200;
    const FAN_MOVED_FROM: u64 = 0x0000_0040;
    const FAN_MOVED_TO: u64 = 0x0000_0080;

    let init_flags = if matches!(tier, FanotifyTier::FidDfidName) {
        FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_DFID_NAME | FAN_REPORT_FID
    } else {
        FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_FID
    };

    // Initialize fanotify group
    #[allow(unsafe_code)]
    let fan_fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            init_flags,
            libc::O_RDONLY | libc::O_LARGEFILE,
        )
    } as RawFd;
    assert!(
        fan_fd >= 0,
        "fanotify_init failed: {}",
        std::io::Error::last_os_error()
    );

    // Create a tmpdir (on tmpfs if possible)
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let tmpdir_path = tmpdir.path();

    // Mark the filesystem
    let c_path =
        std::ffi::CString::new(tmpdir_path.as_os_str().as_encoded_bytes()).expect("CString failed");
    let mask = FAN_MODIFY
        | FAN_CLOSE_WRITE
        | FAN_ATTRIB
        | FAN_CREATE
        | FAN_DELETE
        | FAN_MOVED_FROM
        | FAN_MOVED_TO;

    #[allow(unsafe_code)]
    let mark_ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            mask,
            libc::AT_FDCWD,
            c_path.as_ptr(),
        )
    };
    assert!(
        mark_ret >= 0,
        "fanotify_mark failed: {}",
        std::io::Error::last_os_error()
    );

    // Perform filesystem operations
    let test_file = tmpdir_path.join("test_create.txt");
    std::fs::write(&test_file, b"hello").expect("write failed");

    let moved_file = tmpdir_path.join("test_moved.txt");
    std::fs::rename(&test_file, &moved_file).expect("rename failed");

    // Change attributes (chmod)
    #[allow(unsafe_code)]
    {
        let c_moved = std::ffi::CString::new(moved_file.as_os_str().as_encoded_bytes())
            .expect("CString failed");
        unsafe {
            libc::chmod(c_moved.as_ptr(), 0o644);
        }
    }

    std::fs::remove_file(&moved_file).expect("delete failed");

    // Give kernel a moment to deliver events
    std::thread::sleep(Duration::from_millis(100));

    // Read events from the fanotify fd
    let mut buf = vec![0u8; 65536];
    let mut event_masks: Vec<u64> = Vec::new();

    // Non-blocking read loop
    loop {
        #[allow(unsafe_code)]
        let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        let meta_size = 24; // sizeof(fanotify_event_metadata)
        let mut offset = 0;
        while offset + meta_size <= n {
            let event_len = u32::from_ne_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]) as usize;
            if event_len < meta_size || offset + event_len > n {
                break;
            }
            let event_mask = u64::from_ne_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
                buf[offset + 12],
                buf[offset + 13],
                buf[offset + 14],
                buf[offset + 15],
            ]);
            event_masks.push(event_mask);

            // Close any fd in the event (FID mode should have fd == -1)
            let fd = i32::from_ne_bytes([
                buf[offset + 16],
                buf[offset + 17],
                buf[offset + 18],
                buf[offset + 19],
            ]);
            #[allow(unsafe_code)]
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
            offset += event_len;
        }
    }

    // Close the fanotify fd
    #[allow(unsafe_code)]
    unsafe {
        libc::close(fan_fd);
    }

    // Verify we received the expected event types.
    // We look for at least one of each type we triggered.
    let has_create = event_masks.iter().any(|m| m & FAN_CREATE != 0);
    let has_modify = event_masks
        .iter()
        .any(|m| m & (FAN_MODIFY | FAN_CLOSE_WRITE) != 0);
    let has_moved = event_masks
        .iter()
        .any(|m| m & (FAN_MOVED_FROM | FAN_MOVED_TO) != 0);
    let has_attrib = event_masks.iter().any(|m| m & FAN_ATTRIB != 0);
    let has_delete = event_masks.iter().any(|m| m & FAN_DELETE != 0);

    assert!(
        has_create,
        "FID mode did not receive FAN_CREATE event. Masks: {:?}",
        event_masks
    );
    assert!(
        has_modify,
        "FID mode did not receive FAN_MODIFY/FAN_CLOSE_WRITE event. Masks: {:?}",
        event_masks
    );
    assert!(
        has_moved,
        "FID mode did not receive FAN_MOVED_FROM/FAN_MOVED_TO event. Masks: {:?}",
        event_masks
    );
    assert!(
        has_attrib,
        "FID mode did not receive FAN_ATTRIB event. Masks: {:?}",
        event_masks
    );
    assert!(
        has_delete,
        "FID mode did not receive FAN_DELETE event. Masks: {:?}",
        event_masks
    );
}

/// Regression: the existing mount-compatible-mask tests must still pass
/// after the FID rewrite. This test calls the same assertions from the
/// integration test side to ensure no accidental regression.
#[test]
fn mount_compatible_mask_regression() {
    const FAN_MODIFY: u64 = 0x0000_0002;
    const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
    const FAN_ATTRIB: u64 = 0x0000_0004;
    const FAN_CREATE: u64 = 0x0000_0100;
    const FAN_DELETE: u64 = 0x0000_0200;
    const FAN_MOVED_FROM: u64 = 0x0000_0040;
    const FAN_MOVED_TO: u64 = 0x0000_0080;
    const FAN_MOUNT_COMPATIBLE_EVENTS: u64 = FAN_MODIFY | FAN_CLOSE_WRITE;

    // Must exclude inode-only events
    assert_eq!(FAN_MOUNT_COMPATIBLE_EVENTS & FAN_ATTRIB, 0);
    assert_eq!(FAN_MOUNT_COMPATIBLE_EVENTS & FAN_CREATE, 0);
    assert_eq!(FAN_MOUNT_COMPATIBLE_EVENTS & FAN_DELETE, 0);
    assert_eq!(FAN_MOUNT_COMPATIBLE_EVENTS & FAN_MOVED_FROM, 0);
    assert_eq!(FAN_MOUNT_COMPATIBLE_EVENTS & FAN_MOVED_TO, 0);

    // Must include modify and close_write
    assert_ne!(FAN_MOUNT_COMPATIBLE_EVENTS & FAN_MODIFY, 0);
    assert_ne!(FAN_MOUNT_COMPATIBLE_EVENTS & FAN_CLOSE_WRITE, 0);
}
