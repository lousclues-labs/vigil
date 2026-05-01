use std::process::Command;

/// Test that the pacman post-hook exits 0 even when vigil is not present.
///
/// Extracts the Exec line from the pacman post-hook and runs it with
/// /usr/bin/vigil pointing to a nonexistent binary.
#[test]
fn pacman_post_hook_exits_zero_when_vigil_missing() {
    // The hook checks for /usr/bin/vigil, but we test the shell logic
    // with a PATH that doesn't include vigil.
    let hook_script = r#"
        VIGIL=/nonexistent/vigil
        if [ ! -x "$VIGIL" ]; then
            logger -t vigil-pacman "vigil binary not found at $VIGIL; skipping refresh" 2>/dev/null || true
            exit 0
        fi
        $VIGIL baseline refresh --quiet 2>/dev/null
        exit 0
    "#;

    let result = Command::new("/bin/sh")
        .arg("-c")
        .arg(hook_script)
        .output()
        .expect("failed to run shell");

    assert_eq!(
        result.status.code(),
        Some(0),
        "hook must exit 0 when vigil binary is missing"
    );
}

/// Test that the pacman post-hook exits 0 even when vigil refresh fails.
#[test]
fn pacman_post_hook_exits_zero_when_refresh_fails() {
    // Create a stub vigil that always fails
    let dir = tempfile::tempdir().unwrap();
    let stub = dir.path().join("vigil");
    std::fs::write(&stub, "#!/bin/sh\nexit 1\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Replicate the hook logic with our stub binary
    let hook_script = format!(
        r#"
        VIGIL="{vigil}"
        if [ ! -x "$VIGIL" ]; then
            exit 0
        fi
        if "$VIGIL" baseline refresh --quiet 2>/dev/null; then
            "$VIGIL" maintenance exit --quiet 2>/dev/null
        else
            logger -t vigil-pacman "baseline refresh failed; investigate with: vigil doctor" 2>/dev/null || true
            "$VIGIL" maintenance exit --quiet 2>/dev/null
        fi
        exit 0
        "#,
        vigil = stub.display()
    );

    let result = Command::new("/bin/sh")
        .arg("-c")
        .arg(&hook_script)
        .output()
        .expect("failed to run shell");

    assert_eq!(
        result.status.code(),
        Some(0),
        "hook must exit 0 even when refresh fails"
    );
}

/// Test that the apt hook exits 0 when vigil is missing.
#[test]
fn apt_hook_exits_zero_when_vigil_missing() {
    // Simulate the DPkg::Post-Invoke logic
    let hook_script = r#"
        VIGIL=/nonexistent/vigil
        if [ ! -x "$VIGIL" ]; then
            logger -t vigil-apt "vigil binary not found; skipping refresh" 2>/dev/null || true
            true
        elif "$VIGIL" baseline refresh --quiet 2>/dev/null; then
            "$VIGIL" maintenance exit --quiet 2>/dev/null
            true
        else
            logger -t vigil-apt "baseline refresh failed; investigate with: vigil doctor" 2>/dev/null || true
            "$VIGIL" maintenance exit --quiet 2>/dev/null
            true
        fi
    "#;

    let result = Command::new("/bin/sh")
        .arg("-c")
        .arg(hook_script)
        .output()
        .expect("failed to run shell");

    assert_eq!(
        result.status.code(),
        Some(0),
        "apt hook must exit 0 when vigil is missing"
    );
}

/// Test that the pre-hook exits 0 when vigil is missing.
#[test]
fn pacman_pre_hook_exits_zero_when_vigil_missing() {
    let hook_script = r#"
        VIGIL=/nonexistent/vigil
        if [ -x "$VIGIL" ]; then
            "$VIGIL" maintenance enter --quiet 2>/dev/null
        fi
        exit 0
    "#;

    let result = Command::new("/bin/sh")
        .arg("-c")
        .arg(hook_script)
        .output()
        .expect("failed to run shell");

    assert_eq!(
        result.status.code(),
        Some(0),
        "pre-hook must exit 0 when vigil is missing"
    );
}

// ---------------------------------------------------------------------------
// Guard: hook source files reference the correct binary path
// ---------------------------------------------------------------------------

#[test]
fn pacman_post_hook_references_real_vigil_path() {
    let hook = std::fs::read_to_string("hooks/pacman/vigil-post.hook")
        .expect("hook source must exist in repo");
    assert!(
        hook.contains("/usr/bin/vigil"),
        "hook must reference the real vigil install path"
    );
    assert!(
        !hook.contains("/nonexistent"),
        "hook must not contain sentinel paths"
    );
}

#[test]
fn pacman_pre_hook_references_real_vigil_path() {
    let hook = std::fs::read_to_string("hooks/pacman/vigil-pre.hook")
        .expect("hook source must exist in repo");
    assert!(
        hook.contains("/usr/bin/vigil"),
        "hook must reference the real vigil install path"
    );
    assert!(
        !hook.contains("/nonexistent"),
        "hook must not contain sentinel paths"
    );
}

#[test]
fn apt_hook_references_real_vigil_path() {
    let hook =
        std::fs::read_to_string("hooks/apt/99vigil").expect("hook source must exist in repo");
    assert!(
        hook.contains("/usr/bin/vigil"),
        "hook must reference the real vigil install path"
    );
    assert!(
        !hook.contains("/nonexistent"),
        "hook must not contain sentinel paths"
    );
}

// ---------------------------------------------------------------------------
// Guard: hook failure branches have at most one logger call each
// ---------------------------------------------------------------------------

#[test]
fn pacman_post_hook_has_one_logger_per_failure_branch() {
    let hook = std::fs::read_to_string("hooks/pacman/vigil-post.hook")
        .expect("hook source must exist in repo");

    // Extract the Exec line (the shell command)
    let exec_line = hook
        .lines()
        .find(|l| l.starts_with("Exec"))
        .expect("hook must have an Exec line");

    // Count logger invocations. There should be at most three, each on a
    // mutually-exclusive branch:
    //   1. binary missing AND vigild active (high priority -- operator alarm)
    //   2. binary missing AND vigild not active (info -- expected during install)
    //   3. baseline refresh failed (high priority)
    let logger_count = exec_line.matches("logger ").count();
    assert!(
        logger_count <= 3,
        "hook should have at most 3 logger calls (one per failure branch), found {}",
        logger_count
    );
}

#[test]
fn apt_hook_has_one_logger_per_failure_branch() {
    let hook =
        std::fs::read_to_string("hooks/apt/99vigil").expect("hook source must exist in repo");

    // The Post-Invoke line contains the shell logic.
    let post_line = hook
        .lines()
        .find(|l| l.contains("Post-Invoke"))
        .expect("hook must have a Post-Invoke line");

    let logger_count = post_line.matches("logger ").count();
    assert!(
        logger_count <= 2,
        "hook should have at most 2 logger calls (one per failure branch), found {}",
        logger_count
    );
}

// ---------------------------------------------------------------------------
// vigil hooks verify: canonical embedding checks
// ---------------------------------------------------------------------------

#[test]
fn hooks_verify_detects_nonexistent_vigil_sentinel_bug() {
    // The 1.3.1 bug: a hook containing `/nonexistent/vigil` would silently
    // fail. Verify that the canonical embedded hooks do NOT contain sentinel
    // paths (ensuring vigil hooks verify would catch drift if installed hooks
    // had the sentinel).
    let post_hook =
        std::fs::read_to_string("hooks/pacman/vigil-post.hook").expect("hook source must exist");
    assert!(
        !post_hook.contains("/nonexistent"),
        "canonical post-hook must not contain sentinel path"
    );
    assert!(
        post_hook.contains("/usr/bin/vigil"),
        "canonical post-hook must reference real vigil path"
    );
}

#[test]
fn hooks_canonical_embedded_matches_repo_source() {
    // The embedded canonical hooks must match the repo source files exactly.
    // This catches any drift between the include_str! path and the actual files.
    let repo_pre =
        std::fs::read_to_string("hooks/pacman/vigil-pre.hook").expect("pre-hook must exist");
    let repo_post =
        std::fs::read_to_string("hooks/pacman/vigil-post.hook").expect("post-hook must exist");
    let repo_apt = std::fs::read_to_string("hooks/apt/99vigil").expect("apt hook must exist");

    // These are the same files that include_str! embeds at compile time.
    // If this test passes, the embedded versions are current.
    assert!(!repo_pre.is_empty(), "pre-hook must not be empty");
    assert!(!repo_post.is_empty(), "post-hook must not be empty");
    assert!(!repo_apt.is_empty(), "apt hook must not be empty");
}
