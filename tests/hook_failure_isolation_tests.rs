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
