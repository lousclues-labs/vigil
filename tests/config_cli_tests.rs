/// Create a minimal vigil.toml for testing.
fn write_test_config(path: &std::path::Path) {
    std::fs::write(
        path,
        r#"
[daemon]
pid_file = "/tmp/vigil-test.pid"
db_path = "/tmp/vigil-test.db"
log_level = "info"
monitor_backend = "fanotify"
control_socket = ""
detection_wal = true
detection_wal_persistent = false

[scanner]
schedule = "0 3 * * *"
mode = "incremental"

[alerts]
desktop_notifications = true

[exclusions]
patterns = []
system_exclusions = []

[security]
hmac_signing = false

[database]
wal_mode = true

[watch.system_critical]
severity = "critical"
paths = ["/usr/bin/", "/etc/passwd"]

[watch.network]
severity = "medium"
paths = ["/etc/hosts"]
"#,
    )
    .unwrap();
}

/// Parse a TOML file and return the document.
fn read_toml(path: &std::path::Path) -> toml_edit::DocumentMut {
    let content = std::fs::read_to_string(path).unwrap();
    content.parse::<toml_edit::DocumentMut>().unwrap()
}

/// Check that a path exists in a watch group's paths array.
fn group_has_path(doc: &toml_edit::DocumentMut, group: &str, path: &str) -> bool {
    doc.get("watch")
        .and_then(|w| w.get(group))
        .and_then(|g| g.get("paths"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().any(|v| v.as_str() == Some(path)))
        .unwrap_or(false)
}

// ──────────────────────────────────────────────────────────────
// vigil config watch add
// ──────────────────────────────────────────────────────────────

#[test]
fn watch_add_path_to_existing_group() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "watch",
            "add",
            "/etc/vigil",
            "--group",
            "system_critical",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "exit code: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = read_toml(&config_path);
    assert!(
        group_has_path(&doc, "system_critical", "/etc/vigil"),
        "path should be in group after add"
    );
    // Original paths should still be present
    assert!(group_has_path(&doc, "system_critical", "/usr/bin/"));
    assert!(group_has_path(&doc, "system_critical", "/etc/passwd"));
}

#[test]
fn watch_add_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "config",
                "watch",
                "add",
                "/etc/vigil",
                "--group",
                "system_critical",
            ])
            .output()
            .unwrap()
    };

    let first = run();
    assert!(first.status.success());

    let second = run();
    assert!(second.status.success());
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        stdout.contains("already in"),
        "second add should report idempotent: {}",
        stdout
    );

    // Path should appear exactly once
    let doc = read_toml(&config_path);
    let count = doc
        .get("watch")
        .and_then(|w| w.get("system_critical"))
        .and_then(|g| g.get("paths"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|v| v.as_str() == Some("/etc/vigil"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(count, 1, "path should appear exactly once");
}

#[test]
fn watch_add_creates_new_group() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "watch",
            "add",
            "/opt/myapp",
            "--group",
            "custom_apps",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = read_toml(&config_path);
    assert!(group_has_path(&doc, "custom_apps", "/opt/myapp"));

    // New group should have severity = "high"
    let severity = doc
        .get("watch")
        .and_then(|w| w.get("custom_apps"))
        .and_then(|g| g.get("severity"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    assert_eq!(
        severity, "high",
        "new groups should default to severity high"
    );
}

// ──────────────────────────────────────────────────────────────
// vigil config watch remove
// ──────────────────────────────────────────────────────────────

#[test]
fn watch_remove_existing_path() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "watch",
            "remove",
            "/etc/passwd",
            "--group",
            "system_critical",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = read_toml(&config_path);
    assert!(
        !group_has_path(&doc, "system_critical", "/etc/passwd"),
        "path should be removed"
    );
    // Other paths should remain
    assert!(group_has_path(&doc, "system_critical", "/usr/bin/"));
}

#[test]
fn watch_remove_nonexistent_path_errors() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "watch",
            "remove",
            "/nonexistent/path",
            "--group",
            "system_critical",
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "should fail when path not in group"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in watch group") || stderr.contains("is not in"),
        "error should mention path not in group: {}",
        stderr
    );
}

// ──────────────────────────────────────────────────────────────
// vigil config set / get
// ──────────────────────────────────────────────────────────────

#[test]
fn config_set_bool() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "set",
            "daemon.detection_wal_persistent",
            "true",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = read_toml(&config_path);
    let val = doc
        .get("daemon")
        .and_then(|d| d.get("detection_wal_persistent"))
        .and_then(|v| v.as_bool());
    assert_eq!(val, Some(true));
}

#[test]
fn config_set_int() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "set",
            "alerts.rate_limit",
            "50",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = read_toml(&config_path);
    let val = doc
        .get("alerts")
        .and_then(|a| a.get("rate_limit"))
        .and_then(|v| v.as_integer());
    assert_eq!(val, Some(50));
}

#[test]
fn config_set_string() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "set",
            "daemon.log_level",
            "\"debug\"",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = read_toml(&config_path);
    let val = doc
        .get("daemon")
        .and_then(|d| d.get("log_level"))
        .and_then(|v| v.as_str());
    assert_eq!(val, Some("debug"));
}

#[test]
fn config_set_unknown_key_errors() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "set",
            "nonexistent.foo",
            "true",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "should fail for unknown section");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown config section"),
        "error should mention unknown section: {}",
        stderr
    );
}

#[test]
fn config_set_dry_run_does_not_modify() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let before = std::fs::read_to_string(&config_path).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "set",
            "daemon.detection_wal_persistent",
            "true",
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let after = std::fs::read_to_string(&config_path).unwrap();
    assert_eq!(before, after, "dry-run should not modify the file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dry run"), "should indicate dry run");
}

#[test]
fn config_get_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "get",
            "daemon.detection_wal_persistent",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim() == "false",
        "should print 'false', got: {}",
        stdout.trim()
    );
}

#[test]
fn config_set_unsafe_key_errors() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "set",
            "security.hmac_key_path",
            "\"/tmp/evil.key\"",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "should refuse unsafe key");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be changed via"),
        "should explain why key is refused: {}",
        stderr
    );
}

// ──────────────────────────────────────────────────────────────
// Atomic write safety
// ──────────────────────────────────────────────────────────────

#[test]
fn config_write_is_atomic_no_orphan_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("vigil.toml");
    write_test_config(&config_path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "config",
            "watch",
            "add",
            "/etc/vigil",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    // No orphaned .new file should remain
    let new_file = config_path.with_extension("toml.new");
    assert!(
        !new_file.exists(),
        "orphaned .toml.new should not exist after successful write"
    );
}
