//! Promise Driven Development (PDD) canaries.
//!
//! These are the test-suite canaries of the PDD spine
//! (Principles -> Promises -> Canaries -> Ledger). Each test is written as an
//! assertion about a *promise* in `PROMISES.md`, not about a feature, and it
//! fails loudly when the promise stops being true.
//!
//! Traceability: every test names the promise (PRn) it guards and the canary
//! id (C-...) recorded in `PROMISES.md` and `AUDIT_FINDINGS.md`.
//!
//! A canary must live where the promise lives. Source-scanning canaries read
//! the tree from `CARGO_MANIFEST_DIR`; behavioral canaries drive the real
//! exported types (`vigil::types`, `vigil::alert`, `vigil::db`,
//! `vigil::bloom`, `vigil::config`, `vigil::metrics`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vigil::types::{
    BaselineEntry, BaselineSource, Change, ContentFingerprint, FileIdentity, FileSnapshot,
    FileType, PermissionState, SecurityState, Severity, SnapshotOrDeleted,
};

// ===========================================================================
// Shared helpers
// ===========================================================================

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_surface(rel: &str) -> String {
    let path = manifest().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Recursively collect every `.rs` file under `root`.
fn rs_files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The `.rs` files that make up the detection surface: the modules that
/// observe the filesystem and turn observations into verdicts.
fn detection_surface() -> Vec<PathBuf> {
    let root = manifest();
    let mut files = rs_files_under(&root.join("src/monitor"));
    for rel in [
        "src/worker.rs",
        "src/scanner.rs",
        "src/detection.rs",
        "src/baseline_diff.rs",
        "src/types/snapshot.rs",
        "src/types/change.rs",
    ] {
        files.push(root.join(rel));
    }
    files.sort();
    files
}

/// Drop whole-line comments so tokens that appear only in explanatory prose
/// are not mistaken for behavior. Code lines are left intact, so a constant or
/// a string literal is never mangled.
fn code_only(src: &str) -> String {
    src.lines()
        .filter(|line| {
            let t = line.trim_start();
            !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Drop `#[cfg(test)]` items wherever they appear. Test code may write,
/// delete, and re-permission files to build fixtures; the promises are about
/// what the shipped code does, not about what the fixtures do.
///
/// This strips each test item individually rather than truncating the file at
/// the first `#[cfg(test)]`. Truncating left everything after a test module
/// unscanned, which is how a breach could hide behind the fixtures (AF-004).
fn strip_test_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        if !trimmed.starts_with("#[cfg(test)]") {
            out.push(line);
            i += 1;
            continue;
        }

        let indent = &line[..line.len() - trimmed.len()];
        let closer = format!("{indent}}}");
        i += 1;

        // Skip the item the attribute applies to: either a block, closed by a
        // brace at the attribute's own indentation, or a single-line item.
        while i < lines.len() {
            let item = lines[i].trim_end();
            i += 1;
            if item.ends_with('{') {
                while i < lines.len() && lines[i].trim_end() != closer {
                    i += 1;
                }
                i += 1;
                break;
            }
            if item.ends_with(';') {
                break;
            }
        }
    }

    out.join("\n")
}

/// Shipped code only: no comments, no test fixtures.
fn shipped_code(path: &Path) -> String {
    let src = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    code_only(&strip_test_code(&src))
}

fn rel(path: &Path) -> String {
    path.strip_prefix(manifest())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// The `[dependencies]` and `[dev-dependencies]` blocks of the manifest, with
/// comment lines stripped.
fn manifest_dependency_lines() -> Vec<String> {
    let cargo = read_surface("Cargo.toml");
    let mut lines = Vec::new();
    let mut inside = false;
    for line in cargo.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed.contains("dependencies");
            continue;
        }
        if inside && !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed.to_string());
        }
    }
    lines
}

// ===========================================================================
// P1 / PR1: the fanotify backend is notification class only.
// ===========================================================================

/// PR1, canary C-NOTIF-CLASS-ONLY.
///
/// Vigil must not hold the kernel interface that would let it block a syscall.
/// Every `fanotify_init` must use `FAN_CLASS_NOTIF`, and no permission-class
/// constant, permission event, or response path may exist anywhere in `src/`.
#[test]
fn watch_never_act_fanotify_is_notification_class_only() {
    const FORBIDDEN: &[&str] = &[
        "FAN_CLASS_CONTENT",
        "FAN_CLASS_PRE_CONTENT",
        "FAN_OPEN_PERM",
        "FAN_ACCESS_PERM",
        "FAN_OPEN_EXEC_PERM",
        "FAN_ALLOW",
        "FAN_DENY",
        "fanotify_response",
    ];

    let mut breaches = Vec::new();
    for file in rs_files_under(&manifest().join("src")) {
        let code = shipped_code(&file);
        for token in FORBIDDEN {
            if code.contains(token) {
                breaches.push(format!("{}: {token}", rel(&file)));
            }
        }
    }
    assert!(
        breaches.is_empty(),
        "C-NOTIF-CLASS-ONLY breach (PR1): permission-class fanotify usage found. \
         Vigil watches; it does not arbitrate. Breaches: {breaches:#?}"
    );

    // Every fanotify_init flag expression must carry FAN_CLASS_NOTIF.
    let monitor = shipped_code(&manifest().join("src/monitor/fanotify.rs"));
    let init_flag_lines: Vec<&str> = monitor
        .lines()
        .filter(|l| l.contains("FAN_CLOEXEC |"))
        .collect();
    assert!(
        !init_flag_lines.is_empty(),
        "C-NOTIF-CLASS-ONLY breach (PR1): no fanotify_init flag expression found; \
         the canary can no longer see what class fanotify is opened in."
    );
    for line in init_flag_lines {
        assert!(
            line.contains("FAN_CLASS_NOTIF"),
            "C-NOTIF-CLASS-ONLY breach (PR1): fanotify opened without FAN_CLASS_NOTIF: {line}"
        );
    }
}

// ===========================================================================
// P1 / PR2: no detection path acts.
// ===========================================================================

/// PR2, canary C-NO-ACTUATION.
///
/// The modules that observe and compare must contain nothing that deletes,
/// truncates, renames, re-permissions, re-owns, or executes. A witness that
/// can act will eventually act wrong.
#[test]
fn watch_never_act_detection_paths_contain_no_actuation() {
    const FORBIDDEN: &[&str] = &[
        "remove_file",
        "remove_dir",
        "set_permissions",
        "fs::write",
        "File::create",
        "OpenOptions",
        "fs::rename",
        "set_len",
        "fchown",
        "libc::chmod",
        "libc::chown",
        "libc::unlink",
        "libc::rename",
        "libc::truncate",
        "Command::new",
        "quarantine",
    ];

    let mut breaches = Vec::new();
    for file in detection_surface() {
        let code = shipped_code(&file);
        for token in FORBIDDEN {
            if code.contains(token) {
                breaches.push(format!("{}: {token}", rel(&file)));
            }
        }
    }

    assert!(
        breaches.is_empty(),
        "C-NO-ACTUATION breach (PR2): a detection path gained the ability to act. \
         Vigil reports; the operator decides. Breaches: {breaches:#?}"
    );
}

/// PR2, canary C-NO-ACTUATION (process half).
///
/// Vigil never signals a process it did not spawn. The single `libc::kill`
/// call site is a liveness probe: signal 0 delivers nothing. Reaping a
/// subprocess Vigil itself started (the package-manager query, killed on
/// timeout) is the only other `kill` in the tree, and it lives in
/// `src/package.rs`.
#[test]
fn watch_never_act_kill_is_liveness_probe_only() {
    let mut external_signals = Vec::new();
    let mut child_reaps = Vec::new();

    for file in rs_files_under(&manifest().join("src")) {
        let code = shipped_code(&file);
        for line in code.lines() {
            if line.contains("libc::kill(") && !line.contains(", 0)") {
                external_signals.push(format!("{}: {}", rel(&file), line.trim()));
            }
            if line.contains(".kill()") {
                child_reaps.push(rel(&file));
            }
        }
    }

    assert!(
        external_signals.is_empty(),
        "C-NO-ACTUATION breach (PR2): a kill() call delivers a real signal. \
         Only the liveness probe kill(pid, 0) is permitted. Breaches: {external_signals:#?}"
    );

    child_reaps.dedup();
    assert_eq!(
        child_reaps,
        vec!["src/package.rs".to_string()],
        "C-NO-ACTUATION breach (PR2): process termination appeared outside the \
         package-query timeout path in src/package.rs."
    );
}

// ===========================================================================
// P2 / PR3: the verdict is a pure comparison.
// ===========================================================================

fn fixture_baseline() -> BaselineEntry {
    let mut xattrs = BTreeMap::new();
    xattrs.insert("user.canary".to_string(), "before".to_string());

    BaselineEntry {
        id: None,
        path: PathBuf::from("/etc/shadow"),
        identity: FileIdentity {
            inode: 4_242,
            device: 66,
            file_type: FileType::Regular,
            symlink_target: None,
        },
        content: ContentFingerprint {
            hash: "baseline-hash".into(),
            size: 1024,
        },
        permissions: PermissionState {
            mode: 0o640,
            owner_uid: 0,
            owner_gid: 0,
            capabilities: None,
        },
        security: SecurityState {
            xattrs,
            security_context: "system_u:object_r:shadow_t:s0".into(),
        },
        mtime: 1_700_000_000,
        package: None,
        source: BaselineSource::AutoScan,
        added_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    }
}

fn fixture_snapshot_changed() -> FileSnapshot {
    let mut xattrs = BTreeMap::new();
    xattrs.insert("user.canary".to_string(), "after".to_string());
    xattrs.insert("security.selinux".to_string(), "added".to_string());

    FileSnapshot {
        path: PathBuf::from("/etc/shadow"),
        identity: FileIdentity {
            inode: 9_999,
            device: 66,
            file_type: FileType::Regular,
            symlink_target: None,
        },
        content: ContentFingerprint {
            hash: "tampered-hash".into(),
            size: 2048,
        },
        permissions: PermissionState {
            mode: 0o666,
            owner_uid: 1000,
            owner_gid: 1000,
            capabilities: Some("0200000000".into()),
        },
        security: SecurityState {
            xattrs,
            security_context: "unconfined_u:object_r:etc_t:s0".into(),
        },
        mtime: 1_700_000_500,
    }
}

/// `Change` carries no `PartialEq`, so the canary compares the debug rendering,
/// which captures both the variant set and the order.
fn render(changes: &[Change]) -> String {
    format!("{changes:?}")
}

/// PR3, canary C-DETERMINISTIC-DIFF.
///
/// The verdict must be a pure function of (snapshot, baseline). Same inputs,
/// same output, every time, in the same order. Nothing about a verdict may
/// depend on the clock, on randomness, or on how many comparisons came before.
#[test]
fn determinism_diff_is_a_pure_function_of_snapshot_and_baseline() {
    let baseline = fixture_baseline();
    let snapshot = fixture_snapshot_changed();

    let first = render(&snapshot.diff(&baseline));
    assert!(
        !first.is_empty() && first != "[]",
        "C-DETERMINISTIC-DIFF setup failure (PR3): the fixture must produce changes, \
         otherwise the canary proves nothing."
    );

    for round in 0..512 {
        let again = render(&snapshot.diff(&baseline));
        assert_eq!(
            first, again,
            "C-DETERMINISTIC-DIFF breach (PR3): the verdict changed on round {round}. \
             The comparison is no longer a pure function of its two inputs."
        );
    }

    // Structurally equal inputs must also produce equal output.
    let twin_baseline = fixture_baseline();
    let twin_snapshot = fixture_snapshot_changed();
    assert_eq!(
        first,
        render(&twin_snapshot.diff(&twin_baseline)),
        "C-DETERMINISTIC-DIFF breach (PR3): two structurally identical inputs \
         produced different verdicts."
    );
}

/// PR4, canary C-NO-HEURISTICS (source half).
///
/// The detection surface must contain no score, model, feed, or reputation
/// lookup. Severity comes from the operator's watch-group configuration and
/// from nowhere else.
#[test]
fn determinism_detection_surface_has_no_scoring_or_ml() {
    const FORBIDDEN: &[&str] = &[
        "risk_score",
        "riskscore",
        "threat_score",
        "confidence",
        "probabilit",
        "heuristic",
        "reputation",
        "threat_feed",
        "threat_intel",
        "machine_learning",
        "neural",
        "inference",
        "virustotal",
        "yara",
    ];

    let mut breaches = Vec::new();
    for file in detection_surface() {
        let code = shipped_code(&file).to_lowercase();
        for token in FORBIDDEN {
            if code.contains(token) {
                breaches.push(format!("{}: {token}", rel(&file)));
            }
        }
    }

    assert!(
        breaches.is_empty(),
        "C-NO-HEURISTICS breach (PR4): the detection surface started guessing. \
         Vigil compares; it does not judge. Breaches: {breaches:#?}"
    );
}

/// PR4, canary C-NO-HEURISTICS (dependency half).
///
/// No crate in the dependency set may supply a model, a feed, or a reputation
/// service. The guard sits on the manifest because a dependency is how this
/// capability would actually arrive.
#[test]
fn determinism_dependency_set_has_no_ml_or_feed_crates() {
    const FORBIDDEN: &[&str] = &[
        "tract",
        "onnx",
        "tch",
        "torch",
        "linfa",
        "smartcore",
        "candle",
        "burn",
        "tensorflow",
        "rustlearn",
        "yara",
        "clamav",
        "virustotal",
    ];

    let mut breaches = Vec::new();
    for line in manifest_dependency_lines() {
        let name = line.split(['=', ' ']).next().unwrap_or("").to_lowercase();
        for token in FORBIDDEN {
            if name == *token || name.starts_with(&format!("{token}-")) {
                breaches.push(line.clone());
            }
        }
    }

    assert!(
        breaches.is_empty(),
        "C-NO-HEURISTICS breach (PR4): a model or feed crate entered the dependency set: \
         {breaches:#?}"
    );
}

// ===========================================================================
// P3 / PR5, PR6: silence means intact.
// ===========================================================================

/// PR5, canary C-NO-FALSE-NEGATIVE-PREFILTER.
///
/// The Bloom prefilter is one-sided. A false positive costs a wasted
/// comparison; a false negative is a silently dropped event on a watched path,
/// which would make silence a lie. The filter must accept every watched path
/// and every descendant of one.
#[test]
fn silence_prefilter_never_rejects_a_watched_path() {
    let config = vigil::config::default_config();
    let watch_paths = vigil::monitor::collect_watch_paths(&config);
    assert!(
        !watch_paths.is_empty(),
        "C-NO-FALSE-NEGATIVE-PREFILTER setup failure (PR5): the default config \
         watches nothing, so the canary proves nothing."
    );

    let bloom = vigil::bloom::BloomFilter::from_watch_paths(&watch_paths);

    let mut rejected = Vec::new();
    for path in &watch_paths {
        if !bloom.might_contain_prefix_of(path) {
            rejected.push(path.display().to_string());
        }
        for suffix in [
            "canary",
            "nested/canary",
            "a/b/c/d/e/canary.sh",
            ".hidden/payload",
        ] {
            let descendant = path.join(suffix);
            if !bloom.might_contain_prefix_of(&descendant) {
                rejected.push(descendant.display().to_string());
            }
        }
    }

    assert!(
        rejected.is_empty(),
        "C-NO-FALSE-NEGATIVE-PREFILTER breach (PR5): the prefilter rejected a watched \
         path. Events for these paths would be dropped before comparison: {rejected:#?}"
    );
}

/// PR6, canary C-CLEAN-IS-SILENT.
///
/// An untouched file must produce no change, and a touched one must produce a
/// change on the very next comparison. Quiet has to be a fact about the
/// filesystem, not an artifact of a suppression path.
#[test]
fn silence_unchanged_file_yields_no_change_and_a_touched_file_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("watched.conf");
    fs::write(&path, b"root:x:0:0:root:/root:/bin/bash\n").expect("write fixture");

    let opts = vigil::types::CaptureOpts {
        force_hash: true,
        max_file_size: 2_147_483_648,
        mmap_threshold: 1_048_576,
        baseline_mtime: None,
        baseline_hash: None,
    };

    let captured = match FileSnapshot::from_path(&path, &opts).expect("capture") {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("fixture file vanished during capture"),
    };

    let baseline = BaselineEntry {
        id: None,
        path: captured.path.clone(),
        identity: captured.identity.clone(),
        content: captured.content.clone(),
        permissions: captured.permissions.clone(),
        security: captured.security.clone(),
        mtime: captured.mtime,
        package: None,
        source: BaselineSource::AutoScan,
        added_at: captured.mtime,
        updated_at: captured.mtime,
    };

    let unchanged = match FileSnapshot::from_path(&path, &opts).expect("re-capture") {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("fixture file vanished during re-capture"),
    };
    let quiet = unchanged.diff(&baseline);
    assert!(
        quiet.is_empty(),
        "C-CLEAN-IS-SILENT breach (PR6): an untouched file reported changes: {quiet:?}"
    );

    fs::write(
        &path,
        b"root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/:/bin/sh\n",
    )
    .expect("tamper fixture");

    let tampered = match FileSnapshot::from_path(&path, &opts).expect("post-change capture") {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("fixture file vanished after modification"),
    };
    let loud = tampered.diff(&baseline);
    assert!(
        loud.iter()
            .any(|c| matches!(c, Change::ContentModified { .. })),
        "C-CLEAN-IS-SILENT breach (PR6): a modified file did not report \
         ContentModified: {loud:?}"
    );
}

// ===========================================================================
// P4 / PR7, PR8: the audit trail never lies.
// ===========================================================================

fn canary_change(path: &str) -> vigil::types::ChangeResult {
    vigil::types::ChangeResult {
        path: Arc::new(PathBuf::from(path)),
        changes: vec![Change::ContentModified {
            old_hash: "before".into(),
            new_hash: "after".into(),
        }],
        severity: Severity::High,
        monitored_group: "pdd_canary".into(),
        process: None,
        package: None,
        package_update: false,
        disambiguation: None,
    }
}

/// PR7, canary C-SUPPRESSED-STILL-AUDITED.
///
/// Suppression is a decision about the operator's attention, never about the
/// truth. A duplicate inside the cooldown window is not notified, and it is
/// still written to the audit log, flagged as suppressed.
#[test]
fn audit_truth_suppressed_alerts_are_still_recorded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.db");

    let mut config = vigil::config::default_config();
    // Silence every sink so the canary exercises the audit decision alone.
    config.alerts.syslog = false;
    config.alerts.desktop_notifications = false;
    config.alerts.log_file = PathBuf::new();
    config.hooks.signal_socket = String::new();
    // A long cooldown guarantees the second detection is suppressed.
    config.alerts.cooldown_seconds = 3_600;

    let metrics = Arc::new(vigil::metrics::Metrics::new());
    let dispatcher = vigil::alert::AlertDispatcher::new(
        &config,
        &audit_path,
        metrics,
        None,
        false,
        "pdd-canary".to_string(),
    )
    .expect("dispatcher");

    let (tx, rx) = crossbeam_channel::unbounded();
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || dispatcher.run(rx, worker_shutdown));

    let payload = vigil::alert::AlertPayload {
        change: canary_change("/etc/shadow"),
        maintenance_window: false,
    };
    tx.send(payload.clone()).expect("send first detection");
    tx.send(payload).expect("send duplicate detection");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut entries = Vec::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        let conn = rusqlite::Connection::open(&audit_path).expect("open audit db");
        entries = vigil::db::audit_ops::get_recent(&conn, 10).expect("read audit log");
        if entries.len() >= 2 {
            break;
        }
    }

    shutdown.store(true, Ordering::Release);
    drop(tx);
    handle.join().expect("dispatcher thread");

    assert_eq!(
        entries.len(),
        2,
        "C-SUPPRESSED-STILL-AUDITED breach (PR7): expected both detections in the audit \
         log, found {}. Suppression must never delete evidence.",
        entries.len()
    );
    assert_eq!(
        entries.iter().filter(|e| e.suppressed).count(),
        1,
        "C-SUPPRESSED-STILL-AUDITED breach (PR7): the suppressed detection was not \
         recorded as suppressed. The audit log must say what the operator was not told."
    );
    assert!(
        entries.iter().all(|e| e.path == "/etc/shadow"),
        "C-SUPPRESSED-STILL-AUDITED breach (PR7): the audit rows do not name the \
         path that changed."
    );
}

/// PR8, canary C-AUDIT-CHAIN-TAMPER.
///
/// Each audit row carries the hash of the row before it. Editing a row's
/// content must break verification, so an attacker with write access to the
/// database cannot quietly rewrite history.
#[test]
fn audit_truth_tampering_with_an_audit_row_breaks_the_chain() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
    vigil::db::schema::create_audit_tables(&conn).expect("audit schema");

    let genesis = blake3::hash(b"vigil-audit-chain-genesis")
        .to_hex()
        .to_string();

    let mut previous = genesis;
    for path in ["/etc/passwd", "/etc/shadow", "/usr/bin/sudo"] {
        previous = vigil::db::audit_ops::insert_audit_entry(
            &conn,
            &canary_change(path),
            false,
            false,
            None,
            &previous,
        )
        .expect("insert audit entry");
    }

    let (total, valid, breaks, _missing) =
        vigil::db::audit_ops::verify_chain(&conn).expect("verify clean chain");
    assert_eq!(total, 3, "expected three audit entries");
    assert_eq!(valid, 3, "an untampered chain must verify clean");
    assert!(
        breaks.is_empty(),
        "C-AUDIT-CHAIN-TAMPER setup failure (PR8): the chain did not verify clean \
         before tampering: {breaks:?}"
    );

    conn.execute(
        "UPDATE audit_log SET path = '/tmp/innocent' WHERE id = 2",
        [],
    )
    .expect("tamper with audit row");

    let (_total, _valid, breaks_after, _missing) =
        vigil::db::audit_ops::verify_chain(&conn).expect("verify tampered chain");
    assert!(
        !breaks_after.is_empty(),
        "C-AUDIT-CHAIN-TAMPER breach (PR8): an edited audit row still verified clean. \
         The audit trail is no longer tamper-evident."
    );
}

// ===========================================================================
// P5 / PR9, PR10: degradation is announced.
// ===========================================================================

/// Extract a Rust function body by name: from `fn name(` to the closing brace
/// at the function's indentation. Returns None if the function is absent.
fn rust_function_body(src: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}(");
    let start = src.find(&needle)?;
    let after = &src[start..];
    let mut depth = 0usize;
    let mut seen_open = false;
    for (idx, ch) in after.char_indices() {
        match ch {
            '{' => {
                depth += 1;
                seen_open = true;
            }
            '}' => {
                depth -= 1;
                if seen_open && depth == 0 {
                    return Some(after[..=idx].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// PR9, canary C-DEGRADED-IS-LOUD.
///
/// A fallback backend or a reduced event mask must be reported as a warning
/// that names the reduced coverage. Silent degradation is the failure that
/// turns a monitor into a liability, so the degraded branch may never carry an
/// OK status.
#[test]
fn fail_loud_degraded_backend_never_reports_ok() {
    let checks = code_only(&read_surface("src/doctor/checks.rs"));

    let backend = rust_function_body(&checks, "check_backend").expect(
        "C-DEGRADED-IS-LOUD breach (PR9): check_backend is gone; the canary can no \
         longer see how a fallback backend is reported.",
    );
    let (_ok_branch, fallback) = backend
        .split_once("} else {")
        .expect("check_backend must keep an explicit fallback branch");
    assert!(
        fallback.contains("CheckStatus::Warning") || fallback.contains("CheckStatus::Failed"),
        "C-DEGRADED-IS-LOUD breach (PR9): the inotify fallback branch no longer warns."
    );
    assert!(
        !fallback.contains("CheckStatus::Ok"),
        "C-DEGRADED-IS-LOUD breach (PR9): the inotify fallback branch reports OK. \
         Reduced coverage must never look healthy."
    );
    assert!(
        fallback.to_lowercase().contains("reduced coverage"),
        "C-DEGRADED-IS-LOUD breach (PR9): the fallback branch stopped naming the \
         reduced coverage the operator is running with."
    );

    let coverage = rust_function_body(&checks, "check_realtime_coverage").expect(
        "C-DEGRADED-IS-LOUD breach (PR9): check_realtime_coverage is gone; a partial \
         event mask would no longer be reported.",
    );
    let (_full, partial) = coverage
        .split_once("} else {")
        .expect("check_realtime_coverage must keep an explicit degraded branch");
    assert!(
        partial.contains("CheckStatus::Warning") || partial.contains("CheckStatus::Failed"),
        "C-DEGRADED-IS-LOUD breach (PR9): a reduced event mask no longer warns."
    );
    assert!(
        !partial.contains("CheckStatus::Ok"),
        "C-DEGRADED-IS-LOUD breach (PR9): a reduced event mask reports OK."
    );
}

/// PR10, canary C-BLIND-SPOTS-COUNTED.
///
/// A blind spot must be a number the operator can read, not an absence they
/// have to infer. Removing any of these counters from the exported snapshot
/// fails this canary at compile time, which is exactly as loud as it should be.
#[test]
fn fail_loud_blind_spot_counters_are_exported() {
    let metrics = vigil::metrics::Metrics::new();
    let snapshot = metrics.snapshot();

    let blind_spots: [(&str, u64); 4] = [
        ("events_dropped", snapshot.events_dropped),
        ("kernel_queue_overflows", snapshot.kernel_queue_overflows),
        (
            "fanotify_overflow_scans_triggered",
            snapshot.fanotify_overflow_scans_triggered,
        ),
        (
            "userspace_drop_scans_triggered",
            snapshot.userspace_drop_scans_triggered,
        ),
    ];

    for (name, value) in blind_spots {
        assert_eq!(
            value, 0,
            "C-BLIND-SPOTS-COUNTED breach (PR10): {name} did not start at zero, so the \
             counter cannot be read as a blind-spot total."
        );
    }

    metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
    assert_eq!(
        metrics.snapshot().events_dropped,
        1,
        "C-BLIND-SPOTS-COUNTED breach (PR10): a dropped event did not reach the \
         exported snapshot. A blind spot that is not counted is a blind spot the \
         operator cannot see."
    );
}

// ===========================================================================
// P6 / PR11, PR12: local by design.
// ===========================================================================

/// PR11, canary C-NO-NETWORK-DEPS (manifest half).
///
/// The network is not a dependency Vigil is allowed to grow. No HTTP client,
/// telemetry SDK, crash reporter, cloud SDK, or update-check crate may enter
/// the manifest.
#[test]
fn local_by_design_no_http_or_telemetry_dependencies() {
    const FORBIDDEN: &[&str] = &[
        "reqwest",
        "ureq",
        "hyper",
        "isahc",
        "surf",
        "attohttpc",
        "curl",
        "awc",
        "sentry",
        "opentelemetry",
        "tracing-opentelemetry",
        "datadog",
        "posthog",
        "segment",
        "mixpanel",
        "amplitude",
        "self_update",
        "self-update",
        "update-informer",
        "aws-sdk-s3",
        "google-cloud",
        "azure_core",
    ];

    let mut breaches = Vec::new();
    for line in manifest_dependency_lines() {
        let name = line.split(['=', ' ']).next().unwrap_or("").to_lowercase();
        if FORBIDDEN.contains(&name.as_str()) {
            breaches.push(line.clone());
        }
    }

    assert!(
        breaches.is_empty(),
        "C-NO-NETWORK-DEPS breach (PR11): a network or telemetry crate entered the \
         manifest: {breaches:#?}"
    );
}

/// PR11, canary C-NO-NETWORK-DEPS (source half).
///
/// Network code exists in exactly two files, both of them operator-configured
/// alert sinks. Anywhere else, a socket is a promise breach.
#[test]
fn local_by_design_network_code_is_confined_to_the_two_opt_in_sinks() {
    const NET_TOKENS: &[&str] = &["std::net", "TcpStream", "UdpSocket", "TcpListener"];
    const ALLOWED: &[&str] = &["src/alert/webhook.rs", "src/alert/remote_syslog.rs"];

    let mut offenders = Vec::new();
    for file in rs_files_under(&manifest().join("src")) {
        let relative = rel(&file);
        if ALLOWED.contains(&relative.as_str()) {
            continue;
        }
        let code = shipped_code(&file);
        for token in NET_TOKENS {
            if code.contains(token) {
                offenders.push(format!("{relative}: {token}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "C-NO-NETWORK-DEPS breach (PR11): network code appeared outside the two opt-in \
         alert sinks: {offenders:#?}"
    );

    // The two allowed files must still be the alert sinks they claim to be.
    for allowed in ALLOWED {
        let code = read_surface(allowed);
        assert!(
            code.contains("AlertSink"),
            "C-NO-NETWORK-DEPS breach (PR11): {allowed} holds the network exemption but \
             is no longer an alert sink."
        );
    }
}

/// PR12, canary C-EGRESS-OFF-BY-DEFAULT.
///
/// A default install must perform no outbound network I/O at all. Both sinks
/// stay dark until the operator turns one on.
#[test]
fn local_by_design_outbound_sinks_are_off_by_default() {
    let config = vigil::config::default_config();

    assert!(
        config.alerts.webhook_url.is_empty(),
        "C-EGRESS-OFF-BY-DEFAULT breach (PR12): the default config ships a webhook URL \
         ({}). Outbound integrations are the operator's choice.",
        config.alerts.webhook_url
    );
    assert!(
        !config.alerts.remote_syslog.enabled,
        "C-EGRESS-OFF-BY-DEFAULT breach (PR12): remote syslog is enabled by default."
    );
    assert!(
        config.alerts.remote_syslog.server.is_empty(),
        "C-EGRESS-OFF-BY-DEFAULT breach (PR12): the default config ships a remote syslog \
         server address."
    );
    assert!(
        config.hooks.signal_socket.is_empty(),
        "C-EGRESS-OFF-BY-DEFAULT breach (PR12): the default config ships a signal socket \
         path."
    );
}

// ===========================================================================
// P7 / PR13, PR14: stands alone, stays small.
// ===========================================================================

/// PR13, canary C-STANDS-ALONE.
///
/// Vigil must compile, run, and do its whole job with no sibling tool present.
/// It imports none of them and reads none of their state.
#[test]
fn stands_alone_no_sibling_tool_coupling() {
    const SIBLING_CRATES: &[&str] = &["shroud", "vpn-shroud", "vpn_shroud", "peek"];
    const SIBLING_PATHS: &[&str] = &[
        "/var/lib/shroud",
        "/etc/shroud",
        "/run/shroud",
        "/var/lib/peek",
        "/etc/peek",
        "/run/peek",
    ];

    let mut breaches = Vec::new();

    for line in manifest_dependency_lines() {
        let name = line.split(['=', ' ']).next().unwrap_or("").to_lowercase();
        if SIBLING_CRATES.contains(&name.as_str()) {
            breaches.push(format!("Cargo.toml: {line}"));
        }
    }

    for file in rs_files_under(&manifest().join("src")) {
        let code = shipped_code(&file);
        for crate_name in SIBLING_CRATES {
            let import = format!("{}::", crate_name.replace('-', "_"));
            if code.contains(&format!("use {import}")) {
                breaches.push(format!("{}: use {import}", rel(&file)));
            }
        }
        for path in SIBLING_PATHS {
            if code.contains(path) {
                breaches.push(format!("{}: {path}", rel(&file)));
            }
        }
    }

    assert!(
        breaches.is_empty(),
        "C-STANDS-ALONE breach (PR13): Vigil grew a dependency on a sibling tool: \
         {breaches:#?}"
    );
}

/// PR14, canary C-UNSAFE-BOUNDARY.
///
/// The crate denies unsafe code. The exemption exists only where a Linux
/// syscall must be made or a file descriptor must cross a thread boundary.
/// That list is enumerated in PROMISES.md; growing it is a promise review and
/// a ledger entry, not a routine commit.
#[test]
fn stands_alone_unsafe_is_confined_to_the_syscall_boundary() {
    const ALLOWLIST: &[&str] = &[
        "src/control.rs",
        "src/daemon/mod.rs",
        "src/display/term.rs",
        "src/hash.rs",
        "src/monitor/fanotify.rs",
        "src/monitor/mod.rs",
        "src/types/event.rs",
        "src/util/owned_fd.rs",
        "src/util/process.rs",
        "src/util/random.rs",
        "src/worker.rs",
    ];

    let lib = read_surface("src/lib.rs");
    assert!(
        lib.contains("#![deny(unsafe_code)]"),
        "C-UNSAFE-BOUNDARY breach (PR14): src/lib.rs no longer denies unsafe code, so \
         every module is free to reach past the compiler."
    );

    let mut exempt: Vec<String> = Vec::new();
    for file in rs_files_under(&manifest().join("src")) {
        if code_only(&fs::read_to_string(&file).expect("read source"))
            .contains("allow(unsafe_code)")
        {
            exempt.push(rel(&file));
        }
    }
    exempt.sort();

    let expected: Vec<String> = ALLOWLIST.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        exempt, expected,
        "C-UNSAFE-BOUNDARY breach (PR14): the set of modules exempted from \
         #![deny(unsafe_code)] changed. Every entry must be a Linux syscall boundary, \
         and a new one needs a promise review and an AUDIT_FINDINGS.md entry."
    );
}

// ===========================================================================
// P8 / PR15, PR16: the proof ships and fails loud.
// ===========================================================================

/// PR15, canary C-CI-GATE (test half; the workflow run is the other).
///
/// The canary surface is worthless if it is not merge-blocking. The gate job
/// must depend on every canary job in the workflow, so a red canary cannot be
/// merged past.
#[test]
fn proof_ships_ci_gate_depends_on_every_canary_job() {
    let workflow = read_surface(".github/workflows/pdd-canaries.yml");

    let gate_line = workflow
        .lines()
        .find(|l| l.trim_start().starts_with("needs: ["))
        .expect(
            "C-CI-GATE breach (PR15): the pdd-canary-gate job has no needs list; it can \
             no longer block on the canaries.",
        );

    for job in [
        "watch-never-act",
        "local-by-design",
        "stands-alone",
        "canary-tests",
        "release-provenance",
    ] {
        assert!(
            workflow.contains(&format!("  {job}:")),
            "C-CI-GATE breach (PR15): canary job `{job}` is missing from the workflow."
        );
        assert!(
            gate_line.contains(job),
            "C-CI-GATE breach (PR15): canary job `{job}` is not in the gate's needs list, \
             so a breach there would still report a green required check."
        );
    }

    assert!(
        workflow.contains("pdd-canary-gate:"),
        "C-CI-GATE breach (PR15): the required gate job is gone."
    );
}

/// PR16, canary C-RELEASE-PROVENANCE (test half; the attestation is the other).
///
/// What we hand an operator has to be verifiable by that operator. Every
/// release must ship a SHA256 checksum and a build-provenance attestation over
/// the same tarball.
#[test]
fn proof_ships_release_publishes_checksum_and_provenance() {
    let release = read_surface(".github/workflows/release.yml");

    assert!(
        release.contains("sha256sum"),
        "C-RELEASE-PROVENANCE breach (PR16): the release no longer publishes a SHA256 \
         checksum."
    );
    assert!(
        release.contains("attest-build-provenance"),
        "C-RELEASE-PROVENANCE breach (PR16): the release no longer attests build \
         provenance, so an operator cannot confirm the bytes came from this repository."
    );
    assert!(
        release.contains(".tar.gz.sha256"),
        "C-RELEASE-PROVENANCE breach (PR16): the checksum file is no longer attached to \
         the release."
    );
}

/// P8, canary C-PROMISE-SET-INTEGRITY.
///
/// The methodology's own rule, guarded: a principle that spawns no promise is
/// decoration, and a promise with no canary is just prose. This canary reads
/// the three ledger documents as a graph and fails if any edge is missing, so
/// the promise set cannot quietly grow a claim nothing proves.
#[test]
fn proof_ships_promise_set_has_no_unguarded_claims() {
    let principles = read_surface("PRINCIPLES.md");
    let promises = read_surface("PROMISES.md");
    let canary_tests = read_surface("tests/pdd_canaries.rs");
    let workflow = read_surface(".github/workflows/pdd-canaries.yml");

    fn promise_ids(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let bytes: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i + 2 < bytes.len() {
            if bytes[i] == 'P' && bytes[i + 1] == 'R' && bytes[i + 2].is_ascii_digit() {
                let mut j = i + 2;
                let mut num = String::new();
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    num.push(bytes[j]);
                    j += 1;
                }
                out.push(format!("PR{num}"));
                i = j;
            } else {
                i += 1;
            }
        }
        out.sort();
        out.dedup();
        out
    }

    // Every principle must spawn at least one promise that exists.
    let declared: Vec<String> = promises
        .lines()
        .filter_map(|l| l.strip_prefix("### "))
        .filter_map(|l| l.split('.').next())
        .filter(|id| id.starts_with("PR"))
        .map(|id| id.to_string())
        .collect();
    assert!(
        !declared.is_empty(),
        "C-PROMISE-SET-INTEGRITY breach: PROMISES.md declares no promises."
    );

    let mut current_principle = String::new();
    let mut principles_seen = 0;
    for line in principles.lines() {
        if let Some(heading) = line.strip_prefix("## P") {
            current_principle = format!("P{}", heading.split('.').next().unwrap_or(""));
            if current_principle
                .trim_start_matches('P')
                .parse::<u32>()
                .is_ok()
            {
                principles_seen += 1;
            }
        }
        if line.starts_with("Spawns promise") {
            let spawned = promise_ids(line);
            assert!(
                !spawned.is_empty(),
                "C-PROMISE-SET-INTEGRITY breach: principle {current_principle} spawns no \
                 promise. A principle that guards nothing is decoration."
            );
            for id in spawned {
                assert!(
                    declared.contains(&id),
                    "C-PROMISE-SET-INTEGRITY breach: principle {current_principle} spawns \
                     {id}, which PROMISES.md does not declare."
                );
            }
        }
    }
    assert!(
        principles_seen >= 1,
        "C-PROMISE-SET-INTEGRITY breach: PRINCIPLES.md declares no principles."
    );

    // Every declared promise must name at least one canary, and every canary it
    // names must actually exist in the test suite or in the workflow.
    let sections: Vec<&str> = promises.split("\n### ").skip(1).collect();
    for section in sections {
        let id = section.split('.').next().unwrap_or("").to_string();
        if !id.starts_with("PR") {
            continue;
        }
        assert!(
            section.contains("Canary `C-"),
            "C-PROMISE-SET-INTEGRITY breach: {id} names no canary. A promise with no \
             canary is prose; demote it to an aspiration or build the guard."
        );

        for token in section.split("Canary `").skip(1) {
            let canary = token.split('`').next().unwrap_or("");
            assert!(
                canary.starts_with("C-"),
                "C-PROMISE-SET-INTEGRITY breach: {id} names a malformed canary id."
            );
            assert!(
                canary_tests.contains(canary) || workflow.contains(canary),
                "C-PROMISE-SET-INTEGRITY breach: {id} names canary {canary}, which exists \
                 in neither tests/pdd_canaries.rs nor the CI gate."
            );
        }
    }

    // Every promise declared must be claimed by some principle.
    let spawned_all: Vec<String> = principles
        .lines()
        .filter(|l| l.starts_with("Spawns promise"))
        .flat_map(promise_ids)
        .collect();
    for id in &declared {
        assert!(
            spawned_all.contains(id),
            "C-PROMISE-SET-INTEGRITY breach: {id} descends from no principle. A promise \
             that traces back to nothing is how promise inflation starts."
        );
    }
}
