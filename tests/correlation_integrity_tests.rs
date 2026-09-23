//! Integrity boundary between correlation and the signed baseline.
//!
//! Correlation is derived, advisory data. These tests pin the boundary it must
//! never cross: it cannot alter a raw detection, cannot write to the baseline,
//! cannot affect baseline signing, and cannot be forged into an acceptance.
//!
//! If a future change makes correlation an input to any of these, one of these
//! tests fails.

use std::path::PathBuf;
use std::sync::Arc;

use vigil::acceptance::{revalidate, Revalidation, ReviewedState};
use vigil::correlate::{
    correlate, CorrelationInput, EventKind, PackageAction, PackageTransition, TransactionRecord,
    TransactionSource, TransactionStatus,
};
use vigil::db::{baseline_ops, schema};
use vigil::package::PackageVerification;
use vigil::types::{
    BaselineEntry, BaselineSource, CaptureOpts, Change, ChangeResult, ContentFingerprint, Severity,
};

const T0: i64 = 1_758_326_834;
const KEY: &[u8] = b"test-hmac-key-for-vigil-baseline";

fn opts() -> CaptureOpts {
    CaptureOpts {
        force_hash: true,
        max_file_size: 1024 * 1024,
        mmap_threshold: 1024 * 1024,
        baseline_mtime: None,
        baseline_hash: None,
    }
}

fn detection(path: &str) -> ChangeResult {
    ChangeResult {
        path: Arc::new(PathBuf::from(path)),
        changes: vec![Change::ContentModified {
            old_hash: "old".into(),
            new_hash: "new".into(),
        }],
        severity: Severity::Critical,
        monitored_group: "system".into(),
        process: None,
        package: None,
        package_update: false,
        disambiguation: None,
    }
}

fn verified_input(path: &str, package: &str) -> CorrelationInput {
    let mut input = CorrelationInput::new();
    let mut tx = TransactionRecord::new(TransactionSource::Apt, T0);
    tx.end = Some(T0 + 2);
    tx.status = TransactionStatus::Completed;
    let mut transition = PackageTransition::new(package, PackageAction::Upgrade)
        .with_versions(Some("1.0"), Some("1.1"));
    transition.installed_complete = Some(true);
    tx.packages.push(transition);
    tx.normalize();

    input.transactions.push(tx);
    input
        .ownership
        .insert(PathBuf::from(path), vec![package.to_string()]);
    input
        .verification
        .insert(path.to_string(), PackageVerification::Verified);
    input
        .observed_change_time
        .insert(PathBuf::from(path), T0 + 1);
    input.installed.insert(package.to_string(), "1.1".into());
    input
}

fn sample_entry(path: &str, hash: &str) -> BaselineEntry {
    BaselineEntry {
        id: None,
        path: PathBuf::from(path),
        identity: Default::default(),
        content: ContentFingerprint {
            hash: hash.into(),
            size: 100,
        },
        permissions: Default::default(),
        security: Default::default(),
        mtime: T0,
        package: None,
        source: BaselineSource::AutoScan,
        added_at: T0,
        updated_at: T0,
    }
}

// ── 1. Correlation never changes the raw record ────────────

#[test]
fn correlation_does_not_mutate_raw_detections() {
    let changes = vec![detection("/usr/bin/gs")];
    let snapshot_before = format!("{changes:?}");

    let input = verified_input("/usr/bin/gs", "ghostscript");
    let result = correlate(&changes, &input);

    assert_eq!(result.events.len(), 1);
    assert_eq!(
        format!("{changes:?}"),
        snapshot_before,
        "the detection list must be byte-identical after correlation"
    );
    assert_eq!(
        changes[0].severity,
        Severity::Critical,
        "raw severity is never rewritten by an explanation"
    );
}

/// An event may reference a detection, but the reference is a pointer, not a
/// replacement: the raw path, severity and change list are reproduced exactly.
#[test]
fn event_members_reference_rather_than_restate_detections() {
    let changes = vec![detection("/usr/bin/gs")];
    let input = verified_input("/usr/bin/gs", "ghostscript");
    let result = correlate(&changes, &input);

    let member = &result.events[0].members[0];
    assert_eq!(member.raw.index, 0);
    assert_eq!(member.raw.path, *changes[0].path.as_ref());
    assert_eq!(member.raw.severity, changes[0].severity);
    assert_eq!(member.raw.changes, vec!["content_modified".to_string()]);
}

// ── 2. Correlation never auto-accepts ──────────────────────

#[test]
fn correlation_never_writes_to_the_baseline() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();
    baseline_ops::upsert(&conn, &sample_entry("/usr/bin/gs", "baseline-hash")).unwrap();

    let before = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();

    // A fully verified transaction: the strongest verdict the tool can reach.
    let changes = vec![detection("/usr/bin/gs")];
    let input = verified_input("/usr/bin/gs", "ghostscript");
    let result = correlate(&changes, &input);
    assert_eq!(
        result.events[0].confidence,
        vigil::correlate::Confidence::VerifiedTransaction
    );

    let after = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();
    assert_eq!(
        before, after,
        "even a verified transaction must leave the baseline untouched"
    );

    let entry = baseline_ops::get_by_path(&conn, "/usr/bin/gs")
        .unwrap()
        .expect("entry still present");
    assert_eq!(
        entry.content.hash, "baseline-hash",
        "the baseline still holds the reviewed value, not the observed one"
    );
}

/// The correlation API surface offers no way to accept anything. This is a
/// structural guarantee, not a behavioural one: there is no write path.
#[test]
fn correlation_result_carries_no_acceptance_signal() {
    let changes = vec![detection("/usr/bin/gs")];
    let input = verified_input("/usr/bin/gs", "ghostscript");
    let event = &correlate(&changes, &input).events[0];

    // Disposition is reported as an explanation only.
    assert_eq!(event.kind, EventKind::AptTransaction);
    assert!(event.fully_explained());
    // Nothing in the event names a baseline state, because correlation does
    // not participate in one.
    let serialized = serde_json::to_string(event).unwrap();
    assert!(
        !serialized.contains("accepted"),
        "an event must not carry an acceptance field: {serialized}"
    );
}

/// Build a baseline entry plus the detection the operator would have reviewed,
/// by capturing the old state, applying the change, and diffing for real.
fn reviewed_pair(file: &std::path::Path, old: &[u8], new: &[u8]) -> (BaselineEntry, ChangeResult) {
    use vigil::types::{FileSnapshot, SnapshotOrDeleted};

    std::fs::write(file, old).unwrap();
    let before = match FileSnapshot::from_path(file, &opts()).unwrap() {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("unexpected deletion"),
    };
    let baseline = BaselineEntry {
        id: None,
        path: file.to_path_buf(),
        identity: before.identity.clone(),
        content: before.content.clone(),
        permissions: before.permissions.clone(),
        security: before.security.clone(),
        mtime: before.mtime,
        package: None,
        source: BaselineSource::AutoScan,
        added_at: 0,
        updated_at: 0,
    };

    std::fs::write(file, new).unwrap();
    let after = match FileSnapshot::from_path(file, &opts()).unwrap() {
        SnapshotOrDeleted::Snapshot(s) => s,
        SnapshotOrDeleted::Deleted => panic!("unexpected deletion"),
    };
    let change = ChangeResult {
        path: Arc::new(file.to_path_buf()),
        changes: after.diff(&baseline),
        severity: Severity::Critical,
        monitored_group: "system".into(),
        process: None,
        package: None,
        package_update: false,
        disambiguation: None,
    };
    (baseline, change)
}

// ── 3 & 4. Acceptance revalidation ─────────────────────────

#[test]
fn acceptance_refuses_state_that_changed_after_review() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("binary");
    let (baseline, change) = reviewed_pair(&file, b"original content", b"reviewed content");

    // Confirmed while the state still matches.
    assert!(revalidate(&change, Some(&baseline), &opts()).is_confirmed());

    // An attacker substitutes content between the report and the acceptance.
    std::fs::write(&file, b"attacker content").unwrap();

    match revalidate(&change, Some(&baseline), &opts()) {
        Revalidation::Stale { differences } => {
            assert!(
                differences.iter().any(|d| d.contains("content hash")),
                "{differences:?}"
            );
        }
        _ => panic!("acceptance must refuse a path that moved after review"),
    }
}

/// A verified transaction does not lower the bar for revalidation. Explanation
/// and acceptance are independent dimensions.
#[test]
fn a_verified_explanation_does_not_bypass_revalidation() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gs");
    let (baseline, change) = reviewed_pair(&file, b"old", b"from the package");

    // Correlate it as a fully verified package transaction.
    let path_str = file.to_string_lossy().into_owned();
    let input = verified_input(&path_str, "ghostscript");
    let result = correlate(std::slice::from_ref(&change), &input);
    assert_eq!(
        result.events[0].confidence,
        vigil::correlate::Confidence::VerifiedTransaction
    );

    // Now the file changes again. Revalidation must still refuse it.
    std::fs::write(&file, b"something else entirely").unwrap();
    assert!(
        !revalidate(&change, Some(&baseline), &opts()).is_confirmed(),
        "a verified explanation must not license accepting unreviewed bytes"
    );
}

#[test]
fn reviewed_state_records_every_dimension_the_operator_saw() {
    let change = ChangeResult {
        path: Arc::new(PathBuf::from("/x")),
        changes: vec![
            Change::ContentModified {
                old_hash: "a".into(),
                new_hash: "b".into(),
            },
            Change::PermissionsChanged {
                old: 0o644,
                new: 0o755,
            },
            Change::OwnerChanged {
                old_uid: 0,
                new_uid: 1000,
                old_gid: 0,
                new_gid: 1000,
            },
        ],
        severity: Severity::Critical,
        monitored_group: "system".into(),
        process: None,
        package: None,
        package_update: false,
        disambiguation: None,
    };

    let reviewed = ReviewedState::from_change(&change);
    assert_eq!(reviewed.hash.as_deref(), Some("b"));
    assert_eq!(reviewed.mode, Some(0o755));
    assert_eq!(reviewed.uid, Some(1000));
    assert!(reviewed.is_checkable());
}

// ── 5 & 6. Baseline signing is unaffected ──────────────────

/// The baseline HMAC covers the same fields it always has. Correlation data is
/// not among them, and cannot be: it is never written to the baseline at all.
#[test]
fn baseline_hmac_is_unchanged_by_correlation_activity() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();
    baseline_ops::upsert(&conn, &sample_entry("/etc/passwd", "h1")).unwrap();
    baseline_ops::upsert(&conn, &sample_entry("/etc/shadow", "h2")).unwrap();

    let expected = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();

    for _ in 0..3 {
        let changes = vec![detection("/etc/passwd")];
        let input = verified_input("/etc/passwd", "base-files");
        let _ = correlate(&changes, &input);
    }

    assert_eq!(
        baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap(),
        expected,
        "repeated correlation must not perturb the signature"
    );
}

/// The v3 symlink columns are deliberately outside the baseline HMAC, so a
/// baseline signed before they existed still verifies afterwards.
#[test]
fn v3_symlink_columns_do_not_invalidate_an_existing_signature() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    let mut entry = sample_entry("/etc/systemd/system/x.service", "h1");
    entry.identity.file_type = vigil::types::FileType::Symlink;
    entry.identity.symlink_target = Some(PathBuf::from("/lib/systemd/system/x.service"));
    baseline_ops::upsert(&conn, &entry).unwrap();

    let without_link_data = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();

    // Populate the v3 link columns, as a rescan would.
    entry.identity.link_text = Some(PathBuf::from("/lib/systemd/system/x.service"));
    entry.identity.link_inode = Some(4242);
    entry.identity.link_device = Some(1);
    baseline_ops::upsert(&conn, &entry).unwrap();

    let with_link_data = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();

    assert_eq!(
        without_link_data, with_link_data,
        "the signed field set is unchanged, so an older signed baseline still verifies"
    );

    // And the link data really was stored.
    let stored = baseline_ops::get_by_path(&conn, "/etc/systemd/system/x.service")
        .unwrap()
        .unwrap();
    assert_eq!(stored.identity.link_inode, Some(4242));
}

/// Corrupting correlation input cannot produce a baseline write or a signature
/// change, because correlation has no path to either.
#[test]
fn corrupt_correlation_evidence_cannot_alter_a_baseline() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();
    baseline_ops::upsert(&conn, &sample_entry("/usr/bin/gs", "trusted")).unwrap();
    let before = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();

    // Evidence claiming a perfect transaction for a path that is not what the
    // baseline holds, with contradictory internal state.
    let changes = vec![detection("/usr/bin/gs")];
    let mut input = verified_input("/usr/bin/gs", "ghostscript");
    input.installed.insert("ghostscript".into(), "999".into()); // disagrees
    let result = correlate(&changes, &input);

    // The engine notices the contradiction rather than accepting the claim.
    assert_eq!(
        result.events[0].confidence,
        vigil::correlate::Confidence::ConflictingEvidence
    );

    assert_eq!(
        baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap(),
        before,
        "no correlation verdict, honest or forged, can move the baseline"
    );
}

#[test]
fn hmac_mismatch_remains_detectable_after_the_schema_change() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();
    baseline_ops::upsert(&conn, &sample_entry("/etc/passwd", "original")).unwrap();

    let signed = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();

    // Tamper with a signed field directly in the database.
    conn.execute(
        "UPDATE baseline SET hash = 'tampered' WHERE path = '/etc/passwd'",
        [],
    )
    .unwrap();

    let recomputed = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();
    assert_ne!(
        signed, recomputed,
        "tampering with a signed field must still break the HMAC"
    );
}

/// Tampering with a v3 link column is caught by the ordinary detection path
/// even though the column sits outside the HMAC: any semantic retarget also
/// moves the canonical target, which *is* signed.
#[test]
fn retargeting_a_symlink_still_moves_a_signed_field() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::create_baseline_tables(&conn).unwrap();

    let mut entry = sample_entry("/etc/systemd/system/x.service", "h1");
    entry.identity.file_type = vigil::types::FileType::Symlink;
    entry.identity.symlink_target = Some(PathBuf::from("/lib/systemd/system/x.service"));
    entry.identity.link_text = Some(PathBuf::from("/lib/systemd/system/x.service"));
    entry.identity.link_inode = Some(1);
    entry.identity.link_device = Some(1);
    baseline_ops::upsert(&conn, &entry).unwrap();
    let signed = baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap();

    // Repoint the link somewhere else: canonical target is a signed field.
    entry.identity.symlink_target = Some(PathBuf::from("/tmp/evil.service"));
    baseline_ops::upsert(&conn, &entry).unwrap();

    assert_ne!(
        signed,
        baseline_ops::compute_baseline_hmac(&conn, KEY).unwrap(),
        "a retarget changes the canonical target, which the HMAC covers"
    );
}

// ── 7. Determinism, so a receipt can name an event ─────────

#[test]
fn event_ids_are_reproducible_across_runs() {
    let changes = vec![detection("/usr/bin/gs"), detection("/usr/bin/gsc")];
    let mut input = verified_input("/usr/bin/gs", "ghostscript");
    input.ownership.insert(
        PathBuf::from("/usr/bin/gsc"),
        vec!["ghostscript".to_string()],
    );
    input
        .verification
        .insert("/usr/bin/gsc".into(), PackageVerification::Verified);
    input
        .observed_change_time
        .insert(PathBuf::from("/usr/bin/gsc"), T0 + 1);

    let first = correlate(&changes, &input);
    let second = correlate(&changes, &input);

    assert_eq!(
        first.events[0].event_id, second.events[0].event_id,
        "an acceptance receipt must be able to name a stable event id"
    );
    assert_eq!(first.events[0].event_id.len(), 16);
}

// ── 8. Untrusted paths cannot rewrite the report ───────────

/// A hostile filename must be inert in the *raw* detection view too, not only
/// in the correlated event view. The two render into the same report, so a gap
/// in either one is a gap in both.
#[test]
fn raw_check_output_neutralizes_control_characters_in_paths() {
    use vigil::display::{render_check, CheckReport, CheckReportMeta};
    use vigil::scanner::ScanResult;
    use vigil::types::{OutputFormat, ScanMode};

    let hostile = "/tmp/\x1b[2J\x1b[1;32mNO CHANGES DETECTED\x1b[0m";
    let scan = ScanResult {
        total_checked: 1,
        changes_found: 1,
        errors: 0,
        warnings: Vec::new(),
        changes: vec![detection(hostile)],
        duration_ms: 1,
    };

    let report = CheckReport::from_scan(
        scan,
        CheckReportMeta {
            mode: ScanMode::Incremental,
            baseline_fingerprint: None,
            baseline_established: None,
            hmac_signed: false,
            total_baseline_entries: 1,
            previous_check_at: None,
            previous_check_changes: None,
            db_path: PathBuf::from("/tmp/x.db"),
        },
    );

    let term = vigil::display::term::TermInfo {
        width: 120,
        height: 40,
        is_tty: false,
        supports_color: false,
    };

    let correlation = vigil::correlate::CorrelationResult::default();
    for verbose in [false, true] {
        let out = render_check(
            &report,
            OutputFormat::Human,
            &term,
            verbose,
            false,
            &correlation,
        );
        assert!(
            !out.contains('\x1b'),
            "no raw escape byte may reach the terminal (verbose={verbose})"
        );
        assert!(
            out.contains("\\x1b"),
            "the escape must be rendered literally (verbose={verbose})"
        );
    }
}

// ── 9. Schema v3 compatibility on read-only paths ──────────

/// A read-only connection cannot run the v3 migration, so readers must cope
/// with a baseline that still lacks the symlink object columns. `vigil attest`
/// opens read-only; hard-failing it on `no such column: link_text` would block
/// attestation on any not-yet-migrated database.
#[test]
fn a_pre_v3_baseline_is_still_readable_without_migrating() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();

    // Exactly the v2 table shape: no link_* columns.
    conn.execute_batch(
        "CREATE TABLE baseline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE,
            inode INTEGER NOT NULL,
            device INTEGER NOT NULL,
            file_type TEXT NOT NULL DEFAULT 'regular',
            symlink_target TEXT,
            hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            mode INTEGER NOT NULL,
            owner_uid INTEGER NOT NULL,
            owner_gid INTEGER NOT NULL,
            capabilities TEXT,
            xattrs_json TEXT NOT NULL DEFAULT '{}',
            security_context TEXT NOT NULL DEFAULT '',
            mtime INTEGER NOT NULL,
            package TEXT,
            source TEXT NOT NULL DEFAULT 'auto_scan',
            added_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        INSERT INTO baseline (path, inode, device, hash, size, mode, owner_uid,
                              owner_gid, mtime, added_at, updated_at)
        VALUES ('/etc/passwd', 7, 1, 'legacy-hash', 42, 420, 0, 0, 5, 5, 5);",
    )
    .unwrap();

    let all = baseline_ops::get_all(&conn).expect("a pre-v3 baseline must still read");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].content.hash, "legacy-hash");
    assert_eq!(
        all[0].identity.link_text, None,
        "absent columns read as unknown, not as a value"
    );
    assert!(!all[0].identity.has_link_object_data());

    let one = baseline_ops::get_by_path(&conn, "/etc/passwd")
        .expect("lookup must succeed")
        .expect("entry present");
    assert_eq!(one.content.size, 42);
}

// ── 9. The default view must reduce volume, not add to it ──

/// The apt upgrade an operator actually reported, reproduced as a fixture.
///
/// Synthetic fixtures kept agreeing with whatever the renderer happened to
/// do. This one is taken from a real `apt upgrade` on a desktop, and carries
/// the parts that made the original output unusable: enough package-owned
/// files to bury everything else, symlink aliases whose own objects never
/// changed, a package-owned config file at a different severity, boot files
/// no package in the transaction owns, and an unrelated change that happened
/// to land in the same window.
fn upgrade_scenario() -> (
    vigil::display::CheckReport,
    vigil::correlate::CorrelationResult,
) {
    use vigil::display::{CheckReport, CheckReportMeta};
    use vigil::scanner::ScanResult;
    use vigil::types::ScanMode;

    // package -> (old, new, owned paths)
    let pkgs: Vec<(&str, &str, &str, Vec<&str>)> = vec![
        (
            "sudo",
            "1.9.17p2-1ubuntu3",
            "1.9.17p2-1ubuntu3.1",
            vec![
                "/usr/bin/cvtsudoers.ws",
                "/usr/bin/sudo.ws",
                "/usr/bin/sudoreplay.ws",
                "/usr/sbin/sudo_sendlog.ws",
                "/usr/sbin/visudo.ws",
                "/usr/lib/sudo/sudoers.so",
            ],
        ),
        (
            "linux-tools-common",
            "7.0.0-31.31",
            "7.0.0-34.34",
            vec![
                "/usr/bin/acpidbg",
                "/usr/bin/cpupower",
                "/usr/bin/rtla",
                "/usr/bin/bpftrace",
                "/usr/bin/usbipd",
                "/usr/bin/turbostat",
                "/usr/bin/x86_energy_perf_policy",
            ],
        ),
        (
            "google-chrome-stable",
            "153.0.8010.52-1",
            "154.0.8037.57-1",
            vec!["/opt/google/chrome/google-chrome"],
        ),
        (
            "linux-perf",
            "7.0.0-31.31",
            "7.0.0-34.34",
            vec!["/usr/bin/perf"],
        ),
        (
            "bpftool",
            "7.7.0+7.0.0-31.31",
            "7.7.0+7.0.0-34.34",
            vec!["/usr/sbin/bpftool"],
        ),
    ];

    let mut changes: Vec<ChangeResult> = Vec::new();
    let mut input = CorrelationInput::new();
    let mut tx = TransactionRecord::new(TransactionSource::Apt, T0);
    tx.end = Some(T0 + 18);
    tx.status = TransactionStatus::Completed;
    tx.actor = Some("ghost (1000)".into());

    for (name, from, to, paths) in &pkgs {
        let mut t = PackageTransition::new(*name, PackageAction::Upgrade)
            .with_versions(Some(*from), Some(*to));
        t.installed_complete = Some(true);
        tx.packages.push(t);
        input.installed.insert(name.to_string(), to.to_string());
        for path in paths {
            changes.push(detection(path));
            input
                .ownership
                .insert(PathBuf::from(*path), vec![name.to_string()]);
            input
                .observed_change_time
                .insert(PathBuf::from(*path), T0 + 3);
        }
    }

    // A package-owned config file: same transaction, different severity.
    let cron = "/etc/cron.daily/google-chrome";
    let mut cron_change = detection(cron);
    cron_change.severity = Severity::High;
    changes.push(cron_change);
    input.ownership.insert(
        PathBuf::from(cron),
        vec!["google-chrome-stable".to_string()],
    );
    input
        .observed_change_time
        .insert(PathBuf::from(cron), T0 + 3);

    // Two symlinks whose own objects never moved; only their shared target
    // was replaced. These must attach to the target's package, not read as
    // two more independent critical replacements.
    for alias in ["/usr/bin/google-chrome", "/usr/bin/gnome-www-browser"] {
        changes.push(ChangeResult {
            path: Arc::new(PathBuf::from(alias)),
            changes: vec![Change::SymlinkTargetReplaced {
                target: PathBuf::from("/opt/google/chrome/google-chrome"),
                old_target_inode: 17_861_045,
                new_target_inode: 17_828_087,
            }],
            severity: Severity::Critical,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        });
        input
            .observed_change_time
            .insert(PathBuf::from(alias), T0 + 3);
    }

    // Boot files no package in this transaction owns. A kernel postinst
    // regenerates these, so they land in the window without being explained
    // by it -- exactly the case that must stay visible.
    for p in [
        "/boot/grub/grub.cfg",
        "/boot/initrd.img",
        "/boot/initrd.img.old",
        "/boot/vmlinuz",
        "/boot/vmlinuz.old",
    ] {
        changes.push(detection(p));
        input.observed_change_time.insert(PathBuf::from(p), T0 + 5);
    }

    // Unrelated activity that merely coincided with the window.
    let gpg = "/home/ghost/.gnupg/reader_0.status";
    let mut gpg_change = detection(gpg);
    gpg_change.severity = Severity::Medium;
    changes.push(gpg_change);
    input
        .observed_change_time
        .insert(PathBuf::from(gpg), T0 + 9);

    input.transactions.push(tx);

    let correlation = correlate(&changes, &input);
    let scan = ScanResult {
        total_checked: 12_481,
        changes_found: changes.len() as u64,
        errors: 0,
        warnings: Vec::new(),
        changes,
        duration_ms: 1_200,
    };
    let report = CheckReport::from_scan(
        scan,
        CheckReportMeta {
            mode: ScanMode::Incremental,
            baseline_fingerprint: Some("fp".into()),
            baseline_established: Some(T0 - 200_000),
            hmac_signed: true,
            total_baseline_entries: 12_481,
            previous_check_at: None,
            previous_check_changes: None,
            db_path: PathBuf::from("/tmp/x.db"),
        },
    );
    (report, correlation)
}

fn wide_term() -> vigil::display::term::TermInfo {
    vigil::display::term::TermInfo {
        width: 100,
        height: 40,
        is_tty: false,
        supports_color: false,
    }
}

/// Order the report the way an operator reads it.
///
/// The first implementation appended the explanation to the rendered report,
/// putting it below every raw change, below "Next steps" and below the exit
/// code -- an afterthought to a report already scrolled past. The correction
/// is not simply to move it to the top: what needs a human comes first, and
/// the activity that explains the rest is context that follows it.
#[test]
fn triage_leads_and_explained_activity_follows_what_needs_review() {
    use vigil::display::render_check;
    use vigil::types::OutputFormat;

    let (report, correlation) = upgrade_scenario();
    let out = render_check(
        &report,
        OutputFormat::Human,
        &wide_term(),
        false,
        false,
        &correlation,
    );

    let triage = out
        .find("need review")
        .expect("the default view must lead with how much needs a human");
    let detail = out
        .find("Explained by package activity")
        .expect("the default view must carry an event summary");
    let next_steps = out
        .find("Next steps")
        .expect("next steps must still render");
    let unexplained = out
        .find("/boot/vmlinuz")
        .expect("an unexplained change must still be listed");

    assert!(
        triage < unexplained,
        "the triage line states the split and must come before any detail"
    );
    assert!(
        unexplained < detail,
        "what needs review must precede explained activity; an operator reads \
         for what to act on first and for context second"
    );
    assert!(
        detail < next_steps,
        "the explanation must sit inside the report, not after its closing \
         guidance"
    );
}

/// Correlation must cost less text than it saves.
#[test]
fn the_default_view_collapses_explained_changes() {
    use vigil::display::render_check;
    use vigil::types::OutputFormat;

    let (report, correlation) = upgrade_scenario();
    let term = wide_term();
    let plain = render_check(
        &report,
        OutputFormat::Human,
        &term,
        false,
        false,
        &vigil::correlate::CorrelationResult::default(),
    );
    let correlated = render_check(
        &report,
        OutputFormat::Human,
        &term,
        false,
        false,
        &correlation,
    );

    assert!(
        correlated.lines().count() < plain.lines().count(),
        "correlation made the default view longer ({} lines vs {}); it is meant \
         to replace a per-file wall with a summary, not print both",
        correlated.lines().count(),
        plain.lines().count()
    );

    assert!(
        !correlated.contains("/usr/bin/sudo.ws"),
        "an explained path was expanded in the default view as well as being \
         represented in the summary above it"
    );
}

/// Collapsing is only safe because nothing is lost.
#[test]
fn unexplained_changes_stay_prominent_and_verbose_shows_everything() {
    use vigil::display::render_check;
    use vigil::types::OutputFormat;

    let (report, correlation) = upgrade_scenario();
    let term = wide_term();

    let default = render_check(
        &report,
        OutputFormat::Human,
        &term,
        false,
        false,
        &correlation,
    );
    for p in ["/boot/vmlinuz", "/boot/initrd.img"] {
        assert!(
            default.contains(p),
            "{p} is explained by nothing and must never be collapsed"
        );
    }

    let verbose = render_check(
        &report,
        OutputFormat::Human,
        &term,
        true,
        false,
        &correlation,
    );
    for p in [
        "/usr/bin/sudo.ws",
        "/usr/bin/cvtsudoers.ws",
        "/usr/sbin/visudo.ws",
        "/usr/bin/perf",
        "/boot/vmlinuz",
        "/boot/initrd.img",
    ] {
        assert!(verbose.contains(p), "--verbose must still list {p}");
    }
}

/// Raw severity must survive the summary intact.
#[test]
fn raw_severity_totals_are_unchanged_by_collapsing() {
    use vigil::display::render_check;
    use vigil::types::OutputFormat;

    let (report, correlation) = upgrade_scenario();
    let out = render_check(
        &report,
        OutputFormat::Human,
        &wide_term(),
        false,
        false,
        &correlation,
    );
    assert!(
        out.contains("CRITICAL") && out.contains("raw severity unchanged"),
        "the summary must restate raw severity rather than soften it"
    );
}

/// A routine upgrade must not look like an incident.
///
/// This is the constraint the whole feature exists to satisfy. If an
/// authorised `apt upgrade` renders as a screen of CRITICAL, the operator
/// learns that CRITICAL does not track anything they must act on -- and a
/// signal that is always loud is one they turn off. Severity is never
/// rewritten to achieve this; prominence is allocated to what is unaccounted
/// for, and the explained remainder is stated at its real severity without
/// the visual weight.
#[test]
fn a_routine_upgrade_does_not_render_as_a_wall_of_critical() {
    use vigil::display::render_check;
    use vigil::types::OutputFormat;

    let (report, correlation) = upgrade_scenario();
    let out = render_check(
        &report,
        OutputFormat::Human,
        &wide_term(),
        false,
        false,
        &correlation,
    );

    // Derive what the bar *should* read from the correlation itself, so the
    // assertion tracks the fixture rather than a number copied out of one
    // run of the renderer.
    let explained = vigil::display::correlate::explained_paths(&correlation);
    let unexplained_critical = report
        .scan
        .changes
        .iter()
        .filter(|c| !explained.contains(c.path.as_ref()))
        .filter(|c| c.severity == Severity::Critical)
        .count() as u64;
    let total_critical = report
        .scan
        .changes
        .iter()
        .filter(|c| c.severity == Severity::Critical)
        .count() as u64;
    assert!(
        unexplained_critical < total_critical,
        "fixture must contain explained critical changes for this to mean \
         anything"
    );

    let bar = out
        .lines()
        .find(|l| l.contains("CRITICAL") && l.contains('█'))
        .expect("a severity bar must still be drawn for what needs review");
    let shown: u64 = bar
        .split_whitespace()
        .find_map(|t| t.parse::<u64>().ok())
        .expect("the bar must carry a count");
    assert_eq!(
        shown, unexplained_critical,
        "the severity bar reads {shown}, but {unexplained_critical} of \
         {total_critical} critical changes are unaccounted for. Sizing it by \
         the explained total is what trains an operator to ignore it: {bar}"
    );

    // Severity is restated, not softened.
    assert!(
        out.contains("raw severity unchanged"),
        "the explained block must still name the severities it covers"
    );

    // One line must say how much needs a human, before any detail.
    assert!(
        out.contains("need review") || out.contains("needs review"),
        "the report must lead with how much actually needs attention"
    );
}

/// The two Chrome symlinks must attach to the package that replaced their
/// target, not read as two more independent critical replacements.
///
/// This is the case that produced six HIGH deletions for one Snap refresh and
/// three spurious criticals for one Chrome upgrade: the link objects never
/// moved, only the file they both point at.
#[test]
fn unchanged_symlink_aliases_attach_to_the_package_that_moved_their_target() {
    use vigil::display::render_check;
    use vigil::types::OutputFormat;

    let (report, correlation) = upgrade_scenario();

    let explained = vigil::display::correlate::explained_paths(&correlation);
    for alias in ["/usr/bin/google-chrome", "/usr/bin/gnome-www-browser"] {
        assert!(
            explained.contains(&PathBuf::from(alias)),
            "{alias} is an unchanged link to a replaced target and must be \
             accounted for by the transaction that replaced it"
        );
    }

    // And they must not be presented as things needing review.
    let out = render_check(
        &report,
        OutputFormat::Human,
        &wide_term(),
        false,
        false,
        &correlation,
    );
    let review_section = out
        .split("Explained by package activity")
        .next()
        .unwrap_or("");
    for alias in ["/usr/bin/google-chrome", "/usr/bin/gnome-www-browser"] {
        assert!(
            !review_section.contains(alias),
            "{alias} was presented as needing review despite its link object \
             being unchanged"
        );
    }
}

/// An unrelated change that merely lands inside the window must not be
/// absorbed by it.
///
/// Timestamp proximity is not causation. The GPG keyring write happened
/// during the upgrade and is owned by no package in it, so it has to survive
/// as something the operator sees.
#[test]
fn coincidental_activity_in_the_window_is_not_absorbed() {
    use vigil::display::render_check;
    use vigil::types::OutputFormat;

    let (report, correlation) = upgrade_scenario();
    let gpg = PathBuf::from("/home/ghost/.gnupg/reader_0.status");

    let explained = vigil::display::correlate::explained_paths(&correlation);
    assert!(
        !explained.contains(&gpg),
        "a change owned by no package in the transaction was absorbed by it \
         on timing alone"
    );

    let out = render_check(
        &report,
        OutputFormat::Human,
        &wide_term(),
        false,
        false,
        &correlation,
    );
    assert!(
        out.contains("reader_0.status"),
        "unrelated activity must remain visible in the default view"
    );
}
