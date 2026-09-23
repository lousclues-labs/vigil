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

    for verbose in [false, true] {
        let out = render_check(&report, OutputFormat::Human, &term, verbose, false);
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
