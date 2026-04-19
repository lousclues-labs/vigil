use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rusqlite::params;
use tempfile::TempDir;

use vigil::attest;
use vigil::attest::diff::ChainComparison;
use vigil::attest::format::{Attestation, Scope};
use vigil::config;
use vigil::db::{audit_ops, baseline_ops};
use vigil::types::{
    BaselineEntry, BaselineSource, ContentFingerprint, FileIdentity, FileType, PermissionState,
    SecurityState,
};

fn test_config(tmp: &TempDir) -> vigil::config::Config {
    let mut cfg = config::default_config();
    cfg.daemon.db_path = tmp.path().join("baseline.db");
    cfg
}

fn mk_entry(path: &str, hash: &str, inode: u64) -> BaselineEntry {
    BaselineEntry {
        id: None,
        path: PathBuf::from(path),
        identity: FileIdentity {
            inode,
            device: 1,
            file_type: FileType::Regular,
            symlink_target: None,
        },
        content: ContentFingerprint {
            hash: hash.to_string(),
            size: 123,
        },
        permissions: PermissionState {
            mode: 0o644,
            owner_uid: 0,
            owner_gid: 0,
            capabilities: None,
        },
        security: SecurityState {
            xattrs: BTreeMap::new(),
            security_context: String::new(),
        },
        mtime: 1,
        package: None,
        source: BaselineSource::Manual,
        added_at: 1,
        updated_at: 1,
    }
}

fn insert_audit_event(
    conn: &rusqlite::Connection,
    ts: i64,
    path: &str,
    severity: &str,
    changes_json: &str,
) {
    let prev = audit_ops::get_last_chain_hash(conn)
        .unwrap()
        .unwrap_or_else(|| {
            blake3::hash(b"vigil-audit-chain-genesis")
                .to_hex()
                .to_string()
        });
    let chain_hash = audit_ops::compute_chain_hash(&prev, ts, path, changes_json, severity);

    conn.execute(
        "INSERT INTO audit_log (
            timestamp, path, changes_json, severity, monitored_group,
            process_json, package, maintenance, suppressed, hmac, chain_hash
        ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, 0, 0, NULL, ?5)",
        params![ts, path, changes_json, severity, chain_hash],
    )
    .unwrap();
}

fn seed_state(cfg: &vigil::config::Config) {
    let baseline_conn = vigil::db::open_baseline_db(cfg).unwrap();
    baseline_ops::upsert(&baseline_conn, &mk_entry("/etc/passwd", "abc123", 100)).unwrap();

    let audit_conn = vigil::db::open_audit_db(cfg).unwrap();
    insert_audit_event(&audit_conn, 1700000000, "/etc/passwd", "high", "[]");
}

fn create_attestation_file(
    cfg: &vigil::config::Config,
    out: &Path,
    key_path: &Path,
    scope: Scope,
    deterministic_time: Option<&str>,
) {
    let opts = attest::create::CreateOpts {
        scope,
        out_path: Some(out),
        key_path: Some(key_path),
        deterministic_time,
    };
    attest::create::create_attestation(cfg, &opts).unwrap();
}

fn read_attestation(path: &Path) -> Attestation {
    let bytes = std::fs::read(path).unwrap();
    attest::format::deserialize_attestation(&bytes).unwrap()
}

fn write_attestation(path: &Path, att: &Attestation) {
    let bytes = attest::format::serialize_attestation(att).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn attest_create_is_deterministic_with_pinned_time() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    seed_state(&cfg);

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out1 = tmp.path().join("one.vatt");
    let out2 = tmp.path().join("two.vatt");
    let fixed = "2026-04-18T14:22:01Z";

    create_attestation_file(&cfg, &out1, &key_path, Scope::Full, Some(fixed));
    create_attestation_file(&cfg, &out2, &key_path, Scope::Full, Some(fixed));

    let b1 = std::fs::read(&out1).unwrap();
    let b2 = std::fs::read(&out2).unwrap();
    assert_eq!(b1, b2, "pinned-time attestations must be byte-identical");
}

#[test]
fn attest_verify_accepts_format_v1() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    seed_state(&cfg);

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out = tmp.path().join("ok.vatt");
    create_attestation_file(
        &cfg,
        &out,
        &key_path,
        Scope::Full,
        Some("2026-04-18T14:22:01Z"),
    );

    let (report, _) = attest::verify::verify_attestation(&out, Some(&key_path)).unwrap();
    assert!(report.valid);
}

#[test]
fn attest_verify_rejects_unknown_format_version() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    seed_state(&cfg);

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out = tmp.path().join("bad-version.vatt");
    create_attestation_file(
        &cfg,
        &out,
        &key_path,
        Scope::Full,
        Some("2026-04-18T14:22:01Z"),
    );

    let mut att = read_attestation(&out);
    att.header.format_version = 999;
    write_attestation(&out, &att);

    let (report, _) = attest::verify::verify_attestation(&out, Some(&key_path)).unwrap();
    assert!(!report.valid);
    assert!(report
        .steps
        .iter()
        .any(|s| s.name == "Format version" && !s.passed));
}

#[test]
fn attest_tamper_detection_header_body_footer() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    seed_state(&cfg);

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let base = tmp.path().join("base.vatt");
    create_attestation_file(
        &cfg,
        &base,
        &key_path,
        Scope::Full,
        Some("2026-04-18T14:22:01Z"),
    );

    // Header tamper -> content hash mismatch
    let mut h = read_attestation(&base);
    h.header.host_id_hint.push_str("-tampered");
    let h_path = tmp.path().join("tamper-header.vatt");
    write_attestation(&h_path, &h);
    let (h_report, _) = attest::verify::verify_attestation(&h_path, Some(&key_path)).unwrap();
    assert!(!h_report.valid);
    assert!(h_report
        .steps
        .iter()
        .any(|s| s.name == "Content hash" && !s.passed));

    // Body tamper -> content hash mismatch
    let mut b = read_attestation(&base);
    if let Some(ref mut entries) = b.body.baseline_entries {
        entries[0].hash.push('x');
    }
    let b_path = tmp.path().join("tamper-body.vatt");
    write_attestation(&b_path, &b);
    let (b_report, _) = attest::verify::verify_attestation(&b_path, Some(&key_path)).unwrap();
    assert!(!b_report.valid);
    assert!(b_report
        .steps
        .iter()
        .any(|s| s.name == "Content hash" && !s.passed));

    // Footer tamper -> signature failure
    let mut f = read_attestation(&base);
    f.footer.signature[0] ^= 0xff;
    let f_path = tmp.path().join("tamper-footer.vatt");
    write_attestation(&f_path, &f);
    let (f_report, _) = attest::verify::verify_attestation(&f_path, Some(&key_path)).unwrap();
    assert!(!f_report.valid);
    assert!(f_report
        .steps
        .iter()
        .any(|s| s.name == "Signature" && !s.passed));
}

#[test]
fn attest_diff_against_current_detects_structural_change() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    seed_state(&cfg);

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out = tmp.path().join("state.vatt");
    create_attestation_file(
        &cfg,
        &out,
        &key_path,
        Scope::BaselineOnly,
        Some("2026-04-18T14:22:01Z"),
    );
    let att = read_attestation(&out);

    // mutate baseline after attestation
    let baseline_conn = vigil::db::open_baseline_db(&cfg).unwrap();
    baseline_ops::upsert(&baseline_conn, &mk_entry("/etc/passwd", "zzz999", 100)).unwrap();

    let report = attest::diff::diff_against_current(&att, &cfg).unwrap();
    assert_eq!(report.changed.len(), 1);
}

#[test]
fn attest_diff_against_current_detects_chain_fork() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    seed_state(&cfg);

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out = tmp.path().join("fork.vatt");
    create_attestation_file(
        &cfg,
        &out,
        &key_path,
        Scope::Full,
        Some("2026-04-18T14:22:01Z"),
    );
    let att = read_attestation(&out);

    // Rewrite audit chain to a new branch.
    let audit_conn = vigil::db::open_audit_db(&cfg).unwrap();
    audit_conn.execute("DELETE FROM audit_log", []).unwrap();
    insert_audit_event(&audit_conn, 1700000100, "/etc/shadow", "critical", "[]");

    let report = attest::diff::diff_against_current(&att, &cfg).unwrap();
    assert!(matches!(report.chain_comparison, ChainComparison::Forked));
}

#[test]
fn attest_verify_is_standalone_without_local_state() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    seed_state(&cfg);

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out = tmp.path().join("portable.vatt");
    create_attestation_file(
        &cfg,
        &out,
        &key_path,
        Scope::Full,
        Some("2026-04-18T14:22:01Z"),
    );

    // Remove local DB state: verify should still work with file + key.
    std::fs::remove_file(&cfg.daemon.db_path).unwrap();
    let audit_path = vigil::db::audit_db_path(&cfg);
    std::fs::remove_file(audit_path).unwrap();

    let (report, _) = attest::verify::verify_attestation(&out, Some(&key_path)).unwrap();
    assert!(report.valid);
}

#[test]
fn attest_create_and_verify_empty_state() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);

    // Create empty baseline and empty audit databases.
    let _baseline_conn = vigil::db::open_baseline_db(&cfg).unwrap();
    let _audit_conn = vigil::db::open_audit_db(&cfg).unwrap();

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out = tmp.path().join("empty.vatt");
    create_attestation_file(
        &cfg,
        &out,
        &key_path,
        Scope::Full,
        Some("2026-04-18T14:22:01Z"),
    );

    let att = read_attestation(&out);
    assert_eq!(att.header.baseline_entry_count, 0);
    assert_eq!(att.header.audit_entry_count, 0);

    let (report, _) = attest::verify::verify_attestation(&out, Some(&key_path)).unwrap();
    assert!(report.valid);
}

#[test]
#[ignore = "large-state stress test"]
fn attest_large_state_100k_entries() {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);

    let baseline_conn = vigil::db::open_baseline_db(&cfg).unwrap();
    let tx = baseline_conn.unchecked_transaction().unwrap();
    for i in 0..100_000_u64 {
        let p = format!("/var/lib/test/file-{}", i);
        baseline_ops::upsert(&tx, &mk_entry(&p, "abc123", i + 1)).unwrap();
    }
    tx.commit().unwrap();

    let _audit_conn = vigil::db::open_audit_db(&cfg).unwrap();

    let key_path = tmp.path().join("attest.key");
    attest::key::generate_attest_key(&key_path).unwrap();

    let out = tmp.path().join("large.vatt");
    create_attestation_file(
        &cfg,
        &out,
        &key_path,
        Scope::BaselineOnly,
        Some("2026-04-18T14:22:01Z"),
    );

    let (report, _) = attest::verify::verify_attestation(&out, Some(&key_path)).unwrap();
    assert!(report.valid);
}
