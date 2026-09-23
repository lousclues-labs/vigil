//! External command and format contracts.
//!
//! # Why this file exists
//!
//! Every parser in the correlation layer is tested against fixtures. Fixtures
//! prove the parser handles the input it is *given*; they cannot prove the code
//! asks the tool for that input in the first place.
//!
//! That gap shipped a real bug. `snap changes` prints relative timestamps
//! ("yesterday at 13:24 EDT") unless `--abs-time` is passed. Every unit test
//! passed against RFC3339 fixtures while the live code, which did not pass the
//! flag, received four whitespace tokens where it expected one and silently
//! produced nothing. The feature was inert on real machines and green in CI.
//!
//! These tests pin the two halves together:
//!
//! 1. **Invocation contracts** — the exact argument vectors the code sends to
//!    external tools. Changing an invocation without revisiting the parser
//!    fails here.
//! 2. **Format contracts** — fixtures captured verbatim from real tool output,
//!    with a note recording where each came from, so a parser cannot be
//!    "fixed" into accepting a shape the tool never emits.
//!
//! When a tool genuinely changes its output, update the fixture *and* say so in
//! the comment. Do not relax an assertion to make a test pass.

use std::fs;
use std::path::{Path, PathBuf};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source(rel: &str) -> String {
    fs::read_to_string(manifest().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Strip line comments so a contract cannot be "satisfied" by prose.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── 1. Invocation contracts ────────────────────────────────

/// snapd prints relative times by default. Both snap invocations must ask for
/// absolute ones, because the parsers require a single-token timestamp.
///
/// Verified against snapd on a live host:
///   `snap changes`            -> `61  Done  yesterday at 13:24 EDT  ...`
///   `snap changes --abs-time` -> `61  Done  2026-09-21T13:24:14-04:00  ...`
#[test]
fn snap_is_always_invoked_with_abs_time() {
    let code = code_only(&source("src/correlate/snap.rs"));

    for invocation in [
        r#"&["changes", "--abs-time"]"#,
        r#"&["tasks", "--abs-time""#,
    ] {
        assert!(
            code.contains(invocation),
            "snap invocation contract broken: expected `{invocation}` in \
             src/correlate/snap.rs. snapd prints relative timestamps without \
             --abs-time, which shifts every column and makes the parser read \
             garbage while every fixture test still passes."
        );
    }

    // And no bare invocation may creep back in alongside it.
    for bare in [r#"&["changes"]"#, r#"&["tasks", &change.id]"#] {
        assert!(
            !code.contains(bare),
            "snap invocation contract broken: `{bare}` requests relative \
             timestamps. Pass --abs-time."
        );
    }
}

/// `run_snap` is the only way this module may reach snapd, so the flag
/// contract above cannot be bypassed by a second call site.
#[test]
fn snap_has_a_single_invocation_helper() {
    let code = code_only(&source("src/correlate/snap.rs"));
    let spawns = code.matches("Command::new(").count();
    assert_eq!(
        spawns, 1,
        "src/correlate/snap.rs must reach snapd through exactly one helper; \
         found {spawns} spawn sites, so the --abs-time contract is bypassable."
    );
    assert!(
        code.contains("Command::new(SNAP_PATH)"),
        "snapd must be invoked by absolute path, not via PATH lookup."
    );
}

/// Package-manager binaries are invoked by absolute path everywhere, so a
/// hostile PATH cannot substitute them.
#[test]
fn package_tools_are_invoked_by_absolute_path() {
    let code = code_only(&source("src/package.rs"));
    for bad in [
        r#"Command::new("dpkg")"#,
        r#"Command::new("rpm")"#,
        r#"Command::new("pacman")"#,
        r#"Command::new("dpkg-query")"#,
    ] {
        assert!(
            !code.contains(bad),
            "PATH-relative invocation {bad} in src/package.rs; use the absolute \
             path constant."
        );
    }
}

/// Subprocess arguments are passed as arrays. A shell would make every package
/// name, path and unit name a potential injection point.
#[test]
fn no_shell_is_used_to_reach_external_tools() {
    for file in [
        "src/package.rs",
        "src/correlate/snap.rs",
        "src/correlate/apt.rs",
        "src/correlate/mod.rs",
        "src/correlate/engine.rs",
    ] {
        let code = code_only(&source(file));
        for shell in [
            r#"Command::new("sh")"#,
            r#"Command::new("bash")"#,
            r#"Command::new("/bin/sh")"#,
            "-c\").arg(",
        ] {
            assert!(
                !code.contains(shell),
                "{file} reaches a tool through a shell ({shell}); untrusted \
                 values would become code."
            );
        }
    }
}

/// The log paths the APT collector reads are the real ones.
///
/// Pinning `normalize_owner_field` at the call site, not just testing the
/// function, is deliberate: a unit test of the normalizer passes whether or
/// not anything calls it. The wiring is the part that broke.
#[test]
fn dpkg_owner_field_is_normalized_before_correlation_uses_it() {
    let code = code_only(&source("src/correlate/mod.rs"));
    assert!(
        code.contains("normalize_owner_field"),
        "src/correlate/mod.rs must normalize `dpkg -S` owner fields before \
         populating the ownership map. Raw owners are arch-qualified \
         (`libc6:amd64`) while transactions and the package database say \
         `libc6`, so unnormalized names match nothing and every multi-arch \
         package in an upgrade silently fails to correlate."
    );
}

#[test]
fn apt_collector_reads_the_canonical_log_paths() {
    let code = code_only(&source("src/correlate/apt.rs"));
    for path in [
        "/var/log/apt/history.log",
        "/var/log/dpkg.log",
        "/var/lib/dpkg/status",
    ] {
        assert!(
            code.contains(path),
            "APT collector no longer references {path}; the evidence source \
             moved without the parser being revisited."
        );
    }
}

// ── 2. Format contracts ────────────────────────────────────

/// Captured verbatim from `dpkg -S` on a Debian-family host:
///
/// ```text
/// $ dpkg -S /usr/bin/gs
/// ghostscript: /usr/bin/gs
/// $ dpkg -S /usr/lib/x86_64-linux-gnu/libc.so.6
/// libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6
/// $ dpkg -S /etc/init.d
/// bluez, libvirt-daemon-common, apparmor, ...: /etc/init.d
/// ```
///
/// The arch qualifier is the trap: `/var/log/apt/history.log` and
/// `/var/lib/dpkg/status` both say `libc6`, so an unnormalized `libc6:amd64`
/// matches no transaction and every shared-library package in an upgrade goes
/// uncorrelated.
#[test]
fn dpkg_owner_field_shapes_are_handled() {
    use vigil::package::normalize_owner_field;

    assert_eq!(normalize_owner_field("ghostscript"), vec!["ghostscript"]);
    assert_eq!(
        normalize_owner_field("libc6:amd64"),
        vec!["libc6"],
        "the arch qualifier must be stripped to match transaction records"
    );
    assert_eq!(
        normalize_owner_field("bluez, libvirt-daemon-common, apparmor"),
        vec!["bluez", "libvirt-daemon-common", "apparmor"],
        "a multi-owner path must yield each owner, not one concatenated name"
    );
}

/// Captured verbatim from `/var/log/apt/history.log`, including an
/// arch-qualified package and an epoch-bearing version.
#[test]
fn real_apt_history_stanza_parses() {
    use vigil::correlate::TransactionStatus;

    let real = "\
Start-Date: 2026-09-01  06:06:14
Commandline: /usr/bin/unattended-upgrade
Requested-By: operator (1000)
Upgrade: libjavascriptcoregtk-4.1-0:amd64 (2.52.3-0ubuntu0.26.04.3, 2.52.6-0ubuntu0.26.04.1), gir1.2-webkit2-4.1:amd64 (2.52.3-0ubuntu0.26.04.3, 2.52.6-0ubuntu0.26.04.1)
End-Date: 2026-09-01  06:06:19
";
    let (txs, errs) = vigil::correlate::apt::parse_apt_history(real);
    assert!(errs.is_empty(), "real history must parse cleanly: {errs:?}");
    assert_eq!(txs.len(), 1);

    let tx = &txs[0];
    assert_eq!(tx.status, TransactionStatus::Completed);
    assert_eq!(tx.duration_secs(), Some(5));

    // Arch-stripped, so it compares equal to a normalized dpkg -S owner.
    let pkg = tx
        .package("libjavascriptcoregtk-4.1-0")
        .expect("arch suffix must be stripped from transaction records");
    assert_eq!(pkg.old_version.as_deref(), Some("2.52.3-0ubuntu0.26.04.3"));
    assert_eq!(pkg.new_version.as_deref(), Some("2.52.6-0ubuntu0.26.04.1"));
}

/// The end-to-end name contract: a `dpkg -S` owner and an apt-history package
/// name must compare equal after normalization. This is the join the whole
/// APT correlation path depends on.
#[test]
fn owner_names_and_transaction_names_meet_after_normalization() {
    use vigil::package::normalize_owner_field;

    let history = "\
Start-Date: 2026-09-01  06:06:14
Upgrade: libc6:amd64 (2.41-6ubuntu1, 2.41-6ubuntu2)
End-Date: 2026-09-01  06:06:19
";
    let (txs, _) = vigil::correlate::apt::parse_apt_history(history);
    let tx = &txs[0];

    // What `dpkg -S /usr/lib/x86_64-linux-gnu/libc.so.6` really prints.
    let owners = normalize_owner_field("libc6:amd64");

    assert!(
        owners.iter().any(|o| tx.package(o).is_some()),
        "ownership names and transaction names must meet: owners={owners:?}, \
         transaction packages={:?}. If this fails, every multi-arch package in \
         an upgrade silently fails to correlate.",
        tx.packages.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

/// Captured verbatim from `snap changes --abs-time` and `snap tasks
/// --abs-time` during a real two-snap auto-refresh.
#[test]
fn real_snap_transcript_parses_and_yields_both_revisions() {
    let changes_text = "\
ID   Status  Spawn                      Ready                      Summary
61   Done    2026-09-21T13:24:14-04:00  2026-09-21T13:24:20-04:00  Auto-refresh snaps \"desktop-security-center\", \"prompting-client\"
";
    let tasks_text = "\
Status  Spawn                      Ready                      Summary
Done    2026-09-21T13:24:14-04:00  2026-09-21T13:24:15-04:00  Download snap \"desktop-security-center\" (188) from channel \"1/stable/ubuntu-26.04\"
Done    2026-09-21T13:24:16-04:00  2026-09-21T13:24:17-04:00  Make current revision for snap \"desktop-security-center\" unavailable
Done    2026-09-21T13:24:18-04:00  2026-09-21T13:24:19-04:00  Make snap \"desktop-security-center\" (188) available to the system
Done    2026-09-21T13:24:19-04:00  2026-09-21T13:24:20-04:00  Remove snap \"desktop-security-center\" (150) from the system
";

    let (mut changes, errs) = vigil::correlate::snap::parse_snap_changes(changes_text);
    assert!(errs.is_empty(), "real snap changes must parse: {errs:?}");
    assert_eq!(changes.len(), 1);

    let (tasks, errs) = vigil::correlate::snap::parse_snap_tasks(tasks_text);
    assert!(errs.is_empty(), "real snap tasks must parse: {errs:?}");
    changes[0].tasks = tasks;

    let tx = vigil::correlate::snap::change_to_transaction(&changes[0]);
    let pkg = tx.package("desktop-security-center").expect("snap present");
    assert_eq!(
        pkg.old_version.as_deref(),
        Some("150"),
        "the removed revision must be the old one, or the deleted \
         snap-...-150.mount unit can never be attributed"
    );
    assert_eq!(pkg.new_version.as_deref(), Some("188"));
}

/// The default (relative-time) shape must be rejected, not silently accepted.
/// This is the exact output that shipped broken.
#[test]
fn relative_time_snap_output_is_rejected() {
    let default_shape = "\
ID   Status  Spawn                   Ready                   Summary
61   Done    yesterday at 13:24 EDT  yesterday at 13:24 EDT  Auto-refresh snaps \"firefox\"
";
    let (changes, errs) = vigil::correlate::snap::parse_snap_changes(default_shape);
    assert!(
        changes.is_empty(),
        "relative-time output must not become a transaction: {changes:?}"
    );
    assert!(
        !errs.is_empty(),
        "rejecting a row must be reported, not silent"
    );
}

/// Captured verbatim from `/var/log/dpkg.log`.
#[test]
fn real_dpkg_log_lines_parse() {
    let real = "\
2026-09-01 06:06:14 startup archives unpack
2026-09-01 06:06:15 upgrade libc6:amd64 2.41-6ubuntu1 2.41-6ubuntu2
2026-09-01 06:06:16 status half-configured libc6:amd64 2.41-6ubuntu2
2026-09-01 06:06:17 status installed libc6:amd64 2.41-6ubuntu2
2026-09-01 06:06:18 trigproc libc-bin:amd64 2.41-6ubuntu2 <none>
";
    let (entries, errs) = vigil::correlate::apt::parse_dpkg_log(real);
    assert!(
        errs.is_empty(),
        "real dpkg log must parse cleanly: {errs:?}"
    );

    let reached = vigil::correlate::apt::packages_reaching_installed(&entries, 0, i64::MAX);
    assert_eq!(
        reached.get("libc6").map(String::as_str),
        Some("2.41-6ubuntu2"),
        "completion evidence must be keyed by the arch-stripped name"
    );
}

/// Captured verbatim from `/var/lib/dpkg/status`. `Package:` carries no arch
/// qualifier there, which is why the other two sources must be stripped to it.
#[test]
fn real_dpkg_status_stanza_parses() {
    let real = "\
Package: libc6
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 2.41-6ubuntu2

Package: half-done
Status: install ok half-configured
Version: 1.0
";
    let installed = vigil::correlate::apt::parse_installed_packages(real);
    assert_eq!(
        installed.get("libc6").map(String::as_str),
        Some("2.41-6ubuntu2")
    );
    assert!(
        !installed.contains_key("half-done"),
        "only `install ok installed` is a complete install"
    );
}

// ── 3. The contract on this file ───────────────────────────

/// Every fixture here must say where it came from, so a future reader can tell
/// a captured shape from an invented one.
#[test]
fn every_format_contract_records_its_provenance() {
    let text = source("tests/external_format_contracts.rs");
    let markers = ["Captured verbatim", "Verified against"];
    let count: usize = markers.iter().map(|m| text.matches(m).count()).sum();
    assert!(
        count >= 6,
        "format contracts must document where their fixtures came from; \
         found {count} provenance markers. An undocumented fixture is an \
         assumption wearing a test's clothes."
    );
}

/// The correlation layer must not reach a tool this file does not pin.
#[test]
fn no_unpinned_external_invocations_in_the_correlation_layer() {
    let dir = manifest().join("src/correlate");
    let mut spawn_sites = Vec::new();
    collect_spawn_sites(&dir, &mut spawn_sites);

    // snap.rs::run_snap is the only sanctioned one, and it is pinned above.
    assert_eq!(
        spawn_sites,
        vec!["snap.rs".to_string()],
        "an unpinned external invocation appeared in src/correlate. Add its \
         invocation and format contract here before relying on its output."
    );
}

fn collect_spawn_sites(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_spawn_sites(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let code = code_only(&fs::read_to_string(&path).unwrap_or_default());
            if code.contains("Command::new(") {
                out.push(
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                );
            }
        }
    }
    out.sort();
    out.dedup();
}

/// Captured verbatim from `/var/log/apt/history.log`:
///
/// ```text
/// Install: libsuil-0-0:amd64 (0.10.24-1, automatic), audacity:amd64 (3.7.7+dfsg-1), ...
/// ```
///
/// `automatic` marks a dependency install. Read as a version it becomes the
/// recorded "new version", which then cannot equal the installed version — so
/// an ordinary `apt install` grades as conflicting evidence. That is a false
/// alarm on the exact workflow this feature exists to explain.
#[test]
fn apt_automatic_dependency_marker_is_not_read_as_a_version() {
    let real = "\
Start-Date: 2026-09-01  06:06:14
Install: libsuil-0-0:amd64 (0.10.24-1, automatic), audacity:amd64 (3.7.7+dfsg-1)
End-Date: 2026-09-01  06:06:19
";
    let (txs, errs) = vigil::correlate::apt::parse_apt_history(real);
    assert!(errs.is_empty(), "{errs:?}");

    let dep = txs[0].package("libsuil-0-0").expect("dependency present");
    assert_eq!(
        dep.new_version.as_deref(),
        Some("0.10.24-1"),
        "the version, not the `automatic` flag, is the installed version"
    );
    assert_eq!(
        dep.old_version, None,
        "an install has no previous version; `automatic` must not become one"
    );

    let explicit = txs[0]
        .package("audacity")
        .expect("explicit install present");
    assert_eq!(explicit.new_version.as_deref(), Some("3.7.7+dfsg-1"));
}

/// An upgrade's two-version list must still be read as (old, new).
#[test]
fn apt_upgrade_version_pair_is_unaffected_by_the_automatic_filter() {
    let real = "\
Start-Date: 2026-09-01  06:06:14
Upgrade: ghostscript:amd64 (10.06.0~dfsg-3ubuntu1, 10.06.0~dfsg-3ubuntu1.1)
End-Date: 2026-09-01  06:06:19
";
    let (txs, _) = vigil::correlate::apt::parse_apt_history(real);
    let p = txs[0].package("ghostscript").unwrap();
    assert_eq!(p.old_version.as_deref(), Some("10.06.0~dfsg-3ubuntu1"));
    assert_eq!(p.new_version.as_deref(), Some("10.06.0~dfsg-3ubuntu1.1"));
}

/// Captured verbatim from `snap tasks --abs-time 61`: snapd appends a dotted
/// separator and its own log lines after the task table. Treating those as
/// malformed task rows reported parse errors on every healthy refresh.
#[test]
fn snap_trailing_log_section_is_not_reported_as_malformed() {
    let real = "\
Status  Spawn                      Ready                      Summary
Done    2026-09-21T13:24:19-04:00  2026-09-21T13:24:20-04:00  Remove snap \"desktop-security-center\" (150) from the system

......................................................................

2026-09-21T13:24:20-04:00 INFO No re-refreshes found.
";
    let (tasks, errs) = vigil::correlate::snap::parse_snap_tasks(real);
    assert_eq!(tasks.len(), 1, "only the real task row is a task");
    assert!(
        errs.is_empty(),
        "snapd's own log output is not a malformed task row: {errs:?}"
    );
}

/// The window test must key on **ctime**, never mtime.
///
/// Measured on a Debian-family host. dpkg restores the mtime recorded in the
/// package archive (the upstream build date) rather than stamping install
/// time:
///
/// ```text
/// $ stat -c 'mtime=%y ctime=%z' /usr/bin/gs
/// mtime=2026-09-18 13:43:41 -0400   ctime=2026-09-22 00:07:14 -0400
/// ```
///
/// The transaction that installed it ran `2026-09-22 00:07:14..00:07:16`.
/// Counting every regular file the package ships:
///
/// ```text
/// ghostscript: 42 files -> mtime in window: 0   ctime in window: 42
/// ```
///
/// An mtime-keyed window is therefore a hard filter that rejects every genuine
/// package file, and the APT correlation path produces nothing on a real
/// system while fixture tests — which supply a timestamp inside the window —
/// all pass.
///
/// ctime is also the harder of the two to forge: `utimes(2)` sets mtime to any
/// value, which would let an attacker place a tampered file inside a
/// transaction window and borrow its explanation. Nothing sets ctime directly.
#[test]
fn the_transaction_window_is_keyed_on_ctime_not_mtime() {
    let code = code_only(&source("src/correlate/mod.rs"));

    assert!(
        code.contains("meta.ctime()"),
        "observed_times must record ctime; dpkg restores mtime from the package \
         archive, so an mtime-keyed window matches no real package file."
    );
    assert!(
        !code.contains("meta.mtime()"),
        "observed_times must not record mtime for window matching: it is the \
         package build date, and it is settable with utimes(2)."
    );

    let engine = code_only(&source("src/correlate/engine.rs"));
    assert!(
        engine.contains("observed_change_time"),
        "the engine must consume the ctime-keyed map"
    );
    assert!(
        !engine.contains("observed_mtime"),
        "no mtime-keyed window check may remain in the engine"
    );
}

/// Demonstrates the failure numerically, without touching the host: a file
/// carrying a build-date mtime and an install-time ctime must correlate.
#[test]
fn a_package_file_with_a_build_date_timestamp_still_correlates() {
    use std::path::PathBuf;
    use std::sync::Arc;
    use vigil::correlate::{
        correlate, CorrelationInput, PackageAction, PackageTransition, TransactionRecord,
        TransactionSource, TransactionStatus,
    };
    use vigil::package::PackageVerification;
    use vigil::types::{Change, ChangeResult, Severity};

    // Transaction ran at T; the file's mtime is four days earlier.
    const INSTALL: i64 = 1_790_050_034;
    const BUILD: i64 = INSTALL - 4 * 24 * 3600;

    let change = ChangeResult {
        path: Arc::new(PathBuf::from("/usr/bin/gs")),
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
    };

    let mut tx = TransactionRecord::new(TransactionSource::Apt, INSTALL);
    tx.end = Some(INSTALL + 2);
    tx.status = TransactionStatus::Completed;
    let mut t = PackageTransition::new("ghostscript", PackageAction::Upgrade).with_versions(
        Some("10.06.0~dfsg-3ubuntu1"),
        Some("10.06.0~dfsg-3ubuntu1.1"),
    );
    t.installed_complete = Some(true);
    tx.packages.push(t);
    tx.normalize();

    let mut input = CorrelationInput::new();
    input.transactions.push(tx);
    input.ownership.insert(
        PathBuf::from("/usr/bin/gs"),
        vec!["ghostscript".to_string()],
    );
    input
        .verification
        .insert("/usr/bin/gs".to_string(), PackageVerification::Verified);
    input.installed.insert(
        "ghostscript".to_string(),
        "10.06.0~dfsg-3ubuntu1.1".to_string(),
    );
    // The value the collector supplies is ctime: install time, not BUILD.
    input
        .observed_change_time
        .insert(PathBuf::from("/usr/bin/gs"), INSTALL + 1);

    let result = correlate(std::slice::from_ref(&change), &input);
    assert_eq!(
        result.events.len(),
        1,
        "a package file installed inside the window must correlate even though \
         its mtime ({BUILD}) predates the transaction"
    );
    assert!(result.uncorrelated.is_empty());
}

/// Captured verbatim from `dpkg -S` on a host with diversions:
///
/// ```text
/// $ dpkg -S -- /lib64/ld-linux-x86-64.so.2
/// diversion by libc6 from: /lib64/ld-linux-x86-64.so.2
/// diversion by libc6 to: /lib64/ld-linux-x86-64.so.2.usr-is-merged
/// ```
///
/// Splitting those on `": "` yields the package name
/// `"diversion by libc6 from"`, which matches no transaction and was rendered
/// to the operator verbatim.
#[test]
fn dpkg_diversion_lines_are_not_treated_as_owners() {
    let code = code_only(&source("src/package.rs"));
    assert!(
        code.contains(r#"line.starts_with("diversion by ")"#),
        "batch_query_dpkg must skip `diversion by ...` records; otherwise the \
         prose becomes a package name for every diverted path."
    );

    use vigil::package::normalize_owner_field;
    let owners = normalize_owner_field("diversion by libc6 from");
    assert!(
        owners.iter().all(|o| !o.contains(' ')),
        "a package name never contains a space; got {owners:?}"
    );
}

/// Package names must be normalized identically wherever they originate.
///
/// Measured on a stock Ubuntu host: 1430 of 2842 `/var/lib/dpkg/info/*.list`
/// filenames are arch-qualified (`libc6:amd64.list`), while
/// `/var/lib/dpkg/status` and `/var/log/apt/history.log` both say `libc6`.
/// The bulk cache derives the baseline's `package` column from those
/// filenames, so leaving the qualifier on recorded a name for over half of all
/// packages that no other source in the system uses.
#[test]
fn package_names_are_normalized_wherever_they_originate() {
    use vigil::package::strip_arch_qualifier;

    assert_eq!(strip_arch_qualifier("libc6:amd64"), "libc6");
    assert_eq!(strip_arch_qualifier("ghostscript"), "ghostscript");
    assert_eq!(strip_arch_qualifier("zlib1g:i386"), "zlib1g");

    // The bulk cache builder must apply it to the .list filename.
    let code = code_only(&source("src/package.rs"));
    assert!(
        code.contains(r#"strip_arch_qualifier(name_str.trim_end_matches(".list"))"#),
        "build_cache_dpkg_once must strip the arch qualifier from .list \
         filenames; otherwise the baseline's package column disagrees with \
         every other source."
    );

    // And the ownership path must use the same helper, not its own copy.
    assert_eq!(
        code.matches("fn strip_arch_qualifier").count(),
        1,
        "exactly one definition of the arch-stripping rule"
    );
}
