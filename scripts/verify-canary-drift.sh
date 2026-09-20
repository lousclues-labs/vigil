#!/usr/bin/env bash
# Canary drift verification: prove every PDD canary fails when its promise is
# violated. A canary that stays green through a breach is theater.
#
# Each case: apply a mutation that breaks a promise, run the canary that
# guards it, require a FAILURE, then revert. Run from the repo root.
set -uo pipefail

cd "$(dirname "$0")/.."

PASS=0
FAIL=0

# Mutations are reverted from a pristine backup rather than from git, because
# the PDD documents and the canary workflow may not be committed yet.
BACKUP_DIR="$(mktemp -d)"
trap 'rm -rf "$BACKUP_DIR"' EXIT

TOUCHED=(
  src/monitor/fanotify.rs
  src/detection.rs
  src/util/process.rs
  src/types/snapshot.rs
  src/bloom.rs
  src/alert/mod.rs
  src/baseline_diff.rs
  src/db/audit_ops.rs
  src/doctor/checks.rs
  src/metrics.rs
  src/config/mod.rs
  src/scanner.rs
  src/package.rs
  Cargo.toml
  PROMISES.md
  .github/workflows/pdd-canaries.yml
  .github/workflows/release.yml
)

for f in "${TOUCHED[@]}"; do
  mkdir -p "$BACKUP_DIR/$(dirname "$f")"
  cp "$f" "$BACKUP_DIR/$f"
done

revert() {
  local f
  for f in "$@"; do
    if [ -f "$BACKUP_DIR/$f" ]; then
      cp "$BACKUP_DIR/$f" "$f"
    else
      git checkout -- "$f" 2>/dev/null || true
    fi
  done
}

# expect_red <canary test name> <description> [cargo target args]
#
# Defaults to the PDD canary suite. Some canaries live in the lib's own test
# module, so the target is overridable.
expect_red() {
  local test_name="$1"
  local desc="$2"
  local target="${3:---test pdd_canaries}"
  local rc=0

  # shellcheck disable=SC2086
  cargo test $target -- --exact "$test_name" >/tmp/canary_drift.log 2>&1 || rc=$?

  # A test name that matches nothing exits 0 and proves nothing. Without this
  # check a typo in a canary name reads as a passing drift case, which would
  # make the guard on the guards the very theater it exists to catch.
  if grep -qE '^test result: ok\. 0 passed' /tmp/canary_drift.log; then
    echo "  HARNESS BUG: $test_name matched no test in \`cargo test $target\`"
    FAIL=$((FAIL + 1))
    return
  fi

  if [ "$rc" -eq 0 ]; then
    echo "  THEATER: $test_name stayed green through: $desc"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: $test_name went red on: $desc"
    PASS=$((PASS + 1))
  fi
}

echo "== PR1 C-NOTIF-CLASS-ONLY =="
sed -i 's|^const FAN_CLASS_NOTIF: u32 = 0x0000_0000;|const FAN_CLASS_NOTIF: u32 = 0x0000_0000;\nconst FAN_OPEN_PERM: u32 = 0x0001_0000;|' src/monitor/fanotify.rs
expect_red watch_never_act_fanotify_is_notification_class_only "permission-class fanotify constant added"
revert src/monitor/fanotify.rs

echo "== PR2 C-NO-ACTUATION (mutation) =="
printf '\nfn quarantine_offender(p: &std::path::Path) { let _ = std::fs::remove_file(p); }\n' >> src/detection.rs
expect_red watch_never_act_detection_paths_contain_no_actuation "quarantine added to the detection path"
revert src/detection.rs

echo "== PR2 C-NO-ACTUATION (signal) =="
printf '\nfn terminate(pid: i32) { let _ = unsafe { libc::kill(pid, 9) }; }\n' >> src/util/process.rs
expect_red watch_never_act_kill_is_liveness_probe_only "kill(pid, 9) added"
revert src/util/process.rs

echo "== PR3 C-DETERMINISTIC-DIFF =="
sed -i 's|    pub fn diff(&self, baseline: \&BaselineEntry) -> Vec<Change> {\n        let mut changes = Vec::new();|&|' src/types/snapshot.rs
python3 - <<'PY'
import re
p = "src/types/snapshot.rs"
s = open(p).read()
needle = "    pub fn diff(&self, baseline: &BaselineEntry) -> Vec<Change> {\n        let mut changes = Vec::new();\n"
inject = needle + """        if std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
            % 2
            == 0
        {
            changes.push(Change::InodeChanged { old: 0, new: 1 });
        }
"""
assert needle in s, "diff() anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red determinism_diff_is_a_pure_function_of_snapshot_and_baseline "verdict made to depend on the clock"
revert src/types/snapshot.rs

echo "== PR4 C-NO-HEURISTICS (source) =="
printf '\npub fn risk_score(_c: &crate::types::ChangeResult) -> f32 { 0.72 }\n' >> src/detection.rs
expect_red determinism_detection_surface_has_no_scoring_or_ml "risk score added to the detection surface"
revert src/detection.rs

echo "== PR4 C-NO-HEURISTICS (dependency) =="
sed -i 's|^semver = "1"|semver = "1"\nlinfa = "0.7"|' Cargo.toml
expect_red determinism_dependency_set_has_no_ml_or_feed_crates "ML crate added to the manifest"
revert Cargo.toml

echo "== PR5 C-NO-FALSE-NEGATIVE-PREFILTER =="
python3 - <<'PY'
p = "src/bloom.rs"
s = open(p).read()
needle = "    pub fn might_contain_prefix_of(&self, path: &std::path::Path) -> bool {\n"
inject = needle + "        if path.components().count() > 3 {\n            return false;\n        }\n"
assert needle in s, "bloom anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red silence_prefilter_never_rejects_a_watched_path "prefilter given a false negative"
revert src/bloom.rs

echo "== PR6 C-CLEAN-IS-SILENT =="
python3 - <<'PY'
p = "src/types/snapshot.rs"
s = open(p).read()
needle = "        if self.content.hash != baseline.content.hash {"
inject = "        if self.content.hash == baseline.content.hash {"
assert needle in s, "content compare anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red silence_unchanged_file_yields_no_change_and_a_touched_file_does "content comparison inverted"
revert src/types/snapshot.rs

echo "== PR7 C-SUPPRESSED-STILL-AUDITED =="
python3 - <<'PY'
p = "src/alert/mod.rs"
s = open(p).read()
needle = """                    if !self.wal_active {
                        self.record_audit(&payload, suppressed);
                    }
                    if suppressed {"""
inject = """                    if !self.wal_active && !suppressed {
                        self.record_audit(&payload, suppressed);
                    }
                    if suppressed {"""
assert needle in s, "dispatcher anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red audit_truth_suppressed_alerts_are_still_recorded "suppression made to skip the audit write"
revert src/alert/mod.rs

echo "== PR8 C-AUDIT-CHAIN-TAMPER =="
python3 - <<'PY'
p = "src/db/audit_ops.rs"
s = open(p).read()
needle = "pub fn verify_chain(conn: &Connection) -> Result<AuditChainVerifyResult> {\n    verify_chain_with_hmac(conn, None)\n}"
inject = "pub fn verify_chain(conn: &Connection) -> Result<AuditChainVerifyResult> {\n    let (t, v, _b, m) = verify_chain_with_hmac(conn, None)?;\n    Ok((t, v, Vec::new(), m))\n}"
assert needle in s, "verify_chain anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red audit_truth_tampering_with_an_audit_row_breaks_the_chain "chain verification made to swallow breaks"
revert src/db/audit_ops.rs

echo "== PR18 C-OWNERSHIP-IS-NOT-PROOF =="
python3 - <<'PYX'
p = "src/baseline_diff.rs"
s = open(p).read()
needle = """        let verdict = verdicts
            .get(&entry.path)
            .copied()
            .unwrap_or(PackageVerification::Unknown);"""
inject = """        let verdict = verdicts
            .get(&entry.path)
            .copied()
            .unwrap_or(PackageVerification::Verified);"""
assert needle in s, "split_by_verification anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PYX
expect_red audit_truth_package_ownership_is_never_proof_of_authorship "missing verdict treated as verified"
revert src/baseline_diff.rs

echo "== PR18 C-OWNERSHIP-IS-NOT-PROOF (AF-013: silence outside coverage) =="
python3 - <<'PYX'
p = "src/package.rs"
s = open(p).read()
needle = """        None => match coverage {
            Some(covered) if !covered.contains(path) => PackageVerification::Unknown,
            _ => PackageVerification::Verified,
        },"""
inject = """        None => PackageVerification::Verified,"""
assert needle in s, "coverage gate anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PYX
expect_red package::tests::silence_about_a_path_with_no_recorded_digest_is_not_a_pass "coverage gate removed from the verdict" "--lib"
revert src/package.rs

echo "== PR9 C-DEGRADED-IS-LOUD =="
python3 - <<'PY'
p = "src/doctor/checks.rs"
s = open(p).read()
needle = """            status: CheckStatus::Warning,
            detail: "inotify fallback (reduced coverage)".to_string(),"""
inject = """            status: CheckStatus::Ok,
            detail: "inotify fallback".to_string(),"""
assert needle in s, "doctor fallback anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red fail_loud_degraded_backend_never_reports_ok "degraded backend made to report OK"
revert src/doctor/checks.rs

echo "== PR10 C-BLIND-SPOTS-COUNTED =="
python3 - <<'PY'
p = "src/metrics.rs"
s = open(p).read()
needle = "            events_dropped: self.events_dropped.load(Ordering::Relaxed),"
inject = "            events_dropped: 0,"
assert needle in s, "metrics anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red fail_loud_blind_spot_counters_are_exported "drop counter no longer exported"
revert src/metrics.rs

echo "== PR11 C-NO-NETWORK-DEPS (manifest) =="
sed -i 's|^semver = "1"|semver = "1"\nreqwest = "0.12"|' Cargo.toml
expect_red local_by_design_no_http_or_telemetry_dependencies "HTTP client added to the manifest"
revert Cargo.toml

echo "== PR11 C-NO-NETWORK-DEPS (source) =="
printf '\nfn phone_home() { let _ = std::net::TcpStream::connect("example.com:80"); }\n' >> src/scanner.rs
expect_red local_by_design_network_code_is_confined_to_the_two_opt_in_sinks "socket opened outside the opt-in sinks"
revert src/scanner.rs

echo "== PR12 C-EGRESS-OFF-BY-DEFAULT =="
python3 - <<'PY'
p = "src/config/mod.rs"
s = open(p).read()
needle = "            webhook_url: String::new(),"
inject = '            webhook_url: "http://example.com/alerts".to_string(),'
assert needle in s, "webhook default anchor not found"
open(p, "w").write(s.replace(needle, inject, 1))
PY
expect_red local_by_design_outbound_sinks_are_off_by_default "webhook turned on by default"
revert src/config/mod.rs

echo "== PR13 C-STANDS-ALONE =="
printf '\nconst SIBLING_DB: &str = "/var/lib/shroud/state.db";\n' >> src/package.rs
expect_red stands_alone_no_sibling_tool_coupling "sibling tool state path referenced"
revert src/package.rs

echo "== PR14 C-UNSAFE-BOUNDARY =="
printf '\n#[allow(unsafe_code)]\nfn widened_boundary() {}\n' >> src/metrics.rs
expect_red stands_alone_unsafe_is_confined_to_the_syscall_boundary "unsafe exemption added to a new module"
revert src/metrics.rs

echo "== PR15 C-CI-GATE =="
sed -i 's|    needs: \[watch-never-act, local-by-design, stands-alone, canary-tests, release-provenance\]|    needs: [watch-never-act, local-by-design, stands-alone, canary-tests]|' .github/workflows/pdd-canaries.yml
expect_red proof_ships_ci_gate_depends_on_every_canary_job "a canary job dropped from the gate"
revert .github/workflows/pdd-canaries.yml

echo "== PR16 C-RELEASE-PROVENANCE =="
sed -i 's|        uses: actions/attest-build-provenance@|        uses: actions/DISABLED-attestation@|' .github/workflows/release.yml
expect_red proof_ships_release_publishes_checksum_and_provenance "provenance attestation removed from the release"
revert .github/workflows/release.yml

echo "== PR17 C-PROMISE-SET-INTEGRITY (promise without canary) =="
python3 - <<'PYX'
p = "PROMISES.md"
s = open(p).read()
anchor = "## Aspirations (not yet promises: no canary yet)"
inject = """### PR99. Vigil is fast
An unguarded claim, injected to prove the promise-set canary catches it.

""" + anchor
assert anchor in s, "aspirations anchor not found"
open(p, "w").write(s.replace(anchor, inject, 1))
PYX
expect_red proof_ships_promise_set_has_no_unguarded_claims "promise added with no canary"
revert PROMISES.md

echo "== PR17 C-PROMISE-SET-INTEGRITY (canary that does not exist) =="
sed -i 's|`C-CLEAN-IS-SILENT`|`C-IMAGINARY-GUARD`|' PROMISES.md
expect_red proof_ships_promise_set_has_no_unguarded_claims "promise pointing at a canary that does not exist"
revert PROMISES.md

echo
echo "canaries proven to fail on drift: $PASS"
echo "canaries that stayed green (theater): $FAIL"
exit "$FAIL"
