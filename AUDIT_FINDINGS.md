# Audit Findings

This is the ledger layer of Promise Driven Development (PDD) for Vigil
Baseline: the memory that keeps drift from returning. Each finding records a
claim that drifted or shipped unguarded, why it mattered, the change that
closed it, and the canary that now fails loudly if it recurs.

Rules:
- Findings are numbered and severity-graded, and tracked from open to closed.
- A finding closed without a canary is not closed. "Fixed" is not a status; a
  named canary is.
- New self-claims are expected to add a promise, a canary, and, when they
  correct drift, a finding here. See [CONTRIBUTING.md](CONTRIBUTING.md).

Severity: **High** (a safety or trust claim could be false without notice),
**Medium** (a detection or privacy claim could rot silently), **Low** (a
boundary could erode), **Info** (process gap).

This ledger is not the vulnerability record. A finding is about a *promise*
that stopped being provable. A vulnerability is about an attack that became
possible. Vulnerabilities live in
[docs/VULNERABILITIES.md](docs/VULNERABILITIES.md) under `VIGIL-VULN-*` IDs,
and the two cross-reference each other when one event is both.

| ID | Severity | Status | Promise | Canary |
|----|----------|--------|---------|--------|
| AF-001 | High | Closed | PR1, PR2 | C-NOTIF-CLASS-ONLY, C-NO-ACTUATION |
| AF-002 | Medium | Closed | PR3, PR4 | C-DETERMINISTIC-DIFF, C-NO-HEURISTICS |
| AF-003 | Medium | Closed | PR5, PR6 | C-NO-FALSE-NEGATIVE-PREFILTER, C-CLEAN-IS-SILENT |
| AF-004 | High | Closed | PR7, PR8 | C-SUPPRESSED-STILL-AUDITED, C-AUDIT-CHAIN-TAMPER |
| AF-005 | Medium | Closed | PR9, PR10 | C-DEGRADED-IS-LOUD, C-BLIND-SPOTS-COUNTED |
| AF-006 | Medium | Closed | PR11, PR12 | C-NO-NETWORK-DEPS, C-EGRESS-OFF-BY-DEFAULT |
| AF-007 | Low | Closed | PR13, PR14 | C-STANDS-ALONE, C-UNSAFE-BOUNDARY |
| AF-008 | Info | Closed | PR15, PR16, PR17 | C-CI-GATE, C-RELEASE-PROVENANCE, C-PROMISE-SET-INTEGRITY |
| AF-009 | Medium | Closed | PR2, PR4, PR11, PR13 | C-NO-ACTUATION and the other source scans, via `strip_test_code` |
| AF-010 | High | Closed | PR18 | C-OWNERSHIP-IS-NOT-PROOF |
| AF-011 | Medium | Closed | PR18 | C-OWNERSHIP-IS-NOT-PROOF (reporting half), hook surfacing |
| AF-012 | High | Closed | PR18 | `a_failed_verifier_run_is_never_reported_as_verified` |

---

## AF-001: "Watch, don't act" was a convention, not a guarded boundary

- **Severity:** High
- **Status:** Closed
- **Principle / Promise:** P1 / PR1, PR2

**What drifted.** [docs/PRINCIPLES.md](docs/PRINCIPLES.md) opens with "Vigil
Baseline is a watchman. It does not kill processes. It does not quarantine
files." The README repeats it: "It doesn't kill processes, quarantine files, or
block execution." Nothing in the tree enforced any of that. The fanotify
backend already used `FAN_CLASS_NOTIF`, which is the correct and deliberate
choice, but a contributor could have switched it to a permission class and
added a deny verdict, and every test would still have passed. The same was true
of adding a "helpful" auto-repair that re-permissioned a drifted file.

**Why it mattered.** This is the load-bearing claim of the whole tool. A
witness that can act will eventually act wrong, and it will act at the moment
the operator can least afford a surprise. The dangerous version of Vigil is the
one that quietly grew a remediation feature because it seemed convenient.

**Closing change.** PDD retrofit (this change set). No code behavior changed:
the boundary was already correct, and it is now enforced.

**Canary that prevents recurrence.**
`watch_never_act_fanotify_is_notification_class_only` (C-NOTIF-CLASS-ONLY),
`watch_never_act_detection_paths_contain_no_actuation` and
`watch_never_act_kill_is_liveness_probe_only` (C-NO-ACTUATION) in
[tests/pdd_canaries.rs](tests/pdd_canaries.rs), repeated as merge-blocking CI
greps in [.github/workflows/pdd-canaries.yml](.github/workflows/pdd-canaries.yml).

---

## AF-002: Determinism was asserted in prose, with nothing to stop a score

- **Severity:** Medium
- **Status:** Closed
- **Principle / Promise:** P2 / PR3, PR4

**What drifted.** "It does not guess. It does not infer. No machine learning,
behavioral analysis, or statistical models" was a principle with no guard. The
comparison in `FileSnapshot::diff` was pure, but nothing asserted that it
stayed pure, and nothing stopped a future commit from adding a confidence value
to a detection or a feed client to the manifest.

**Why it mattered.** The reason an operator can act on a Vigil alert is that
the alert is a fact, not an opinion. The first heuristic in the detection path
turns every alert into something the operator has to second-guess, and a tool
whose output you second-guess is a tool you eventually ignore.

**Closing change.** PDD retrofit (this change set). The Bloom prefilter is
named explicitly in [PROMISES.md](PROMISES.md) as the one probabilistic
structure, allowed because a "maybe" is always resolved by exact comparison and
never becomes a verdict.

**Canary that prevents recurrence.**
`determinism_diff_is_a_pure_function_of_snapshot_and_baseline`
(C-DETERMINISTIC-DIFF) evaluates the real diff 512 times over fixed inputs;
`determinism_detection_surface_has_no_scoring_or_ml` and
`determinism_dependency_set_has_no_ml_or_feed_crates` (C-NO-HEURISTICS) guard
the source and the manifest.

---

## AF-003: "Silence is the default" had no guard against silence-by-drop

- **Severity:** Medium
- **Status:** Closed
- **Principle / Promise:** P3 / PR5, PR6

**What drifted.** The project promises a quiet tool, and quiet was measured
only by the absence of alerts. But a dropped event looks exactly like a clean
system. The Bloom prefilter sits in front of every fanotify event, and its
one-sidedness (false positives are harmless, false negatives are catastrophic)
was documented in a comment in [src/bloom.rs](src/bloom.rs) and asserted only
by a unit test over four hand-written strings, not over the real default watch
set.

**Why it mattered.** Silence is the product. If silence can mean "an event was
discarded before it reached the comparison," then the tool's primary output
signal is ambiguous, and the operator has no way to tell the two cases apart.

**Closing change.** PDD retrofit (this change set). The prefilter canary now
builds the filter from the real `default_config()` watch set and asserts
acceptance for every watched path and for deep descendants of each.

**Canary that prevents recurrence.**
`silence_prefilter_never_rejects_a_watched_path`
(C-NO-FALSE-NEGATIVE-PREFILTER) and
`silence_unchanged_file_yields_no_change_and_a_touched_file_does`
(C-CLEAN-IS-SILENT), which exercises real capture and diff against a temporary
file.

---

## AF-004: The audit-truth claim was never driven end to end

- **Severity:** High
- **Status:** Closed
- **Principle / Promise:** P4 / PR7, PR8

**What drifted.** Principle XIII states that suppression affects notifications
and never the audit trail, and a comment in
[src/alert/mod.rs](src/alert/mod.rs) cites that principle at the exact line
where an inode-only package change is suppressed. The unit tests around it
called `write_audit_entry` directly, or checked `is_suppressed` in isolation.
No test drove a suppressed detection through the real dispatcher loop and then
looked in the audit database. Reordering two statements in `run()` would have
silently made suppression delete evidence, and the suite would have stayed
green.

**Why it mattered.** The audit log is the only record that survives the
operator not being at the keyboard. An attacker who moves during a maintenance
window is exactly the case the principle was written for, and it was the case
with the least test coverage.

**Closing change.** PDD retrofit (this change set). The canary spawns the real
`AlertDispatcher::run` loop, sends a duplicate inside the cooldown window, and
reads the audit database back.

**Canary that prevents recurrence.**
`audit_truth_suppressed_alerts_are_still_recorded`
(C-SUPPRESSED-STILL-AUDITED) and
`audit_truth_tampering_with_an_audit_row_breaks_the_chain`
(C-AUDIT-CHAIN-TAMPER).

---

## AF-005: Silent degradation was one refactor away

- **Severity:** Medium
- **Status:** Closed
- **Principle / Promise:** P5 / PR9, PR10

**What drifted.** "Fail open, fail loud" requires that a fallback backend or a
reduced event mask reach the operator as a warning. The doctor checks did that
correctly, by convention. Changing `CheckStatus::Warning` to `CheckStatus::Ok`
on the inotify fallback branch would have been a one-token diff that made a
half-blind daemon look healthy, and no test covered it.

**Why it mattered.** Principle X says it plainly: silent degradation is a
security vulnerability. An operator budgets their attention against the
coverage they believe they have. A green status on a degraded backend spends
that budget on a lie.

**Closing change.** PDD retrofit (this change set).

**Canary that prevents recurrence.**
`fail_loud_degraded_backend_never_reports_ok` (C-DEGRADED-IS-LOUD) reads the
fallback branches of `check_backend` and `check_realtime_coverage` and asserts
they carry a non-OK status and name the reduced coverage;
`fail_loud_blind_spot_counters_are_exported` (C-BLIND-SPOTS-COUNTED) asserts
the drop counters stay on the exported metrics snapshot.

---

## AF-006: "No network I/O" was a README sentence

- **Severity:** Medium
- **Status:** Closed
- **Principle / Promise:** P6 / PR11, PR12

**What drifted.** "No telemetry, no auto-updates, no network calls of any kind"
appeared in the README, and Principle XIV made it a value. The tree was
genuinely clean: two opt-in sinks, both off by default, and no HTTP client in
the manifest. None of it was enforced. One `reqwest` dependency added for
convenience, or one default that pre-filled a webhook URL, would have
contradicted the claim without breaking a single test.

**Why it mattered.** Local-only operation is why a file integrity monitor can
be trusted with a view of the whole filesystem. The claim is also the easiest
one in the project to break by accident, because network code arrives as a
transitive convenience rather than as a decision.

**Closing change.** PDD retrofit (this change set).

**Canary that prevents recurrence.**
`local_by_design_no_http_or_telemetry_dependencies` and
`local_by_design_network_code_is_confined_to_the_two_opt_in_sinks`
(C-NO-NETWORK-DEPS), `local_by_design_outbound_sinks_are_off_by_default`
(C-EGRESS-OFF-BY-DEFAULT), plus a CI job that greps the built `vigil` and
`vigild` binaries for telemetry hosts.

---

## AF-007: Independence and the unsafe boundary were unenforced

- **Severity:** Low
- **Status:** Closed
- **Principle / Promise:** P7 / PR13, PR14

**What drifted.** "Vigil Baseline Stands Alone" and "Complexity Is a
Vulnerability" were principles with tests only for module line counts and
cross-module import rules
([tests/architecture_invariants_test.rs](tests/architecture_invariants_test.rs)).
Nothing stopped a sibling-tool dependency, and nothing bounded where
`#[allow(unsafe_code)]` could appear. The crate-level `#![deny(unsafe_code)]`
in [src/lib.rs](src/lib.rs) was doing real work, but the exemption list could
have grown module by module without anyone noticing the trend.

**Why it mattered.** Coupling is how a tool that can be audited in isolation
stops being auditable. An unbounded unsafe allowlist is how a `#![deny]` turns
into decoration.

**Closing change.** PDD retrofit (this change set). The eleven syscall-boundary
modules are enumerated in [PROMISES.md](PROMISES.md); a twelfth entry is now a
promise review and a ledger entry.

**Canary that prevents recurrence.** `stands_alone_no_sibling_tool_coupling`
(C-STANDS-ALONE) and `stands_alone_unsafe_is_confined_to_the_syscall_boundary`
(C-UNSAFE-BOUNDARY).

---

## AF-008: The claims had no merge-blocking gate, and provenance was unnamed

- **Severity:** Info
- **Status:** Closed
- **Principle / Promise:** P8 / PR15, PR16, PR17

**What drifted.** Before this change set there was no promise set, so there was
nothing for CI to gate on. Separately, the release workflow already produced a
SHA256 checksum and a GitHub build-provenance attestation, which is a real
operator-verifiable proof, but it was never stated as a promise and never
guarded. Deleting the attestation step would have been an invisible downgrade
of what an operator could verify.

**Why it mattered.** A canary that does not block a merge is a suggestion. A
proof that is not named as a promise is an accident of the pipeline, and
accidents get optimized away. A promise set with no guard on its own structure
is how a project ends up with claims that sound guarded and are not.

**Closing change.** PDD retrofit (this change set). The `pdd-canary-gate` job
is the status branch protection should require, and the promise set is now held
to its own rules: every principle spawns a promise, every promise names a
canary, and every canary named exists in the suite or in the gate.

**Canary that prevents recurrence.** The `pdd-canary-gate` job (C-CI-GATE),
asserted from the test side by
`proof_ships_ci_gate_depends_on_every_canary_job`,
`proof_ships_release_publishes_checksum_and_provenance`
(C-RELEASE-PROVENANCE), and `proof_ships_promise_set_has_no_unguarded_claims`
(C-PROMISE-SET-INTEGRITY).

---

## AF-009: The first source-scan canaries stopped reading at the first test module

- **Severity:** Medium
- **Status:** Closed
- **Principle / Promise:** P8 / PR2, PR4, PR11, PR13 (the canary gap itself)

**What drifted.** The source-scanning canaries strip `#[cfg(test)]` code,
because test fixtures legitimately write and delete files and would otherwise
trip the no-actuation net. The first implementation did that by truncating each
file at the first `#[cfg(test)]`. Every line after a test module was therefore
invisible to the scan. Since most Rust files put tests at the bottom, this
looked correct and was not.

**Why it mattered.** This is the dangerous failure mode from the methodology
itself: a canary that is green while guarding slightly less than the promise
claims. It was found by mutation, not by review. Appending a sibling-tool state
path to the end of [src/package.rs](src/package.rs) left
`stands_alone_no_sibling_tool_coupling` green, which means every source scan
had the same blind spot at the same time.

**How it was found.** [scripts/verify-canary-drift.sh](scripts/verify-canary-drift.sh)
breaks each promise on purpose and requires the guarding canary to go red. One
of the nineteen canaries that existed at the time stayed green. The gap was
the finding.

**Closing change.** PDD retrofit (this change set). `strip_test_code` in
[tests/pdd_canaries.rs](tests/pdd_canaries.rs) now skips each `#[cfg(test)]`
item individually, by matching the closing brace at the attribute's own
indentation, and resumes scanning after it. The CI greps do the same with an
awk block skip instead of `sed '/^#\[cfg(test)\]/q'`.

**Canary that prevents recurrence.** The drift verification script itself. It
is the guard on the guards: every canary must be proven to fail on a real
breach, and the run that closed this finding proved every one of them does.

---

---

## AF-010: A package-owned path could be tampered with and the next update would launder it

- **Severity:** High
- **Status:** Closed
- **Principle / Promise:** P4 / PR18

**What drifted.** `compute_diff` classified a changed file as a routine
package update whenever *some* package owned the path:

> Hash changed and new entry has a package owner -> changed_pkg

Those changes were absorbed into the refreshed baseline with no alert and no
path-level record; only files that no package owned were recorded. So a
tampered `/usr/bin/sudo` was filed as a package update because the `sudo`
package owns that path, regardless of whether `sudo` was part of the
transaction, and regardless of whether the new bytes were anything the `sudo`
package ever shipped. The attacker's hash became the new definition of
"correct".

This compounded with a second problem. Inside a maintenance window,
package-owned Critical and High changes were deliberately *not* suppressed, and
`/usr/bin/`, `/usr/sbin/` and `/boot/` are all in the Critical watch group,
which routes as Immediate with no coalescing. A routine `apt upgrade` therefore
fired one desktop notification per binary until the storm detector tripped. The
flood buried the real alert, and the refresh that followed erased it.

**Why it mattered.** These two together turned the most dangerous event the
tool can observe into its quietest. The operator reported it as a usability
problem ("vigil gets flooded when I update, and I have no way of knowing if a
change happened before the update"), which is exactly how it presents: the
noise is what you notice, and the laundering is what you do not.

**Closing change.** Ownership is no longer treated as authorship. Every
supported package manager records a digest for every file it ships, so the
refresh now asks the package manager whether the content on disk is what that
package actually shipped ([src/package.rs](src/package.rs),
`verify_changed_paths`), one subprocess per package rather than one per path.
Changed package files split four ways: `verified` (matches the recorded
digest, absorbed silently), `conffile` (the package marks it operator-editable,
so divergence proves nothing), `mismatch` (content contradicts the package,
recorded as a **Critical** deviation), and `unverifiable` (the verifier could
not answer, reported rather than assumed).

With verification in place, per-file alerting inside a window is no longer
needed and no longer wanted: package-owned changes are now deferred at every
severity, and the post-transaction verdict raises exactly the changes that
failed the digest check. That is the flood fix and the laundering fix in one
move, and it makes the remaining alerts evidence rather than guesses.

**Canary that prevents recurrence.**
`audit_truth_package_ownership_is_never_proof_of_authorship`
(C-OWNERSHIP-IS-NOT-PROOF) in [tests/pdd_canaries.rs](tests/pdd_canaries.rs),
backed by [tests/package_verification_tests.rs](tests/package_verification_tests.rs)
and the parser canaries in [src/package.rs](src/package.rs), which are pinned
to verbatim `dpkg --verify` output captured from a live system.

---

## AF-011: The refresh computed the high-signal answer and threw it away

- **Severity:** Medium
- **Status:** Closed
- **Principle / Promise:** P5, P4 / PR18

**What drifted.** The refresh already computed `changed_unattributed` and
rendered it in full, but only `if is_tty`, and only when not `--quiet`. The apt
post-hook runs `vigil baseline refresh --quiet` from a non-interactive context,
so on the one path where an operator most needs the answer, the answer was
computed, formatted, and discarded. The hook captured that output solely to
quote it back in a log line if the refresh had *failed*.

**Why it mattered.** Silent degradation is a security vulnerability
(Principle X), and this was its documentation equivalent: the tool knew
something the operator needed and did not say it. It also meant the machinery
for answering "did anything change that no package vouches for" existed and had
never once reached a human.

**Closing change.** Findings are now reported regardless of `--quiet`:
`--quiet` means "do not narrate progress", never "hide evidence". The refresh
prints a stable `VIGIL UNPROVEN CHANGES` block on stderr listing every
mismatch and every unattributed change, untruncated. The apt, pacman, and dnf
hooks parse that marker, log every path to the system journal, and raise a
single critical notification naming the count.

**Canary that prevents recurrence.** C-OWNERSHIP-IS-NOT-PROOF covers the
classification; the marker itself is a documented contract in
[src/commands/baseline.rs](src/commands/baseline.rs) consumed by all three
hooks.

---

## AF-012: A verification that never ran was reported as a verification that passed

- **Severity:** High
- **Status:** Closed
- **Principle / Promise:** P4, P8 / PR18

**What drifted.** The first implementation of `verify_changed_paths` ignored
the verifier's exit status, on the reasoning that `dpkg --verify` exits
non-zero when it finds problems. It does not: dpkg exits 0 whether or not it
reports differences, and exits non-zero when the *package* is unknown. So a
package name the verifier could not resolve produced an empty problem map,
which every requested path then fell through as `Verified`.

That is the failure this whole change set exists to prevent, reproduced inside
the fix: a claim of proof where no proof was obtained.

**How it was found.** A live run against the real package manager on a
developer machine, checking a deliberately nonexistent package alongside real
ones. Two of three verdicts were right; `/usr/bin/whatever` under a package
that is not installed came back `verified`.

**Closing change.** `finalize_verify` in [src/package.rs](src/package.rs)
distinguishes "the tool ran and found nothing" from "the tool did not run": a
non-zero exit with nothing parseable returns no answer at all, and every path
in that group is `Unknown`. The rule holds across backends that disagree about
exit codes (`rpm -V` exits non-zero *because* it found differences, and its
findings are still used).

**Canary that prevents recurrence.**
`a_failed_verifier_run_is_never_reported_as_verified` in
[src/package.rs](src/package.rs), which asserts all three cases: failed run,
non-zero-with-findings, and clean run.

---

*Findings are the memory layer. The values they defend are in
[PRINCIPLES.md](PRINCIPLES.md); the commitments they enforce are in
[PROMISES.md](PROMISES.md).*