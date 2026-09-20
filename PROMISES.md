# Promises

This is the commitments layer of Promise Driven Development (PDD) for Vigil
Baseline. Each promise descends from a principle in
[PRINCIPLES.md](PRINCIPLES.md) and is guarded by a canary. A promise is narrow,
observable, and falsifiable.

Rule: **no promise without a canary.** A claim we cannot guard is demoted to an
aspiration at the bottom of this file, not stated as a promise.

Canary types, matched to where each promise lives:
- **test** runs under `cargo test --test pdd_canaries` (see
  [tests/pdd_canaries.rs](tests/pdd_canaries.rs)).
- **ci** is a gate job that goes red on a breach (see
  [.github/workflows/pdd-canaries.yml](.github/workflows/pdd-canaries.yml)).
  See PR15 for where that gate is enforced.
- **release** is verifiable by the operator on the published artifact.

---

## From P1: A witness watches. It never acts.

### PR1. The fanotify backend is opened in notification class and never answers a permission event
Every `fanotify_init` call in [src/monitor/fanotify.rs](src/monitor/fanotify.rs)
uses `FAN_CLASS_NOTIF`. The tree contains no permission-class constant
(`FAN_CLASS_CONTENT`, `FAN_CLASS_PRE_CONTENT`), no permission event
(`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`, `FAN_OPEN_EXEC_PERM`), and no response
path (`fanotify_response`, `FAN_ALLOW`, `FAN_DENY`). Vigil does not hold the
kernel interface that would let it block a syscall.

- Falsifiable by: opening fanotify in a permission class, or writing a verdict
  back to the fanotify fd.
- Canary `C-NOTIF-CLASS-ONLY` (test + ci):
  `watch_never_act_fanotify_is_notification_class_only` scans the monitor
  source with comment lines stripped; the ci job repeats the scan across all of
  `src/`.

### PR2. No detection path mutates a watched file or signals another process
The modules that observe and compare ([src/monitor](src/monitor),
[src/worker.rs](src/worker.rs), [src/scanner.rs](src/scanner.rs),
[src/detection.rs](src/detection.rs), [src/types/snapshot.rs](src/types/snapshot.rs))
contain no call that deletes, truncates, renames, re-permissions, or re-owns a
file, and no call that spawns a process. Across the whole tree, the only use of
`kill` is the liveness probe `kill(pid, 0)`, which delivers no signal.

- Falsifiable by: adding quarantine, rollback, auto-repair, or process
  termination to any detection path.
- Canary `C-NO-ACTUATION` (test + ci):
  `watch_never_act_detection_paths_contain_no_actuation` scans those modules
  for mutation and process-control calls, and
  `watch_never_act_kill_is_liveness_probe_only` asserts every `kill(` call
  site in `src/` passes signal `0`.

---

## From P2: The verdict is a comparison, never a judgment.

### PR3. The same snapshot and baseline always produce the same change list
`FileSnapshot::diff` is a pure function of its two inputs. Repeated evaluation
of identical inputs yields an identical, identically ordered change list, and
two structurally equal inputs produce equal output. No clock, no counter, no
hash-map iteration order, and no previous call can influence a verdict.

- Falsifiable by: making the verdict depend on time, randomness, call order, or
  any state outside the two inputs.
- Canary `C-DETERMINISTIC-DIFF` (test):
  `determinism_diff_is_a_pure_function_of_snapshot_and_baseline` evaluates the
  real `vigil::types::FileSnapshot::diff` 512 times over fixed inputs and
  asserts every result is byte-identical.

### PR4. No scoring, machine learning, reputation, or threat-feed machinery exists
The detection surface contains no risk score, confidence value, probability,
reputation lookup, threat feed, or model inference, and the dependency set
contains no crate that provides one. Severity comes from the operator's own
watch-group configuration and from nowhere else.

- Falsifiable by: adding a score, a model, or a feed client to the detection
  surface or to `Cargo.toml`.
- Canary `C-NO-HEURISTICS` (test + ci):
  `determinism_detection_surface_has_no_scoring_or_ml` scans the detection
  modules with comments stripped, and
  `determinism_dependency_set_has_no_ml_or_feed_crates` scans
  [Cargo.toml](Cargo.toml).

### PR5. The event prefilter has no false negatives
The Bloom prefilter in [src/bloom.rs](src/bloom.rs) is one-sided by
construction: it may return "maybe" for an unwatched path (harmless, the exact
comparison then rejects it), and it never returns "no" for a watched path. An
event for a watched path is never discarded before the comparison runs.

- Falsifiable by: any watched path or descendant for which
  `might_contain_prefix_of` returns false.
- Canary `C-NO-FALSE-NEGATIVE-PREFILTER` (test):
  `silence_prefilter_never_rejects_a_watched_path` builds the filter from the
  real default watch set and asserts acceptance for every default path and for
  deep descendants of each.

---

## From P3: Silence means intact, never ignored.

### PR6. An unchanged file produces no change
A real file captured with `FileSnapshot::from_path`, recorded as a baseline
entry, and re-captured yields an empty change list. Quiet is a fact about the
filesystem, not an artifact of a suppression path. When the file's content
does change, the very next comparison reports `ContentModified`.

- Falsifiable by: a spurious change on an untouched file, or a missed change on
  a modified one.
- Canary `C-CLEAN-IS-SILENT` (test):
  `silence_unchanged_file_yields_no_change_and_a_touched_file_does` exercises
  capture and diff against a real temporary file.

---

## From P4: The audit trail never lies.

### PR7. A suppressed detection is still written to the audit log
Cooldown, rate limiting, storm suppression, and maintenance windows decide
whether the operator is notified. They never decide whether the event is
recorded. Every detection that reaches the dispatcher is written to the audit
log, with suppressed events flagged `suppressed = true`.

- Falsifiable by: a dispatcher path that skips `write_audit_entry` for a
  suppressed event.
- Canary `C-SUPPRESSED-STILL-AUDITED` (test):
  `audit_truth_suppressed_alerts_are_still_recorded` drives the real
  `vigil::alert::AlertDispatcher` with a duplicate inside the cooldown window
  and asserts both detections are present in the audit database, exactly one of
  them flagged suppressed.

### PR18. Package ownership is never treated as proof of package authorship
A changed file under a package-owned path is absorbed into the baseline
silently only when the package manager confirms the content matches a digest
it actually recorded for that path. Three things are each insufficient on
their own, and none of them may stand in for proof:

- **Ownership.** A package owning a path says only that a package could have
  written there.
- **A quiet verifier.** Silence is a pass only for paths inside the package
  manager's recorded digest set. dpkg holds no digest for roughly a fifth of
  `/usr/bin` and nearly all of `/boot` on a stock Ubuntu install, and says
  nothing about those files because it has nothing to say.
- **A verifier that did not run.** A failed or unavailable verification is
  `Unknown`, never `Verified`.

A file whose content contradicts a digest its package did record is a Critical
deviation, reported and never silently absorbed.

- Falsifiable by: classifying a path as verified because a package owns it,
  because the verifier was quiet about a path it holds no digest for, or
  because a failed run returned no findings.
- Canary `C-OWNERSHIP-IS-NOT-PROOF` (test):
  `audit_truth_package_ownership_is_never_proof_of_authorship` in
  [tests/pdd_canaries.rs](tests/pdd_canaries.rs), with
  `a_path_with_no_verdict_is_never_counted_as_verified`,
  `a_failed_verifier_run_is_never_reported_as_verified`, and
  `silence_about_a_path_with_no_recorded_digest_is_not_a_pass` covering the
  three insufficiencies in [tests/package_verification_tests.rs](tests/package_verification_tests.rs)
  and [src/package.rs](src/package.rs). The parser canaries pin the verdict for
  verbatim `dpkg --verify` output.

### PR20. Drift that predates a transaction is distinguishable from drift the transaction brought
A deviation found after a package transaction looks identical whether it
arrived with the transaction or was already there. So the verdict is taken
before anything is written: `vigil maintenance enter --seal` scans the watched
set, records every deviation it finds into the tamper-evident chain with a
timestamp that precedes the transaction, and reports the count. Recording goes
through the daemon-owned WAL, never a second writer on the audit chain. A seal
that cannot scan reports failure and never reports a clean system.

- Falsifiable by: a seal that reports clean when the scan failed, a seal that
  records deviations under a timestamp after the transaction, or a second
  process writing the audit chain directly.
- Canary `C-SEAL-PRECEDES-TRANSACTION` (test):
  `audit_truth_a_seal_records_pre_transaction_deviations` drives the real
  `vigil::baseline_diff::record_seal_deviations_to_wal` and asserts the
  records carry the scan's own severities, the `pre_transaction_seal` group,
  and no package attribution that a maintenance window could later use to
  silence them.

### PR8. Editing or deleting an audit row is detectable
Audit entries are chain-linked: each row carries the hash of the row before it.
Altering a row's content or removing a row from the middle of the chain breaks
verification, and `verify_chain` reports the break.

- Falsifiable by: a mutation of the audit table that still verifies clean.
- Canary `C-AUDIT-CHAIN-TAMPER` (test):
  `audit_truth_tampering_with_an_audit_row_breaks_the_chain` inserts entries
  through the real API, mutates one row with direct SQL, and asserts
  `vigil::db::audit_ops::verify_chain` reports a break.

---

## From P5: Degradation is announced, never silent.

### PR9. A degraded backend is reported as a warning, never as OK
The diagnostic that reports the monitor backend marks the fanotify path OK and
the inotify fallback a warning that names the reduced coverage. The reduced
real-time coverage check does the same for a partial event mask. No degraded
branch may carry an OK status.

- Falsifiable by: reporting `CheckStatus::Ok` on the fallback branch, or
  dropping the "reduced coverage" wording from it.
- Canary `C-DEGRADED-IS-LOUD` (test):
  `fail_loud_degraded_backend_never_reports_ok` reads
  [src/doctor/checks.rs](src/doctor/checks.rs) and asserts the fallback branches
  of `check_backend` and `check_realtime_coverage` carry a non-OK status and
  the coverage warning.

### PR19. A maintenance window always ends
A window suppresses every package-owned change at every severity, so one that
never closes is a silent hole in coverage. A window that outlives
`maintenance.max_window_seconds` is force-closed, and that closure is durable:
the on-disk breadcrumb goes with it, and a daemon start never resumes a
breadcrumb already older than the cap. A breadcrumb with no readable timestamp
is treated as expired, because the fail-safe direction is to stop suppressing.

- Falsifiable by: resuming an expired breadcrumb, or force-closing in memory
  while leaving the breadcrumb on disk for the next start to pick up.
- Canary `C-WINDOW-ALWAYS-ENDS` (test):
  `fail_loud_a_maintenance_window_always_ends` drives the real
  `vigil::coordinator::maintenance_window_expired` across the boundary, an
  expired breadcrumb, and an unreadable one.

### PR10. Blind spots are counted and exported
Dropped events, kernel queue overflows, and the compensating scans they trigger
are counters on the exported metrics snapshot, so a blind spot is a number the
operator can read rather than an absence they have to infer.

- Falsifiable by: removing a drop counter from the exported snapshot, or
  dropping events on a path that increments nothing.
- Canary `C-BLIND-SPOTS-COUNTED` (test):
  `fail_loud_blind_spot_counters_are_exported` asserts the public
  `vigil::metrics` snapshot carries `events_dropped`, `kernel_queue_overflows`,
  `fanotify_overflow_scans_triggered`, and `userspace_drop_scans_triggered`.

---

## From P6: Local by design.

### PR11. The tree links no HTTP client, telemetry SDK, or cloud service crate, and no network code lives outside the two opt-in sinks
[Cargo.toml](Cargo.toml) contains no HTTP client, analytics, crash-reporting,
cloud, or update-check dependency. `std::net` appears in exactly two files:
[src/alert/webhook.rs](src/alert/webhook.rs) and
[src/alert/remote_syslog.rs](src/alert/remote_syslog.rs), both operator-configured
alert sinks. Nothing else in the tree can open a socket to the outside.

- Falsifiable by: adding such a dependency, or using `std::net` in a third
  file.
- Canary `C-NO-NETWORK-DEPS` (test + ci):
  `local_by_design_no_http_or_telemetry_dependencies` scans the manifest and
  `local_by_design_network_code_is_confined_to_the_two_opt_in_sinks` scans
  `src/`; the ci job repeats both and greps the built binary for telemetry
  hosts.

### PR12. Both outbound sinks are off in the default configuration
`vigil::config::default_config()` ships `alerts.webhook_url` empty and
`alerts.remote_syslog.enabled` false. A default install performs no outbound
network I/O at all. Nothing turns either sink on except the operator editing
the config.

- Falsifiable by: a default that populates a webhook URL or enables remote
  syslog.
- Canary `C-EGRESS-OFF-BY-DEFAULT` (test):
  `local_by_design_outbound_sinks_are_off_by_default` asserts both defaults on
  the real `default_config()`.

---

## From P7: Stands alone, and stays small.

### PR13. Vigil depends on no sibling tool and reads no sibling tool's state
Neither the manifest nor the source references another lousclues project or its
data files. Removing every other tool from the system leaves Vigil compiling,
running, and doing its whole job.

- Falsifiable by: importing a sibling crate, or reading a sibling tool's
  database or socket.
- Canary `C-STANDS-ALONE` (test + ci):
  `stands_alone_no_sibling_tool_coupling` scans [Cargo.toml](Cargo.toml) and
  `src/` for sibling-project identifiers and their state paths.

### PR14. Unsafe code is confined to the enumerated syscall-boundary modules
[src/lib.rs](src/lib.rs) carries `#![deny(unsafe_code)]`. The exemption
`allow(unsafe_code)` appears only in the modules that must call a Linux syscall
or hand a file descriptor across a thread boundary:

```
src/control.rs        src/daemon/mod.rs      src/display/term.rs
src/hash.rs           src/monitor/fanotify.rs  src/monitor/mod.rs
src/types/event.rs    src/util/owned_fd.rs   src/util/process.rs
src/util/random.rs    src/worker.rs
```

Adding a twelfth file to that list is a promise review and a ledger entry, not
a routine commit.

- Falsifiable by: removing the crate-level deny, or introducing `unsafe` in any
  module outside the list.
- Canary `C-UNSAFE-BOUNDARY` (test + ci):
  `stands_alone_unsafe_is_confined_to_the_syscall_boundary` asserts the deny
  attribute is present and that the set of files containing `unsafe` is exactly
  the list above.

---

## From P8: A self-claim ships with a proof that fails loud.

### PR15. A breach never ships silently
Every push and pull request runs the whole canary surface, and a final gate job
depends on every canary job so no breach can report green.

Where that gate is *enforced* depends on how changes reach `main`, and the
honest answer today is: this is a single-maintainer project with no merge to
block. A merge-gate would be theater, because the CI run fires after the push
has already landed. So the enforcement point is the push itself
([scripts/git-hooks/pre-push](scripts/git-hooks/pre-push), enabled with
`git config core.hooksPath scripts/git-hooks`), which runs the canaries and
refuses the push on a breach. CI is the second look, and it still goes red on
anything pushed with `--no-verify`.

If the project ever takes contributors and changes start arriving by pull
request, the same `pdd-canary-gate` job becomes the status to require in branch
protection. The gate does not change; only where it is enforced does.

- Falsifiable by: a canary job missing from the gate's `needs` list, the
  workflow no longer running on a push to `main`, or a pre-push hook that does
  not actually run the canaries.
- Canary `C-CI-GATE` (ci + test):
  `proof_ships_ci_gate_depends_on_every_canary_job` asserts every canary job is
  in the gate's `needs` list, that the workflow triggers on pushes to `main`,
  and that the pre-push hook runs the canary suite and exits non-zero on a
  breach.

### PR16. Every release ships operator-verifiable provenance
Each tagged release publishes a SHA256 checksum alongside the tarball and a
GitHub build-provenance attestation over that tarball, so an operator can
confirm offline that the bytes they hold are the bytes this repository built:

```bash
sha256sum -c vigil-baseline-<version>-linux-x86_64.tar.gz.sha256
gh attestation verify vigil-baseline-<version>-linux-x86_64.tar.gz \
  --repo lousclues-labs/vigil
```

- Falsifiable by: a release published without the checksum or without the
  attestation step.
- Canary `C-RELEASE-PROVENANCE` (ci + test + release): the `release-provenance`
  job and `proof_ships_release_publishes_checksum_and_provenance` both assert
  [.github/workflows/release.yml](.github/workflows/release.yml) still produces
  both, and the attestation itself is the proof the operator runs.

### PR17. No principle is decoration and no promise is prose
This document and [PRINCIPLES.md](PRINCIPLES.md) are held to the methodology's
own two rules. Every principle spawns at least one promise that exists here.
Every promise here descends from a principle and names at least one canary, and
every canary it names exists in [tests/pdd_canaries.rs](tests/pdd_canaries.rs)
or in the CI gate. A claim we cannot prove goes in the aspirations section
below, not in the promise set.

- Falsifiable by: adding a promise with no canary, naming a canary that does
  not exist, or writing a principle that forbids nothing.
- Canary `C-PROMISE-SET-INTEGRITY` (test):
  `proof_ships_promise_set_has_no_unguarded_claims` reads the two documents as
  a graph and fails on any missing edge.

---

## The guard on the guards

A canary that stays green through a real breach is theater, and it is the
failure mode this methodology is most vulnerable to. So the canaries are
themselves tested.

[scripts/verify-canary-drift.sh](scripts/verify-canary-drift.sh) breaks each
promise on purpose, one at a time, and requires the canary that guards it to go
red before reverting the mutation. Every canary in this file has been proven to
fail on drift. Adding a promise means adding a case to that script.

```bash
bash scripts/verify-canary-drift.sh
```

---

## Aspirations (not yet promises: no canary yet)

These are things we want but cannot currently falsify cheaply. They are stated
here honestly as aspirations, not as promises, until a canary exists.

- **One alert per day, at most, on a clean desktop.** The seven-day quiet-run
  test in [docs/PRINCIPLES.md](docs/PRINCIPLES.md) is a real bar, but it takes
  a week of real desktop use to run and no CI job can stand in for it. PR6
  guards the narrow part we can prove, which is that an unchanged file produces
  no change.
- **Reproducible builds.** We aspire to bit-for-bit reproducible release
  binaries. The build-provenance attestation (PR16) proves where a binary came
  from, not that anyone else can rebuild it identically. Until a
  reproducibility canary exists, this is not a promise.
- **Complete coverage of every persistence mechanism.** The default watch set
  aims at the paths that matter most. Completeness against an evolving Linux
  desktop is not something we can assert, so we promise the comparison, not the
  coverage.
