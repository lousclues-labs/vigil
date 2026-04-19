# Changelog

All notable changes to Vigil Baseline will be documented in this file.

## [0.43.0] - 2026-04-19

### Inviting: silence the journal for healthy systems

- **Auth-disabled warning fires once.** Control socket `hmac_signing=false` warning downgraded from `WARN` on every connection to a `OnceLock`-guarded one-time `INFO` at first connection. Counter `control_unauthenticated_connections` added.
- **Default config paths do not warn.** `validate_config_deep()` downgrades "path does not exist" from warning to `INFO` for groups with `expect_present = false` (the default for shipped groups). New `[watch.<group>] expect_present` config knob.
- **Control socket command logging downgraded.** `status`, `baseline_count`, `metrics_prometheus` log at `debug`. `reload`, `scan`, `maintenance_enter/exit`, `baseline_refresh` log at `info`. Only real failures (auth, oversized request) remain at `warn`.
- **Drop-rate logging rate-limited.** `error!` only on entering Degraded. `warn!` summary every 10 ticks while Degraded. `info!` on recovery. Journal goes from "error per minute" to "one error when something changed."
- **Backup retention configurable.** `[update] backup_retention_count = 5` (default). `vigil update` prunes after successful install.
- **drift_velocity always present.** `state.json` emits `null` while warming up, never omits. Downstream parsers see a stable schema.
- **`vigil status` operator-shaped.** Default output is two compact lines: state, uptime, baseline count, last scan, alert count. Full JSON available via `vigil status --json`.

### Paranoid: security wins from the deep review

- **WAL truncate-then-open data-loss bug fixed.** Open replacement file BEFORE rename. If open fails, old WAL is still canonical and no entries are lost.
- **WAL HMAC binds instance nonce and sequence.** HMAC now covers `(instance_nonce || sequence || payload)`. Entries cannot be replayed from one host's WAL into another's.
- **WAL header fingerprint cached at open.** `scan_entries()` no longer re-reads bytes 16-32 from disk on every scan. An attacker with WAL write access cannot downgrade the HMAC policy between scans.
- **Bloom filter generation counter.** `FsEvent.bloom_generation` field tags events with the bloom generation that admitted them. Workers can reject stale-generation events after config reload.

### Notification redesign

- **Severity-aware delivery policies.** `[notifications.critical]`, `[notifications.high]`, `[notifications.medium]`, `[notifications.low]` config sections with `deliver`, `coalesce_within_secs`, `escalate_at_secs`, `channels`.
- **Coalescing by (group, parent, kind).** Coalesced notifications show file list with package attribution and likely cause.
- **Storm suppression preserves Critical.** Storm detector suppresses non-critical delivery above threshold; critical alerts always deliver.
- **Optional ack with escalate-twice-then-stop.** `vigil ack <event_id>` and `vigil ack --all` cancel escalation. No disposition required.
- **Maintenance-window prefix.** Coalesced notifications include maintenance window context when active.
- **No webhook or MQTT channels.** The signal socket is the extension point. Stay local.

### Self-healing

- **Inode auto-recovery config knob.** `[security] auto_recover_inode_changes = false` (default OFF). When true, re-stat and verify content before accepting new inode.

### Texture

- **DegradedReason schema-stability test.** Display strings locked by test to prevent silent schema breakage for `state.json` consumers.
- **NotificationsConfig + UpdateConfig sections.** Config structs for notification policies and update settings.

## [0.42.0] - 2026-04-19

### Resilience

- **Coordinator split into two loops.** `src/coordinator.rs` now runs a fast `vigil-guardian` loop (1s cadence for watchdog, backpressure, and live state snapshots) plus a heavy `vigil-maintenance` loop (60s cadence for DB/WAL identity checks, rotation, drift, and housekeeping).
- **Fanotify supervision with bounded restarts.** The monitor path adds recovery behavior for transient fanotify thread failures and records restart telemetry.
- **Worker DB reopen backoff.** Workers now attempt baseline DB reopen with exponential backoff and transition to explicit degraded state on unrecoverable failure.
- **Event-drop recovery threshold.** Degraded transitions caused by event loss now honor `monitor.event_loss_alert_threshold` and recover after sustained clean ticks.
- **Baseline refresh lock-scope fix.** Baseline refresh no longer contends on the long-lived coordinator connection; it uses a separate connection path.

### Alerting

- **Notification routing foundation.** Added severity-policy routing primitives (`immediate`, `coalesce`, `digest`) with coalescing keys, rolling-window storm detection, and critical escalation tracking in `src/alert/router.rs`.
- **Webhook sink implementation.** Added `src/alert/webhook.rs` with optional bearer-token auth and retry/backoff behavior for transient delivery failures.
- **Alert config extensions.** Added/standardized notification controls for `webhook_bearer_token`, `storm_threshold`, and `storm_window_secs`.

### Correctness

- **Auto-rebaseline validation.** Worker auto-rebaseline now rejects invalid baseline records before write/dispatch (`empty hash`, `zero mtime`) and increments explicit metrics.
- **Reload hash semantics tightened.** Coordinator now updates observed config hash on every reload attempt, even when reload validation fails, preventing repeated stale-hash warnings.
- **Drift snapshot contract fixed.** `drift_velocity` is always present in state snapshots (nullable when unavailable), improving consumer stability.
- **Typed degraded reasons.** `DegradedReason` and `DaemonStateHandle` were introduced to remove stringly-typed state transitions and centralize state mutation logic.
- **Monitor API tightening.** `start_monitor` now requires daemon state and scan trigger in production call paths to prevent silent loss of degradation and overflow signaling.

### Internal

- **Coordinator tick deduplication.** Repeated phase-timing boilerplate replaced with `time_phase!` macro.
- **Status serialization cleanup.** Control/status JSON now derives from `MetricsSnapshot::status_view()` to keep schema extensions synchronized with metric additions.
- **Worker refactor cleanup.** Removed duplicate event-processing path and added `WorkerContext::for_test` for deterministic tests.
- **Utility extraction.** Shared FD guard, random nonce, and mount-delta helpers moved to `src/util/`.

### Documentation

- Added `docs/NOTIFICATIONS.md` covering routing policy, coalescing behavior, storm suppression, escalation lifecycle, and webhook configuration.
- Updated architecture and configuration documentation for guardian/maintenance coordinator behavior and notification-routing configuration fields.

## [0.41.0] - 2026-04-18

### Features

- **`vigil attest` (new):** create, verify, diff, show, and list signed portable attestation artifacts (`.vatt`) capturing baseline/audit state for offline evidence workflows.
- **`vigil setup attest` (new):** generate dedicated attestation signing key (`/etc/vigil/attest.key`, mode `0600`) with independent key lifecycle from audit HMAC key.
- **Doctor coverage:** `vigil doctor` now checks attestation key presence/permissions and reports `Attest key` health status.
- **Audit anchoring for evidence generation:** successful `vigil attest create` writes an `attestation_created` receipt into the audit chain with the attestation content hash.
- **Portable verification path:** `vigil attest verify` remains standalone (file + key + binary), validating magic/version/content-hash/signature/embedded chain links without daemon runtime.

- **`vigil status` (enhanced):** one-shot query of Vigil's current state with `ok`/`degraded`/`down` verdict. Works with or without daemon running. Stable JSON schema.
- **`vigil explain <path>`:** query why a path is watched, its watch group, severity, baseline entry, and audit history. Shows nearby watched paths when a path is not covered.
- **`vigil why-silent`:** query every reason Vigil could currently be silent. Ends with a single-sentence headline reason.
- **`vigil check --reason`:** record a verification receipt (`check_completed`) in the audit chain after each check. Receipt hash commits the verifier to the exact paths considered and results.
- **Closed-set directory watches:** new `mode = "closed_set"` for watch groups. Detects unknown-filename additions and removals. Default closed-set on `~/.ssh/`, cron directories, `/etc/sudoers.d/`.
- **Daemon-driven `vigil doctor`:** `self_check_interval` config field (default `"6h"`) for periodic self-health checks written to the audit chain. `vigil doctor --now` flag.
- **`vigil inspect`:** offline forensic comparator against arbitrary paths and baselines. `--baseline-db`, `--recursive`, `--root` prefix translation. Strictly read-only. No daemon required.
- **`vigil test alert`:** synthetic alert through full delivery pipeline with per-channel status reporting. Records `test_alert` audit entry.
- **Per-channel delivery status in alert log:** each alert entry includes per-channel delivery result (`ok`, `failed`, `no_listener`, `unconfigured`).

### Documentation

- **`docs/ATTEST.md` (new):** complete attestation design, wire format, key lifecycle, workflows, and verifier exit-code contract.
- **`README.md` + `docs/README.md`:** added attestation capability and index links for operator discoverability.
- **`docs/CLI.md`:** documented `vigil attest` verbs, `vigil setup attest`, and `attest verify` exit codes.
- **`docs/SECURITY.md`:** added attestation signing key lifecycle guidance and rotation recommendations.
- **`docs/THREAT_MODEL.md`:** added attestation-specific threat model, guarantees, and non-goals.
- **`docs/MINIMUM_VIABLE.md`:** documented "minimum viable trust" mode for constrained environments.
- **`docs/FORENSICS.md`:** offline comparison workflows with `vigil inspect`.
- **`docs/TROUBLESHOOTING.md`:** added quick diagnostic commands table, `vigil why-silent` and `vigil test alert` recommendations.
- **`docs/CLI.md`:** added `explain`, `why-silent`, `inspect`, `test alert` references. Documented stable JSON schemas. Added `--reason` flag to `check`. Added `--now` flag to `doctor`.
- **`docs/CONFIGURATION.md`:** documented `mode` field for watch groups and `self_check_interval` daemon config.
- **`docs/THREAT_MODEL.md`:** added closed-set detection, absence-of-receipts signal, alert delivery degradation tracking.

### Testing

- **`tests/attest_tests.rs` (new):** deterministic create tests, tamper detection, unknown-version rejection, standalone verification without local DBs, structural diff, and chain-fork detection.
- **Fuzzing additions:** new fuzz targets for attestation parser/serializer and verifier paths (`fuzz_attest_file`, `fuzz_attest_verify`).

### Dependencies

- Added `ciborium` for deterministic CBOR attestation serialization.

### New Audit Entry Types

- `attestation_created` -- recorded on successful attestation generation with content-hash reference
- `check_completed` -- verification receipt from `vigil check --reason`
- `self_check` -- daemon-driven or operator-invoked health check result
- `self_check_skipped` -- daemon skipped a scheduled self-check
- `test_alert` -- synthetic alert from `vigil test alert`

### Schema Extensions

- `delivery` field added to alert log entries (non-breaking; old entries without it remain valid)
- `dirent_set` tracking for closed-set watch groups in baseline DB

## [0.40.0] - 2026-04-18

### Resilience

- **Package cache self-healing with retry and backoff.** `build_package_cache()` now retries up to 3 times with 2s/5s/10s backoff delays when the initial cache build returns 0 entries. This handles the common case where the pacman post-transaction hook fires while the package manager database lock is still held.
- **Package manager lock-file awareness.** Before each retry, vigil polls for the package manager's lock file (`/var/lib/pacman/db.lck`, `/var/lib/dpkg/lock-frontend`, `/var/lib/rpm/.rpm.lock`) and waits up to the backoff duration for it to disappear. This directly addresses lock contention during package upgrades.
- **`build_package_cache()` returns `Option<HashMap>`.** `None` means the query failed (timeout, command error); `Some(empty)` means the package manager genuinely reported no files. Callers (scanner.rs) now fall back to per-file queries when the bulk cache is unavailable instead of silently proceeding with no attribution.

### Internal

- `build_cache_pacman_once()`, `build_cache_dpkg_once()`, `build_cache_rpm_once()` -- single-attempt cache builders returning `Option`.
- `build_cache_with_retry()` -- generic retry wrapper with configurable backoff.
- `wait_for_package_lock()` -- polls for lock-file release with 250ms interval.
- 6 new unit tests covering retry success, retry exhaustion, lock-wait behavior, and API shape.

## [0.39.0] - 2026-04-17

### Bug Fixes

- **Fix duplicate ownership warnings.** Repository discovery no longer emits ownership warnings during candidate scanning -- warnings now fire exactly once during the explicit validation step.
- **Suppress orphan cargo `Finished` line on cached builds.** When cargo has nothing to compile, its lone `Finished` line is suppressed to avoid a contextless fragment in the output. `--verbose` still emits it.
- **Fix step labels to use `vigild` not `daemon`.** Stop, start, and health check steps now reference the actual systemd unit name (`vigild`) for searchability in logs and journals.
- **De-redundant binary step labels.** `Backing up existing binaries` → `Backing up vigil and vigild`; `Installing new binaries` → `Installing vigil and vigild`.
- **Fix tautological `Checking post-install checks`.** PostCheck now renders as `Running post-install doctor ... ok`.
- **Remove pipe-delimited PostCheck detail.** The version transition, daemon status, and baseline count were redundant with the header, prior steps, and doctor output. PostCheck now renders with no trailing detail.
- **Add archive path to backup step.** `Archiving backups ... ok -- /var/lib/vigil/binary-backups/<ts>` now shows the forensic recovery path.
- **Remove stray `⚠` eprintln in archive_backups.** Archive creation failure now logs via tracing instead of unscoped `eprintln!`.

### Internal

- `pass_through()` now tracks `Compiling` lines and defers lone `Finished` lines; verbose mode bypasses the filter.
- `archive_backups()` returns `Option<PathBuf>` so the caller can render the path as step detail.
- 2 new tests: `cargo_lone_finished_suppressed_in_human_mode`, `cargo_compiling_plus_finished_both_emitted`.

## [0.38.0] - 2026-04-17

### Bug Fixes

- **Fix spinner collision with cargo output.** The spinner line was not erased before cargo's `Compiling`/`Finished` output streamed in, causing garbled lines. The spinner is now explicitly cleared (`\r\x1b[2K`) before any pass-through child output, and a 250ms grace period suppresses spinner drawing for sub-second steps.
- **Fix header position.** The `Updating vigil-baseline X → Y` header now appears as the first output line, before any warnings or step output. Previously it printed after the build step.
- **Fix build step double attribution.** The `BuildRelease` step is now silent in human mode -- only cargo's native `Compiling`/`Finished` lines render. JSON `begin`/`ok` events still emit.
- **Fix hyphen where em-dash specified.** Detail separators and the `Finished` summary line now use ` -- ` (U+2014) instead of ` - `.
- **Fix ASCII arrow in header.** Version transitions now use `→` (U+2192) instead of `->`.
- **Fix redundant step details.** Step details that duplicate header content (repo path, version transition) are no longer rendered.
- **Fix skipped-step labels.** Short labels now match spec: `stop, backup, install, units, start, health, archive, doctor`. Previously labels like `daemon` appeared twice.
- **Fix verbose skip reason.** No-op early exit now shows `no version change` instead of repeating the version string.
- **Fix stray blank line before Finished.** The `Finished` summary now follows immediately after the last step or skip line with no blank line separator.
- **Fix verbose warning text.** Ownership warnings are now terse: `warning: /path is owned by uid N (not root)`. Redundant filename and trailing admonition removed.

### Internal

- `begin_step_silent()` / `end_step_ok_silent()` methods for steps where a child process owns the visual output.
- Spinner thread 250ms grace period via `first_draw_at` field in `SpinnerState`.
- `read_cargo_toml_version()` helper reads version from Cargo.toml without building.
- 6 new unit tests: `skipped_step_short_labels_match_spec`, `header_uses_unicode_arrow`, `build_step_silent_in_human_mode`, `step_detail_uses_em_dash`, `finished_uses_em_dash`, `no_blank_line_before_finished`.

## [0.37.0] - 2026-04-17

### User Experience

- **`vigil update` visual polish (cargo-style grammar).** Human progress output now uses a right-aligned 12-column verb gutter (`Verifying`, `Building`, `Installing`, etc.) with concise per-step subjects instead of `[N/total]` counters.
- **Scoped warnings with `warning:` prefix.** Operator warnings are now emitted at column 0 with consistent `warning: ...` styling so warning lines are easy to grep in CI logs and postmortems.
- **No more pass-through framing.** Cargo output is now streamed unframed, preserving native cargo readability and avoiding mixed visual metaphors.
- **Skipped-step collapse.** No-op and early-exit paths now print a single collapsed `Skipping N steps (reason): ...` summary in non-verbose mode, while verbose mode still renders per-step skip detail.
- **Honest final summary.** Final line now reports `Finished update in <T> - <outcome>` with explicit outcomes such as version transition, no changes installed, or rolled back.
- **Update header line.** Once versions are known, update output prints a scoped header (`Updating vigil-baseline <from> -> <to>`) with optional repo/sudo context in explicit or verbose flows.

### Internal

- `src/ui/progress.rs` now includes cargo-style verb/subject mapping, scoped warning rendering, skip-collapse support, and elapsed formatting that omits noisy sub-100ms step timings.
- `src/commands/update.rs` now feeds reasons into skip-collapse, emits repo ownership warnings through the progress renderer, and sets explicit summary outcomes for success/no-op/rollback.
- Progress renderer unit tests were updated and expanded to cover warnings, header rendering, unframed passthrough, and duration threshold behavior.

## [0.36.0] - 2026-04-17

### User Experience

- **`vigil update` operator experience overhaul.** Every phase of the update process now shows a step counter `[N/11]`, elapsed time, and a live spinner (TTY) or clean ASCII (non-TTY). No silent gap exceeds ~200ms.
- **Step 9 (Verify daemon health)** shows attempt counter and live countdown between probes: `[attempt 2/3, next probe in 4s]`.
- **Cargo build output framing:** cargo's native output is preserved byte-for-byte but wrapped in visible `╭─ cargo build --release ─────` / `╰─────` delimiters so operators can distinguish Vigil's phases from cargo's.
- **Rollback rendering:** when the daemon fails health checks, the rollback path renders its own mini-plan with the same renderer. Summary clearly distinguishes "rolled back" from "no rollback available".
- **New flags:** `--quiet` / `-q`, `--verbose` / `-v`, `--no-progress` for update command.
- **Machine-readable output:** `--format=json` emits one NDJSON object per step event on stdout (stderr retains human output). Schema documented in docs/CLI.md.
- **Environment variable support:** `VIGIL_PROGRESS=plain|auto|fancy`, `NO_COLOR`, `TERM=dumb` all respected.
- **All output now goes to stderr** (stdout reserved for `--format=json`), matching cargo/shroud convention.

### Bug Fixes

- **Fix 4-minute hang at step 3/11 and 6/11.** `vigild` has no CLI argument parsing; running `vigild --version` launched a full daemon that blocked until killed. New `smoke_test_binary_exists()` checks file existence and executable permission instead of running the binary. `smoke_test_binary()` (with `--version`) is still used for the `vigil` CLI binary.
- **Fix silent cargo build.** Step 2 used `.output()` which buffered all cargo output until completion. Changed to `Stdio::inherit()` so cargo's `Compiling…` / `Building…` lines stream live to the terminal.

### Internal

- New `src/ui/` module with in-tree progress renderer (~500 lines, no new dependencies).
- `src/ui/progress.rs`: `Plan`, `Progress`, `UpdateStep` types with full TTY/non-TTY/color/no-color matrix.
- 11 new unit tests for the progress renderer (labels, modes, JSON events, passthrough framing).
- 6 new CLI flag parsing tests.
- All `println!` removed from update command non-test code paths; all output via `Progress` struct or `eprintln!` for low-level helpers.

## [0.35.0] - 2026-04-17

### Release Summary
WAL HMAC hardening, deletion event detection, clock-drift resilience, and v0.34.0 follow-up fixes. 8 VIGIL-VULN entries (067–074).

### Security

- **VIGIL-VULN-067 (Critical):** WAL HMAC verification bypass fixed. Forged entries with all-zero HMAC fields are now rejected when the WAL header contains a non-zero HMAC key fingerprint. WAL refuses to open without a key when the header demands one (sticky-HMAC enforcement). Magic number `50` replaced with documented `MIN_ENTRY_SIZE` constant. New metric `wal_entries_rejected_hmac`.
- **VIGIL-VULN-068 (High):** Fanotify path resolution now strips the kernel's ` (deleted)` suffix from `/proc/self/fd/N` targets. Deleted files are detected as `FsEventType::Delete` instead of being silently dropped by the Bloom filter.
- **VIGIL-VULN-069 (High):** New mounts overlapping watched paths now receive dynamic `fanotify_mark` via a mount-mark control channel from the coordinator to the fanotify thread. Disappeared mounts are un-marked. Inotify backend logs error (no equivalent API).
- **VIGIL-VULN-070 (Medium):** Clock anomaly detection now compares wall-clock delta against monotonic (`Instant`) delta with 5-second tolerance. Slow drift that previously evaded the 3600s threshold is caught. Audit rotation refused when `MAX(timestamp)` in audit log exceeds current time. Degraded state entered on clock skew detection.
- **VIGIL-VULN-071 (Medium):** Coordinator drops stale `rusqlite::Connection` immediately when entering Degraded state for `*_db_replaced`. Subsequent rotations, checkpoints, and config HMAC checks early-return with warnings instead of operating on orphaned inodes.
- **VIGIL-VULN-072 (Medium):** User-space `events_dropped` and kernel `kernel_queue_overflows` deltas exceeding `monitor.event_loss_alert_threshold` (default 10) now trigger Degraded state. Recovery after 5 consecutive clean ticks. New `DetectionSource::HealthDegraded` variant for health-driven alerts.
- **VIGIL-VULN-073 (Medium, composite):** v0.34.0 follow-up fixes:
  - Thread-spawn failure in control socket no longer leaks the in-flight connection slot.
  - `current_euid()` cached in `OnceLock` (called once, not per-connection).
  - Backup archive timestamp includes 4-byte random hex suffix to prevent sub-second collisions.
  - `sudo systemctl` invocations in `vigil update` use absolute `/usr/bin/systemctl` path (consistent with rest of codebase).
  - `prune_old_backup_archives` filters directories by archive-name pattern; non-conforming names are preserved with warning.
  - `start_monitor` logs at error level when `state` or `scan_trigger` are `None` (production callers must provide them).
- **VIGIL-VULN-074 (Medium, composite):** Cleanups:
  - `load_hmac_key` returns `Zeroizing<Vec<u8>>`; intermediate `content` buffer zeroized. All call sites updated.
  - `dup_to_file` uses `F_DUPFD_CLOEXEC` instead of `dup()` to prevent fd leaks across exec.
  - Worker `consecutive_db_errors` threshold extracted to `WORKER_DB_REOPEN_THRESHOLD` const.
  - Worker cache cleared after panic in `process_safe` to avoid logically-inconsistent state.
  - WAL `random_nonce()` uses `libc::getrandom` syscall instead of per-call `/dev/urandom` open.

### Added

- `Cargo.toml` declares `rust-version = "1.85"` (MSRV hoisted from CI-only to manifest).
- `cargo test --release` CI job exercises release-profile code paths (e.g. HMAC permission hard-fail).
- Config sections: `[monitor]` with `event_loss_alert_threshold`, `[maintenance]` with `max_window_seconds`.
- Release pipeline: `actions/attest-build-provenance@v1` for cosign-keyless signatures, `cargo-cyclonedx` SBOM generation, `--locked` on publish, changelog extracted from `CHANGELOG.md`, `--allow-dirty` removed.
- `MountMarkRequest` / `MountMarkOp` types for dynamic fanotify mount marking.
- `MonitorHandle::mount_mark_tx` channel.
- `strip_deleted_suffix()` helper in `monitor::fanotify`.

### Changed

- WAL `scan_entries` reads header fingerprint to determine HMAC requirement independently of caller-supplied key.
- Coordinator DB connections are `Option<Connection>`; dropped on Degraded transitions.
- Maintenance timeout reads from `cfg.maintenance.max_window_seconds` instead of hardcoded `1800`.
- `check_event_drops` tracks both user-space and kernel event loss deltas with threshold-based Degraded transitions.

### Tests Added

- `wal_rejects_zero_hmac_entry_when_hmac_required`
- `wal_open_refuses_hmac_keyless_when_header_demands_key`
- `wal_rejects_bad_hmac_entry_when_hmac_required`
- `strip_deleted_suffix_strips_when_present`
- `strip_deleted_suffix_passthrough_when_absent`
- `strip_deleted_suffix_handles_paths_with_parens`

## [0.34.0] - 2026-04-17

### Release Summary
- Security and resilience hardening sweep covering 24 audit findings across the daemon, control socket, fanotify monitor, update command, and package introspection. Two CRITICAL fixes: (1) control socket HMAC authentication now uses constant-time verification via `hmac::verify_hmac()` -- the previous string-equality compare was both timing-leaky and bypassable on empty client responses (`unwrap_or_default()` produced an empty string that was compared against the expected MAC); (2) the fanotify event loop now validates `event_len` against the metadata header size and remaining buffer length before advancing the read offset -- a malformed kernel event with `event_len == 0` previously caused an infinite loop pinning a CPU core. Additional security fixes: control socket peer UID enforcement (rejects connections from non-root, non-daemon-EUID peers), 8-connection concurrency cap to prevent thread-exhaustion DoS, package manager `--` separators to prevent path-as-flag injection, and absolute paths for all helper binary invocations (`systemctl`, `journalctl`, `notify-send`, `vigil`) as PATH-hijacking defense-in-depth. Resilience fixes: fanotify mark/read failures now degrade daemon state and increment dedicated counters, `FAN_Q_OVERFLOW` triggers a Full scan request and Degraded state, mountinfo octal-escape parsing for paths containing spaces or tabs, `vigil update` rolls back binaries when the daemon fails to start (not only when started-but-unhealthy), and binary backups are now archived under `/var/lib/vigil/binary-backups/<timestamp>/` keeping the last 3. All 262 tests pass (6 new regression tests), `cargo clippy --all-targets -- -D warnings` clean.

### Security
- **VIGIL-VULN-057 (Critical):** control socket HMAC authentication used `client_response.unwrap_or_default() != expected_hmac` -- non-constant-time string comparison and bypassable on EOF/empty responses. Replaced with `crate::hmac::verify_hmac(key, nonce.as_bytes(), client_response)` which uses the underlying `subtle::ConstantTimeEq` and fails closed on malformed input. Regression test `verify_hmac_rejects_empty_response` covers the bypass path (`src/control.rs`).
- **VIGIL-VULN-058 (Critical):** fanotify event reader incremented `offset += event.event_len as usize` without validating `event_len`. A kernel event with `event_len < FAN_EVENT_METADATA_LEN` or `offset + len > buffer_size` would either loop forever or read past the buffer. Now validates both bounds; on violation, increments `fanotify_read_errors`, logs at error, and breaks the resync loop (`src/monitor/fanotify.rs`).
- **VIGIL-VULN-059 (High):** control socket accepted connections from any local UID. SO_PEERCRED was retrieved for logging only, not enforced. Now rejects the connection when SO_PEERCRED is unavailable, when the peer UID is not 0, and when the peer UID does not match the daemon's effective UID. Daemon EUID resolved via new `current_euid()` helper (`src/control.rs`).
- **VIGIL-VULN-060 (High):** control socket spawned an unbounded thread per connection -- a local attacker could exhaust the thread/FD budget. Now uses an `AtomicUsize` semaphore capping concurrent handler threads at `MAX_CONCURRENT_CONNECTIONS = 8`; excess connections receive a JSON rejection and are closed (`src/control.rs`).
- **VIGIL-VULN-061 (High):** `vigil update` only rolled back binaries when the daemon started but health-checked unhealthy. If `systemctl start vigild` itself failed, the new binaries remained installed even though the daemon was not running. Rollback now triggers on `backups_exist && (!daemon_started || !healthy)` (`src/commands/update.rs`).
- **VIGIL-VULN-062 (High):** package manager queries (`pacman -Qo`, `dpkg -S`, `rpm -qf`) passed user-derived paths positionally without a `--` separator. A path beginning with `-` could be interpreted as a flag. All four call sites (`query_pacman`, `query_dpkg`, `query_rpm`, `batch_query_dpkg`) now insert `--` before the path argument(s) (`src/package.rs`).
- **VIGIL-VULN-063 (High):** `vigil update` and helper binary invocations (`systemctl`, `journalctl`, `notify-send`, `vigil`) used bare command names, relying on PATH resolution. Now all call sites resolve to absolute paths (`/usr/bin/...` or `/bin/...`), with results cached in `OnceLock<Option<PathBuf>>` for `notify-send`. Fallback to PATH only when no canonical location matches, ensuring deterministic behavior even when a service runs with an unexpected PATH (`src/doctor.rs`, `src/commands/log.rs`, `src/commands/update.rs`, `src/alert/dbus.rs`, `src/lib.rs`).
- **VIGIL-VULN-064 (Medium):** fanotify `FAN_Q_OVERFLOW` events were logged but produced no operational response -- the kernel had dropped events and the baseline could silently drift. Now sets daemon state to `Degraded { reason: "fanotify_queue_overflow" }`, sends a `Full` `ScanRequest` via the scan trigger channel (try_send to avoid blocking the read loop), and increments the new `fanotify_overflow_scans_triggered` counter (`src/monitor/fanotify.rs`).
- **VIGIL-VULN-065 (Medium):** fanotify mountinfo parsing did not decode the octal `\NNN` escapes the kernel uses for whitespace, backslash, and other special characters in mount points. Mount points containing spaces, tabs, or backslashes were misparsed and would not receive marks. New `unescape_mountinfo()` decodes `\040`, `\011`, `\134`, etc.; covered by 5 new unit tests (`src/monitor/fanotify.rs`).
- **VIGIL-VULN-066 (Medium):** initial fanotify mark application failures were silently logged and ignored. The daemon would continue running with no real-time monitoring on the failed mounts. Now increments `fanotify_mark_failures` and, on the reload path where state is available, transitions to `Degraded { reason: "fanotify_mark_failure" }`. Read-side `read()` failures are similarly classified: EAGAIN/EWOULDBLOCK/EINTR are benign and continue the loop; other errno values increment `fanotify_read_errors`, degrade state, and stop the monitor cleanly (`src/monitor/fanotify.rs`).

### Added
- **metrics:** five new counters exposed via Prometheus exposition -- `fanotify_overflow_scans_triggered`, `fanotify_mark_failures`, `fanotify_read_errors`, `package_cache_failures`, plus the previously-defined-but-unexposed `control_commands` and `backpressure_events`. All are `AtomicU64` with relaxed ordering, accessible via the existing `Metrics` API (`src/metrics.rs`).
- **control:** `MAX_CONCURRENT_CONNECTIONS = 8` with an `AtomicUsize` semaphore. `ControlHandler.baseline_conn` field type changed from `rusqlite::Connection` to `Arc<Mutex<rusqlite::Connection>>` (parking_lot Mutex) so the handler can be `Arc`-shared across worker threads. Connection access in `handle_baseline_count()` and `handle_baseline_refresh()` now locks the Mutex (`src/control.rs`).
- **control:** `current_euid()` helper -- returns the daemon's effective UID via `libc::geteuid()`. Annotated with `#[allow(unsafe_code)]` to override the crate-level `#![deny(unsafe_code)]` for this single FFI call (`src/control.rs`).
- **monitor/fanotify:** `unescape_mountinfo(s: &str) -> String` -- decodes the octal escape sequences the kernel uses for whitespace, backslash, and other special characters in `/proc/self/mountinfo` mount-point fields (`src/monitor/fanotify.rs`).
- **commands/update:** `archive_backups(timestamp: &str)` -- moves `.vigil.backup` and `.vigild.backup` files into `/var/lib/vigil/binary-backups/<timestamp>/` after a successful update so historical binaries can be restored manually for forensics or extended rollback (`src/commands/update.rs`).
- **commands/update:** `prune_old_backup_archives()` -- keeps the 3 most recent archive directories under `/var/lib/vigil/binary-backups/`, removing older ones to bound disk usage (`src/commands/update.rs`).
- **commands/update:** `installed_vigil_path()` -- returns the absolute path of the installed `vigil` binary (`/usr/local/bin/vigil`). Used by `installed_version()` and the post-update `vigil doctor` invocation to ensure the same binary is queried regardless of PATH state (`src/commands/update.rs`).
- **commands/update:** `daemon_is_active()` helper -- returns `true` when `systemctl is-active --quiet vigild` succeeds. Used to determine whether `systemctl stop` failure is fatal (active daemon) or benign (already stopped) (`src/commands/update.rs`).

### Changed
- **monitor/fanotify:** `start()` signature gains two parameters -- `state: Option<Arc<RwLock<DaemonState>>>` and `scan_trigger: Option<Sender<crate::control::ScanRequest>>`. Both are `Option` to preserve test ergonomics. Annotated `#[allow(clippy::too_many_arguments)]` (now 9 args). Reload path rebuilds the bloom filter *before* applying marks so a fresh start always uses the new filter (`src/monitor/fanotify.rs`).
- **monitor/mod.rs:** `start_monitor()` accepts and forwards the new `state` and `scan_trigger` parameters to `fanotify::start()` (`src/monitor/mod.rs`).
- **control:** `ControlHandler::write_response()` now propagates the underlying I/O error instead of silently dropping it via `let _ =`. Connection-level errors are now visible in logs and to the caller (`src/control.rs`).
- **commands/update:** `verify_daemon_health()` now probes immediately on entry and sleeps only between retries -- previously it slept first, then probed, adding 2 s of latency to the common success path. Total max wait unchanged (`src/commands/update.rs`).
- **commands/update:** `install_file_if_changed()` treats `ErrorKind::NotFound` from the source path as a benign skip (returns `Ok(false)`) instead of a fatal error. Allows running `vigil update` from a partial repository without manually pruning the file list (`src/commands/update.rs`).
- **commands/update:** `systemctl stop vigild` failure now hard-fails the update when `daemon_is_active()` returns `true`. Previously, stop failures were warned about and the update continued, risking installation of a binary the running daemon had open (`src/commands/update.rs`).
- **package:** `run_with_timeout()` signature gains an explicit `use_breaker: bool` parameter, replacing the prior heuristic that compared the timeout duration to a sentinel value to decide whether to engage the circuit breaker. All 7 call sites updated; the long-running `build_package_cache()` calls pass `false`, the short query calls pass `true` (`src/package.rs`).
- **package:** empty package-cache builds (`build_cache_pacman/dpkg/rpm`) now log at `error` level instead of `info` -- an empty cache means subsequent attribution will be wrong for every event, which is a degraded-mode condition deserving operator attention (`src/package.rs`).
- **db/baseline_ops:** `batch_upsert()` ROLLBACK failures now log at `error` level instead of being discarded via `let _ =`. A failed rollback after a transaction error indicates database corruption and must surface in logs (`src/db/baseline_ops.rs`).
- **lib:** all 7 background thread `JoinHandle::join()` calls in the drain path (worker, baseline_writer, audit_writer, sink_runner, alert, coordinator, scan_scheduler) now log at `tracing::warn!` on join failure with the thread name. Previously these were `let _ = handle.join()` and panicked threads were silently lost (`src/lib.rs`).
- **lib:** scan trigger channel is now created earlier in `Daemon::start()` (capacity 4, before the monitor) so it can be passed to `monitor::start_monitor()`. The duplicate creation site below was removed. Control handler's baseline DB connection is now wrapped in `Arc::new(parking_lot::Mutex::new(...))` to support the new concurrent control handler (`src/lib.rs`).
- **alert/dbus:** `notify_desktop()` (also in `src/lib.rs`) refactored to resolve `notify-send` to an absolute path via a `OnceLock<Option<PathBuf>>` cache. Prefers `/usr/bin/notify-send`, then `/bin/notify-send`, falls back to PATH lookup (`src/lib.rs`, `src/alert/dbus.rs`).

### Tests
- **control:** `verify_hmac_rejects_empty_response` -- regression test for VIGIL-VULN-057. Generates an HMAC for a known nonce, verifies that an empty client response is rejected by `crate::hmac::verify_hmac()` (`src/control.rs`).
- **monitor/fanotify:** 5 new unit tests for `unescape_mountinfo()` covering: no escapes (passthrough), single space (`\040`), single tab (`\011`), backslash (`\134`), and mixed escapes in a realistic mount-point path (`src/monitor/fanotify.rs`).
- All 4 existing control handler test sites updated to wrap the baseline DB connection in `Arc::new(parking_lot::Mutex::new(...))`.
- All 262 tests pass (`cargo test --all-targets`); `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt --check` clean; `cd fuzz && cargo check` clean.

### Documentation
- **docs/VULNERABILITIES.md:** added VIGIL-VULN-057 through VIGIL-VULN-066 entries with severity, fixed-in version (0.34.0), description, and remediation for each.

## [0.33.0] - 2026-04-17

### Release Summary
- Six new features and six security fixes (VIGIL-VULN-051 through VIGIL-VULN-056). Workers now self-heal after database connection failures. Package manager queries are protected by a circuit breaker that suspends subprocess calls after repeated timeouts. The coordinator tracks per-sub-method tick timing for watchdog debugging and auto-recovers from transient backpressure degradation. A drift velocity metric detects anomalous rates of baseline deviations. Error messages gain structured context via `VigilError::with_context()`. Three critical security fixes: baseline HMAC mismatch no longer silently recomputes (enters Degraded state instead), `baseline_refresh` uses the daemon's live HMAC-verified config instead of re-reading from disk, and control socket reads are bounded to 64KB to prevent OOM. Two high-severity fixes: HMAC key files with group/other permissions are now rejected in release builds, and `vigil update` under sudo no longer searches user-writable home directories for source repositories. All 266 tests pass, clippy clean.

### Security
- **VIGIL-VULN-051 (Critical):** baseline HMAC mismatch in `ensure_baseline_health()` silently recomputed and stored the new HMAC, nullifying tamper-evidence. Now enters `Degraded` state with reason `baseline_hmac_mismatch` and sends `Critical` desktop notification. Escape hatch: `security.trust_baseline_on_hmac_mismatch = true` for genuine version upgrades (`src/lib.rs`).
- **VIGIL-VULN-052 (Critical):** `handle_baseline_refresh()` called `load_config(None)` which re-read config from disk without HMAC verification, bypassing the coordinator's config integrity check. Now uses the daemon's live config via `Arc<ArcSwap<Config>>`. Additionally gated on daemon state -- refuses execution when `Degraded` to prevent cementing compromised filesystem state (`src/control.rs`).
- **VIGIL-VULN-053 (Critical):** `read_request()` and `authenticate_and_read()` used `BufReader::read_line()` with no size limit. A local process could OOM the daemon with a multi-gigabyte newline-less payload. Now bounded to 64KB via `read_bounded_line()` using `Read::take()` (`src/control.rs`).
- **VIGIL-VULN-054 (High):** `check_hmac_key_permissions()` logged a warning when the HMAC key file was world-readable but continued using the key. Now returns `Err` in release builds (`#[cfg(not(any(test, debug_assertions)))]`) when mode & 0o077 != 0, refusing to load the key. Test/debug builds warn instead (`src/hmac.rs`).
- **VIGIL-VULN-055 (High):** under `sudo vigil update`, `$HOME` may point to an unprivileged user's home. `discover_vigil_repo()` searched user-writable paths, and `validate_vigil_repo()` only checked the package name -- a user-placed malicious Rust project could execute arbitrary code as root. Now skips `$HOME`-relative candidates when running as root (unless `$HOME=/root`). As defense-in-depth, `validate_vigil_repo()` checks directory and `Cargo.toml` ownership in release builds (`src/commands/update.rs`).
- **VIGIL-VULN-056 (Medium):** process attribution via `/proc/{pid}/exe` did not distinguish successful from failed readlink -- stale PID attribution was indistinguishable from valid attribution. Now detects exited processes and logs at `debug` level with `exe: None` flagging (`src/monitor/fanotify.rs`).

### Added
- **worker:** self-healing database connections -- `WorkerContext` gains `consecutive_db_errors: u32` and `db_path: PathBuf` fields. On `get_by_path()` failure, the counter increments; on success, it resets to 0. After 5 consecutive failures, the worker attempts `open_baseline_db_readonly()` -- on success, replaces the connection, clears the LRU cache, and resets the counter. On failure, logs at `error` and retries after 5 more failures. Never panics on reconnect failure (Principle IV) (`src/worker.rs`).
- **package:** circuit breaker for package manager queries -- module-level `CONSECUTIVE_TIMEOUTS: AtomicU32` and `CIRCUIT_OPEN_UNTIL: AtomicI64` statics. After 3 consecutive `run_with_timeout()` timeouts on the `PKG_QUERY_TIMEOUT` (5s) path, the circuit opens for 60 seconds -- all queries return `None` immediately without spawning subprocesses. Successful queries reset the counter. `build_package_cache()` (30s timeout) is unaffected. `is_circuit_open()` logs at `info` when the circuit closes (`src/package.rs`).
- **coordinator:** per-sub-method tick duration tracking -- each of the 12 sub-method calls in `tick()` is wrapped with `Instant::now()` / `elapsed()`. Individual durations exceeding 5 seconds log at `warn` with method name. Total tick exceeding 10 seconds logs at `warn` with full breakdown. Negligible overhead (one `Instant::now()` per sub-method per 60-second tick). Does not change existing `notify_watchdog()` placement (`src/coordinator.rs`).
- **coordinator:** backpressure auto-recovery -- `check_backpressure()` now transitions back from `Degraded { reason: "event_backpressure" }` to `Healthy` when the backpressure flag clears. Only recovers from `event_backpressure` -- security-related degradation (`baseline_db_replaced`, `audit_db_replaced`, `wal_file_replaced`, `baseline_hmac_mismatch`) requires daemon restart (`src/coordinator.rs`).
- **coordinator:** drift velocity metric -- `Coordinator` gains `drift_samples: [u64; 5]`, `drift_sample_idx: usize`, and `last_changes_seen: u64`. `check_drift_velocity()` computes the 5-minute rolling average of changes per tick. When the average exceeds `scanner.drift_velocity_threshold` (default 50) and no maintenance window is active, logs at `error`: "high baseline drift velocity -- possible active compromise". Suppressed during maintenance windows. Included in `state.json` as `drift_velocity` field (`src/coordinator.rs`).
- **config:** `scanner.drift_velocity_threshold: Option<u64>` -- average baseline changes per coordinator tick that triggers a high-drift-velocity warning. `None` (default) uses hardcoded 50. (`src/config/mod.rs`).
- **config:** `security.trust_baseline_on_hmac_mismatch: bool` -- when `true`, HMAC mismatch on startup recomputes and stores the new HMAC (with warning) instead of entering Degraded state. Default `false`. Use temporarily after version upgrades that change baseline HMAC field coverage (`src/config/mod.rs`).
- **error:** `VigilError::with_context(self, ctx: &str) -> Self` -- prepends context to string-based error variants (Config, Daemon, Baseline, Alert, etc.). For variants wrapping external errors (Io, Database, TomlParse, Json, GlobPattern), converts to the appropriate string variant with context prefix. No new dependencies (`src/error.rs`).
- **control:** `ControlHandler` gains `config: Arc<ArcSwap<Config>>` field -- provides access to the daemon's live, HMAC-verified config. Threaded from `DaemonRuntime::start()` where `daemon.config` is available (`src/control.rs`, `src/lib.rs`).
- **control:** `read_bounded_line()` helper -- reads a single line from a `UnixStream` bounded to `MAX_REQUEST_LINE_BYTES` (64KB) using `Read::take()`. Returns `Err` on empty connection, size limit exceeded, or I/O error (`src/control.rs`).

### Changed
- **lib:** `ensure_baseline_health()` -- HMAC mismatch branch now checks `config.security.trust_baseline_on_hmac_mismatch`. When `false` (default): logs at `error`, sends `Critical` desktop notification, transitions to `Degraded`. When `true`: logs at `warn`, recomputes and stores the HMAC. Previously always recomputed silently (`src/lib.rs`).
- **lib:** `db::open_baseline_db()` call in `Daemon::from_config()` now wrapped with `.map_err(|e| e.with_context("opening baseline database during daemon startup"))` (`src/lib.rs`).
- **lib:** `db::open_audit_db()` call in `Daemon::from_config()` now wrapped with `.map_err(|e| e.with_context("opening audit database during startup"))` (`src/lib.rs`).
- **lib:** `scanner::build_initial_baseline()` call in `ensure_baseline_health()` now wrapped with `.map_err(|e| e.with_context("building initial baseline"))` (`src/lib.rs`).
- **control:** `handle_baseline_refresh()` -- uses `self.config.load()` instead of `crate::config::load_config(None)`. Checks daemon state before execution and refuses with clear error when `Degraded` (`src/control.rs`).
- **control:** `read_request()` and `authenticate_and_read()` -- replaced `BufReader::read_line()` with `read_bounded_line()` (`src/control.rs`).
- **hmac:** `check_hmac_key_permissions()` -- changed from void function to `Result<()>`. In release builds, returns `Err(VigilError::HmacVerification(...))` on permissive mode. `load_hmac_key()` now propagates the error via `?` (`src/hmac.rs`).
- **coordinator:** `write_state_snapshot()` -- now takes an optional `drift_velocity: Option<u64>` parameter and includes it in the state JSON when available (`src/coordinator.rs`).
- **commands/check:** `open_baseline_db()` call now wrapped with `.map_err(|e| e.with_context("opening baseline database for check"))` (`src/commands/check.rs`).
- **commands/update:** `validate_vigil_repo()` call now wrapped with `.map_err(|e| e.with_context(...))` with the repo path in context (`src/commands/update.rs`).
- **commands/update:** `discover_vigil_repo()` -- when running as root, skips `$HOME`-relative candidates unless `$HOME` is `/root`. Logs at `debug` when skipping (`src/commands/update.rs`).
- **commands/update:** `validate_vigil_repo()` -- when running as root in release builds, checks directory and `Cargo.toml` ownership (UID must be 0) (`src/commands/update.rs`).
- **monitor/fanotify:** process attribution -- failed `/proc/{pid}/exe` readlink now logged at `debug` ("process exited before attribution -- PID may be stale") and `ProcessAttribution` populated with `exe: None` (`src/monitor/fanotify.rs`).

### Tests
- **worker:** `worker_consecutive_db_errors_increments` -- creates a `WorkerContext` with an in-memory DB that lacks baseline tables, verifies `consecutive_db_errors` increments to 4 after 4 failed `evaluate()` calls (`src/worker.rs`).
- **package:** `circuit_breaker_opens_after_threshold` -- sets `CIRCUIT_OPEN_UNTIL` to future timestamp, verifies `is_circuit_open()` returns `true` (`src/package.rs`).
- **package:** `circuit_breaker_closes_after_expiry` -- sets `CIRCUIT_OPEN_UNTIL` to past timestamp, verifies `is_circuit_open()` returns `false` and counters reset (`src/package.rs`).
- **package:** `circuit_breaker_resets_on_success` -- verifies `CONSECUTIVE_TIMEOUTS` can be reset to 0 (`src/package.rs`).
- **error:** `with_context_prepends_message` -- verifies `VigilError::Config("missing field").with_context("loading config")` produces a message containing both strings (`src/error.rs`).
- **error:** `with_context_io_becomes_daemon` -- verifies `VigilError::Io(...)` converts to `VigilError::Daemon(...)` with context prefix and "I/O error" tag (`src/error.rs`).
- **control:** `read_bounded_line_rejects_oversized_request` -- sends 65KB+ without newline via `UnixStream::pair()`, verifies `read_bounded_line()` returns error mentioning "exceeds maximum size" (`src/control.rs`).
- **control:** `baseline_refresh_refused_when_degraded` -- constructs `ControlHandler` with `Degraded` state, verifies `handle_baseline_refresh()` returns `ok: false` with error mentioning "degraded" (`src/control.rs`).
- **hmac:** `check_hmac_key_permissions_permissive_mode_in_test` -- creates key with mode 0644, verifies test-build returns `Ok` (would fail in release), confirms underlying mode check would flag it (`src/hmac.rs`).
- **hmac:** `check_hmac_key_permissions_strict_mode_ok` -- creates key with mode 0600, verifies `check_hmac_key_permissions()` returns `Ok` (`src/hmac.rs`).
- **update:** `validate_vigil_repo_ownership_check_logic` -- creates temp repo, verifies ownership metadata (UID non-zero when non-root, zero when root) (`src/commands/update.rs`).
- All 266 tests pass (`cargo test --all-targets`), `cargo clippy --all-targets` clean.

### Documentation
- **docs/VULNERABILITIES.md:** added VIGIL-VULN-051 through VIGIL-VULN-056 with severity, fixed-in version, detailed description, and remediation for each.
- **docs/RESILIENCE.md:** added sections for worker self-healing, package manager circuit breaker, backpressure recovery, baseline HMAC mismatch handling, control socket size limits, and process attribution limitations.
- **docs/CONFIGURATION.md:** documented `scanner.drift_velocity_threshold` and `security.trust_baseline_on_hmac_mismatch` options with defaults.
- **docs/SECURITY.md:** added 7 entries to the threat scope table for the new security coverage areas.

## [0.32.3] - 2026-04-16

### Release Summary
- Hardened `vigil update` for crash safety, rollback capability, and sudo-aware repository discovery. Under `sudo`, the update command now correctly finds the source repository via `SUDO_USER` instead of searching only under `/root`. Build artifacts are smoke-tested before touching installed binaries. Existing binaries are backed up and automatically restored if any install step or post-install health check fails. Daemon health verification retries up to 3 times before triggering rollback. Failed repository candidates now show *why* they were rejected, not just *that* they were checked.

### Fixed
- **update:** `discover_vigil_repo()` now checks `SUDO_USER` environment variable to derive the invoking user's home directory when running under `sudo`. Previously, `HOME=/root` caused the search to miss `/home/<user>/src/vigil` even when it was the correct repository. Candidates are deduplicated so the same path is never checked or printed twice (`src/commands/update.rs`).
- **update:** `discover_vigil_repo()` error message now includes the *reason* each candidate was rejected (e.g., "Cargo.toml not found", "package name is 'foo', expected 'vigil-baseline'") instead of just listing the paths that were checked (`src/commands/update.rs`).

### Added
- **update:** `smoke_test_binary()` -- verifies build artifacts are functional (`--version` exits 0) before any installed binary is touched. If a corrupt artifact is detected, the update aborts early with the binary path and stderr output in the error message (`src/commands/update.rs`).
- **update:** `install_binaries_with_rollback()` -- backs up existing `/usr/local/bin/vigil` and `/usr/local/bin/vigild` to `.vigil.backup` / `.vigild.backup`, installs new binaries atomically (copy → chmod → rename), smoke-tests the installed copies, and automatically restores backups if any step fails (`src/commands/update.rs`).
- **update:** `rollback_binaries()` -- restores `.backup` files to their original paths via `sudo mv`, with per-binary success/failure reporting (`src/commands/update.rs`).
- **update:** `verify_daemon_health()` -- retries daemon health check up to 3 times with 2-second intervals (total max wait: 6 seconds) instead of a single check after a 2-second sleep. Returns `true` on first successful response, reports attempt progress (`src/commands/update.rs`).
- **update:** post-restart rollback -- if the daemon fails all 3 health checks and backup binaries exist, the update command stops the daemon, restores backup binaries, restarts the daemon with the old version, and returns an error explaining what happened. If no backups exist (first install), it warns instead (`src/commands/update.rs`).
- **update:** version downgrade warning -- when the new version string is lexicographically lower than the current version (after stripping `v` prefix), prints a `⚠ downgrade detected` warning. Does not block the update (`src/commands/update.rs`).
- **update:** `backup_path()` helper -- computes `.backup` path for a given binary destination (e.g., `/usr/local/bin/vigil` → `/usr/local/bin/.vigil.backup`) (`src/commands/update.rs`).
- **update:** `cleanup_backups()` helper -- removes `.backup` files after a fully successful update (`src/commands/update.rs`).

### Changed
- **update:** `validate_vigil_repo()` now returns structured error messages: "Cargo.toml not found", "Cargo.toml parse error: {details}", or "package name is '{name}', expected 'vigil-baseline', 'vigilbaseline', or 'vigil'". Previously returned a generic "not a Vigil Baseline repository" message for all failure modes (`src/commands/update.rs`).
- **update:** `normalize_version()` now handles empty and whitespace-only input by returning `"unknown"` instead of panicking on `.unwrap()` (`src/commands/update.rs`).

### Tests
- **update:** `test_discover_vigil_repo_uses_sudo_user` -- validates backup path generation and repo validation with SUDO_USER-style directory layout (`src/commands/update.rs`).
- **update:** `validate_vigil_repo_error_messages` -- verifies structured error messages for missing Cargo.toml, parse errors, and wrong package names (`src/commands/update.rs`).
- **update:** `normalize_version_edge_cases` -- covers empty string, whitespace-only, tab/newline, and multi-word version output (`src/commands/update.rs`).
- **update:** `test_rollback_sequence` -- validates backup path computation and verifies all new function signatures compile correctly (`src/commands/update.rs`).

## [0.32.2] - 2026-04-15

### Changed
- **package:** renamed crate from `vigilbaseline` to `vigil-baseline` for crates.io publishing. Binary names (`vigil`, `vigild`) and library name (`vigil`) are unchanged (`Cargo.toml`).
- **package:** added crates.io metadata -- `repository`, `homepage`, `readme`, `keywords`, `categories` (`Cargo.toml`).
- **fuzz:** renamed fuzz crate from `vigilbaseline-fuzz` to `vigil-baseline-fuzz` and updated dependency to `package = "vigil-baseline"` (`fuzz/Cargo.toml`).
- **update:** `validate_vigil_repo()` now accepts `vigil-baseline` as a valid Cargo.toml package name alongside legacy names `vigilbaseline` and `vigil` (`src/commands/update.rs`).
- **docs:** updated all repository URLs from `github.com/loujr/vigil` to `github.com/lousclues-labs/vigil` across 6 files -- `CONTRIBUTING.md`, `TRADEMARKS.md`, `docs/DEVELOPMENT.md`, `docs/INSTALL.md`, `licenses/CONTRIBUTOR-LICENSE.md`, `licenses/DEPENDENCY-AUDIT.md`.

### Added
- **aur:** `aur/PKGBUILD` -- Arch Linux AUR package build script for `vigil-baseline`. Installs binaries, systemd units, documentation, and example config (`aur/PKGBUILD`).
- **aur:** `aur/vigil-baseline.install` -- pacman install hook with quickstart instructions, upgrade guidance, and clean service stop/disable on removal (`aur/vigil-baseline.install`).
- **ci:** `.github/workflows/release.yml` -- automated release workflow triggered by version tags. Validates Cargo.toml version matches tag, runs tests, builds release binaries, strips them, creates GitHub Release with tarball + checksum, and publishes to crates.io (`.github/workflows/release.yml`).

## [Unreleased]

## [0.32.1] - 2026-04-15

### Fixed
- **audit:** fixed "BaselineBaseline" typo in audit chain verification header -- was "Vigil BaselineBaseline", now "Vigil Baseline" (`src/commands/audit.rs`).
- **lib:** config HMAC storage failure in `Daemon::from_config()` now logs at error level with "tamper detection weakened" message instead of silently discarding via `let _ =`. The coordinator path was fixed in v0.32.0, but the startup path was missed (`src/lib.rs`).
- **scan_scheduler:** on-demand scan response delivery failure now logs at warn level ("requester disconnected") instead of silently discarding via `let _ =` (`src/scan_scheduler.rs`).
- **worker:** `drain_debounced()` WAL append failure log now includes the path of the affected file for diagnostic context, matching the behavior of `dispatch_detection()` (`src/worker.rs`).

### Changed
- **lib:** `config_search_paths_for_hash()` -- replaced 28-line reimplementation of config path resolution with 3-line delegation to `config::config_search_paths(None)`, eliminating duplicated `VIGIL_CONFIG` env handling and production ownership validation logic (`src/lib.rs`).
- **coordinator:** `config_file_content()` -- replaced 23-line reimplementation with 3-line delegation to `config::config_search_paths(None)`, eliminating the same duplication (`src/coordinator.rs`).
- **coordinator:** `check_mount_evasion()` -- `expand_user_paths()` now called once before the mount iteration loop instead of once per mount × per watch group. On systems with many mounts and watch groups, this eliminates redundant path expansion (`src/coordinator.rs`).
- **scanner:** `CaptureOpts` in `build_initial_baseline()` hoisted above the file walk loop -- the struct has identical values for every file (force_hash=true, no baseline mtime/hash), so it's constructed once instead of per-file (`src/scanner.rs`).
- **lib:** `Daemon` struct fields tightened from `pub` to `pub(crate)` -- only `shutdown` remains `pub` (used by integration tests). Internal fields (`config`, `baseline_conn`, `metrics`, `state`, `reload_flag`, `watch_index`, `*_identity`, `startup_hmac_key`, `maintenance_*`) are no longer part of the public API surface (`src/lib.rs`).
- **lib:** removed dead `config_hash: Option<String>` field from `Daemon` struct -- was set at construction but never read. The coordinator independently computes its own config hash for reload detection (`src/lib.rs`).

### Removed
- **scanner:** `refresh_baseline()` one-line alias removed -- callers (`commands/baseline.rs`, `control.rs`) now call `build_initial_baseline()` directly (`src/scanner.rs`).

## [0.32.0] - 2026-04-15

### Release Summary
- Comprehensive code quality audit -- the single biggest maintainability change since the project began. The 2,810-line `main.rs` monolith -- which contained every CLI command handler -- has been decomposed into a `src/commands/` module with 15 focused submodules (one per command). A new `src/detection.rs` module extracts the WAL-or-alert dispatch pattern that was copy-pasted 5 times across `worker.rs` and `scan_scheduler.rs`. Silent error swallowing on security-critical paths (WAL append for panic records, config HMAC storage) now logs at error level. The hardcoded `/etc/vigil/vigil.toml` in worker self-protection is replaced with dynamic config path lookup. Duplicate buffered-reader code in `hash.rs` is extracted into a shared helper. Hot-path allocations are reduced: `Cow<str>` replaces `to_string_lossy().to_string()` in the worker event loop, `as_encoded_bytes()` replaces `to_string_lossy().as_bytes()` in the Bloom filter. Dead code removed, API surface tightened, comments cleaned. README rewritten with sharper voice and structural clarity. Zero warnings from `cargo clippy --all-targets -- -D warnings`. All 250+ tests pass.

### Added
- **detection:** new `src/detection.rs` module with `dispatch_detection()` helper -- shared WAL-or-alert dispatch logic extracted from 5 duplicate sites across `worker.rs` and `scan_scheduler.rs`. Tries WAL append first, falls back to alert channel on failure, logs at error level if the alert channel is disconnected (detection would be lost). Returns `bool` indicating channel disconnect for caller shutdown logic (`src/detection.rs`).
- **commands:** new `src/commands/` module directory with 15 submodules -- `mod.rs` (re-exports), `common.rs` (shared helpers: `print_header`, `format_count`, `truncate_hash`, `print_change_detail`, `pipe_to_pager`, `parse_time_filter`, `parse_time_filter_strict`, `resolve_config_path`, `update_config_toml`, `format_audit_timestamp`, `query_control_socket`), `init.rs` (`cmd_init`), `check.rs` (`cmd_check`, `cmd_check_live`, `CheckOpts`), `watch.rs` (`cmd_watch`), `diff.rs` (`cmd_diff`, `render_diff_history_panel`, `summarize_audit_changes`), `status.rs` (`cmd_status`), `doctor.rs` (`cmd_doctor`, `print_check`), `audit.rs` (`cmd_audit`, `entries_to_json`), `config.rs` (`cmd_config`), `setup.rs` (`cmd_setup`, `cmd_setup_hmac`, `cmd_setup_socket`), `log.rs` (`cmd_log`), `maintenance.rs` (`cmd_maintenance`), `baseline.rs` (`cmd_baseline`, `cmd_baseline_refresh`), `update.rs` (`cmd_update`, `validate_vigil_repo`, `discover_vigil_repo`, `atomic_install`, and related helpers) (`src/commands/`).
- **metrics:** `Metrics::record_scan(changes_found, duration_ms, total_checked)` method -- consolidates the 6-line scan metric update pattern that was duplicated between on-demand and scheduled scan paths in `scan_scheduler.rs` (`src/metrics.rs`).
- **config:** `config_search_paths()` made `pub` -- exposes the config file resolution logic for use in worker self-protection checks, replacing the hardcoded `/etc/vigil/vigil.toml` path (`src/config/mod.rs`).
- **hash:** `hash_buffered(file, hasher)` helper -- extracted from the identical mmap-fallback and non-mmap buffered reader paths in `blake3_hash_fd()`, eliminating verbatim code duplication (`src/hash.rs`).

### Changed
- **main:** reduced from 2,810 lines to ~120 lines -- now contains only `main()`, `init_tracing()`, and the `run()` match dispatch calling into `commands::*`. All command implementations, helper functions, formatting utilities, and control socket logic moved to `src/commands/` (`src/main.rs`).
- **worker:** `evaluate()` now uses `Cow<str>` for LRU cache lookups instead of `to_string_lossy().to_string()`, avoiding a heap allocation on every filesystem event. Cache insertion uses `into_owned()` only when a new entry must be stored. `drain_debounced()` similarly uses `Cow<str>` for cache eviction (`src/worker.rs`).
- **worker:** `process_event_inner()` -- removed unused `_conn: &Connection` parameter. The function never used the database connection; callers updated (`src/worker.rs`).
- **worker:** self-protection config path check now uses `crate::config::config_search_paths(None)` to check all standard config locations (`/etc/vigil/vigil.toml`, `~/.config/vigil/vigil.toml`, `$VIGIL_CONFIG`) instead of the hardcoded `/etc/vigil/vigil.toml` (`src/worker.rs`).
- **worker:** WAL append failure for panic detection records now logs at error level with path context instead of silently discarding via `let _ =` (`src/worker.rs`).
- **worker:** realtime event dispatch in `spawn_workers()` now uses `detection::dispatch_detection()` instead of inline WAL-or-alert logic (~40 lines replaced by single function call) (`src/worker.rs`).
- **scan_scheduler:** both on-demand and scheduled scan dispatch loops now use `detection::dispatch_detection()` instead of inline WAL-or-alert logic. Scan metric recording now uses `Metrics::record_scan()` instead of 3 separate atomic operations (`src/scan_scheduler.rs`).
- **coordinator:** config HMAC storage failure now logs at error level with "tamper detection weakened" message instead of silently discarding via `let _ =` (`src/coordinator.rs`).
- **coordinator:** `atomic_write()` visibility tightened from `pub` to `pub(crate)` -- only used within the crate (`src/coordinator.rs`).
- **coordinator:** `is_notify_socket_safe()` visibility tightened from `pub` to `pub(crate)` -- only used within the crate (`src/coordinator.rs`).
- **coordinator:** `atomic_write()` doc comment condensed -- removed first line that restated the function name, kept the useful note about `rename()` atomicity on Linux (`src/coordinator.rs`).
- **bloom:** `might_contain_prefix_of()` and `from_watch_paths()` now use `as_os_str().as_encoded_bytes()` (stable since Rust 1.74) instead of `to_string_lossy().as_bytes()`, avoiding UTF-8 conversion overhead and handling non-UTF-8 paths correctly (`src/bloom.rs`).
- **scanner:** `run_scan_with_progress()` now hoists `force_hash`, `max_file_size`, and `mmap_threshold` before the scan loop instead of re-reading from config on every file. `build_initial_baseline()` similarly hoists the common fields (`src/scanner.rs`).
- **metrics:** removed redundant "Operational metrics for the Vigil daemon" doc comment -- the struct name `Metrics` already communicates this. Kept the useful second line about relaxed atomic ordering (`src/metrics.rs`).
- **bloom:** removed opaque "(Item 21)" reference from doc comment -- replaced with no reference since the original design document is not linked (`src/bloom.rs`).
- **README:** rewritten with sharper voice and structural clarity -- "The Baseline" section replaces "The Philosophy", "What You Get" reorganized into outcome-oriented sections (Establish/Watch/Detect/Prove/Stay informed), Quick Start commands updated with descriptive comments, "How It Gets Built" condensed, added baseline self-protection principle (`README.md`).

### Removed
- **watch_index:** `WatchGroupIndex::update_from_config()` -- dead code. The coordinator creates a new index via `WatchGroupIndex::from_config()` and swaps the `ArcSwap`; in-place mutation is impossible through the `ArcSwap` indirection (`src/watch_index.rs`).
- **scanner:** `collect_all_paths()` -- dead code behind `#[cfg(feature = "parallel")]` with no callers (`src/scanner.rs`).
- **worker:** `UpdateReason::AutoRebaseline` variant -- never constructed. `PackageUpdate` is the only variant used (`src/worker.rs`).
- **worker:** doc comment on `dup_to_file()` -- restated the function name and return type. The `// SAFETY:` comments inside the function body are retained (`src/worker.rs`).

### Tests
- All 250+ tests pass (`cargo test --all-targets`), `cargo clippy --all-targets -- -D warnings` clean, `cd fuzz && cargo check` clean.
- Tests moved from `main.rs` to `src/commands/update.rs`: `validate_vigil_repo_accepts_valid_package_name`, `validate_vigil_repo_accepts_legacy_package_name`, `validate_vigil_repo_rejects_other_package_name`, `normalize_version_prefixes_v_when_missing`.

## [0.31.0] - 2026-04-12

### Release Summary
- Reimagined display system -- a new `src/display/` module (~1,960 lines across 6 files) that replaces the ad-hoc inline formatting in `main.rs` with a consolidated rendering layer. `vigil check` now produces layered, severity-triaged output with a visual histogram, progressive disclosure (≤5 changes: full detail; ≤20: expanded investigate/attention; >20: grouped benign), structural "why" explanations (e.g. "setuid bit added -- investigate", "SSH authorized keys changed"), package-aware grouping for LOW-severity changes, and self-documenting exit codes. `vigil init` gains a baseline profile panel (executables, setuid, config files, package-owned percentages) and guided next-step commands. `vigil check --since` is now functional -- it filters current scan results against audit DB timestamps to show only changes with evidence in the specified time window, while keeping paths with no audit history visible (fail loud, Principle X). `vigil diff` now includes a recent per-path audit history panel showing the last 8 audit entries for the inspected file. Terminal rendering respects `NO_COLOR`, detects TTY/width/height via ioctl with environment fallback, and auto-pages through `$PAGER` when output exceeds terminal height. Accept flow gains `--dry-run`, `--accept-severity`, and `--accept-group` filters with preview and fingerprint receipts. JSON output maintains backward compatibility with the original `ScanResult` shape.

### Added
- **display:** new `src/display/` module with 6 files -- `mod.rs` (public API surface, `CheckReport`/`InitReport`/`BaselineProfile` structs, `render_check`/`render_init` dispatch), `check.rs` (report construction, human/brief/JSON renderers, init renderers, severity triage, package grouping), `format.rs` (ANSI color system with `Style`/`Styled`, `format_count`/`format_size`/`format_age`/`format_fingerprint`/`truncate_hash`/`truncate_path`, exit code descriptions), `explain.rs` (structural change explanations mapping changes to human-readable "why" lines), `term.rs` (`TermInfo` terminal capability detection), `widgets.rs` (severity histogram, change comparison tables) (`src/display/`).
- **display:** `CheckReport` struct -- enriched report built from `ScanResult` + baseline metadata via `CheckReport::from_scan(scan, CheckReportMeta)`. Contains: baseline fingerprint, HMAC status, scan mode, delta composition (modified/created/deleted/unchanged counts), severity histogram (`BTreeMap<Severity, u64>`), triage grouping (investigate/attention/benign), package grouping, temporal context (previous check age/outcome), and DB path (`src/display/mod.rs`).
- **display:** `CheckReportMeta` struct -- builder metadata passed to `CheckReport::from_scan()` containing mode, fingerprint, established timestamp, HMAC status, baseline count, previous check state, and DB path (`src/display/mod.rs`).
- **display:** `InitReport` struct -- enriched report for `vigil init` with baseline fingerprint, HMAC status, DB path, and optional `BaselineProfile` (`src/display/mod.rs`).
- **display:** `BaselineProfile` struct -- classification of baselined files by property: total, executables, setuid, setgid, config files, keys/certs, package-owned, unpackaged. Computed via SQL aggregation in `baseline_ops::compute_baseline_profile()` (`src/display/mod.rs`, `src/db/baseline_ops.rs`).
- **display:** `explain::explain(change, path)` -- pure function mapping structural changes to human-readable explanations. Covers: setuid/setgid bit changes, world-writable permissions, capability changes, root ownership changes on system binaries, content changes to high-value files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, SSH keys, cron, systemd units), file deletion/creation in system paths, and SELinux/AppArmor security context changes. No heuristics -- every explanation maps to a binary structural fact (Principle III) (`src/display/explain.rs`).
- **display:** `TermInfo::detect()` -- terminal capability detection: TTY via `IsTerminal`, `NO_COLOR` environment variable, width/height from `$COLUMNS`/`$LINES` with `ioctl(TIOCGWINSZ)` fallback, defaults to 80×24 on failure (Principle X: fail open) (`src/display/term.rs`).
- **display:** severity histogram widget -- horizontal bar chart in Unicode box-drawing frame, adapts bar width to terminal width, colored by severity (`src/display/widgets.rs`).
- **display:** `render_check()` dispatch -- single function routing to human/brief/JSON renderers based on `OutputFormat`. No trait indirection (`src/display/mod.rs`).
- **display:** `render_init()` dispatch -- routes to human/brief/JSON init renderers (`src/display/mod.rs`).
- **display:** human check renderer -- layered output with baseline identity line, scan summary, HMAC status, coverage stats, temporal context (previous check age with stale warning >24h), severity histogram, progressive disclosure by change count, "why" explanation lines, scan issues section with guidance, next-step commands, and self-documenting exit code line (`src/display/check.rs`).
- **display:** brief check renderer -- single-line output: `● ok (N files, Xs)` when clean, `✗ N critical · M high (N files, Xs)` when changes detected (`src/display/check.rs`).
- **display:** JSON check renderer -- backward-compatible with original `ScanResult` shape: `total_checked`, `changes_found`, `errors`, `warnings`, `changes`, `duration_ms` (`src/display/check.rs`).
- **display:** human init renderer -- baseline fingerprint, HMAC status, per-group file counts, total with throughput, DB size, baseline profile panel (when available), next-step commands including systemd enable hint and HMAC setup suggestion (`src/display/check.rs`).
- **display:** package grouping for LOW-severity changes -- groups by package name when `package_update` flag is set or when ≥3 files share the same package. Grouped changes show collapsed path prefix summary. Ungrouped LOW changes render individually (`src/display/check.rs`).
- **check:** `--since <TIME>` flag is now functional -- parses time expressions (`24h`, `7d`, `today`, `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS`, unix timestamp), opens audit DB, queries per-path audit window state via `get_path_window_state()`, keeps changes with audit evidence in the time window, keeps changes with no audit history (fail loud -- Principle X), drops changes whose last audit evidence predates the window. Emits informational scan warnings documenting what was filtered and why. Rejects `--since` with `--now` (requires local audit DB access) (`src/main.rs`, `src/cli.rs`).
- **check:** `--dry-run` flag (requires `--accept`) -- previews what would be accepted without mutating the baseline. Shows accept preview with filter summary and condensed change list, then exits with "Baseline was not modified" (`src/cli.rs`, `src/main.rs`).
- **check:** `--accept-severity <LEVEL>` flag (requires `--accept`) -- filters accept candidates by severity level (`src/cli.rs`, `src/main.rs`).
- **check:** `--accept-group <NAME>` flag (requires `--accept`) -- filters accept candidates by watch group name (`src/cli.rs`, `src/main.rs`).
- **check:** accept flow preview -- before mutating baseline, shows condensed preview of selected changes (up to 10 lines with "... and N more"), active filter summary, and baseline fingerprint receipt (old → new) after acceptance (`src/main.rs`).
- **check:** pager support -- pipes output through `$PAGER` (defaulting to `less -R`) when output exceeds terminal height. Disabled for brief mode, JSON output, and accept flow (operator must see receipts directly). Falls back to direct print on empty/invalid pager or spawn failure (`src/main.rs`).
- **check:** exit code semantics -- 0 = no changes, 1 = low/medium severity, 2 = high severity, 3 = critical. Self-documenting exit code line in TTY output when code ≠ 0 (`src/display/check.rs`, `src/display/format.rs`).
- **check:** temporal context -- displays previous check age and outcome (clean / N changes) in check header. Shows "⚠ stale" warning when previous check is >24h old (`src/display/check.rs`).
- **check:** scan issues section -- renders scan errors/warnings with severity markers, per-path detail, and actionable guidance (permission denied → run as root, file too large → raise max_file_size, transient disappearance → normal on active systems). Coverage reduction warning when errors present (`src/display/check.rs`).
- **diff:** audit history panel -- `vigil diff` now opens `audit.db` and renders a "Recent audit history" section showing the last 8 audit entries for the inspected path. Each entry shows timestamp, severity, change type summary, and maintenance/suppression flags. Falls back gracefully if audit DB cannot be opened (`src/main.rs`).
- **db:** `audit_ops::get_recent_for_path(conn, path, limit)` -- exact-match path query returning most recent audit entries for a single file. Uses `WHERE path = ?1` (not LIKE) for precision (`src/db/audit_ops.rs`).
- **db:** `audit_ops::AuditPathWindowState` struct and `get_path_window_state(conn, path, since, until)` -- returns the latest audit timestamp for a path overall and within a specified time window. Used by `--since` filtering to determine whether a change has audit evidence in the requested window (`src/db/audit_ops.rs`).
- **db:** `baseline_ops::get_baseline_fingerprint(conn)` -- reads `baseline_hmac` from `config_state` and formats as `xxxx·xxxx·xxxx·xxxx` via `display::format_fingerprint()` (`src/db/baseline_ops.rs`).
- **db:** `baseline_ops::get_baseline_established(conn)` -- reads the `updated_at` timestamp for the `baseline_hmac` config_state key (`src/db/baseline_ops.rs`).
- **db:** `baseline_ops::compute_baseline_profile(conn)` -- SQL aggregation query computing file classification counts: executables (mode & 0o111), setuid (mode & 0o4000), setgid (mode & 0o2000), config files (/etc/%), keys/certs (.ssh/% or .gnupg/%), package-owned vs unpackaged (`src/db/baseline_ops.rs`).
- **types:** `OutputFormat::Brief` variant added for single-line summary output (`src/types/config_types.rs`).

### Changed
- **main:** `cmd_check()` rewritten -- now builds `CheckReport::from_scan()` with `CheckReportMeta`, uses `display::render_check()` for output, supports pager, handles `--since` filtering against audit DB, handles `--dry-run`/`--accept-severity`/`--accept-group` in accept flow, persists `last_check_at`/`last_check_changes` in config_state for temporal context, returns exit code based on highest severity (`src/main.rs`).
- **main:** `cmd_init()` rewritten -- now accepts `format: OutputFormat`, builds `display::InitReport` with baseline fingerprint, HMAC status, and baseline profile, uses `display::render_init()` for output (`src/main.rs`).
- **main:** `cmd_diff()` extended -- opens audit DB alongside baseline DB, renders per-path audit history panel after baseline comparison (`src/main.rs`).
- **main:** `parse_time_filter()` hardened -- now trims whitespace, normalizes case, accepts `all` case-insensitively. New `parse_time_filter_strict()` wrapper provides error messages with flag name context for CLI validation (`src/main.rs`).
- **main:** formatting helpers deduplicated -- `format_count()`, `format_size()`, `truncate_hash()` in `main.rs` now delegate to `display::fmt_count()`, `display::fmt_size()`, `display::truncate_hash()` (`src/main.rs`).
- **doctor:** `format_count()` and `format_size()` deduplicated -- now delegate to `crate::display::fmt_count()` and `crate::display::fmt_size()` (`src/doctor.rs`).
- **cli:** `check` subcommand gains `--verbose`, `--brief`, `--no-pager`, `--dry-run`, `--accept-severity`, `--accept-group`, and functional `--since` flags (`src/cli.rs`).
- **cli:** `--since` help text updated from "reserved for future use" to describe actual behavior (`src/cli.rs`).

### Tests
- **display (11 new tests):** `severity_histogram_counts`, `package_grouping_threshold`, `exit_code_mapping` (check.rs); `setuid_added`, `setuid_removed`, `world_writable`, `shadow_content`, `ssh_authorized_keys`, `capabilities_added`, `owner_changed_from_root`, `no_explanation_for_simple_content` (explain.rs); `styled_emits_ansi_when_tty`, `styled_no_ansi_when_piped`, `severity_style_mapping`, `format_count_basic`, `format_size_basic`, `format_age_intervals`, `truncate_hash_basic`, `format_fingerprint_basic`, `format_fingerprint_short_input`, `truncate_path_short_unchanged`, `truncate_path_long_gets_ellipsis`, `truncate_path_preserves_filename`, `exit_code_descriptions` (format.rs); `detect_produces_valid_dimensions`, `fallback_defaults` (term.rs); `empty_histogram`, `single_severity`, `multiple_severities`, `oneline_content_change` (widgets.rs) (`src/display/`).
- **cli (3 new tests):** `check_dry_run_requires_accept`, `check_accept_filters_parse`, `check_since_parses` (`src/cli.rs`).
- **db (2 new tests):** `get_recent_for_path_is_exact_match`, `get_path_window_state_reports_latest_and_window` (`src/db/audit_ops.rs`).
- All 251 tests pass (up from 215), `cargo clippy -- -D warnings` clean, `cd fuzz && cargo check` clean.

### Validation
- `cargo check` succeeds with 0 warnings.
- `cargo test --all-targets` passes all 251 tests (0 failures).
- `cargo clippy -- -D warnings` produces 0 errors and 0 warnings.
- `cd fuzz && cargo check` compiles cleanly.
- `NO_COLOR=1 vigil check` produces unstyled output.
- `--since` correctly queries audit DB and emits informational warnings about filtering decisions.
- `vigil diff` renders audit history panel when entries exist, shows "No audit entries found" when none.
- JSON output maintains backward compatibility with `ScanResult` shape.
- Accept flow with `--dry-run` does not mutate baseline.
- Pager respects `$PAGER`, falls back to `less -R`, disabled during accept flow.

## [0.30.0] - 2026-04-12

### Release Summary
- Reconnects the `vigil maintenance` and `vigil baseline` CLI subcommands that were removed during a documentation cleanup (v0.18.1) but are still invoked by every package manager hook (`hooks/pacman/vigil-pre.hook`, `hooks/pacman/vigil-post.hook`, `hooks/apt/99vigil`). Previously, every `pacman -Syu` or `apt upgrade` on a system with Vigil hooks installed produced `error: unrecognized subcommand 'maintenance'` / `error: unrecognized subcommand 'baseline'`. The internal maintenance window suppression logic and baseline refresh infrastructure already existed but were completely disconnected from the CLI. This release wires them together: a shared `maintenance_active` atomic flag flows from the daemon through workers, scan scheduler, and coordinator; control socket methods (`maintenance_enter`, `maintenance_exit`, `baseline_refresh`) expose the flag to the CLI; and the CLI handlers implement graceful degradation (`--quiet` mode exits 0 on any failure) so hooks never block package operations. A 30-minute safety timeout auto-exits stuck maintenance windows.

### Added
- **cli:** `vigil maintenance enter [--quiet]` -- enters maintenance window on the running daemon via control socket. During maintenance, the existing `AlertDispatcher::is_suppressed()` logic suppresses Low/Medium package-owned changes while passing Critical/High through with `maintenance_window=true`. With `--quiet`, exits 0 silently on any failure (daemon not running, no control socket, etc.) so package manager hooks never block upgrades (`src/cli.rs`, `src/main.rs`).
- **cli:** `vigil maintenance exit [--quiet]` -- exits maintenance window on the running daemon. Same `--quiet` graceful degradation semantics (`src/cli.rs`, `src/main.rs`).
- **cli:** `vigil maintenance status` -- queries daemon status via control socket and reports whether a maintenance window is currently active. Uses the existing `status` control method's new `maintenance_window` field (`src/cli.rs`, `src/main.rs`).
- **cli:** `vigil baseline refresh [--quiet]` -- refreshes the baseline from configured watch paths. Tries the running daemon's control socket first (`baseline_refresh` method); if the daemon is not running, falls back to direct database access via `scanner::refresh_baseline()`. With `--quiet`, exits 0 silently on any failure. This dual-path design means hooks work both when the daemon is running and when it isn't (`src/cli.rs`, `src/main.rs`).
- **control:** `maintenance_enter` method -- sets the shared `maintenance_active` atomic flag to `true` and records the entry timestamp in `maintenance_entered_at`. Security-logged via `log_control_action()` (`src/control.rs`).
- **control:** `maintenance_exit` method -- clears `maintenance_active` and resets `maintenance_entered_at` to 0. Security-logged via `log_control_action()` (`src/control.rs`).
- **control:** `baseline_refresh` method -- loads config and calls `scanner::refresh_baseline()` using the control handler's startup database connection. Returns entry count and duration. Security-logged via `log_control_action()` (`src/control.rs`).
- **daemon:** `maintenance_active: Arc<AtomicBool>` and `maintenance_entered_at: Arc<AtomicI64>` fields added to `Daemon` struct. Initialized to `false`/`0` in `Daemon::from_config()`. Threaded through `DaemonRuntime::start()` to `ControlHandler`, `WorkerSpawnArgs`, `scan_scheduler::spawn()`, and `CoordinatorConfig` (`src/lib.rs`).
- **coordinator:** maintenance timeout safety mechanism -- `check_maintenance_timeout()` runs on every coordinator tick (every 60 seconds). If `maintenance_active` has been `true` for longer than 30 minutes, auto-exits maintenance and logs a warning. Prevents stuck maintenance windows when a post-hook fails or the package manager crashes (`src/coordinator.rs`).

### Changed
- **worker:** `WorkerSpawnArgs` and `WorkerContext` gain `maintenance_active: Arc<AtomicBool>` field. All 5 hardcoded `maintenance_window: false` values in the worker event processing paths (panic handler, debounce WAL append, debounce alert fallback, realtime WAL append, realtime alert fallback) replaced with `self.maintenance_active.load(Ordering::Acquire)` / `ctx.maintenance_active.load(Ordering::Acquire)`. When the daemon enters a maintenance window, all detection records and alert payloads produced by workers now correctly carry `maintenance_window: true` (`src/worker.rs`).
- **scan_scheduler:** `spawn()` gains `maintenance_active: Arc<AtomicBool>` parameter. All 4 hardcoded `maintenance_window: false` values (on-demand scan WAL append, on-demand scan alert fallback, scheduled scan WAL append, scheduled scan alert fallback) replaced with maintenance flag reads. All `DetectionRecord::from_change_result()` calls pass the flag value instead of `false` (`src/scan_scheduler.rs`).
- **control:** `ControlHandler` gains `maintenance_active: Arc<AtomicBool>` and `maintenance_entered_at: Arc<AtomicI64>` fields. `dispatch()` now logs `maintenance_enter`, `maintenance_exit`, and `baseline_refresh` as security-relevant commands alongside `reload` and `scan` (`src/control.rs`).
- **control:** `handle_status()` response now includes `"maintenance_window": <bool>` in the `daemon` object, enabling `vigil maintenance status` and enriching `vigil status` output (`src/control.rs`).
- **coordinator:** `CoordinatorConfig` and `Coordinator` structs gain `maintenance_active` and `maintenance_entered_at` fields. `tick()` now calls `check_maintenance_timeout()` after existing checks (`src/coordinator.rs`).

### Fixed
- **hooks:** `vigil maintenance enter --quiet`, `vigil baseline refresh --quiet`, and `vigil maintenance exit --quiet` now work. Previously, every `pacman -Syu` and `apt upgrade` on systems with Vigil hooks installed failed with `error: unrecognized subcommand`. The hooks themselves (`hooks/pacman/vigil-pre.hook`, `hooks/pacman/vigil-post.hook`, `hooks/apt/99vigil`) were correct and required no changes -- only the CLI subcommands were missing.
- **worker:** detection records during maintenance windows now correctly set `maintenance_window: true`. Previously, all worker-produced records hardcoded `maintenance_window: false` regardless of daemon state, meaning the existing suppression logic in `AlertDispatcher::is_suppressed()` and `SinkRunner::is_suppressed()` could never activate during real maintenance windows.
- **scan_scheduler:** same fix as workers -- scan-produced detection records now carry the correct maintenance window state instead of hardcoded `false`.

### Tests
- **cli (5 new tests):** `maintenance_enter_quiet_parses`, `maintenance_exit_parses`, `maintenance_status_parses`, `baseline_refresh_quiet_parses`, `baseline_refresh_parses` -- verify `Cli::try_parse_from` for all new subcommand forms (`src/cli.rs`).
- **chaos (5 files updated):** `coordinator_adversarial_tick`, `clock_warfare`, `config_reload_storm`, `coordinated_attack`, `worker_pool_chaos` -- updated `CoordinatorConfig` and `WorkerSpawnArgs` constructors with new `maintenance_active` / `maintenance_entered_at` fields (`tests/chaos/scenarios/`).
- All 215 tests pass (up from 209), `cargo clippy --all-targets -- -D warnings` clean, `cd fuzz && cargo check` clean.

### Validation
- `cargo check` succeeds with 0 warnings.
- `cargo test --all-targets` passes all 215 tests (0 failures).
- `cargo clippy --all-targets -- -D warnings` produces 0 errors and 0 warnings.
- `cd fuzz && cargo check` compiles cleanly.
- Package manager hooks verified: `hooks/pacman/vigil-pre.hook` calls `vigil maintenance enter --quiet`, `hooks/pacman/vigil-post.hook` calls `vigil baseline refresh --quiet && vigil maintenance exit --quiet`, `hooks/apt/99vigil` calls both sequences. All commands now parse and dispatch correctly.
- Existing maintenance window suppression infrastructure (`AlertDispatcher::is_suppressed`, `SinkRunner::is_suppressed`, desktop notification `[during maintenance window]` suffix, audit DB `maintenance`/`suppressed` columns) is now reachable via the CLI.
- VIGIL-VULN-014 safety invariant preserved: Critical/High alerts are never fully suppressed during maintenance -- they pass through with `maintenance_window=true`.

## [0.29.3] - 2026-04-11

### Changed
- Project display name formatting update.

## [0.29.2] - 2026-04-11

### Changed
- License and project metadata update.

## [0.29.1] - 2026-04-11

### Release Summary
- CI stabilization for the chaos engineering test suite: fixes inode-reuse flakiness on container/overlay filesystems that caused `coordinator_adversarial_tick` to fail in GitHub Actions, and applies `cargo fmt` formatting corrections to satisfy CI's rustfmt version.

### Fixed
- **chaos/coordinator_adversarial_tick:** inode swap test failed on CI container filesystems (overlayfs, Docker overlay2) where `delete → create` reuses the same inode number. `DbFileIdentity::is_replaced()` returned `false` because the new file received the same inode as the deleted one. Fix: after deleting the original file, a "blocker" file is created to occupy the freed inode slot before the target file is recreated, guaranteeing a different inode. Applied to all four swap locations: baseline DB, audit DB, WAL file, and the coordinator pre-swap test (`tests/chaos/scenarios/coordinator_adversarial_tick.rs`).

### Changed
- **chaos:** applied `cargo fmt` formatting to all chaos test files to match CI's rustfmt edition. Affected files: `tests/chaos.rs`, `tests/chaos/harness.rs`, and all 8 scenario files under `tests/chaos/scenarios/`. Module declarations in `tests/chaos.rs` reordered alphabetically by rustfmt (`tests/chaos.rs`, `tests/chaos/harness.rs`, `tests/chaos/scenarios/*.rs`).

### Validation
- `cargo fmt --all --check` passes.
- `cargo clippy --all-targets -- -D warnings` produces 0 errors and 0 warnings.
- `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` succeeds.
- `cargo test --all-targets` passes all 209 tests (0 failures).
- `CHAOS_SEED=42`, `CHAOS_SEED=12345`, `CHAOS_SEED=99999` all pass at Tier A.
- Coordinator adversarial tick test verified with single-inode-number pressure (blocker file pattern).

## [0.29.0] - 2026-04-10

### Release Summary
- Chaos engineering test suite -- a deterministic, seed-reproducible test harness that validates Vigil's resilience under compound environmental faults: concurrent WAL operations, crash recovery, filesystem races, coordinator adversarial tampering, config reload storms, sink suppression determinism, clock anomalies, and full-system coordinated stress. 8 scenario files, 13 machine-checked invariants, 3 CI tiers, ~2,800 lines of test infrastructure. Also fixes two pre-existing lint failures: rustdoc private intra-doc links in WAL module, and 8 clippy warnings in test code.

### Added
- **chaos:** new test suite under `tests/chaos/` -- entry point at `tests/chaos.rs` with `#[path]` attributes routing to the structured test tree. Run with `cargo test --test chaos`, control via `CHAOS_SEED=N` (deterministic replay) and `CHAOS_TIER=A|B|C` (scale selection) (`tests/chaos.rs`).
- **chaos/harness:** `ChaosRng` -- xoshiro256** PRNG with SplitMix64 seeding, `fork()` for thread-safe child RNGs, bounded sampling, weighted coin flips, Fisher-Yates shuffle. Every chaos scenario is fully deterministic given a seed (`tests/chaos/harness.rs`).
- **chaos/harness:** `InjectedClock` -- atomic clock abstraction supporting forward jump (+Ns), backward jump (-Ns), freeze (VM-pause simulation), and jitter (+/-ms) via `AtomicI64` offset. Thread-safe, cloneable, resettable (`tests/chaos/harness.rs`).
- **chaos/harness:** `FsMutator` -- filesystem fault injector supporting create, modify, delete, rename, chmod, symlink replacement, inode reuse (delete-and-create), and partial write. `seed_files()` generates randomized test content (`tests/chaos/harness.rs`).
- **chaos/harness:** `DbPermissionToggler` -- toggles a database file between mode 0600 (writable) and 0400 (read-only) to simulate permission flapping (`tests/chaos/harness.rs`).
- **chaos/harness:** `CrashFailpoint` enum -- models AuditWriter crash injection points (`after_read_before_commit`, `after_commit_before_mark_audit_done`, `after_mark_audit_done_before_truncate`) for replayable crash scenarios (`tests/chaos/harness.rs`).
- **chaos/harness:** `InvariantEngine` -- accumulates structured invariant check results with step tracking, failure context maps, summary reports, and `assert_ok()` panic-on-failure. Checks 13 global invariants (I1–I13) corresponding to the specification (`tests/chaos/harness.rs`).
- **chaos/harness:** `ArtifactWriter` -- collects forensic replay artifacts: seed, scenario config, timeline of injected faults with elapsed timestamps, WAL summary (file size, pending count, total appended), audit DB summary (entry count, chain validity, chain breaks), and invariant failure details. Writes artifact file on failure for post-mortem analysis (`tests/chaos/harness.rs`).
- **chaos/harness:** `ChaosTier` enum and `ScaleParams` -- three CI integration tiers: Tier A (default CI, 1 seed, 4 threads, 100 iterations, ~6s), Tier B (nightly, 10 seeds, 8 threads, 1000 iterations, ~5min), Tier C (manual, 100 seeds, 16 threads, 10000 iterations). Tier selected via `CHAOS_TIER` env var (`tests/chaos/harness.rs`).
- **chaos/harness:** `ChaosSchedule`, `ScheduledAction`, `FaultAction`, `FsMutation`, `ClockFault` types -- structured fault injection vocabulary for deterministic schedule generation (`tests/chaos/harness.rs`).
- **chaos/common:** `chaos_common` module -- factory functions for `DetectionRecord` creation (`make_record`, `make_record_at`, `make_sentinel`, `make_panic_record`), WAL helpers (`open_wal`, `open_wal_sized`, `open_wal_hmac`), database helpers (`open_audit_db`, `open_baseline_db`, `audit_count`), config helper (`chaos_config` with cleared exclusions for tempdir compatibility), and WAL permission checker (`wal_file_mode`) (`tests/chaos/chaos_common.rs`).
- **chaos/scenario 1:** `wal_concurrency_and_recovery` -- spawns N threads (4–16 depending on tier) performing randomized WAL operations (`append`, `mark_audit_done`, `mark_sink_done`, `iter_unconsumed`, `truncate_consumed`) from a deterministic schedule. Validates I1 (unique monotonic sequences), I2 (iter_unconsumed excludes fully consumed), I4 (truncate never increases file size), I5 (mark idempotent), I10 (WAL permissions 0600), I11 (pending_count consistency). Includes recovery cycle: drops WAL handle, reopens, reverifies all invariants (`tests/chaos/scenarios/wal_concurrency.rs`).
- **chaos/scenario 2:** `pipeline_crash_recovery` -- generates N records (50–5000) with ~10% sentinels, runs repeated AuditWriter crash-restart cycles (each cycle: open fresh DB connections, run `recover()`, spawn writer, process for random duration, signal shutdown). Final pass runs writer to quiescence. Validates I3 (no permanent loss: every non-sentinel path present in audit DB), I6 (sentinels excluded from audit DB), I7 (HMAC chain contiguous with zero breaks), I10 (WAL permissions), plus checks that duplicates are bounded by crash cycle count (`tests/chaos/scenarios/pipeline_recovery.rs`).
- **chaos/scenario 3:** `coordinator_adversarial_tick` -- tests `DbFileIdentity` inode-swap detection directly for baseline DB, audit DB, and WAL file (copy-remove-copy pattern). Then spawns a coordinator with a pre-swapped baseline inode and verifies it transitions to Degraded on first tick (coordinator initializes `last_tick` to `now - 60s` so first tick fires immediately). Also verifies coordinator survives 20 rapid state transitions (Healthy ↔ Degraded) with concurrent reload signals without panicking. Validates I12 (`tests/chaos/scenarios/coordinator_adversarial_tick.rs`).
- **chaos/scenario 4:** `worker_pool_filesystem_chaos` -- spawns a real worker pool via `WorkerSpawnArgs` with WAL, injects high-rate `FsEvent`s across randomized event types while concurrently mutating the filesystem (create/modify/delete/inode-reuse). Verifies workers don't crash (thread joins succeed), and that any caught panics produce records with `DetectionSource::Panic`, `Severity::Critical`, and empty changes vec. Validates I8 (`tests/chaos/scenarios/worker_pool_chaos.rs`).
- **chaos/scenario 5:** `config_reload_storm` -- spawns coordinator, then rapidly alternates between valid config writes (randomized `worker_threads`) and invalid config writes (broken TOML, negative values, empty strings, malformed sections) with concurrent reload signals. Verifies effective runtime config remains valid (worker_threads > 0) and coordinator doesn't panic. Validates I13 (`tests/chaos/scenarios/config_reload_storm.rs`).
- **chaos/scenario 6:** `sink_suppression_determinism` -- creates two `DetectionWal` instances with identical ordered record streams (same seed-derived severity/source distribution), creates two `SinkRunner` instances with identical configs, runs both to completion. Verifies dispatch count, suppress count, and WAL sink dispatch metrics are identical between the two instances. Validates suppression determinism regardless of thread scheduling (`tests/chaos/scenarios/sink_determinism.rs`).
- **chaos/scenario 7:** `clock_warfare` -- applies four clock fault types (forward jump +1h, backward jump -30s, freeze, jitter +500ms) via `InjectedClock` while appending WAL records with injected timestamps. Verifies all entries survive clock manipulation and sequence numbers remain unique/monotonic despite timestamp chaos. Spawns a coordinator and verifies it doesn't panic under normal operation. Tests `EventFilter` debounce drain under clock jitter. Validates I1, I12 (`tests/chaos/scenarios/clock_warfare.rs`).
- **chaos/scenario 8:** `coordinated_attack` -- full-system compound stress test running coordinator, worker pool, AuditWriter, SinkRunner, and AlertDispatcher simultaneously for a configurable duration (5–120s by tier). During the run: filesystem warfare (randomized create/modify/delete on monitored files), audit DB permission flapping every 2s, config reload signals every 5s, on-demand WAL appends every 3s. At shutdown: verifies clean thread joins (no deadlocks), metric consistency (`wal_appends + wal_replayed >= committed + pending`), WAL permissions intact. Validates I3, I9, I10 (`tests/chaos/scenarios/coordinated_attack.rs`).

### Fixed
- **wal:** `mark_audit_done()` and `mark_sink_done()` doc comments linked to private `Self::mark_flag` using intra-doc link syntax `[`mark_flag`](Self::mark_flag)`, causing `rustdoc::private-intra-doc-links` error under `-D warnings`. Changed to plain backtick references `` `mark_flag` `` (`src/wal/mod.rs`).
- **chaos:** 8 clippy violations in test code -- 5 useless `format!` calls changed to string literals in `ArtifactWriter::to_report()`, 1 `push_str("\n")` changed to `push('\n')`, 1 `match` on single pattern changed to `if let` in WAL concurrency scenario, 1 `#[allow(clippy::enum_variant_names)]` added to `CrashFailpoint` enum (variant names intentionally match spec failpoint names) (`tests/chaos/harness.rs`, `tests/chaos/scenarios/wal_concurrency.rs`).

### Tests
- **chaos suite (8 scenarios):** `wal_concurrency_and_recovery`, `pipeline_crash_recovery`, `coordinator_adversarial_tick`, `worker_pool_filesystem_chaos`, `config_reload_storm`, `sink_suppression_determinism`, `clock_warfare`, `coordinated_attack`.
- **invariant coverage:** I1 (unique monotonic seq), I2 (iter_unconsumed correctness), I3 (no permanent loss), I4 (truncate never increases size), I5 (mark idempotent), I6 (sentinel excluded from durability), I7 (audit HMAC chain no gaps), I8 (panic severity critical), I9 (WAL-mediated path), I10 (WAL permissions 0600), I11 (pending count correct), I12 (coordinator degraded on inode change), I13 (invalid config rejected).
- **CI tiers:** Tier A (default `cargo test`, 1 seed, ~6s), Tier B (`CHAOS_TIER=B`, 10 seeds, ~5min), Tier C (`CHAOS_TIER=C`, 100 seeds, extended run).
- **seed determinism:** all scenarios reproduce identically given `CHAOS_SEED=N`. Failures emit artifact files with seed, timeline, and invariant report for forensic replay.
- All 209 tests pass, `cargo clippy --all-targets -- -D warnings` clean, `cargo doc --no-deps` clean.

### Validation
- `cargo check` succeeds with 0 warnings.
- `cargo test --all-targets` passes all 209 tests (0 failures).
- `cargo clippy --all-targets -- -D warnings` produces 0 errors and 0 warnings.
- `cargo doc --no-deps` succeeds with 0 errors.
- `CHAOS_SEED=42`, `CHAOS_SEED=12345`, `CHAOS_SEED=99999` all pass at Tier A.
- `CHAOS_TIER=B` (10-seed sweep) passes all 8 scenarios in ~5.5 minutes.
- Existing 201 non-chaos tests pass unchanged.

## [0.28.1] - 2026-04-10

### Release Summary
- WAL hardening: gap-scanning DoS prevention via `MAX_GAP_BYTES` limit (64KB), concurrency safety documentation for `mark_flag` read-modify-write, documented `iter_unconsumed` optimization path, and a new test for gap limit enforcement.

### Changed
- **wal:** `scan_entries()` gap scanning now tracks gap position and byte count. When a corrupted gap exceeds `MAX_GAP_BYTES` (64KB), the scanner stops, logs the gap at error level, and returns whatever entries it has already recovered. This prevents an adversarial DoS where an attacker with write access zeros out a large WAL region, forcing the scanner to iterate through millions of byte positions. Recovered gaps and trailing corruption are logged at warn level with start offset and bytes skipped (`src/wal/mod.rs`).
- **wal:** `mark_flag()` now has a comprehensive doc comment explaining the non-atomic read-modify-write on the 2-byte flags field: reads entire entry, ORs the flag bit, recomputes CRC-32, writes back. Documents that `write_lock` is required not just for appends but also for flag updates to prevent concurrent flag overwrites, and warns that per-entry locking must still serialize same-entry flag updates (`src/wal/mod.rs`).
- **wal:** `mark_audit_done()` and `mark_sink_done()` now have doc comments cross-referencing `mark_flag` for concurrency constraints (`src/wal/mod.rs`).
- **wal:** `iter_unconsumed()` now has a documented `OPTIMIZE` comment describing the planned in-memory index of `(sequence, offset, flags)` triples -- update on append/flag/truncation, consumers seek directly to pending offsets. Turns the hot path from O(total_entries) to O(pending_entries). Notes that at current volumes (hundreds of detections/minute) the full scan is acceptable but will become a bottleneck on busy servers with thousands of monitored paths (`src/wal/mod.rs`).

### Added
- **wal:** `MAX_GAP_BYTES` constant (64KB) with detailed doc comment explaining the adversarial DoS threat, the byte-by-byte scanning rationale (entries are not 4-byte aligned), and the alignment optimization trade-off (`src/wal/mod.rs`).
- **wal:** `gap_limit_stops_scanning_large_corruption` test -- verifies the scanner stops after `MAX_GAP_BYTES` of continuous corruption and only returns entries found before the gap (`src/wal/mod.rs`).

### Tests
- **wal core:** test count increased from 13 to 14 (new: `gap_limit_stops_scanning_large_corruption`).
- All 165+ tests pass, `cargo clippy --all-targets -- -D warnings` clean, `cargo fmt --check` clean.

### Validation
- `cargo check` succeeds with 0 warnings.
- `cargo test --all-targets` passes all tests (0 failures).
- `cargo clippy --all-targets -- -D warnings` produces 0 warnings.
- `cargo fmt --check` reports no formatting issues.

## [0.28.0] - 2026-04-10

### Release Summary
- Detection WAL (Write-Ahead Log) -- a crash-safe, HMAC-authenticated binary log that decouples detection output from audit persistence and alert dispatch. Real-time detections, scheduled scan results, on-demand scan results, debounced re-checks, and worker panic events are now written to a local WAL file before being consumed by two independent background threads: the AuditWriter (audit DB persistence with priority ordering and crash recovery) and the SinkRunner (alert sink dispatch with bounded cooldowns). This eliminates the single-threaded bottleneck where a blocked audit DB write could delay alert delivery, and ensures zero detection loss across daemon crashes, audit DB failures, and I/O stalls. Includes 8 pre-existing bug fixes, 11 new metrics, 4 new config fields, and a new fuzz target. Fully backwards-compatible: the WAL is enabled by default but the daemon falls back to the pre-WAL alert channel path when `detection_wal = false` or when a WAL append fails.

### Added
- **wal:** new `src/wal/` module -- `mod.rs` (WAL core), `audit_writer.rs` (audit DB consumer), `sink_runner.rs` (alert sink consumer). The WAL file format is a 64-byte header followed by variable-length entries. Each entry contains a 4-byte size, 8-byte sequence number, 2-byte flags (audit_done / sink_done), 32-byte per-entry HMAC-SHA256 (or zeros when HMAC signing is disabled), MessagePack-serialized payload, and a 4-byte CRC32 checksum. The header contains magic bytes `VWAL`, version 1, creation timestamp, HMAC key fingerprint (BLAKE3 of key truncated to 16 bytes), and a 32-byte random instance nonce from `/dev/urandom` (`src/wal/mod.rs`).
- **wal:** `DetectionRecord` struct -- the WAL payload type with 10 fields: `timestamp`, `path` (String, not PathBuf), `changes`, `severity`, `monitored_group`, `process`, `package`, `package_update`, `maintenance_window`, `source`. Includes `from_change_result()` and `to_change_result()` conversion methods. Derives `serde::Serialize` and `serde::Deserialize` for MessagePack serialization (`src/wal/mod.rs`).
- **wal:** `DetectionSource` enum -- `Realtime`, `ScheduledScan`, `OnDemandScan`, `Debounce`, `Panic`, `Sentinel`. Derives `Serialize`, `Deserialize`, `Clone`, `Copy`, `PartialEq`, `Eq` (`src/wal/mod.rs`).
- **wal:** `DetectionWal` struct -- the core WAL handle. Fields: `file` (Mutex-wrapped for atomic handle replacement during compaction), `path`, `sequence` (AtomicU64), `file_len` (AtomicU64), `write_lock` (parking_lot::Mutex), `hmac_key` (Option<Zeroizing<Vec<u8>>>), `hmac_key_fingerprint`, `instance_nonce`, `max_size_bytes`, `sync_mode`. Key methods: `open()` / `open_with_sync()` (creates with mode 0o600, validates permissions, recovers sequence from last valid entry), `append()` (serialize + HMAC + CRC + pwrite + fdatasync, with double-checked capacity before/after lock), `iter_unconsumed()` (gap-scanning recovery with byte-by-byte retry on CRC failure), `mark_audit_done()` / `mark_sink_done()` (flag updates with CRC recomputation), `truncate_consumed()` (atomic temp-file compaction or truncate-to-header) (`src/wal/mod.rs`).
- **wal:** `AuditWriter` -- background thread (`vigil-wal-audit`) that consumes WAL entries, writes them to the audit DB with HMAC chain integrity, and handles crash recovery. Features: priority ordering (Critical first, then by sequence), sequence gap detection with metrics, deduplication during recovery (SELECT COUNT before INSERT), consecutive failure counting with DB connection reopen after 3 failures, periodic `truncate_consumed()` every 60 seconds, and complete drain on shutdown. The `build_entry_hmac()` function replicates the full 7-argument `build_audit_hmac_data` call including extraction of `old_hash`/`new_hash` from `ContentModified` changes (`src/wal/audit_writer.rs`).
- **wal:** `SinkRunner` -- background thread (`vigil-wal-sinks`) that consumes WAL entries independently of AuditWriter and dispatches alerts to configured sinks. Uses `lru::LruCache<String, Instant>` bounded to 10,000 entries for path cooldowns (same suppression logic as AlertDispatcher). Suppressed entries are marked `sink_done` immediately (no retry). Sleeps 50ms when idle, 10ms when processing (`src/wal/sink_runner.rs`).
- **wal:** WAL self-test at startup -- appends a Sentinel record, reads it back, verifies it was found, marks it consumed. Failure returns `Err(VigilError::Wal(...))` and prevents daemon startup (`src/lib.rs`).
- **wal:** WAL instance nonce stored in baseline DB via `set_config_state("wal_instance_nonce", ...)`. AuditWriter `recover()` verifies the nonce matches before replaying entries, preventing cross-instance replay (`src/lib.rs`, `src/wal/audit_writer.rs`).
- **wal:** WAL file identity tracking -- `DbFileIdentity` recorded for WAL file at creation, passed to coordinator for periodic TOCTOU verification. Coordinator's `check_wal_identity()` detects file replacement and transitions to Degraded state (`src/coordinator.rs`).
- **config:** `detection_wal` (bool, default `true`) -- enables/disables the Detection WAL. When disabled, detections flow through the existing alert channel path unchanged (`src/config/mod.rs`).
- **config:** `detection_wal_max_bytes` (u64, default 64 MiB) -- maximum WAL file size. Validated: must be between 1 MiB and 1 GiB. When exceeded, `append()` returns `Err(VigilError::Wal("WAL full"))` and the worker falls back to the alert channel (`src/config/mod.rs`).
- **config:** `detection_wal_persistent` (bool, default `false`) -- when true, WAL is stored alongside the baseline DB (survives reboots); when false, WAL is in `runtime_dir` (tmpfs). `validate_config_deep()` warns when WAL is on tmpfs (`src/config/mod.rs`).
- **config:** `detection_wal_sync` (enum: `every`/`batched`/`none`, default `every`) -- controls fdatasync behavior after WAL appends (`src/config/mod.rs`).
- **metrics:** 11 new fields in `Metrics` struct -- 7 counters (`detections_wal_appends`, `detections_wal_audit_committed`, `detections_wal_sink_dispatched`, `detections_wal_replayed`, `detections_wal_full`, `detections_wal_tampered`, `detections_wal_gaps`) and 4 gauges (`detections_wal_bytes`, `detections_wal_pending`, `detections_wal_audit_lag`, `detections_wal_sink_lag`). All included in `MetricsSnapshot`, all exposed in Prometheus text format with correct counter/gauge types (`src/metrics.rs`).
- **error:** `VigilError::Wal(String)` variant with `#[error("WAL error: {0}")]` and PartialEq support (`src/error.rs`).
- **worker:** panic handler in `process_safe()` now creates a `DetectionRecord` with `DetectionSource::Panic`, `Severity::Critical`, empty changes vec, and the event's path/process, then appends it to the WAL (best-effort, errors ignored). The `panics_caught` metric is still incremented (`src/worker.rs`).
- **worker:** `drain_debounced()` appends debounced detections to WAL with `DetectionSource::Debounce` when WAL is available, falls back to alert channel vec when not (`src/worker.rs`).
- **fuzz:** `fuzz_wal_recovery` target -- feeds arbitrary bytes as a WAL file and calls `iter_unconsumed()` to exercise gap-scanning recovery (`fuzz/fuzz_targets/fuzz_wal_recovery.rs`).

### Changed
- **worker:** `WorkerSpawnArgs` gains `wal: Option<Arc<DetectionWal>>` field. `WorkerContext` gains matching `wal` field. Worker loop now appends `DetectionRecord` with `DetectionSource::Realtime` to WAL on detection; on WAL append failure, falls back to `alert_tx.send()`. `try_auto_rebaseline` is still called before WAL/alert send (`src/worker.rs`).
- **alert:** `AlertDispatcher::new()` gains 5th parameter `wal_active: bool`. When `wal_active == true`, `run()` skips `record_audit()` (audit writes are handled by AuditWriter). Sink dispatch for fallback alerts still runs. `cooldowns` changed from `HashMap<String, Instant>` to `lru::LruCache<String, Instant>` bounded to 10,000 entries (`src/alert/mod.rs`).
- **scan_scheduler:** `spawn()` gains 8th parameter `wal: Option<Arc<DetectionWal>>`. On-demand scan detections appended to WAL with `DetectionSource::OnDemandScan`; scheduled scan detections with `DetectionSource::ScheduledScan`. Falls back to `alert_tx.send()` on WAL append failure (`src/scan_scheduler.rs`).
- **lib.rs:** `DaemonRuntime` gains `wal: Option<Arc<DetectionWal>>`, `audit_writer_handle: Option<JoinHandle<()>>`, `sink_runner_handle: Option<JoinHandle<()>>`. `start()` initializes WAL when `cfg.daemon.detection_wal == true` (path: runtime_dir or db_path parent depending on `detection_wal_persistent`), stores instance nonce, runs self-test, spawns AuditWriter (with `recover()` called before workers), spawns SinkRunner, passes `wal_active` to AlertDispatcher. `drain()` shutdown ordering: workers → baseline_writer → audit_writer → sink_runner → alert → coordinator → scan_scheduler → final WAL truncation → PID cleanup (`src/lib.rs`).
- **coordinator:** `CoordinatorConfig` gains `wal_identity: Option<DbFileIdentity>` and `wal_path: Option<PathBuf>`. `Coordinator` struct gains matching fields. `tick()` calls `check_wal_identity()` for TOCTOU detection on the WAL file (`src/coordinator.rs`).
- **deps:** added `rmp-serde = "1"` (MessagePack serialization) and `crc32fast = "1"` (CRC32 checksums) to `[dependencies]` (`Cargo.toml`).

### Fixed (pre-existing bugs resolved in this release)
- **control:** `ControlHandler.hmac_key` changed from `Option<Vec<u8>>` to `Option<Zeroizing<Vec<u8>>>` -- HMAC key material is now zeroized on drop. `lib.rs` clones the `Zeroizing` wrapper correctly (`src/control.rs`, `src/lib.rs`).
- **control:** `handle_baseline_count` TOCTOU -- `ControlHandler` now holds a startup `Connection` field and uses it directly instead of calling `open_baseline_db_readonly(&path)` on each request (`src/control.rs`).
- **scanner:** `run_scan_parallel` severity hardcoding -- now accepts `watch_index: &WatchGroupIndex` parameter and uses `watch_index.lookup()` for severity and group name instead of hardcoding `Severity::High` / `Severity::Medium` / `"scheduled_scan"` (`src/scanner.rs`).
- **coordinator:** `detect_clock_anomaly` stale timestamp -- after detecting a clock anomaly (forward or backward), `last_rotation_timestamp` is now updated to the current time. Previously, a large forward jump left the timestamp stale, causing repeated false anomaly detections on every subsequent tick (`src/coordinator.rs`).
- **lib.rs:** baseline writer batch cap -- the `while let Ok(extra) = rx.try_recv()` collection loop now breaks at 500 entries to prevent unbounded growth (`src/lib.rs`).
- **lib.rs:** baseline writer connection reopen -- adds `consecutive_failures` counter; attempts DB connection reopen after 3 consecutive write failures (`src/lib.rs`).
- **coordinator:** bloom filter reload gap -- `Coordinator` now has `reconfigure_tx` field; `handle_reload()` sends new watch paths through the reconfigure channel so the monitor rebuilds its Bloom filter (`src/coordinator.rs`).
- **alert:** cooldown map unbounded growth -- `AlertDispatcher.cooldowns` changed from `HashMap<String, Instant>` to `lru::LruCache<String, Instant>` bounded to 10,000 entries. Prevents memory growth proportional to unique paths over daemon lifetime (`src/alert/mod.rs`).

### Tests
- **wal core (13 tests):** `append_and_read_back`, `concurrent_appends` (8 threads × 1,000 entries), `crc_corruption_detected`, `partial_write_at_eof`, `consumed_flags_independent`, `sequence_resumes_after_reopen`, `wal_full_returns_error`, `truncate_removes_consumed`, `gap_scanning_recovers_after_corruption`, `header_validation`, `entry_hmac_verification`, `instance_nonce_uniqueness`, `sentinel_roundtrip` (`src/wal/mod.rs`).
- **audit writer (5 tests):** `drain_to_audit_db`, `crash_recovery_dedup`, `sequence_gap_detection`, `priority_ordering`, `audit_db_failure_and_reopen` (`src/wal/audit_writer.rs`).
- **sink runner (3 tests):** `bounded_cooldown`, `sink_dispatch_independent`, `suppressed_entries_marked_consumed` (`src/wal/sink_runner.rs`).
- **integration (2 tests):** `panic_produces_detection_record`, `wal_disabled_uses_current_path` (`tests/wal_integration.rs`).
- **fuzz (1 target):** `fuzz_wal_recovery` (`fuzz/fuzz_targets/fuzz_wal_recovery.rs`).

### Validation
- `cargo build` succeeds with 0 warnings.
- `cargo test --all-targets` passes (all 200 tests green, 0 failures).
- `cargo clippy --all-targets -- -D warnings` produces 0 warnings.
- `cd fuzz && cargo check` compiles cleanly.
- `#![deny(unsafe_code)]` remains at crate root; no unsafe blocks in any WAL file.
- All existing tests pass unchanged (AlertDispatcher::new call sites updated for new `wal_active` parameter).
- Shutdown ordering verified: workers drain before AuditWriter, AuditWriter drains before SinkRunner, final WAL truncation after all threads joined.
- Dual-write prevention verified: when WAL is active, AlertDispatcher does NOT write to audit DB; AuditWriter is the sole audit chain writer.

## [0.27.1] - 2026-04-09

### Release Summary
- Fix systemd watchdog timeouts that killed the daemon during startup (initial baseline scan) and during coordinator tick blocking under I/O pressure. Adds watchdog heartbeats throughout the pre-flight sequence, baseline initialization, and coordinator tick sub-methods. Increases `WatchdogSec` from 30s to 120s and adds `TimeoutStartSec=300` to both systemd unit files.

### Fixed
- **daemon:** watchdog starvation during startup pre-flight -- the pre-flight sequence (`record_binary_hash()`, `ensure_baseline_health()`, `DaemonRuntime::start()`) runs synchronously on the main thread before the coordinator thread exists. No watchdog heartbeats were sent until the coordinator's loop began iterating. On systems with large monitored file sets, `ensure_baseline_health()` triggers `build_initial_baseline()`, which walks all watched paths, hashes every file, queries package ownership, and writes to SQLite -- easily taking 15–60+ seconds. With `WatchdogSec=30`, systemd sent SIGABRT before the coordinator could start. Added `send_watchdog_heartbeat()` helper in `src/lib.rs` (guarded by `is_notify_socket_safe()`) and inserted heartbeat calls at 3 points in `Daemon::run()`, before/after all 4 `build_initial_baseline()` call sites in `ensure_baseline_health()`, and at 4 points in `DaemonRuntime::start()` (`src/lib.rs`).
- **daemon:** watchdog starvation during long baseline scans -- `build_initial_baseline()` walks potentially tens of thousands of files without any watchdog heartbeat. Added heartbeat sends at the existing 5,000-file progress interval, after the `COMMIT` of the baseline transaction, and after HMAC computation over the full baseline (`src/scanner.rs`).
- **daemon:** watchdog starvation during coordinator tick -- the coordinator's `tick()` method calls 8 sub-methods sequentially (`check_baseline_db_identity`, `check_audit_db_identity`, `check_mount_evasion`, `detect_clock_anomaly`, `rotate_audit_log`, `write_snapshots`, `check_backpressure`, `check_event_drops`, `maybe_checkpoint_wal`) without any intermediate heartbeat. If `rotate_audit_log()` (SQL queries) or `write_snapshots()` (opens DBs, runs `COUNT(*)`, filesystem metadata) are slow under I/O pressure, the combined tick time exceeds the watchdog interval. Added 3 interleaved `notify_watchdog()` calls within `tick()`: after security checks, after audit rotation, and after snapshot writes (`src/coordinator.rs`).
- **systemd:** `WatchdogSec=30` far too aggressive for a daemon that performs filesystem-wide integrity scanning -- changed to `WatchdogSec=120` in `systemd/vigild.service`. The `contrib/vigild.service` already had `WatchdogSec=120`; both units are now aligned (`systemd/vigild.service`).
- **systemd:** no `TimeoutStartSec` configured -- systemd's default start timeout could kill the daemon during first-ever baseline initialization on large systems. Added `TimeoutStartSec=300` (5 minutes) to both `systemd/vigild.service` and `contrib/vigild.service`.
- **systemd:** `contrib/vigild.service` missing security-critical directives -- added `NotifyAccess=main` (prevents sd_notify spoofing, addresses VIGIL-VULN-034), `ExecReload=/bin/kill -HUP $MAINPID`, and `AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH` to match the production unit's security posture (`contrib/vigild.service`).

### Validation
- `cargo build` succeeds with 0 warnings.
- `cargo test --all-targets` passes (all 173 tests green, 0 failures).
- `cargo clippy --all-targets -- -D warnings` produces 0 warnings.
- `cargo fmt --check` passes.
- All `sd_notify::Watchdog` calls are guarded by `is_notify_socket_safe()` (directly or via `send_watchdog_heartbeat()` / `notify_watchdog()`).
- Zero behavior changes to monitoring, alerting, or security logic.

## [0.27.0] - 2026-04-09

### Release Summary
- Pure structural refactoring of the runtime layer -- the five files that wire up threads, channels, and the daemon lifecycle (`src/lib.rs`, `src/worker.rs`, `src/coordinator.rs`, `src/control.rs`, `src/alert/mod.rs`). Zero behavior changes. Functions that did too many things have been decomposed into context structs with focused methods, shared state is passed as struct fields instead of loose variables, and duplicated error handling has been consolidated. All `#[allow(clippy::too_many_arguments)]` annotations have been removed from these files.

### Changed
- **worker.rs:** introduced `WorkerSpawnArgs` struct to replace the 11 positional arguments to `spawn_workers()` (`src/worker.rs`). Introduced private `WorkerContext` struct that holds per-worker state (connection, config, watch index, metrics, filter, LRU cache, generation tracker, drain timing). Moved event processing into `WorkerContext` methods:
  - `evaluate(&mut self, event)` -- cache lookup + baseline resolution + snapshot capture + diff + severity classification (consolidates the former `process_event_cached` and `process_event_inner` call chain)
  - `process_safe(&mut self, event)` -- wraps `evaluate` in `catch_unwind` with panic metric increment (eliminates duplicated 30-line match arms)
  - `drain_debounced(&mut self)` -- drains debounced events through `process_safe` and returns alert payloads
  - `refresh_cache_if_stale(&mut self)` -- invalidates LRU cache when baseline generation changes
  - `try_auto_rebaseline(&self, change_result, update_tx)` -- package update detection and re-snapshot logic
  - The worker loop is now ~22 lines (down from ~163 lines). `process_event_cached` has been removed; its logic is absorbed into `WorkerContext::evaluate`. The public `process_event` function is preserved for CLI/test callers (`src/worker.rs`).
- **coordinator.rs:** introduced `CoordinatorConfig` struct to replace the 12 positional arguments to `coordinator::spawn()` (`src/coordinator.rs`). Introduced private `Coordinator` struct that owns all coordinator state (config, metrics, daemon state, watch index, shutdown/reload flags, DB connections, timing state, initial mount set). Decomposed the 283-line loop body into named methods on `Coordinator`:
  - `tick(&mut self)` -- calls each housekeeping method in sequence
  - `handle_reload(&mut self)` -- config file integrity check, HMAC verification, load + validate + diff + store new config, update watch index
  - `check_baseline_db_identity(&mut self)` -- TOCTOU check on baseline DB inode/device
  - `check_audit_db_identity(&mut self)` -- TOCTOU check on audit DB inode/device
  - `check_mount_evasion(&self)` -- compare current mounts against initial set, log new mounts over watched paths
  - `detect_clock_anomaly(&mut self)` -- forward/backward clock jump detection
  - `rotate_audit_log(&mut self)` -- safety-guarded audit rotation (>50% deletion guard)
  - `write_snapshots(&self)` -- metrics + state + health snapshots via atomic writes
  - `check_backpressure(&self)` -- backpressure flag → `DaemonState::Degraded`
  - `check_event_drops(&mut self)` -- sustained event drop detection (evasion warning)
  - `maybe_checkpoint_wal(&mut self)` -- periodic WAL checkpoint every 5 ticks
  - `notify_watchdog(&self)` -- systemd watchdog notification
  - The coordinator main loop is now 8 lines: check reload, call `tick()` on interval, notify watchdog, sleep (`src/coordinator.rs`).
- **control.rs:** introduced `ControlHandler` struct to replace the 8 positional arguments to both `spawn()` and `handle_connection()` (`src/control.rs`). The handler struct holds metrics, daemon state, reload flag, scan trigger channel, baseline DB path, HMAC key, and auth-enabled flag. Decomposed `handle_connection` into focused methods:
  - `authenticate_and_read(&self, stream)` -- challenge-response handshake + authenticated request reading
  - `read_request(&self, stream)` -- unauthenticated JSON read
  - `write_response(&self, stream, response)` -- serialize + write + flush (was duplicated in two code paths)
  - `dispatch(&self, method, request)` -- method routing (now a method on `ControlHandler`)
  - `handle_status`, `handle_baseline_count`, `handle_reload`, `handle_scan`, `handle_metrics_prometheus` -- all converted from free functions to `ControlHandler` methods
  - `handle_connection` is now ~18 lines: log peer credentials, authenticate or read, dispatch, write response (`src/control.rs`).
- **alert/mod.rs:** extracted `record_audit(&mut self, payload, suppressed)` method from `AlertDispatcher::run()` -- encapsulates audit DB write, error recovery (retry buffer, consecutive failure counting, DB reopen after 3 failures, buffered entry retry). Extracted `dispatch_to_sinks(&self, alert)` method -- the sink iteration loop. `AlertDispatcher::run()` is now ~17 lines. Added `use std::sync::atomic::{AtomicBool, AtomicU32, Ordering}` import; replaced all 8+ inline `std::sync::atomic::Ordering::Relaxed` occurrences with `Ordering::Relaxed` (`src/alert/mod.rs`).
- **lib.rs:** introduced `DaemonRuntime` struct that owns all `JoinHandle`s, channel senders, shutdown state, and the PID file path. Decomposed `Daemon::run()` into:
  - `DaemonRuntime::start(daemon)` -- all channel creation, thread spawning, `Arc::clone()` wiring, and `sd_notify(Ready)` signaling
  - `DaemonRuntime::wait_for_shutdown(&self)` -- the shutdown sleep loop
  - `DaemonRuntime::drain(self)` -- send shutdown signal, drop senders, join all threads in dependency order, cleanup PID file
  - Extracted `Daemon::record_binary_hash(&self)` -- BLAKE3 hash of `/proc/self/exe`
  - Extracted `Daemon::log_startup_diagnostics(&self, cfg)` -- baseline DB state logging
  - `Daemon::run()` is now 11 lines: harden process, raise nofile limit, record binary hash, log diagnostics, ensure baseline health, start runtime, wait for shutdown, drain (`src/lib.rs`).

### Removed
- All `#[allow(clippy::too_many_arguments)]` annotations from `src/worker.rs`, `src/coordinator.rs`, `src/control.rs`. These are no longer needed because the argument lists have been replaced by context structs (`src/worker.rs`, `src/coordinator.rs`, `src/control.rs`).
- `process_event_cached()` free function in `src/worker.rs` -- its logic has been absorbed into `WorkerContext::evaluate()`.
- All inline `std::sync::atomic::Ordering::Relaxed` full-path usage in `src/alert/mod.rs` -- replaced by imported `Ordering::Relaxed`.

### Validation
- `cargo build` succeeds with 0 warnings.
- `cargo test --all-targets` passes (all 177 tests green, 0 failures).
- `cargo clippy --all-targets` produces 0 warnings.
- `cargo fmt --all --check` passes.
- No `#[allow(clippy::too_many_arguments)]` annotations remain in the modified files.
- No inline `std::sync::atomic::Ordering::Relaxed` full-path usage remains in the modified files.
- All security properties preserved: HMAC verification, TOCTOU detection, self-protection logging, audit chain hashing, nonce generation, peer credential logging, clock anomaly detection.

## [0.26.0] - 2026-04-08

### Release Summary
- Major `vigil update` overhaul: automatic repository discovery, step-by-step progress output, atomic binary replacement, post-update daemon health verification, and improved doctor output positioning. The update command now matches the UX standard set by `cmd_check`, `cmd_init`, and `cmd_doctor`.

### Added
- **cli:** automatic repository discovery for `vigil update` -- when `--repo` is not provided, the command now searches multiple candidate paths instead of requiring the user to `cd` into the repo. Discovery checks, in order: current working directory, binary-relative parent walk (walks up from `std::env::current_exe()` looking for `Cargo.toml` with `name = "vigil"`), well-known home paths (`~/vigil`, `~/src/vigil`, `~/projects/vigil`), and `/opt/vigil`. On success, prints `"Using repository: /path"`. On failure, prints all checked paths with actionable guidance. Extracted into `discover_vigil_repo()` helper (`src/main.rs`).
- **cli:** step-by-step progress output during `vigil update` -- every significant operation (daemon stop, binary install, symlink update, systemd unit check, hook check, daemon start) now prints a status message before execution. Success markers (`✓`) and warning markers (`⚠`) provide immediate feedback. No `sudo` or `systemctl` operation runs silently. Consistent 2-space indented formatting matching existing `cmd_doctor` and `cmd_init` style (`src/main.rs`).
- **cli:** atomic binary replacement via `atomic_install()` helper -- replaces the previous `sudo install -Dm755` which destructively overwrote binaries in-place. New pattern: `sudo cp <src> /usr/local/bin/.<name>.new` → `sudo chmod 755` → `sudo mv` (atomic rename). A crash mid-update can never leave a half-written binary. `mv` on the same filesystem is an atomic `rename(2)` at the kernel level (`src/main.rs`).
- **cli:** post-update daemon health verification -- after `systemctl start vigild.service` succeeds, the update command now sleeps 2 seconds then queries the daemon's control socket via `query_control_socket()` with `{"method":"status"}` to verify the daemon is actually running and responding. The final summary now distinguishes three states: `"restarted"` (start succeeded + health check passed), `"started but not responding (check: sudo journalctl -u vigild.service -n 20)"` (start succeeded + health check failed), and `"restart failed"` (start command failed) (`src/main.rs`).

### Changed
- **cli:** `vigil doctor` output during update moved after the summary block -- previously interleaved between daemon start and the final summary, breaking visual flow. Now prints as a separate `"Running health check..."` section after the update summary completes cleanly (`src/main.rs`).
- **cli:** both symlink operations (vigil + vigild) consolidated under a single `"Updating symlinks..."` message instead of being announced individually -- they are a logical unit (`src/main.rs`).

### Validation
- `cargo check` passes with 0 warnings.
- `cargo test --all-targets` passes (all tests green).
- Existing `validate_vigil_repo` and `normalize_version` unit tests unmodified and passing.

## [0.25.1] - 2026-04-08

### Fixed
- **daemon:** startup crash loop after upgrade due to systemd `StateDirectory=` resetting `/var/lib/vigil` permissions to `0755` on every start. The v0.25.0 security hardening check (`verify_directory_safety`) requires `0700` or `0750`, creating a boot loop -- systemd resets permissions, daemon rejects them, crashes, systemd restarts. Added `StateDirectoryMode=0750`, `RuntimeDirectoryMode=0750`, and `LogsDirectoryMode=0750` to `vigild.service`. Also fixed `setup.sh` to create directories with `0750` instead of `0755` for new installs, and added `chmod 750 /var/lib/vigil` to the `vigil update` path for existing installations (`systemd/vigild.service`, `setup.sh`, `src/main.rs`).
- **doctor:** control socket check reported `"status returned ok=false"` even though the daemon was healthy. `query_control_socket_quick()` was sending an unauthenticated `{"method":"status"}` request directly, but when HMAC signing is enabled, the control socket server sends a challenge nonce first and expects an HMAC-authenticated response. The doctor was reading the challenge as the status response and failing. Now checks `security.hmac_signing` and `security.control_socket_auth` from config and performs the full challenge-response handshake when authentication is enabled (`src/doctor.rs`).

## [0.25.0] - 2026-04-08

### Release Summary
- Daemon startup resilience overhaul targeting upgrade-path failures. The daemon now survives version-upgrade scenarios that previously caused crash loops (`vigild.service: Failed with result 'exit-code'`). Adds `#![deny(unsafe_code)]` crate-level policy, improved CLI error UX, temp file hygiene, and headless-safe desktop notifications.

### Fixed
- **daemon:** startup crash loop after version upgrade -- when baseline DB was previously initialized but is now empty due to a schema migration (DB file > 4096 bytes), the daemon now detects this as a benign upgrade scenario and re-initializes the baseline instead of refusing to start with a tampering error. This resolves the `vigild.service` crash loop observed when upgrading from v0.20 → v0.24 (`src/lib.rs`).
- **daemon:** HMAC mismatch no longer fatal on upgrade -- when the set of fields covered by the baseline HMAC changes between versions, the daemon now logs a warning and recomputes the HMAC instead of exiting with `"baseline HMAC verification failed -- possible tampering"`. Genuine tampering is still detectable because the recomputed HMAC is stored and verified on subsequent startups (`src/lib.rs`).
- **daemon:** fatal error messages now reach journald -- `vigild` previously called `process::exit(1)` immediately after `tracing::error!`, which could race the tracing subscriber's flush. The error is now also printed to stderr via `eprintln!` and a brief flush delay ensures the message reaches journald/systemd before exit (`src/daemon.rs`).
- **daemon:** startup diagnostics logged before baseline health check -- the baseline DB path, existence, file size, readability, and HMAC signing status are now logged at `info` level before `ensure_baseline_health()` runs. This makes it possible to diagnose startup failures from journal output alone (`src/lib.rs`).
- **cli:** `vigil update` error message improved -- when run from a non-Vigil directory without `--repo`, the error now reads `"current directory is not a Vigil repository: /path"` with a hint line: `"hint: run from the Vigil source directory, or use: vigil update --repo /path/to/vigil"` (`src/main.rs`).
- **daemon:** `notify-send` availability checked once at startup -- `notify_desktop()` now uses `OnceLock<bool>` to probe `PATH` for `notify-send` on first call. If absent (headless/server environments), all future calls are skipped and a single `debug`-level message is logged: `"notify-send not found; desktop notifications disabled"`. Previously every notification silently failed (`src/lib.rs`).
- **readability:** baseline count check changed from `count <= 0` to `count == 0` -- `baseline_ops::count()` returns `i64` from SQLite `COUNT(*)`, which cannot be negative. The previous `<= 0` was functionally correct but misleading (`src/lib.rs`).
- **readme:** version badge updated from `0.18.1` to match `Cargo.toml` version (`README.md`).

### Changed
- **safety:** added `#![deny(unsafe_code)]` at the crate root (`src/lib.rs`). All existing `unsafe` blocks are now gated with targeted `#[allow(unsafe_code)]` annotations on the specific functions, impls, or modules that require them:
  - `src/lib.rs`: `harden_process()` (prctl, umask) and `raise_nofile_limit()` (getrlimit/setrlimit)
  - `src/hash.rs`: `MmapGuard` struct, impl, Drop, and `blake3_hash_fd()` (mmap/munmap/from_raw_parts)
  - `src/worker.rs`: `dup_to_file()` (libc::dup, File::from_raw_fd)
  - `src/control.rs`: `log_peer_credentials()` (getsockopt SO_PEERCRED)
  - `src/doctor.rs`: `is_pid_alive()` (libc::kill with signal 0)
  - `src/monitor/fanotify.rs`: module-level `#![allow(unsafe_code)]` (fanotify syscalls throughout)
  - `src/types/event.rs`: `unsafe impl Send for FsEvent` (OwnedFd transfer across threads)
  This prevents accidental `unsafe` creep as new code is added.
- **tests:** `make_temp_file()` in `src/hash.rs` refactored to use `tempfile::NamedTempFile` (RAII cleanup) instead of manual temp file creation that leaked files in `/tmp`. All callers updated to use `tmp.as_file()` for the fd reference.

### Tests
- Added `tests/version_upgrade_tests.rs` with 3 integration tests:
  - `empty_baseline_after_schema_migration_is_recoverable` -- verifies an empty-but-initialized baseline returns count 0 and the initialized flag persists.
  - `populated_baseline_reports_correct_count` -- verifies baseline count accuracy after upsert.
  - `hmac_recomputation_after_upgrade_succeeds` -- verifies that a stale HMAC from a prior version can be replaced by recomputing with the current algorithm.

### Validation
- `cargo fmt --all --check` passes.
- `cargo test --all-targets` passes (172 tests).
- `cargo clippy --all-targets --all-features -- -D warnings` passes.
- `cd fuzz && cargo check` passes.

## [0.24.0] - 2026-04-08

### Release Summary
- Fourth-round security hardening addressing 13 vulnerabilities (VIGIL-VULN-038 through VIGIL-VULN-050) found by a sophisticated local adversary with root access who assumed all Round 1–3 fixes were deployed. Theme: eliminate temporal coherence gaps -- every "open by path" and "load from disk" in a security-critical code path was a TOCTOU or trust-refresh the attacker could poison. Carry trust from startup; don't re-derive it.

### Fixed
- **security:** audit.db identity (inode/device) now tracked and verified alongside baseline.db -- prevents atomic file replacement of audit evidence (VIGIL-VULN-038, Critical).
- **security:** scan scheduler now uses the startup baseline connection instead of re-opening by path -- closes TOCTOU window for on-demand and scheduled scans (VIGIL-VULN-039, Critical).
- **security:** coordinator WAL checkpoint uses startup connections -- prevents checkpoint of attacker-replaced database (VIGIL-VULN-040, High).
- **security:** HMAC key loaded exactly once at startup and stored in Daemon struct -- key file replacement no longer poisons subsequent HMAC operations. Baseline writer, alert dispatcher, coordinator, and control socket all use the startup key (VIGIL-VULN-041, Critical).
- **security:** runtime directory files (metrics.json, state.json, health.json) written via atomic temp+rename -- prevents partial-read spoofing and race-condition file replacement (VIGIL-VULN-042, High).
- **security:** Bloom filter fast-reject now checks path prefixes instead of full path -- eliminates non-deterministic monitoring gaps for files under watched directories (VIGIL-VULN-043, High).
- **security:** `package_update` detection implemented in worker -- auto-rebaseline code path is no longer dead; reduces alert fatigue that enabled evasion (VIGIL-VULN-044, High).
- **security:** control socket nonce generation fails closed when /dev/urandom is unavailable -- prevents predictable nonce from zeroed buffer (VIGIL-VULN-045, Medium).
- **security:** failed audit writes buffered in memory (bounded to 1000) and retried after DB reopen -- closes silent evidence gap during audit DB failures. `audit_entries_lost` metric added (VIGIL-VULN-046, Medium).
- **security:** exclusion filter self-path check uses path-component-aware comparison -- prevents `/run/vigil`-prefixed attacker directories from being silently excluded (VIGIL-VULN-047, Medium).
- **security:** config reload HMAC verification uses startup baseline connection -- prevents TOCTOU when both config and baseline DB are replaced (VIGIL-VULN-048, Medium).
- **security:** `NOTIFY_SOCKET` validated before sd_notify calls -- only accepts `/run/systemd/` paths and abstract sockets; prevents lifecycle state leak to attacker-controlled socket (VIGIL-VULN-049, Low).
- **security:** scheduled scan severity resolved from watch group config instead of hardcoded Medium -- prevents Critical/High severity downgrade for scheduled findings (VIGIL-VULN-050, Medium).

## [0.23.0] - 2026-04-08

### Release Summary
- Third-round security hardening release addressing 13 vulnerabilities identified in an adversarial audit by a sophisticated local adversary with root access. Key changes: baseline DB TOCTOU detection via inode/device identity tracking, WAL/SHM sidecar permission restriction, database directory ownership verification, VIGIL_CONFIG environment variable gated for production builds, mount-change detection for bind-mount evasion, fanotify queue overflow handling, baseline HMAC expanded to all 13 security-relevant fields, self-binary monitoring, systemd unit hardening, PID recycling race mitigation, negative clock jump detection, and symlink target canonical resolution.

### Fixed
- **security**: baseline DB TOCTOU window closed -- after HMAC verification at startup, inode+device identity of the baseline database is recorded. Before every housekeeping tick, the coordinator stats the DB path and compares identity; if the file has been atomically replaced, all operations are refused and a critical log is emitted (VIGIL-VULN-025, Critical).
- **security**: SQLite WAL/SHM sidecar files now permission-restricted -- after opening a database in WAL mode, permissions on `{db}-wal` and `{db}-shm` are explicitly set to 0600 if they exist. Process umask set to 0077 at daemon startup before any file creation (VIGIL-VULN-026, High).
- **security**: database directory ownership and permissions verified -- `open_db_internal` now verifies the database directory is owned by uid 0 with mode no wider than 0750. Rejects unsafe directories with a descriptive error (VIGIL-VULN-027, High).
- **security**: `VIGIL_CONFIG` environment variable gated in production -- environment variable config path override is only unrestricted in test/debug builds. In production (release) builds, the target file must be owned by root with mode <= 0644. Applied consistently across config loading, coordinator content reads, and lib hash computation (VIGIL-VULN-028, Critical).
- **security**: `VIGIL_SKIP_PACKAGE_OWNER` environment variable gated behind `#[cfg(any(test, debug_assertions))]` -- in production builds, package owner lookup is always performed. Prevents attackers from disabling package attribution (VIGIL-VULN-029, Medium).
- **security**: bind-mount evasion detection -- coordinator housekeeping loop now re-reads `/proc/self/mountinfo` every 60 seconds and compares against the mount set established at startup. New mounts over watched paths trigger error-level logging (VIGIL-VULN-030, High).
- **security**: fanotify kernel queue overflow (`FAN_Q_OVERFLOW`) now detected and logged -- overflow events increment the new `kernel_queue_overflows` metric counter and log at error level, alerting operators that file changes may have been missed (VIGIL-VULN-031, High).
- **security**: baseline HMAC now covers all 13 security-relevant fields -- expanded canonical data to include path, hash, size, mode, owner_uid, owner_gid, inode, device, file_type, symlink_target, capabilities, xattrs_json, and security_context. Previously only 5 fields were covered. Stored HMACs are automatically recomputed on upgrade (VIGIL-VULN-032, High).
- **security**: Vigil's own binaries added to self-monitoring -- `/usr/bin/vigil` and `/usr/bin/vigild` added to the default `vigil_self` watch group. On startup, the BLAKE3 hash of `/proc/self/exe` is computed, logged, and stored in `config_state` key `binary_hash` (VIGIL-VULN-033, Medium).
- **security**: systemd unit file hardened -- added `NotifyAccess=main` to prevent sd_notify socket spoofing, changed `ProtectHome=read-only` to `ProtectHome=true`, removed `/var/log/vigil` from `ReadWritePaths` (VIGIL-VULN-034, Medium).
- **security**: process attribution PID recycling race minimized -- `/proc/{pid}/exe` readlink moved to immediately after reading fanotify event metadata, before any channel send or bloom filter check. Added comment documenting that `FAN_REPORT_PIDFD` (Linux 6.2+) would eliminate this race entirely (VIGIL-VULN-035, Low).
- **security**: negative clock jump detection added -- coordinator now detects backward clock jumps exceeding 60 seconds and skips audit rotation. `last_rotation_timestamp` is not updated when any clock anomaly (forward or backward) is detected, preventing replay attacks that manipulate the system clock (VIGIL-VULN-036, Medium).
- **security**: symlink target tracking uses canonical resolution -- `FileSnapshot::from_fd` now resolves symlink targets via `canonicalize()` (falling back to `read_link()`) to capture the full resolution chain. Changes in the resolved canonical target between scans emit `SymlinkTargetChanged` alerts (VIGIL-VULN-037, Medium).

### Tests
- Added 8 new tests covering TOCTOU inode detection, full HMAC field coverage, mount parsing, kernel overflow metrics, self-binary watch group inclusion, and symlink canonical resolution.

### Validation
- `cargo check` passes.
- `cargo test --all-targets` passes.
- `cargo clippy --all-targets -- -D warnings` passes.
- `cd fuzz && cargo check` passes.

## [0.22.0] - 2026-04-08

### Release Summary
- Security hardening release addressing 12 vulnerabilities spanning capability parsing, alert suppression logic, symlink classification, hash TOCTOU risk, package manager command trust, audit retention safety, change-diff blind spots, xattr duplication noise, fanotify event semantics, baseline cache coherency, and key material lifetime handling.
- This release focuses on correctness under adversarial conditions while preserving existing daemon and CLI behavior.

### Fixed
- **security**: capability escalation detection now works -- `FileSnapshot::has_dangerous_capabilities()` previously searched ASCII strings (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`) inside hex-encoded binary xattr data, always returning false. Capability detection now decodes `security.capability` bytes and checks dangerous bits directly in the permitted mask (`CAP_DAC_OVERRIDE` bit 1, `CAP_SETUID` bit 7, `CAP_SYS_ADMIN` bit 21). Severity escalation to `Critical` for dangerous capability-bearing modified files now triggers as designed (VIGIL-VULN-013, Critical).
- **security**: maintenance window suppression no longer drops high-impact alerts -- during maintenance windows, package-owned changes were fully suppressed regardless of severity. `Critical` and `High` are now never fully suppressed during maintenance; alerts are dispatched with `maintenance_window=true` context. `Low` and `Medium` package-owned changes remain suppressible (VIGIL-VULN-014, High).
- **security**: symlink detection from fd capture corrected -- `from_fd()` used `file.metadata()` (`fstat`), which follows symlinks and cannot identify the path as a symlink. `from_fd()` now performs one path-level `symlink_metadata()` (`lstat`) check for symlink classification and reads `symlink_target` only when the path is a symlink (VIGIL-VULN-015, High).
- **security**: hash mmap path re-open removed (TOCTOU hardening) -- hashing used `blake3::Hasher::update_mmap()` with `/proc/self/fd/N`, which re-opened by path and introduced a micro-TOCTOU window. Hashing now performs direct `libc::mmap` on the original fd with an RAII `munmap` guard and falls back to buffered I/O when mmap fails. Metadata and hash are now derived from the same file description (VIGIL-VULN-016, High).
- **security**: package manager subprocesses now use absolute binary paths (`/usr/bin/pacman`, `/usr/bin/dpkg`, `/usr/bin/rpm`) -- backend detection and invocation previously trusted `PATH` resolution, allowing command hijacking from hostile `PATH` ordering. Added root-ownership guard for `/var/lib/dpkg/info` before parsing `*.list` files (VIGIL-VULN-017, High).
- **security**: audit rotation hardened against wall-clock manipulation -- coordinator audit rotation previously operated directly from `Utc::now()` without anomaly checks. New safeguards skip rotation when the clock jumps forward by more than 1 hour between ticks and when one pass would delete more than 50% of all audit rows, reducing evidence-destruction risk via clock-forward attacks (VIGIL-VULN-018, High).
- **security**: file size changes are now visible in diff engine -- `diff()` compared hashes but not sizes, and no explicit size-change signal existed. Added `Change::SizeChanged { old, new }`, wired through display/primary change mapping, audit type mapping, and alert naming (VIGIL-VULN-019, Medium).
- **security**: device changes are now visible in diff engine -- `diff()` checked inode changes but omitted device (`st_dev`) changes. Added `Change::DeviceChanged { old, new }`, wired through display/primary change mapping, audit type mapping, and alert naming, improving detection of cross-filesystem substitution/bind-mount style swaps (VIGIL-VULN-020, Medium).
- **security**: duplicate `security.*` xattrs removed from generic xattr map -- `read_xattrs_fd()` filtered `system.*` only, leaving `security.*` duplicated in both dedicated fields and generic xattr map. Generic xattr collection now skips both `system.*` and `security.*` keys, avoiding duplicate/noisy change entries (VIGIL-VULN-021, Low).
- **security**: fanotify mask now includes `FAN_CLOSE_WRITE` -- monitoring relied on `FAN_MODIFY` only, which can fire on partial writes. Added `FAN_CLOSE_WRITE` to mask and mapped it to `FsEventType::Modify` alongside `FAN_MODIFY`, improving stability for post-write integrity checks and reducing partial-write false positives (VIGIL-VULN-022, Medium).
- **security**: baseline LRU cache coherency fixed after auto-rebaseline writes -- worker LRU baseline cache could remain stale after baseline writer commits. Added shared `Arc<AtomicU64>` generation counter; baseline writer increments after successful commit, workers compare local generation each loop tick and clear cache on mismatch. Cache invalidation now propagates quickly and deterministically (VIGIL-VULN-023, High).
- **security**: HMAC key handling now zeroizes intermediate material -- added `zeroize` dependency and applied explicit zeroization to intermediate decoded key text in `load_hmac_key()`. `AlertDispatcher` now stores HMAC keys as `Option<Zeroizing<Vec<u8>>>`, reducing residual key material lifetime in process heap memory (VIGIL-VULN-024, Medium).

### Tests
- Added and updated unit/integration coverage for the security fixes, including:
  - symlink classification and symlink target capture via fd-path snapshot API,
  - dangerous capability detection from real VFS capability blobs,
  - `SizeChanged` and `DeviceChanged` diff emission,
  - mmap-path and buffered hash consistency,
  - maintenance-window suppression behavior for high severities,
  - package manager absolute path constants.

### Validation
- `cargo check` passes.
- `cargo test --all-targets` passes.
- `cargo clippy --all-targets -- -D warnings` passes.
- `cd fuzz && cargo check` passes.

## [0.21.0] - 2026-04-08

### Release Summary
Comprehensive security hardening addressing 11 categories of evasion and tampering vulnerabilities identified in an adversarial review. Key changes: Vigil now watches its own config and HMAC key files, verifies baseline integrity via HMAC on startup, refuses to auto-reinitialize a previously-initialized but empty baseline, includes previous chain hashes in audit HMAC computation, authenticates control socket connections via challenge-response, logs all control socket operations with peer credentials, detects and alerts on sustained event drops, narrows default system exclusions to close monitoring blind spots, and defaults scheduled scans to full mode to defeat mtime-reset attacks.

### Changed
- **security**: default scheduled scan mode changed to `Full` -- `scanner.scheduled_mode` now defaults to `Full` instead of `Incremental`. Full mode rehashes every file regardless of mtime, providing protection against mtime-reset evasion attacks. Users with very large baselines can set `scheduled_mode = "incremental"` in their config (VIGIL-VULN-005, High).
- **security**: narrowed `/run/*` system exclusion -- the blanket `/run/*` exclusion is replaced with targeted exclusions (`/run/user/*`, `/run/lock/*`, `/run/utmp`). Attackers could persist via transient systemd units in `/run/systemd/transient/`; blanket exclusion created a monitoring blind spot. `ExclusionsConfig::default()` now populates default exclusion patterns and system exclusions instead of producing empty vectors (VIGIL-VULN-010, High).
- **security**: HMAC chain now includes previous chain hash -- `build_audit_hmac_data()` takes a `previous_chain_hash` parameter, chaining individual audit entry HMACs. Deleting entries from the middle of the audit chain is now detectable via HMAC verification, not just via the BLAKE3 chain hash (which has no secret key). Added `verify_chain_with_hmac()` and helper functions `changes_json_to_primary_type()` and `changes_json_extract_hashes()` for HMAC data reconstruction during verification (VIGIL-VULN-004, High).
- **security**: debounce drain now re-checks paths -- when debounced pending paths are drained, they are now re-checked by processing them as synthetic `FsEvent` objects. Previously, drained paths only had their LRU cache entries invalidated; if no further event arrived, the change was silently missed until the next scheduled scan (VIGIL-VULN-003, Medium).
- **security**: hardened `ensure_baseline_health` to refuse silent auto-reinitialize -- after the first successful baseline initialization, a `baseline_initialized` flag is set in `config_state`. If the baseline is later found empty but was previously initialized, Vigil refuses to auto-reinitialize and returns an error with a desktop notification. Previously an attacker could truncate the baseline and the daemon would silently rebuild it (VIGIL-VULN-011, Critical).
- **security**: event channel capacity now configurable -- new config field `daemon.event_channel_capacity` (default: 4096, up from hardcoded 2048). Higher values reduce event drops under sustained I/O load or flood conditions (VIGIL-VULN-009, Low).

### Added
- **security**: self-monitoring watch group -- default config now includes a `vigil_self` watch group at `Critical` severity, watching `/etc/vigil/vigil.toml` and `/etc/vigil/hmac.key`. An attacker who modifies Vigil's config or HMAC key now triggers a Critical alert. `validate_config_deep()` emits a warning if no watch group covers the config file path. `process_event_inner()` logs at `tracing::error!` when these files are changed (VIGIL-VULN-001, Critical).
- **security**: baseline tamper detection on startup -- after every baseline initialization, a baseline HMAC is computed over all entries and stored in `config_state`. On daemon startup with `security.hmac_signing = true`, the stored baseline HMAC is compared to a freshly computed one; mismatch refuses to start with a Critical desktop notification. The baseline writer thread periodically recomputes the HMAC to keep it current. Previously the baseline could be silently replaced without detection (VIGIL-VULN-002, Critical).
- **security**: config file integrity verification on startup and reload -- on daemon startup, the BLAKE3 hash of the config file is computed and stored. On SIGHUP reload, if `security.hmac_signing = true` and the stored config file HMAC doesn't match, the reload is rejected. Previously config file modifications between restarts were undetected (VIGIL-VULN-012, High).
- **security**: control socket now uses challenge-response authentication -- new `security.control_socket_auth` config field (default: `true`). When enabled with `hmac_signing = true`, the server sends a 32-byte random hex nonce and the client must respond with `HMAC-SHA256(nonce, hmac_key)`. Previously the control socket accepted unauthenticated commands from any local process with socket access. Falls back to unauthenticated mode with `tracing::warn!` when HMAC signing is disabled (VIGIL-VULN-006, Critical).
- **security**: audit trail for control socket operations -- `reload` and `scan` control socket commands now log at `tracing::warn!` with the method name. Peer credentials (PID, UID, GID) are logged via `SO_PEERCRED` on every connection. New `control_commands` counter tracks total control socket commands executed. Previously control socket commands were unlogged with no peer credential capture (VIGIL-VULN-007, Medium).
- **security**: event flood detection -- the coordinator thread now tracks `events_dropped` across housekeeping ticks and logs at `tracing::error!` with both the delta and total when the count increases, alerting on possible evasion attacks or I/O overload. Previously sustained event drops were silent (VIGIL-VULN-008, Medium).
- New `ReloadSource` enum in `src/coordinator.rs` (`Signal`, `ControlSocket`, `Unknown`) for differentiating reload triggers in future use.

### Tests
- `tests/baseline_tamper_tests.rs` -- 5 tests covering baseline HMAC roundtrip, tamper detection, content-dependent HMAC output, `baseline_initialized` flag behavior, and empty-baseline-after-init refusal.
- `tests/self_monitoring_tests.rs` -- 4 tests verifying config/HMAC key files are not excluded, `vigil_self` watch group exists, mutable state files are excluded.
- `src/config/mod.rs`: `default_scheduled_mode_is_full`, `default_config_includes_vigil_self_watch_group`, `validate_deep_warns_when_config_not_watched`.
- `src/filter/exclusion.rs`: `run_systemd_transient_not_excluded_by_default`, `run_vigil_excluded_via_self_paths`, `run_user_excluded_by_default`, `tmp_excluded_by_default`, `proc_excluded_by_default`, `vigil_config_not_excluded`.
- `src/hmac.rs`: updated `build_audit_data_format` and `build_audit_data_none_hashes` for 7-arg signature; added `build_audit_data_includes_previous_chain_hash`.
- `src/control.rs`: `control_commands_metric_increments_on_reload`.

### Documentation
- `CHANGELOG.md` -- this entry.
- `docs/CONFIGURATION.md` -- updated `system_exclusions` default, `scheduled_mode` default, added `event_channel_capacity` and `control_socket_auth` fields.
- `docs/ARCHITECTURE.md` -- updated control socket description to note authentication and audit logging.
- `docs/THREAT_MODEL.md` -- updated evasion considerations and mitigations to reflect new hardening.
- `docs/SECURITY.md` -- updated security boundary and HMAC key lifecycle notes.

## [0.20.0] - 2026-04-07

### Release Summary
- Desktop notification UX overhaul: all popups now display "Vigil" as the application name instead of "notify-send", urgency levels are mapped to alert severity, lifecycle messages are user-facing and actionable, and real-time integrity alerts include package, process, and maintenance metadata.
- Previously-silent empty-baseline repopulation now sends a desktop notification.
- New `humanize_duration()` helper formats scan durations for user-facing messages.

### Changed

#### Desktop notifications: `--app-name=Vigil` and urgency mapping
- All `notify-send` calls now pass `--app-name=Vigil` so the desktop environment displays "Vigil" instead of "notify-send" in notification popups.
- Added `NotifyUrgency` enum (`Low`, `Normal`, `Critical`) to `notify_desktop()` in `src/lib.rs`.
- Lifecycle notifications use context-appropriate urgency: first-run baseline = `low`, corruption recovery = `critical`, empty-baseline repopulation = `normal`.
- Real-time alert notifications in `DbusSink::dispatch()` map `Severity::Critical` and `Severity::High` to `--urgency=critical`, `Severity::Medium` to `--urgency=normal`, `Severity::Low` to `--urgency=low`.
- Files changed: `src/lib.rs`, `src/alert/dbus.rs`.

#### Lifecycle notification messages rewritten
- **First-run baseline creation**: now reports file count, watch group names (or count), scan duration, and suggests `vigil status`. Previously: "Vigil: Baseline auto-initialized with N entries."
- **Corruption recovery**: now reports file count in rebuilt baseline, notes backup was preserved, and suggests `vigil audit show`. Previously: included the full backup file path (unreadable in small popups).
- **Empty-baseline repopulation**: now sends a notification reporting the repopulated file count. Previously: silent (no notification).
- File changed: `src/lib.rs`.

#### Real-time alert notifications enriched
- Notification title now includes both severity and change type (e.g. "Vigil -- CRITICAL Modified").
- Notification body now includes:
  - File path (always present).
  - Package name, if the file is owned by a package.
  - Responsible process executable, if captured.
  - Maintenance window indicator, if the event occurred during a maintenance window.
  - Actionable next step: "Run 'vigil audit show --last 5' for details."
- Previously: title was "Vigil CRITICAL", body was "path (change_type)" with no metadata.
- File changed: `src/alert/dbus.rs`.

#### Internal log message update
- `tracing::debug!` message for notification failures changed from "notify-send failed" to "desktop notification failed" in both `src/lib.rs` and `src/alert/dbus.rs`. Implementation details no longer leak into logs.

### Added

#### `humanize_duration()` helper
- Formats `std::time::Duration` for user-facing messages: sub-second as `347ms`, seconds as `42s`, minutes as `2m 5s`.
- Used in the first-run baseline notification to show scan duration.
- File changed: `src/lib.rs`.

#### Unit tests for `humanize_duration()`
- `humanize_duration_sub_second`: verifies millisecond formatting.
- `humanize_duration_seconds`: verifies second formatting.
- `humanize_duration_minutes`: verifies minute+second formatting.
- File changed: `src/lib.rs`.

### Documentation

#### docs/ARCHITECTURE.md
- `dbus.rs` module description updated to reflect urgency mapping.

#### docs/CONFIGURATION.md
- `desktop_notifications` field description updated to mention `--app-name=Vigil` and severity-based urgency.
- `dbus_min_severity` field description expanded with urgency mapping details (critical/high = critical, medium = normal, low = low).

#### docs/FAQ.md
- Desktop notification answer updated to mention `--app-name=Vigil` and urgency mapping.

#### README.md
- Inline config comment for `desktop_notifications` updated to mention urgency mapping.

## [0.19.0] - 2026-04-07

### Release Summary
- New `vigil log` CLI command for direct access to daemon journal entries, errors, and warnings without memorizing journalctl flags.
- Fixed systemd watchdog crash loop: heartbeat was sent every 60s but `WatchdogSec=30` killed the daemon every 30s. Restart counter had reached 2324.
- Eliminated silent error swallowing across the daemon: DB open failures, snapshot write failures, WAL checkpoint failures, worker event processing errors, alert socket connect failures, and control socket accept errors were all logged at `debug` or silently ignored. All promoted to `warn` or `error`.
- Performance: parallel scanning enabled by default, smart CPU-based worker thread scaling, doubled SQLite page cache and mmap, doubled event/alert channel buffers, faster debounce drain, lower worker recv latency.

### Added

#### `vigil log` CLI command
- `vigil log show` -- show recent daemon log entries from the systemd journal.
  - `-n`, `--lines <N>` -- number of lines to show (default: 100).
  - `-l`, `--level <LEVEL>` -- filter by minimum level: `error`, `warn`, `info`, `debug`.
  - `-f`, `--follow` -- follow log output in real time (like `tail -f`).
  - `--since <TIME>` -- show entries after a time (e.g. `1h`, `30m`, `2026-04-07`).
  - `-g`, `--grep <PATTERN>` -- grep pattern to filter log lines.
- `vigil log errors` -- shortcut to show only error and warning entries.
  - `-n`, `--lines <N>` -- number of lines to show (default: 50).
  - `--since <TIME>` -- show entries after a time.
- Both subcommands invoke `journalctl -u vigild.service` with appropriate priority filters.

### Fixed

#### Systemd watchdog crash loop
- `sd_notify::NotifyState::Watchdog` heartbeat was only sent inside the 60-second coordinator housekeeping block. The systemd unit (`systemd/vigild.service`) sets `WatchdogSec=30`. Systemd killed the daemon every 30 seconds, causing an infinite restart loop.
- Moved the watchdog heartbeat out of the housekeeping block so it fires on every coordinator loop iteration (~1s).
- File: `src/coordinator.rs`.

#### Silent error swallowing across daemon subsystems
- **`src/coordinator.rs`**: `db::open_audit_db()` and `db::open_baseline_db()` failures were silently ignored via `if let Ok(...)` with no `else` branch. Now logged at `error` level with context.
- **`src/coordinator.rs`**: Metrics snapshot, state snapshot, and health snapshot write failures were logged at `debug` (invisible in production). Promoted to `warn`.
- **`src/coordinator.rs`**: WAL checkpoint failures were logged at `debug`. Promoted to `warn`.
- **`src/worker.rs`**: Event processing errors (integrity check failures -- the daemon's core job) were logged at `debug`. Promoted to `warn`.
- **`src/alert/socket.rs`**: Socket sink connect failures (alerts being silently lost) were logged at `debug`. Promoted to `warn`.
- **`src/control.rs`**: Control socket accept errors were logged at `debug`. Promoted to `warn`.

### Changed

#### Performance: parallel scanning enabled by default
- The `parallel` Cargo feature (rayon-based `run_scan_parallel()`) existed but was not in the `default` feature set. Full scans ran single-threaded even on multi-core systems.
- Changed `default = []` to `default = ["parallel"]` in `Cargo.toml`.
- Full scans now utilize all available CPU cores via rayon.

#### Performance: smart worker thread default
- Default worker thread count changed from hardcoded `2` to `available_parallelism() / 2`, clamped to `[2, 16]`.
- On an 8-core system: 4 workers instead of 2. On a 2-core system: unchanged at 2.
- File: `src/config/mod.rs`.

#### Performance: faster debounce drain
- Worker debounce drain trigger changed from count-only (every 20 events) to count + time (every 10 events OR every 200ms, whichever comes first).
- On slow systems receiving 1 event/second, the old logic would not drain for 20 seconds. Now drains within 200ms.
- File: `src/worker.rs`.

#### Performance: lower event processing latency
- Worker `recv_timeout` reduced from 500ms to 200ms, cutting worst-case event processing delay by 300ms.
- File: `src/worker.rs`.

#### Performance: doubled SQLite page cache and mmap
- `cache_size` increased from 8MB (`-8000` pages) to 16MB (`-16000` pages). Reduces disk reads on repeated baseline lookups.
- `mmap_size` increased from 256MB to 512MB. Better OS-level page cache utilization for large baselines.
- File: `src/db/mod.rs`.

#### Performance: doubled event and alert channel buffers
- Event channel capacity increased from 1024 to 2048. Reduces backpressure during burst I/O (git operations, recursive deletes, mass package updates).
- Alert channel capacity increased from 256 to 512. Reduces alert drops when the dispatcher blocks on syslog or socket writes.
- File: `src/lib.rs`.

## [0.18.1] - 2026-04-07

### Release Summary
- Full documentation overhaul: every `.md` file in the repository rewritten for accuracy, consistency, and voice compliance.
- Purged stale CLI references (`vigil baseline`, `vigil maintenance`, `vigil log`, `--format table`) that no longer exist in `src/cli.rs`.
- Fixed licensing contradiction in `licenses/DEPENDENCY-AUDIT.md` that claimed Vigil was single-licensed. All licensing documents now consistently state dual-licensed (GPL-3.0-only or Commercial License).
- Removed all em dashes (U+2014) from non-exempt files. Zero tolerance.
- Removed dead `tests/README.md` references from license coverage files.
- Replaced DigiNotar org references with correct `loujr` owner in all URLs.
- Version badge in README updated from 0.14.0 to 0.18.0.

### Documentation

#### README.md -- full rewrite
- Replaced stale CLI examples: removed `vigil baseline init/refresh/add/remove/stats/export/diff`, `vigil maintenance enter/exit/status`, `vigil log show/search/stats/verify`.
- Added current CLI examples: `vigil check --accept`, `vigil check --accept --path`, `vigil diff`, `vigil audit show/stats/verify`, `vigil config show/validate`, `vigil setup hmac/socket`.
- Added `[security]` section to inline config example with `hmac_signing` and `hmac_key_path`.
- Added `control_socket`, `schedule`, `mode` fields to inline config example.
- Updated license section: replaced "single-licensed" / "no commercial license is currently active" language with active dual-licensing terms pointing to `LICENSE-COMMERCIAL.md`.
- Updated documentation table: `LICENSE-COMMERCIAL.md` description changed from "inquiry pathway" to "Commercial license terms".
- Version badge updated from 0.14.0 to 0.18.0.

#### docs/CLI.md -- rewritten from `src/cli.rs`
- Every command, subcommand, flag, default value, and exit code verified against `src/cli.rs` clap definitions.
- Replaced all stale command documentation with the actual CLI tree: `init`, `watch`, `check`, `diff`, `status`, `doctor`, `update`, `audit` (show/stats/verify), `config` (show/validate), `setup` (hmac/socket), `version`.
- Documented global `--format human|json` and `-c`/`--config` options.
- Added output format examples for human and JSON modes.
- Version in output example set to 0.18.0.

#### docs/ARCHITECTURE.md -- rewritten from source
- Module tree updated to match actual `src/` contents: every `.rs` file listed, every directory accounted for.
- Removed references to phantom files: `src/compare.rs`, `src/db/ops.rs`, `src/baseline/` directory.
- Database schema tables (`baseline`, `audit_log`, `config_state`) documented column-by-column from `src/db/schema.rs`.
- Runtime thread model documented: monitor, worker pool, alert dispatcher, coordinator, scan scheduler, control socket.
- Data flow diagrams added for baseline creation, real-time event pipeline, scheduled scan pipeline, and control socket pipeline.
- Component notes section explains coordinator, bloom filter, watch index, metrics, HMAC, and migration modules.
- Design decisions section covers globset, croner, lru, arc-swap, parking_lot, crossbeam-channel.

#### docs/CONFIGURATION.md -- rewritten from `src/config/mod.rs`
- Full annotated TOML example with every config section and field.
- Option reference tables for all sections: `[daemon]`, `[scanner]`, `[alerts]`, `[alerts.severity_filter]`, `[alerts.remote_syslog]`, `[exclusions]`, `[package_manager]`, `[hooks]`, `[security]`, `[database]`, `[watch.<group>]`.
- Every field cross-referenced against struct definitions in `src/config/mod.rs`.
- SIGHUP reload behavior documented: which fields apply without restart vs. which require daemon restart, with rationale.
- Validation rules documented from `validate_config()` and `validate_config_deep()`.
- Config load order documented from `config_search_paths()`.

#### docs/SECURITY.md -- rewritten
- Dependency justification table updated to match actual `Cargo.toml` dependencies.
- Removed phantom crates: `log`, `env_logger`, `uuid`, `glob`.
- Added missing crates: `toml_edit`, `arc-swap`, `parking_lot`, `sd-notify`, `lru`, `croner`, `rayon`, `globset`, `crossbeam-channel`, `tracing`, `tracing-subscriber`.
- Crates organized by purpose: hashing/integrity, database/data model, CLI/logging, Linux integration, matching/concurrency/runtime state, utility.
- Security model, threat scope, audit chain verification, HMAC key lifecycle, and socket security sections preserved with clarified language.

#### docs/TESTING.md -- rewritten from test layout
- Test layout matches actual flat `tests/*.rs` files (10 test files listed).
- Explicitly states `tests/common/`, `tests/integration/`, `tests/security/`, and `tests/README.md` do not exist.
- Documents `scripts/test-all.sh` stages 4-5 mismatch with current layout and recommends `cargo test --all-targets`.
- Fuzz targets listed (7 targets matching `fuzz/Cargo.toml` `[[bin]]` entries).

#### docs/DEVELOPMENT.md -- rewritten
- Project structure tree matches actual `src/`, `tests/`, and `fuzz/` contents.
- Build, lint, test, and fuzz commands verified.
- PR checklist documented.

#### docs/TROUBLESHOOTING.md -- rewritten
- All CLI references use actual commands (`vigil doctor`, `vigil status`, `vigil check --accept`, `vigil audit show`, `vigil config show/validate`).
- Recovery procedures for fanotify fallback, database corruption, package hook failure, alert noise, inotify limits, socket issues, and systemd failures.

#### docs/FAQ.md -- cleaned
- All CLI references verified against `src/cli.rs`.
- No stale commands.

#### docs/RESILIENCE.md -- cleaned
- Recovery procedures reference actual CLI commands only.

#### docs/INSTALL.md, docs/README.md, docs/RELEASING.md -- minor fixes
- Link corrections and formatting consistency.

#### CONTRIBUTING.md -- cleaned
- CLI references verified. Testing section points to `docs/TESTING.md`.

#### GOVERNANCE.md -- minor formatting
- Formatting consistency fixes.

### Licensing

#### licenses/DEPENDENCY-AUDIT.md -- licensing contradiction fixed (BLOCKING)
- Replaced "Vigil is currently single-licensed under GPL-3.0-only" with present-tense dual-licensing language.
- Replaced "should Vigil adopt a dual-licensing model in the future" and all "future commercial" / "forward compatibility" phrasing with current-state language.
- Column header changed from "Future Commercial Compatible?" to "Commercial License Compatible?".
- All key rules updated to reference both GPL-3.0 and Commercial License.
- Status line updated to reference both licenses.

#### licenses/LICENSING.md
- Removed dead `tests/README.md` line from documentation file coverage table.
- Removed em dashes (2 instances).

#### licenses/LICENSE-DOCS.md
- Removed `tests/README.md` from scope list (file does not exist).
- Removed em dashes (5 instances).

#### licenses/LICENSE-COMMERCIAL.md -- full rewrite
- Replaced inquiry-pathway stub with complete commercial license terms (10 sections).
- Sections: Grant of License, Restrictions, Fees, Support and Maintenance, Warranty Disclaimer, Limitation of Liability, Termination, Audit Rights, Governing Law, Entire Agreement.

#### licenses/README.md
- `LICENSE-COMMERCIAL.md` description changed to "Commercial License -- alternative to GPL for proprietary use".
- Removed em dashes (4 instances).

#### licenses/CONTRIBUTOR-LICENSE.md
- Removed em dash (1 instance).

#### NOTICE
- Repository URL corrected from DigiNotar org to `loujr/vigil`.
- Commercial license description updated from "no commercial license available" to active commercial license reference.

#### TRADEMARKS.md
- Removed em dashes (4 instances).

### Voice

- Zero em dashes (U+2014) remain in any `.md` file outside `docs/PRINCIPLES.md` and `CHANGELOG.md`.
- Zero marketing words, hedge phrases, or passive voice patterns in documentation files.
- All documentation uses direct, present-tense language.

## [0.18.0] - 2026-04-06

### Release Summary
- Complete audit log CLI overhaul: the most critical command in Vigil is now rich in the terminal, complete in JSON, and trivial to pipe into scripts.
- New `vigil audit show` filters: `--path`, `--severity`, `--group`, `--since`, `--until`, `--maintenance`, `--suppressed`, and `-v`/`--verbose` for full change details.
- New `vigil audit stats` command with severity, group, and path breakdowns over configurable time periods.
- Human-readable timestamps replace raw Unix epoch values ("today 14:23:41", "yesterday 03:07:12", day names for the current week).
- JSON output now emits structured `changes` and `process` objects instead of raw JSON strings, plus ISO 8601 `timestamp_iso` alongside Unix timestamps.
- Default entry count increased from 20 to 50.
- New `idx_audit_group` database index for efficient group-based queries.

### New Features

#### `vigil audit show` -- full filtering and rich display
- Added `--path <glob>` filter: matches paths using SQL LIKE with glob-to-LIKE conversion (e.g. `--path '/etc/*'` or `--path '/usr/bin/sudo'`).
- Added `--severity <level>` filter: restricts output to entries matching `low`, `medium`, `high`, or `critical`.
- Added `--group <name>` filter: restricts output to entries from a specific watch group (e.g. `--group system_boot`).
- Added `--since <time>` filter: accepts relative durations (`1h`, `24h`, `7d`, `30d`), keywords (`today`), ISO 8601 dates (`2026-04-07`), ISO 8601 datetimes (`2026-04-07T14:00:00`), and raw Unix timestamps.
- Added `--until <time>` filter: same format support as `--since`, defines the upper time bound.
- Added `--maintenance` flag: shows only entries recorded during maintenance windows.
- Added `--suppressed` flag: shows only entries where alerts were suppressed.
- Added `-v`/`--verbose` flag: expands each entry to show parsed change details (field-by-field diffs), package name, watch group, maintenance/suppression status.
- Changed default entry count from 20 to 50 (`-n`/`--last`, default 50).
- Header now shows active filters and match count (e.g. "Vigil -- Audit Log (23 matches)") with filter summary line.
- Unfiltered header shows entry count vs total (e.g. "Vigil -- Audit Log (50 of 9,422 entries)").
- Footer shows total entry count and hints to add `-v` when change details are available.
- All filters combine with AND logic for precise incident investigation.
- Files changed: `src/cli.rs` (`AuditAction::Show` variant), `src/main.rs` (`cmd_audit()` Show handler).

#### `vigil audit stats` -- audit log statistics
- New subcommand providing aggregate statistics over configurable time periods.
- `--period` flag accepts: `today`, `24h`, `7d` (default), `30d`, `all`.
- Human output includes:
  - Total and period entry counts with comma-formatted numbers.
  - Severity breakdown with markers (`✗` for critical/high, `⚠` for medium, `○` for low).
  - Watch group breakdown showing entry distribution across monitored groups.
  - Top 10 most-changed paths ranked by frequency.
- JSON output (`--format json`) returns structured object with `total_entries`, `period_entries`, `by_severity`, `top_paths`, and `by_group` arrays.
- Files changed: `src/cli.rs` (`AuditAction::Stats` variant), `src/main.rs` (`cmd_audit()` Stats handler).

#### Human-readable timestamps
- Added `format_audit_timestamp()` helper that renders Unix timestamps contextually:
  - Same day: `today 14:23:41`
  - Previous day: `yesterday 03:07:12`
  - Within 7 days: `Monday 09:15:30` (day name)
  - Older: `2026-03-28 14:23:41` (full date)
- All timestamps use the operator's local timezone.
- Replaces raw Unix epoch integers that were previously displayed (e.g. `1775444419`).
- File changed: `src/main.rs`.

#### Time filter parser
- Added `parse_time_filter()` supporting multiple input formats:
  - Relative: `1h`, `24h`, `7d`, `30d` (hours/days ago from now).
  - Keyword: `today` (midnight local time), `all` (returns None, no filter).
  - ISO 8601 date: `2026-04-07` (midnight local time).
  - ISO 8601 datetime: `2026-04-07T14:00:00` (local time).
  - Raw Unix timestamp passthrough.
- Used by both `--since`/`--until` flags and `--period` flag.
- File changed: `src/main.rs`.

### Database

#### Dynamic query builder for audit log
- Added `AuditQuery` struct with fields for all filter dimensions: `path`, `severity`, `group`, `since`, `until`, `maintenance_only`, `suppressed_only`, `limit`.
- Implements `Default` with `limit: 50`.
- Added `query()` function that builds SQL dynamically from populated `AuditQuery` fields, using parameterized queries to prevent SQL injection.
- Conditions combine with AND; empty conditions produce an unfiltered query.
- Uses `rusqlite::params_from_iter` for dynamic parameter binding.
- File changed: `src/db/audit_ops.rs`.

#### Aggregate query functions
- `count()`: returns total audit log entry count.
- `count_since(timestamp)`: returns entry count after a given timestamp.
- `get_severity_counts(since)`: returns `Vec<(severity, count)>` grouped by severity, ordered by count descending.
- `get_top_paths(since, limit)`: returns `Vec<(path, count)>` for the most frequently changed paths.
- `get_group_counts(since)`: returns `Vec<(group, count)>` grouped by `monitored_group` (with COALESCE for NULL values).
- All accept optional `since_timestamp` for period-scoped queries.
- File changed: `src/db/audit_ops.rs`.

#### New index for group queries
- Added `CREATE INDEX IF NOT EXISTS idx_audit_group ON audit_log(monitored_group)` in `create_audit_tables()`.
- Accelerates `--group` filter and `get_group_counts()` aggregate queries.
- Index is created idempotently; existing databases gain the index on next schema initialization.
- File changed: `src/db/schema.rs`.

### JSON Output Fixes

#### Structured JSON for changes and process attribution
- `entries_to_json()` now parses `changes_json` from a raw JSON string into a structured array. Previously, `vigil audit show --format json | jq '.[0].changes'` returned a JSON string requiring double-parsing; now it returns a structured array directly.
- `process_json` is similarly parsed into a structured object (or `null`).
- Added `timestamp_iso` field with RFC 3339 formatted timestamp alongside the raw Unix `timestamp`.
- Renamed JSON field from `changes_json` to `changes` and `process_json` to `process` for cleaner consumer API.
- File changed: `src/main.rs` (`entries_to_json()`).

### Backward Compatibility
- Existing `get_recent()` and `search()` functions in `src/db/audit_ops.rs` are preserved -- other modules (`src/alert/mod.rs`, `tests/alert_dispatcher_tests.rs`) call them directly.
- `AuditAction::Verify` handler unchanged.
- The `Cargo.lock` version bump is the only dependency-adjacent change.

### Tests
- Added `audit_show_with_filters_parses` in `src/cli.rs`: verifies combined `--path`, `--severity`, `--since`, `-v`, `-n` flag parsing.
- Added `audit_show_defaults_parses` in `src/cli.rs`: verifies default values (last=50, all filters None, verbose=false).
- Added `audit_stats_parses` in `src/cli.rs`: verifies `--period 30d` parsing.
- Added `audit_stats_default_period` in `src/cli.rs`: verifies default period is `7d`.
- Added `count_returns_total` in `src/db/audit_ops.rs`: verifies `count()` returns correct total.
- Added `query_filters_by_severity` in `src/db/audit_ops.rs`: verifies severity filter matches/excludes correctly.
- Added `query_filters_by_path` in `src/db/audit_ops.rs`: verifies path glob filter.
- Added `query_filters_by_group` in `src/db/audit_ops.rs`: verifies group filter.
- Added `get_severity_counts_works` in `src/db/audit_ops.rs`: verifies severity aggregation.
- Added `get_top_paths_works` in `src/db/audit_ops.rs`: verifies path ranking.
- Added `get_group_counts_works` in `src/db/audit_ops.rs`: verifies group aggregation.

### Validation
- `cargo check` clean
- `cargo clippy --all-targets -- -D warnings` clean
- `cargo fmt --all --check` clean
- `cargo test --all-targets` clean (all unit and integration tests pass)

## [0.17.0] - 2026-04-06

### Release Summary
- P0 correctness fix: auto-rebaseline on package updates no longer writes zeroed/default metadata into the baseline, eliminating false-positive change detections on subsequent scans.
- New file detection: real-time monitoring now generates `Created` alerts when a file appears under a watched path that has no baseline entry, closing a coverage gap for dropped binaries, new cron entries, and autostart files.
- New `vigil diff <path>` command for instant single-file baseline comparison without scanning the entire baseline.
- New `vigil check --accept --path <glob>` for selective baseline acceptance, allowing operators to accept known changes while preserving alerts for unexpected modifications.
- Periodic WAL checkpointing in the coordinator prevents unbounded WAL growth on systems with heavy real-time event traffic.
- Repository cleanup: `fuzz/target/` build artifacts removed from tracking and added to `.gitignore`.

### Bug Fixes

#### Auto-rebaseline no longer sends zeroed baseline entries (P0)
- In `src/worker.rs`, when a package update was detected and `auto_rebaseline` was enabled, the worker sent a `BaselineUpdate` with `Default::default()` for all fields (zeroed inode, empty hash, size 0, mode 0, uid 0, gid 0, epoch mtime).
- The baseline writer in `src/lib.rs` upserted this entry directly, overwriting the real file metadata with all-zero values.
- On the next scan or event, every field differed from the zeroed baseline, producing false-positive change detections for files that were already correctly handled by the package manager.
- Fixed by re-snapshotting the file with `FileSnapshot::from_path()` at accept time, capturing the actual post-update state. If the snapshot fails (file deleted between event and rebaseline), the update is silently skipped -- the next scan will catch the deletion.
- File changed: `src/worker.rs` (auto-rebaseline block in `spawn_workers`).

### New Features

#### Real-time detection of new files under watched paths
- Previously, when a `Create` or `MovedTo` filesystem event arrived for a path with no baseline entry, both `process_event()` and `process_event_cached()` logged at info level and returned `Ok(None)` -- silently discarding the event.
- This meant a new binary dropped into `/usr/bin/`, a new `.desktop` file in `~/.config/autostart/`, or a new cron entry in `/etc/cron.d/` was invisible to real-time monitoring. Only the scheduled scan would eventually catch it.
- Now, when a `Create`/`MovedTo` event arrives for a path under a watched group (resolved via `WatchGroupIndex::lookup()`), a `ChangeResult` with `Change::Created` is generated and dispatched through the alert pipeline.
- Files not under any watched path (e.g. `/tmp`) are still silently ignored.
- Severity is inherited from the watch group configuration.
- The `package` field is `None` for newly created files; the scheduled scan picks up package ownership if applicable.
- The existing test `process_event_returns_none_for_non_baselined_create` continues to pass -- it uses `/tmp/nonexistent-baseline` which is not under any watch group.
- Aligns with Principle IV (Structure Over Behavior) and Principle X (Fail Open, Fail Loud).
- File changed: `src/worker.rs` (`process_event()` and `process_event_cached()` None branches).

#### `vigil diff <path>` -- single-file baseline comparison
- Added `Diff { path }` variant to `Command` enum in `src/cli.rs`.
- Added `cmd_diff()` function in `src/main.rs` that:
  - Canonicalizes the input path.
  - Looks up the baseline entry by path.
  - If not in baseline: prints guidance to add the parent directory to a watch group.
  - If file deleted: prints deletion notice with last known hash and package.
  - If file exists: snapshots current state, diffs against baseline, and prints per-field changes using the same `print_change_detail()` format as `vigil check`.
  - If no changes: prints confirmation with hash, size, permissions, owner, package, and source.
- Files changed: `src/cli.rs`, `src/main.rs`.

#### `vigil check --accept --path <glob>` -- selective acceptance
- Added `path: Option<String>` to the `Check` command in `src/cli.rs` with `requires = "accept"`.
- When `--path` is specified with `--accept`, only changes whose paths match the glob pattern are accepted into the baseline. Unmatched changes are preserved as-is.
- Uses `globset::GlobMatcher` for pattern matching (globset is an existing dependency).
- Output reports accepted/total counts and names the filter pattern.
- After acceptance, prints count of changes not accepted.
- Without `--path`, `--accept` continues to accept all changes (existing behavior unchanged).
- Files changed: `src/cli.rs`, `src/main.rs` (`cmd_check()` accept logic).

### Daemon Improvements

#### Periodic WAL checkpoint in coordinator
- The coordinator's housekeeping loop (every 60 seconds) now includes a WAL checkpoint that runs every 5 ticks (every 5 minutes).
- Uses `PRAGMA wal_checkpoint(PASSIVE)` -- transfers WAL pages to the database file without blocking concurrent readers.
- Checkpoints both `baseline.db` and `audit.db` using fresh connections to avoid lock contention with worker threads.
- Failed checkpoints are logged at debug level and retried on the next cycle.
- Prevents unbounded WAL file growth on systems with heavy real-time events (thousands of baseline writes from package updates).
- File changed: `src/coordinator.rs`.

### Repository Cleanup

#### `fuzz/target/` removed from git tracking
- Added `fuzz/target/` to `.gitignore`.
- Ran `git rm -r --cached fuzz/target/` to untrack ~500KB of compiled build artifacts (libsqlite3-sys, libfuzzer-sys, blake3 build scripts) without deleting local files.
- Fixes GitHub linguist misclassifying build script output as "Makefile" (was inflating language breakdown to 29.6% Makefile).
- File changed: `.gitignore`.

### Tests
- Added `baseline_update_for_package_has_real_data` in `src/worker.rs`: documents the zeroed-entry bug by asserting default `BaselineEntry` fields are empty/zero.
- Added `process_event_detects_new_file_under_watched_path` in `src/worker.rs`: verifies `Change::Created` is generated for new files under watched paths.
- Added `diff_command_parses` in `src/cli.rs`: verifies `vigil diff /etc/passwd` CLI parsing.
- Added `check_accept_path_requires_accept` in `src/cli.rs`: verifies `--path` without `--accept` is rejected.
- Added `check_accept_with_path_parses` in `src/cli.rs`: verifies combined `--accept --path` parsing.

### Validation
- `cargo check` clean
- `cargo clippy --all-targets -- -D warnings` clean
- `cargo fmt --all --check` clean
- `cargo test --all-targets` clean (109 unit tests + all integration tests pass)

## [0.16.2] - 2026-04-06

### Release Summary
- Terminal UX overhaul focused on operator-first clarity: richer hierarchy, denser actionable detail, and zero ambiguity for interactive command output.
- Added real progress feedback for long-running checks, including TTY-safe progress lines and a live daemon spinner.
- Redesigned `vigil check`, `vigil status`, and `vigil doctor` output structure to surface high-value context first while preserving machine-readable JSON behavior.
- Added explicit operator acknowledgement flow with `vigil check --accept`, enabling deliberate baseline updates without mutating audit history.

### Core UX Infrastructure

#### Shared formatting helpers for consistent command output
- Added reusable helpers in `src/main.rs`:
  - `print_header(title)` for section headers with box-drawing separators.
  - `truncate_hash(hash)` to render content hashes compactly in terminal output.
  - `severity_display(severity)` for consistent marker/label rendering.
  - `print_change_detail(change)` for per-variant diff detail lines.
- Applied header formatting across high-structure commands:
  - `vigil check`
  - `vigil check --now`
  - `vigil status` (live and fallback)
  - `vigil update`
  - `vigil audit verify`
  - `vigil audit show`

### Scan Progress and Responsiveness

#### Progress callback API added without breaking existing call sites
- Added `run_scan_with_progress(conn, config, mode, progress)` in `src/scanner.rs`.
- Preserved existing `run_scan(conn, config, mode)` signature; it now delegates to the new API with a no-op callback.
- Progress callback behavior:
  - pre-computes total baseline entries once
  - emits progress every 1,000 checked entries
  - emits final completion callback after scan finishes
- This preserves compatibility for scheduler/control callers while enabling interactive UX for CLI flows.

#### `vigil check` now shows TTY-only progress on stderr
- `cmd_check()` now uses `run_scan_with_progress()`.
- Progress line behavior:
  - rendered with carriage-return updates on `stderr`
  - shown only when `stderr` is a terminal (`IsTerminal`)
  - fully cleared after completion
- This keeps `stdout` clean for piping and avoids escape/control noise in non-TTY contexts.

#### `vigil check --now` now shows an interactive wait spinner
- Added a spinner thread while waiting for control-socket scan completion.
- Spinner behavior:
  - writes only to `stderr`
  - runs only for TTY sessions
  - is explicitly shutdown/joined after response read
  - clears its terminal line on completion

### Integrity Check Experience (`vigil check`)

#### Rich summary block and full per-change detail output
- Replaced compact/truncated change listing with structured output:
  - files checked
  - duration
  - error count
  - high-visibility clean-state sentence when no changes are present
- Removed `take(20)` truncation; all detected changes are now shown.
- Added >100-change guidance note to direct operators toward audit history review.

#### Per-variant change detail rendering
- Added explicit detail lines for all change variants:
  - content hash changes (truncated old/new)
  - permissions
  - owner/group
  - inode
  - file type
  - symlink target
  - capabilities
  - xattrs
  - security context
  - deleted/created markers
- Package attribution is now printed per change when available.

### Baseline Acceptance Workflow (`--accept`)

#### New deliberate baseline update flag
- Added `--accept` to `vigil check` in `src/cli.rs`.
- CLI parsing tests added for:
  - `vigil check --accept`
  - `vigil check --accept --full`

#### Safety rules for acceptance mode
- `--accept` is rejected with `--now` (live daemon trigger), because baseline updates require direct DB access.
- Acceptance is explicit and operator-driven; no hidden baseline mutation.

#### Acceptance execution semantics
- After displaying detected changes, `cmd_check()` can update baseline entries in place:
  - captures fresh snapshots for existing files
  - removes baseline entries for deleted files
  - records accepted updates with `BaselineSource::Manual`
  - prints accepted/failed counters and completion summary
- Audit semantics preserved: acceptance updates baseline state only; historical detection remains in the append-only audit trail.

### Doctor Output Redesign (`vigil doctor`)

#### Grouped diagnostics for operator scanning speed
- Reworked human output into named sections:
  - Runtime
  - Data
  - Configuration
  - Integrations
  - Verdict
- Added `print_check()` helper with widened alignment and fix-line formatting.

#### Config warning visibility improved
- When config check is warning-level, deep validation warnings are now inlined directly in doctor output.
- Removes the need for a second command to discover warning details.

#### Verdict grammar and messaging polished
- Updated `diagnostics_verdict()` in `src/doctor.rs` for singular/plural correctness.
- Added tests for:
  - singular warning text (`1 warning`)
  - singular failure text (`1 issue`)

### Daemon Status Redesign (`vigil status`)

#### Live status now surfaces full runtime metrics
- Live control-socket status output is now grouped by domain:
  - Daemon
  - Events
  - Integrity
  - Alerts
  - Database
  - Internal
- Surfaces all available `MetricsSnapshot` fields in human output, including cache/backpressure/baseline-update/panic counters.
- Includes PID when available from daemon probe.

#### Fallback status now mirrors grouped structure
- File-snapshot fallback output now uses the same high-level sectioned format.
- Explicitly labels data source as stale-capable snapshot.

### Additional Command Polish

#### `vigil audit`
- `audit show` now has structured header and severity markers.
- `audit verify` now has structured summary, break listing, and explicit integrity verdict messaging.

#### `vigil config validate`
- Human output now clearly separates validity confirmation and warning list with proper singular/plural wording.

#### `vigil setup hmac` and `vigil setup socket`
- Added clearer operator guidance, including permissions/ownership notes and restart instructions.

#### `vigil init` and `vigil update`
- `vigil init` now emits a scan progress hint before baseline build and prints a structured completion header.
- `vigil update` now emits a structured completion header and aligned summary lines.

### Compatibility and Behavior Guarantees
- `run_scan()` public signature unchanged; existing scheduler/control callers remain valid.
- JSON mode behavior preserved: no human headers/markers injected into machine output paths.
- Interactive progress/spinner remains TTY-gated to prevent control sequence leakage in piped/non-interactive usage.

### Validation
- `cargo check` clean
- `cargo clippy --all-targets -- -D warnings` clean
- `cargo fmt --all --check` clean
- `cargo test --all-targets` clean (including new CLI and doctor tests)
- `cargo build --features parallel` clean
- `cd fuzz && cargo check` clean

## [0.16.1] - 2026-04-06

### Release Summary
- Bugfix release: eliminates a false-positive warning from `vigil doctor` for the alert socket check, and fixes two unit tests that were environment-dependent.

### Doctor Diagnostics

#### Alert socket check no longer produces false warning when no listener is attached
- `check_signal_socket()` previously returned `CheckStatus::Warning` with detail "configured at <path> but not present" and a fix suggestion "Create or activate socket at <path>" when the alert socket path was configured but no listener process was bound to it.
- This was a false positive: the alert socket (`hooks.signal_socket`) is a client-connect sink -- Vigil connects to it when dispatching alerts. The socket file only exists on disk when an external listener (e.g. `socat UNIX-LISTEN:/run/vigil/alert.sock -`) is actively bound. When no listener is running, the socket file is absent, and this is normal, expected behavior.
- `SocketSink::dispatch()` in `src/alert/socket.rs` already handles this gracefully -- it logs at debug level and returns `Ok(())` when the connect fails. Alerts still reach all other configured sinks (journal, JSON log, D-Bus).
- Changed the "configured but absent" branch to return `CheckStatus::Unknown` with detail "configured (no listener attached)" and no fix suggestion (`fix: None`).
- Doctor output now shows `○ configured (no listener attached)` instead of `⚠ configured at /path but not present`, correctly signaling "informational / not applicable" rather than "something is broken."
- Aligns with **Principle II** (Silence Is the Default): a warning for normal operation is advisory noise. Aligns with **Principle X** (Fail Open, Fail Loud): this is not a failure -- there is no blind spot.
- File changed: `src/doctor.rs` (`check_signal_socket()`).

### Tests

#### Fixed environment-dependent permission-check tests
- `baseline_check_reports_permission_limited_access` and `database_and_audit_checks_report_permission_limited_access` were failing when a running Vigil daemon had written `/run/vigil/health.json`.
- Root cause: both tests used `default_config()` which sets `runtime_dir` to `/run/vigil`. When the test made DB files unreadable (`chmod 0o000`), the snapshot fallback path in `check_baseline()` / `check_database_integrity()` / `check_audit_log()` found the real daemon's health snapshot and returned `CheckStatus::Ok` instead of the expected `CheckStatus::Unknown`.
- Fixed by setting `cfg.daemon.runtime_dir` to an isolated temp subdirectory (`dir.path().join("run")`) in each test, ensuring no real snapshot file is discovered.
- File changed: `src/doctor.rs` (test module).

### Validation
- `cargo fmt --all --check` clean
- `cargo clippy --all-targets -- -D warnings` clean
- All 100 unit tests pass (`cargo test --all-targets`)
- `cargo build --features parallel` clean

## [0.16.0] - 2026-04-06

### Release Summary
- Full control socket implementation with on-demand scan triggering, Prometheus metrics export, and live CLI status queries.
- The daemon is now queryable and commandable over its Unix domain socket without restarting or reading stale files.
- CLI `vigil status` transparently queries the running daemon for live data, falling back to file-based status when the daemon is offline.
- CLI `vigil check --now` triggers a scan on the running daemon and streams back results, avoiding SQLite WAL lock contention.
- `vigil doctor` now includes a control socket health check in its diagnostic suite.

### Control Socket Enhancements

#### On-demand scan via control socket (`scan` method)
- Added `ScanRequest` and `ScanResponse` types to `src/control.rs` for structured scan triggering over the control socket.
- New `scan` method accepts optional `params.mode` (`"full"` or `"incremental"`, default incremental).
- Scan requests are dispatched through a bounded `crossbeam_channel` to the scan scheduler thread, which executes the scan and returns results synchronously.
- The control socket blocks up to 10 minutes waiting for scan completion (suitable for large baselines).
- Detected changes are fed into the alert pipeline identically to scheduled scans.
- Metrics (`changes_detected`, `scan_duration_ms`, `last_scan_total`) are updated after on-demand scans.
- Returns `{"ok": false, "error": "scan channel unavailable"}` when the scan channel is full or disconnected.
- Files changed: `src/control.rs`, `src/scan_scheduler.rs`, `src/lib.rs`.

#### Prometheus metrics export (`metrics_prometheus` method)
- Added `metrics_prometheus` control socket method that returns all daemon metrics in Prometheus text exposition format.
- Added `MetricsSnapshot::to_prometheus()` method with proper `# HELP`, `# TYPE counter`/`gauge` annotations for all 15 metric series.
- Metric names follow Prometheus naming conventions (`vigil_events_received_total`, `vigil_scan_duration_ms`, `vigil_uptime_start_timestamp`, etc.).
- Output is directly consumable by `node-exporter` textfile collector or any Prometheus-compatible scraper.
- Files changed: `src/metrics.rs`, `src/control.rs`.

#### Enriched `status` response format
- Status response now returns structured `daemon` object with `state`, `uptime_seconds`, and `version` fields.
- Metrics are returned as a flat object with named numeric fields instead of the raw `MetricsSnapshot` serialization.
- Files changed: `src/control.rs`.

#### Control socket dispatch refactoring
- Refactored `handle_connection` into a clean `dispatch()` function with per-method handler functions (`handle_status`, `handle_baseline_count`, `handle_reload`, `handle_scan`, `handle_metrics_prometheus`).
- Malformed JSON now returns `{"ok": false, "error": "invalid JSON"}` instead of propagating an error up the call stack.
- Accept loop sleep increased from 100ms to 200ms to reduce idle CPU usage.
- Files changed: `src/control.rs`.

### Scan Scheduler

#### On-demand scan support via trigger channel
- `scan_scheduler::spawn()` now accepts an additional `scan_trigger_rx: Receiver<ScanRequest>` parameter.
- On-demand scan requests are serviced at the top of each scheduler loop iteration via `try_recv()`, ensuring prompt execution even when the next cron tick is hours away.
- Scan results are returned through the request's one-shot response channel.
- Alert pipeline integration is identical to scheduled scans (changes dispatched, metrics updated).
- Files changed: `src/scan_scheduler.rs`, `src/lib.rs`.

### CLI Enhancements

#### Live `vigil status` via control socket
- `cmd_status()` now attempts a live `status` query over the control socket before falling back to file-based metrics.
- Live output displays daemon state, version, uptime, event counts, change counts, and last scan summary.
- Prints `source    live (control socket)` to distinguish live data from stale file reads.
- JSON format mode (`--format json`) returns the full live response when available.
- Added `query_control_socket()` helper function for CLI-to-daemon communication with 5-second timeout.
- Files changed: `src/main.rs`.

#### `vigil check --now` for daemon-triggered scans
- Added `--now` flag to the `Check` CLI command.
- When `--now` is specified, the scan is triggered on the running daemon via the control socket instead of opening the baseline DB directly.
- Uses a 10-minute read timeout to accommodate large baselines.
- Prints human-readable scan results (checked count, changes, errors, duration).
- Returns a clear error if the daemon is not running or the control socket is not configured.
- Files changed: `src/cli.rs`, `src/main.rs`.

### Doctor Diagnostics

#### Control socket health check
- Added `check_control_socket()` diagnostic to `vigil doctor`.
- Checks:
  - Whether `control_socket` is configured (reports `Unknown` / "not configured" if empty).
  - Whether the socket file exists (reports `Warning` with start-daemon fix if missing).
  - Whether the daemon responds to a quick `status` query (reports `Ok` if responsive, `Warning` with restart fix if not).
- Added `query_control_socket_quick()` internal helper with 2-second timeout.
- Diagnostic count increased from 11 to 12.
- Files changed: `src/doctor.rs`.

### Configuration
- Added `control_socket = "/run/vigil/control.sock"` to the default config TOML template.
- File changed: `config/vigil.toml`.

### Tests
- Control socket tests expanded to cover all 5 methods (`status`, `baseline_count`, `reload`, `metrics_prometheus`, `scan`), unknown method error, and malformed JSON handling.
- Added `dispatch_status_fields` unit test verifying the structured status response format.
- Added `prometheus_format_contains_expected_metrics` test verifying Prometheus output contains all expected metric names, correct TYPE annotations, and HELP lines.
- Diagnostic check count test updated from 11 to 12.
- Validation:
  - `cargo fmt --all --check` clean
  - `cargo clippy --all-targets -- -D warnings` clean
  - All integration tests pass
  - `cargo build --features parallel` clean

## [0.15.0] - 2026-04-06

### Release Summary
- Foundational scalability and stability release focused on long-term unattended operation.
- Baseline database schema moved from JSON blob columns to native typed columns, removing the steady-state serde tax from the hot path.
- Worker pipeline now includes per-thread LRU baseline caching and integrated runtime `EventFilter` debouncing.
- Fanotify mount handling now resolves real mount targets from `/proc/self/mountinfo` instead of marking `/` unconditionally.
- Added baseline write-back infrastructure for package-manager-originated updates (auto-rebaseline path).
- Added Unix domain control socket for live daemon introspection and operational commands.
- Added optional parallel scan implementation behind the existing `parallel` feature flag.
- Expanded resilience behavior around audit DB write failures and `/proc`-dependent hashing paths.

### Database & Migration

#### Baseline schema flattened to native columns
- Replaced baseline JSON blob storage (`identity_json`, `content_json`, `perms_json`, `security_json`) with native columns for frequently-read fields:
  - identity: `inode`, `device`, `file_type`, `symlink_target`
  - content: `hash`, `size`
  - permissions: `mode`, `owner_uid`, `owner_gid`, `capabilities`
  - security: `xattrs_json`, `security_context` (`xattrs_json` remains JSON due to dynamic keys)
- This removes repeated serialize/deserialize overhead for baseline reads/writes and enables direct SQL-native filtering over baseline fields.
- Files changed: `src/db/schema.rs`, `src/db/baseline_ops.rs`.

#### v1 -> v2 schema migration path
- Added explicit baseline migration logic that detects legacy v1 schema and performs an in-place upgrade:
  1. creates `baseline_v2`
  2. copies/expands v1 JSON rows into native columns
  3. swaps table names (`baseline_v2` -> `baseline`)
  4. records `schema_version=2` in `config_state`
- Added migration tests covering data preservation and no-op behavior for already-upgraded schemas.
- Files changed: `src/db/migrate.rs`, `src/db/mod.rs`, `tests/baseline_json_tests.rs`.

### Worker Hot Path Improvements

#### Per-worker baseline LRU cache
- Added per-worker in-memory LRU cache (`8192` entries) keyed by absolute path to reduce repeated SQLite lookups for hot files.
- Cache behavior:
  - read-through on miss
  - hit/miss metrics emitted
  - path invalidation on detected change
- Files changed: `Cargo.toml`, `src/worker.rs`, `src/metrics.rs`.

#### EventFilter integrated into runtime worker flow
- `EventFilter` was previously present but not active in the worker runtime pipeline.
- Workers now apply `should_process()` before expensive snapshot/hash work.
- Debounce pending paths are periodically drained and revisited.
- Debounce window is now configurable via `daemon.debounce_ms` (default `100`).
- Files changed: `src/worker.rs`, `src/filter/mod.rs`, `src/config/mod.rs`.

### Monitor, Mounts, and Event Throughput

#### Real fanotify mount-point resolution
- Replaced placeholder mount resolution logic with `/proc/self/mountinfo` parsing.
- Watch paths now map to the actual containing mount points, reducing event load from irrelevant mounts.
- Added startup logging of resolved mount points.
- Falls back to `[/]` when `mountinfo` is unreadable.
- Files changed: `src/monitor/fanotify.rs`.

#### Fanotify fixed-size read buffer
- Replaced heap `Vec<u8>` read buffer with fixed-size boxed array (`Box<[u8; 262144]>`) to reflect non-growing, long-lived allocation intent.
- File changed: `src/monitor/fanotify.rs`.

### Baseline Write-Back Channel

#### Package-update baseline update path
- Added `BaselineUpdate` and `UpdateReason` worker-to-writer message types.
- Added daemon baseline-writer thread with bounded channel and batched transaction writes.
- Baseline update metric counter added (`baseline_updates`).
- Write-back path is wired for package-update-originated changes and auto-rebaseline control flow.
- Files changed: `src/worker.rs`, `src/lib.rs`, `src/metrics.rs`.

### Resilience & Failure Modes

#### Audit DB failure tracking and recovery attempt
- Alert dispatcher now tracks consecutive audit write failures.
- After threshold (`3`) failures, daemon attempts to reopen and reinitialize audit DB connection pragmas.
- Preserves chain-hash safety: chain state is only advanced on successful writes.
- Files changed: `src/alert/mod.rs`.

#### `/proc` availability fallback in hashing path
- `blake3_hash_fd()` mmap path now checks `/proc/self/fd/<fd>` availability and falls back to buffered-reader hashing when unavailable.
- Improves behavior in constrained container/chroot environments where `/proc` may not be mounted.
- File changed: `src/hash.rs`.

### Control Plane & Introspection

#### New Unix control socket server
- Added `vigil-control` thread and `src/control.rs` module.
- Exposes one-request-per-connection JSON line protocol over Unix socket (default `/run/vigil/control.sock`, mode `0600`).
- Implemented methods:
  - `status`: daemon metrics snapshot + daemon state + uptime
  - `baseline_count`: current baseline row count
  - `reload`: triggers config reload flag
- Includes malformed JSON handling and robust accept/read/write error handling.
- Files changed: `src/control.rs`, `src/lib.rs`, `src/config/mod.rs`, `src/error.rs`.

### Scanner Parallelization

#### Parallel scan path behind feature gate
- Activated previously dormant `parallel` feature by adding `rayon`-based parallel scan routines behind `#[cfg(feature = "parallel")]`.
- Added config field `scanner.parallel` (ignored when feature is not compiled).
- Files changed: `src/scanner.rs`, `src/config/mod.rs`.

### Data Model & Allocation Optimization

#### Shared path ownership in pipeline
- Changed event/change path ownership from `PathBuf` to `Arc<PathBuf>` across hot event pipeline structures.
- Reduces path cloning and per-event allocation churn between monitor -> worker -> alert/audit paths.
- Files changed: `src/types/event.rs`, `src/types/change.rs`, plus pipeline call-sites and tests.

#### Supporting type defaults for new update flows
- Added default implementations for selected baseline component structs used in write-back/update paths.
- Files changed: `src/types/identity.rs`, `src/types/content.rs`, `src/types/permissions.rs`.

### Configuration & Metrics
- Added config fields:
  - `daemon.control_socket`
  - `daemon.debounce_ms`
  - `scanner.parallel`
- Added metrics:
  - `cache_hits`, `cache_misses`
  - `baseline_updates`
  - `backpressure_events`
- Files changed: `src/config/mod.rs`, `src/metrics.rs`.

### Dependencies
- Added `lru = "0.12"` for worker baseline cache.
- Enabled serde `rc` support (`features = ["derive", "rc"]`) for shared-ownership serialized fields.
- File changed: `Cargo.toml`.

### Tests & Validation
- Added/updated tests for:
  - baseline v1->v2 migration data preservation
  - baseline native-column round-trip behavior
  - worker and integration-path `Arc<PathBuf>` compatibility
  - control socket round-trip requests
  - updated baseline JSON compatibility/migration expectations
- Validation run highlights:
  - `cargo fmt --all --check` clean
  - `cargo clippy --all-targets --all-features -- -D warnings` clean
  - integration test suites pass
  - note: two pre-existing doctor permission-context test failures are unchanged from previous release baseline

## [0.14.0] - 2026-04-06

### Release Summary
- Major performance overhaul: Bloom filter fast-reject in the fanotify hot path, incremental scan mtime-skip, bulk package ownership cache, and streaming baseline iteration eliminate per-event BTreeMap lookups, redundant hashing, per-file subprocess forks, and full-table materialization respectively.
- Security and correctness fixes: HMAC audit entries now include content hashes, the alert cooldown timer no longer resets on suppressed events, and socket alert messages are newline-delimited for parseable NDJSON output.
- New CLI setup commands for HMAC key generation and socket configuration.
- Reduced wasteful polling across the scan scheduler, coordinator, and daemon main loop.

### Performance

#### BloomFilter fast-reject in fanotify event loop
- The `BloomFilter` (previously implemented but unused) is now integrated into the fanotify monitor's hot path.
- Before every `WatchGroupIndex::is_watched()` BTreeMap lookup, the Bloom filter is checked first. Paths that are *definitely not watched* are rejected immediately with a single BLAKE3 hash check, skipping the expensive BTreeMap traversal entirely.
- The Bloom filter is rebuilt automatically when watch paths change via the reconfiguration channel.
- Files changed: `src/monitor/fanotify.rs`, `src/monitor/mod.rs`.

#### Incremental scan now skips hashing for unchanged files
- `FileSnapshot::from_fd()` previously always computed a full BLAKE3 hash regardless of the `force_hash` flag.
- `CaptureOpts` now carries optional `baseline_mtime` and `baseline_hash` fields. When `force_hash` is false and the file's current mtime matches the baseline, the stored hash is reused -- eliminating redundant I/O and computation for unchanged files.
- Files changed: `src/types/snapshot.rs`, `src/scanner.rs`, `src/worker.rs`.

#### Bulk package ownership cache
- `build_initial_baseline()` previously spawned a subprocess (`pacman -Qo` / `dpkg -S` / `rpm -qf`) for every single file -- up to 59,000+ fork+exec calls.
- A new `build_package_cache()` function runs a single bulk command per package manager:
  - **Pacman**: `pacman -Ql` (one process, full file→package map)
  - **Dpkg**: Parses `/var/lib/dpkg/info/*.list` files directly (zero subprocesses)
  - **RPM**: `rpm -qa --filesbypkg` (one process)
- The baseline init loop now performs HashMap lookups instead of subprocess calls.
- The per-file `query_package_owner()` remains available for single-file lookups elsewhere.
- Files changed: `src/package.rs`, `src/scanner.rs`.

#### Streaming baseline row iteration
- `run_scan()` previously called `baseline_ops::get_all()` which loaded all entries (with 4 JSON deserializations each) into a `Vec` before processing.
- A new `baseline_ops::for_each_entry()` streams rows directly from the SQLite cursor via a callback, avoiding full materialization.
- Files changed: `src/db/baseline_ops.rs`, `src/scanner.rs`.

### Reduced Polling

#### Scan scheduler: channel-based wait
- Replaced the per-second `sleep(1)` loop (up to 25,200 iterations for a 7-hour wait) with a single `crossbeam_channel::recv_timeout()` on a shutdown channel.
- The daemon now sends on the shutdown channel so the scheduler wakes immediately on SIGTERM/SIGINT instead of potentially sleeping up to 1 second.
- Files changed: `src/scan_scheduler.rs`, `src/lib.rs`.

#### Coordinator and daemon main loop
- Coordinator housekeeping sleep increased from 250ms to 1000ms (it only needs per-minute precision).
- Daemon main loop sleep increased from 250ms to 1000ms.
- Files changed: `src/coordinator.rs`, `src/lib.rs`.

### Security & Correctness

#### HMAC now includes content hashes
- The HMAC computation for audit entries previously passed `None` for both `old_hash` and `new_hash`, weakening the tamper-evidence guarantee.
- Now extracts the actual hashes from the first `Change::ContentModified` variant (when present) and includes them in the HMAC data.
- File changed: `src/alert/mod.rs`.

#### Alert cooldown timer reset bug fixed
- `is_suppressed()` previously called `cooldowns.insert(path, now)` *before* checking if the cooldown had elapsed, resetting the timer on every suppressed event. Under sustained modifications this could suppress alerts indefinitely.
- The timestamp is now updated only when the alert is *not* suppressed.
- File changed: `src/alert/mod.rs`.

#### Global rate limit now configurable
- The hardcoded `10,000` alerts-per-minute cap is now controlled by `alerts.max_alerts_per_minute` in the config (default: `10,000`).
- Files changed: `src/alert/mod.rs`, `src/config/mod.rs`.

#### Removed unnecessary `unsafe impl Send/Sync` on BloomFilter
- `BloomFilter` contains only `Vec<u8>`, `usize`, and `u32` -- all inherently `Send + Sync`. The manual unsafe impls were unnecessary and would mask safety issues if the struct ever gained a non-Sync field.
- File changed: `src/bloom.rs`.

#### Socket message framing (NDJSON)
- The socket alert sink previously wrote raw JSON with no delimiter, making back-to-back messages unparseable.
- Each JSON payload now has a trailing newline (`\n`), matching the JSON log sink's NDJSON format.
- File changed: `src/alert/socket.rs`.

### Added

#### `vigil setup hmac` command
- Generates a 32-byte cryptographic key from `/dev/urandom`, hex-encodes it, and writes it to the specified path (default: `/etc/vigil/hmac.key`).
- Sets file permissions to `0400` and ownership to `root:root`.
- Updates the config TOML to set `hmac_signing = true` and `hmac_key_path`.
- Requires root; prints a clear error otherwise.
- Prompts before overwriting an existing key file unless `--force` is passed.
- Files changed: `src/cli.rs`, `src/main.rs`.

#### `vigil setup socket` command
- Configures the alert socket path in the config TOML (default: `/run/vigil/alert.sock`).
- Creates the parent directory if it doesn't exist.
- `--disable` flag clears the socket path in the config.
- Prints a `socat` usage example for consuming alerts.
- Files changed: `src/cli.rs`, `src/main.rs`.

### Minor

#### fanotify metadata alignment safety
- Replaced the pointer cast `&*(buf.as_ptr().add(offset) as *const FanotifyEventMetadata)` with `std::ptr::read_unaligned()` for portability on platforms where buffer offsets may not be aligned.
- File changed: `src/monitor/fanotify.rs`.

#### fanotify fd lifecycle refactor
- The event loop previously had 3 separate `unsafe { libc::close(event.fd) }` branches for unwatched/unrecognized events, risking fd leaks if a new branch were added without a close call.
- Introduced an `EventFdGuard` RAII wrapper that closes the fd on drop unless ownership is explicitly transferred via `take()`.
- File changed: `src/monitor/fanotify.rs`.

#### README version badge
- Updated from `0.9.0` to match the current release.
- File changed: `README.md`.

### Dependencies
- Added `toml_edit = "0.22"` as a direct dependency for config file updates in setup commands (was already a transitive dependency via `toml`).

### Tests
- Added 13 new tests:
  - Cooldown timer fix: suppressed events don't reset the cooldown timestamp.
  - Configurable rate limit: alerts beyond the configured limit are suppressed.
  - HMAC content hash inclusion: audit entries include content hashes when present.
  - Socket NDJSON framing: messages end with a newline delimiter and remain valid JSON.
  - Incremental mtime skip: unchanged files reuse baseline hash; changed files recompute.
  - Package cache parsing: pacman `-Ql` and rpm `--filesbypkg` output parsed correctly; directory entries skipped.
  - Streaming baseline iteration: `for_each_entry()` visits all rows in order.
  - Bloom filter fast-reject: unwatched paths rejected, watched prefixes pass.
  - CLI setup parsing: `vigil setup hmac` and `vigil setup socket` with all flag combinations.
- All 93 unit tests and 10 integration tests pass (2 pre-existing doctor test failures unchanged).

## [0.13.2] - 2026-04-05

### Release Summary
- Fixes a post-update diagnostics timing gap where runtime snapshots could be unavailable during the first minute after daemon restart.

### Fixed
- Coordinator housekeeping now performs its first runtime snapshot tick immediately at daemon startup.
- This removes the initial 60-second window where `vigil doctor`/`vigil status` could still show reduced visibility right after `vigil update` restarts `vigild`.

## [0.13.1] - 2026-04-05

### Release Summary
- Hardens diagnostics and status flows for real-world root-owned service deployments where unprivileged users cannot directly read SQLite baseline/audit databases.
- Adds a structured daemon-authored health snapshot channel so non-root CLI invocations can report meaningful health context without weakening database permissions.
- Preserves strict operator guidance for full-integrity workflows by explicitly separating reduced-coverage snapshot reads from privileged on-disk verification.

### Problem Context
- In default systemd deployments, Vigil databases are root-owned (`0600`) for security.
- When `vigil doctor` and `vigil status` run as an unprivileged user, direct DB opens can fail even though the daemon and data are healthy.
- Prior behavior could degrade into confusing visibility gaps (`unknown`) or suggest unrelated baseline recovery actions.

### Fixed
- `vigil doctor` now treats root-owned database visibility limits as an operator-context issue (reported as `Unknown` with `sudo vigil doctor` guidance) instead of misleading baseline corruption/init failures when run as an unprivileged user.
- Aligned audit diagnostics with the same permission-aware behavior for consistency across baseline, database integrity, and audit checks.
- Added daemon-authored runtime health snapshots (`/run/vigil/health.json`) so unprivileged `vigil doctor` and `vigil status` can fall back to fresh privileged baseline/database visibility data instead of dropping to `unknown` for baseline counts.
- Added reduced-coverage snapshot-based fallback messaging for database/audit checks when direct integrity verification is unavailable without elevated privileges.

### Changed
- `vigil status` now uses baseline count fallback logic that prefers direct DB access and safely falls back to fresh daemon snapshot data when needed.
- `vigil status --format json` now includes a `health` object containing the runtime health snapshot (when present) for automation and debugging.
- Coordinator heartbeat now writes health snapshots alongside `metrics.json` and `state.json` in the runtime directory.
- `vigil update` post-upgrade summary now uses the same resilient baseline-count fallback path.

### Reliability Design Notes
- Snapshot freshness is bounded (`5m` max age) to avoid reporting stale daemon state as authoritative.
- If no fresh snapshot is available, doctor/status safely revert to explicit reduced-coverage guidance rather than fabricating health assertions.
- Snapshot production is best-effort and non-fatal; daemon operation is not interrupted if snapshot writes fail.

### Tests
- Added regression tests for permission-limited doctor paths (baseline, database integrity, and audit checks).
- Added regression coverage for fresh runtime health snapshot fallback behavior.
- Added regression coverage that stale snapshots are rejected and do not mask permission-limited direct checks.

## [0.13.0] - 2026-04-05

### Release Summary
- Overhauls Vigil's end-to-end operator experience from first install through long-term upgrades and diagnostics.
- Introduces one-command setup/uninstall workflows, first-class upgrade orchestration, and comprehensive health diagnostics with actionable remediation hints.
- Improves baseline reliability by adding daemon startup self-healing for missing, empty, or corrupt baseline databases.

### Compatibility and Behavioral Notes
- `vigil init` now prompts before reinitializing a non-empty baseline unless `--force` is provided.
- `vigil status` default human output is now a concise operational pulse (instead of raw JSON dumps).
  - Automation should use `vigil status --format json` for structured machine-readable output.
- New command surfaces were added:
  - `vigil doctor`
  - `vigil update [--repo <path>]`

### Added

#### 1) One-command installer workflow (`setup.sh`)
- Added root-level `setup.sh` with three operational modes:
  - install (default)
  - `--check` dry-run (no changes)
  - `--uninstall` with optional `--purge`
- Install mode now handles:
  - distro-aware dependency detection/install prompts (pacman/apt/dnf)
  - release build and binary verification
  - binary install + compatibility symlinks
  - non-destructive config install
  - runtime directory provisioning
  - systemd unit deployment and enablement
  - package manager hook deployment
  - mandatory baseline initialization
  - final diagnostics via `vigil doctor`
- Uninstall mode now handles:
  - service disable/stop
  - unit/binary/hook removal
  - optional full data purge (`/var/lib/vigil`, `/var/log/vigil`, `/run/vigil`, `/etc/vigil`)

#### 2) Dedicated diagnostics engine (`src/doctor.rs`)
- Added new diagnostics module and command output model:
  - `DiagnosticCheck { name, status, detail, fix }`
  - `CheckStatus::{Ok, Warning, Failed, Unknown}`
- Added broad system-health coverage checks for:
  - daemon runtime state
  - monitor backend mode
  - baseline presence/age/count
  - baseline/audit DB integrity
  - audit chain state
  - config validation/deep validation
  - scan timer presence/activity/next run
  - HMAC key posture (when enabled)
  - package manager hook installation
  - desktop notification availability
  - optional signal socket configuration
- Added explicit verdict synthesis and command exit codes:
  - `0` all checks OK
  - `1` warnings present, no failures
  - `2` one or more failures

#### 3) Offline local-repo update command (`vigil update`)
- Added `vigil update` command with optional `--repo` source path.
- Added repository guardrails to prevent accidental updates from non-Vigil directories.
- Update flow now performs:
  - local `cargo build --release`
  - installed/new version comparison
  - idempotent early exit on no-op upgrades
  - daemon stop/start around binary replacement
  - selective systemd unit replacement only when content changes
  - selective hook replacement only when content changes
  - post-update doctor run and concise summary output
- The update path remains strictly local/offline and does not perform network I/O.

### Changed

#### 4) CLI wiring and command surface (`src/cli.rs`, `src/main.rs`)
- Added `Doctor` and `Update` command variants to the CLI.
- Added `force: bool` to `Init` command.
- Updated command dispatch to support doctor exit-code passthrough semantics.
- Reduced default CLI tracing noise (`warn` default) for cleaner operator output.

#### 5) `vigil status` UX redesign (`src/main.rs`, `src/doctor.rs` helpers)
- Replaced raw-state/raw-metrics human output with concise operational status lines:
  - daemon running/offline signal
  - backend mode
  - baseline entry count
  - recent change count window
  - last scan timestamp summary
- Kept and enhanced structured JSON output for automation by including derived status fields alongside state/metrics snapshots.

#### 6) Rich grouped baseline init output (`src/scanner.rs`, `src/main.rs`)
- Refactored baseline initialization return model to provide structured init telemetry:
  - `BaselineInitResult`
  - `GroupInitResult`
- `vigil init` now reports per-group path coverage, per-group file counts, total duration, and baseline DB size.
- Baseline refresh timestamp is now persisted in config-state metadata during initialization.

### Reliability and Self-Healing

#### 7) Daemon baseline self-healing on startup (`src/lib.rs`)
- Added startup health guard for baseline state before normal daemon operation.
- New behavior:
  - if baseline DB is missing: auto-initialize from configured watch paths
  - if baseline DB integrity fails: back up corrupt DB (`.corrupt.<timestamp>`), remove, and reinitialize
  - if baseline DB is present but empty: repopulate baseline
- Added explicit logging and best-effort desktop notifications for auto-initialization/recovery events.

### Tests and Validation
- Added CLI parsing tests for:
  - `vigil init --force`
  - `vigil doctor --format json`
  - `vigil update --repo ...`
- Added `main.rs` unit coverage for:
  - update repo validation
  - version normalization behavior
- Updated daemon smoke test to validate baseline auto-initialization behavior.
- Verified quality gates for this release state:
  - `cargo check`
  - `cargo test --all-targets`
  - `bash -n setup.sh`

## [0.12.1] - 2026-04-05

### Release Summary
- Fixes an operator-facing upgrade blocker where `vigil init` could appear to hang indefinitely at `Initializing baseline...` on large or loop-prone trees.
- Improves baseline initialization reliability and throughput for clean-install rebuild workflows.

### Fixed
- Reworked baseline initialization traversal to stream files directly instead of recursively collecting all paths first.
- Added safe handling for symlinked directories during baseline walks to avoid recursive loop traps.
- Added periodic baseline init progress logging (`processed_files`/`inserted_entries`) so long runs are observable.
- Wrapped baseline insert/update work in a single transaction for better performance and atomicity.

### Operational
- Added optional `VIGIL_SKIP_PACKAGE_OWNER=1` mode for baseline init to bypass per-file package manager ownership lookups during migration/reset flows where package attribution is not required.

## [0.12.0] - 2026-04-05

### Release Summary
- Delivers the security-audit remediation batch and unblocks CI coverage by isolating a ptrace-incompatible integration test from tarpaulin instrumentation.
- Resolves critical correctness gaps in HMAC signing, event-debounce memory management, and file descriptor ownership under panic scenarios.
- Improves database pragma consistency, config type safety, scan observability metrics, and integration test depth for edge conditions.

### Compatibility and Breaking Notes
- `compute_hmac()` now returns `Result<String>` instead of `String`. Callers must handle initialization errors explicitly.
- Several config fields are now strongly typed enums instead of stringly typed values:
  - `daemon.log_level`
  - `daemon.log_format`
  - `scanner.hash_algorithm`
  - `database.sync_mode`
  - `alerts.remote_syslog.protocol`
  - `alerts.remote_syslog.facility`
- Existing TOML values remain the same lowercase literals; invalid values are now rejected by deserialization before runtime validation.

### CI and Coverage Stability
- Fixed tarpaulin coverage segfault path by skipping `daemon_start_and_shutdown_smoke_test` only when `cfg(tarpaulin)` is active.
- Added `check-cfg` metadata for `tarpaulin` in `Cargo.toml` to keep `unexpected_cfgs` lint noise out of test builds.

### Critical Security and Correctness Fixes

#### 1) HMAC compute path fails closed
- Changed `src/hmac.rs` `compute_hmac()` to return `Result<String>` and propagate `HmacVerification` errors.
- Removed silent empty-string fallback that could previously produce blank HMAC audit fields.
- Updated all affected call sites (including audit entry writing and baseline HMAC computation) to propagate failures correctly.

#### 2) Event debounce map no longer grows unbounded
- Added periodic internal pruning to `EventFilter` with:
  - `last_prune: Instant`
  - `PRUNE_INTERVAL` cadence
  - automatic stale-entry cleanup from `should_process()`
- Prevents long-lived daemons from accumulating stale per-path debounce state indefinitely.

#### 3) Worker fd duplication is panic-safe
- Extracted a tight `dup_to_file()` helper to combine `dup()` and `File::from_raw_fd()` ownership transfer.
- Eliminates leak window where a panic between raw fd duplication and RAII wrapping could leave descriptors unowned.

### Medium-Severity Hardening and Refactors

#### 4) Unified SQLite pragma application
- Added `PragmaOpts` + `apply_pragmas()` in `src/db/mod.rs`.
- Refactored all major connection setup paths to use one canonical pragma function:
  - `open_baseline_db_readonly`
  - `open_db_internal`
  - `open_db_at_with_options`
  - `configure_connection`
  - alert audit connection initialization

#### 5) Strongly typed configuration enums
- Replaced six runtime-validated string fields with serde enums and `rename_all = "lowercase"`.
- Removed redundant string-based runtime validation branches from `validate_config()`.
- Updated downstream consumers (notably remote syslog protocol/facility handling and DB sync pragma mapping).

#### 6) Added edge-case integration coverage
- Added integration tests for:
  - tampered audit chain hash detection
  - self-path exclusion (baseline/audit DB + alert log)
  - graceful scan behavior when baselined files are deleted before scan

#### 7) Added scan duration and volume metrics
- Added `scan_duration_ms` and `last_scan_total` atomics to `Metrics` and `MetricsSnapshot`.
- Added scan timing capture in `run_scan()` and persisted latest values from scheduler execution.

### Low-Severity Items
- Verified exclusion filter path matching already avoids unnecessary `to_string()` allocation in `is_excluded()` call flow.
- Updated RLIMIT logic to read current limits first and prefer safe soft-limit raising:
  - `rlim_cur = min(target, current.rlim_max)`
  - only attempts hard-limit raise when target exceeds existing hard limit
  - fallback path logs and degrades safely when privilege elevation is unavailable

### Tests and Verification
- Added/updated unit and integration tests for all major fixes, including:
  - HMAC error-propagation behavior
  - periodic debounce pruning
  - fd duplication validity
  - pragma application expectations
  - enum deserialization failures
  - audit tamper detection and deleted-file scan handling
- Quality gates pass for this release state:
  - `cargo fmt --all --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets`

## [0.11.0] - 2026-04-05

### Release Summary
- Delivers a full post-rewrite architecture update across the domain model, daemon runtime pipeline, database layout, monitoring path, and alert dispatch layer.
- Replaces older flat data structures with composable typed snapshots and change variants.
- Finalized with a repository-wide verification pass: build, feature build, tests, clippy, and fuzz target compilation all pass.

### Compatibility Notes
- This release is a pre-1.0 MINOR bump. As documented in VERSIONING.md, compatibility may change across 0.y releases.
- Runtime and operational behavior is intentionally improved and more explicit, especially around event handling, scheduled scans, and alert dispatching.
- Existing baseline and audit stores remain migration-safe through additive schema evolution and startup migration hooks.

### Architecture
- Introduced a structured daemon runtime with a first-class `Daemon` type and lifecycle methods (`from_config`, `run`).
- Implemented a lock-free runtime config model based on `Arc<ArcSwap<Config>>` for low-contention reads in hot paths.
- Split event processing into bounded stages:
  - monitor -> coordinator queue
  - coordinator -> worker queue
  - worker -> alert dispatcher queue
- Added dedicated background components for housekeeping and scheduled scan execution.

### Type System and Data Model
- Replaced parallel old/new flat comparison fields with `Vec<Change>` based classification.
- Expanded `Change` into explicit variants for content, permissions, ownership, inode, type, symlink target, capabilities, xattrs, security context, created, and deleted outcomes.
- Reworked baseline and snapshot representations into composed sub-structures:
  - `FileIdentity`
  - `ContentFingerprint`
  - `PermissionState`
  - `SecurityState`
- Standardized file capture and comparison through `FileSnapshot` with `from_fd`, `from_path`, and `diff` methods.
- Added `FsEvent` support for open-fd transfer (`event_fd`) and process attribution (`pid`, `exe`).

### Database and Integrity
- Formalized dual-database operation:
  - `baseline.db` optimized for read-heavy baseline lookups.
  - `audit.db` configured for durability-focused append semantics.
- Stored baseline sub-structures as JSON columns to reduce schema churn and simplify forward compatibility.
- Added and enforced tamper-evident `chain_hash` storage in `audit_log` entries.
- Added chain verification support and CLI access through audit verification flows.
- Increased statement caching and prepared-statement reuse in hot paths.

### Monitoring, TOCTOU, and Security
- Added fd-first capture flow so workers can process fanotify events using the same open descriptor where available.
- Consolidated metadata and content collection so identity, hash, xattrs, and security context are captured consistently.
- Kept hardening protections active at daemon startup, including no-new-privs and non-dumpable process mode.
- Preserved and expanded HMAC-based integrity tooling for baseline verification workflows.

### Alerting and Outputs
- Migrated alert outputs to sink-based polymorphism through an `AlertSink` interface.
- Added/maintained sink implementations for journal, JSON log, desktop notifications, socket, and remote syslog.
- Isolated alert emission on its own bounded dispatch thread to decouple worker throughput from output latency.

### Performance and Scalability
- Added mmap-aware BLAKE3 hashing for large files with high-capacity buffered fallback for smaller files.
- Switched exclusion matching to compiled `globset` rules for efficient repeated matching.
- Added Bloom-filter fast reject support for watch path prefiltering.
- Continued bounded-channel backpressure behavior to prevent unbounded memory growth during spikes.

### Test and Quality Verification
- Integration coverage includes:
  - audit chain break detection
  - baseline JSON compatibility
  - snapshot diff behavior across multiple change dimensions
  - exclusion filter correctness
  - worker event processing
  - daemon smoke behavior
  - alert dispatcher chain integration
- Validation results for this release:
  - `cargo build` passed
  - `cargo build --features parallel` passed
  - `cargo test --all-targets` passed
  - `cargo clippy --all-targets -- -D warnings` passed
  - `cd fuzz && cargo build` passed

### Packaging and Operations
- Updated the primary systemd unit to `Type=notify` to align with daemon `sd_notify` readiness/watchdog lifecycle events.
- Kept watchdog, restart policy, and hardening directives aligned with runtime behavior.

### Cleanup
- Consolidated legacy module layout into the new split `types`, `config`, `db`, and runtime orchestration modules.
- Replaced older integration test tree layout with direct test targets matching the rewritten architecture.

## [0.10.0] - 2026-04-05

### Release Summary
- Delivers Vigil Phase 2 security and operational hardening across anti-tamper controls, process hardening, observability, attribution, schema evolution, and alert routing.
- Keeps backward compatibility through additive SQLite migrations and defaulted config fields.
- Introduces new modules for remote syslog forwarding and Bloom-filter-based path rejection groundwork.

### Added

#### Anti-Tamper and Integrity
- Added tamper-evident audit chaining for `audit_log` entries:
  - New `chain_hash` column with migration support.
  - Chain hash computation at insert time using BLAKE3 over previous hash plus canonical event fields.
  - Chain verification utility in `db::ops::verify_audit_chain()`.
  - `vigil log verify` now reports HMAC validity and chain continuity/break points.
- Added baseline database at-rest integrity HMAC support:
  - `db::ops::compute_baseline_hmac()` computes canonical baseline HMAC.
  - Baseline init/refresh paths update `config_state.database_hmac`.
  - Daemon startup verifies baseline HMAC when HMAC signing is enabled.
  - `vigil doctor` reports baseline HMAC validity/mismatch.

#### Process Hardening and Service Supervision
- Added Linux process hardening at daemon startup:
  - `prctl(PR_SET_DUMPABLE, 0)`.
  - `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
- Added systemd notification lifecycle integration via `sd-notify`:
  - READY notification on successful daemon startup.
  - WATCHDOG and STATUS notifications during housekeeping.
  - STOPPING notification on shutdown.
- Added deployable service unit at `contrib/vigild.service` with `Type=notify`, watchdog settings, capability bounds, and filesystem protections.

#### Configuration and CLI
- Added config schema versioning (`config_version`) with migration handling (`v1 -> v2` in-memory migration).
- Added config fields:
  - `scanner.mmap_threshold`
  - `scanner.scheduled_mode`
  - `daemon.log_format`
  - `daemon.runtime_dir`
  - `alerts.remote_syslog.*`
- Added CLI config actions:
  - `vigil config dump`
  - `vigil config migrate`

#### Alert Routing and Telemetry
- Added remote syslog sender module (`src/alert/remote_syslog.rs`) with RFC 5424 formatting and UDP/TCP transport.
- Extended `AlertEngine` to optionally dispatch alerts to remote syslog with fail-open behavior.
- Added `VigilError::Syslog` variant for syslog-specific error surfacing.

#### New Modules and Tests
- Added Bloom filter module (`src/bloom.rs`) with insertion/membership logic and probabilistic behavior tests.
- Added integration audit-chain tests (`tests/integration/audit_chain_tests.rs`) covering:
  - Valid chain traversal.
  - Mid-log deletion break detection.
  - Tampered row mismatch detection.

### Changed

#### Logging Stack Migration
- Replaced `env_logger` initialization paths with `tracing-subscriber` setup.
- Added `tracing-log` bridge so existing `log::*` call sites continue to emit without mass call-site rewrites.

#### Hashing and Performance Plumbing
- Enabled `blake3` `mmap` feature in dependencies.
- Added `blake3_hash_file_with_threshold()` helper:
  - Supports mmap hashing path for large files.
  - Uses 128KB buffered read path for non-mmap hashing.

#### SQLite Access Patterns
- Expanded prepared statement caching usage (`prepare_cached`) for additional baseline/audit operations.
- Replaced dynamic `search_audit()` SQL assembly with four pre-defined cached statement variants.

#### Domain Model Expansion
- Extended baseline/file metadata model with:
  - `file_type`
  - `symlink_target`
  - `capabilities`
- Extended event/change/audit model with process attribution:
  - `responsible_pid`
  - `responsible_exe`
- Added new change types:
  - `TypeChanged`
  - `SymlinkTargetChanged`
  - `CapabilitiesChanged`

#### Monitor Attribution
- Fanotify events now attempt best-effort process attribution via `/proc/<pid>/exe`.
- Self-generated fanotify events are filtered (`pid == current process id`).
- Inotify events explicitly set attribution fields to `None`.

### Database and Config Migration Notes
- `schema::create_tables()` now calls `schema::migrate_tables()` to apply additive column migrations safely.
- Existing databases remain readable/writable; new columns are optional/additive.
- Existing configs without `config_version` are treated as v1 and migrated in-memory to v2 defaults.

### Validation
- `cargo build --all-targets`
- `cargo build --all-targets --features parallel`
- `cargo test --all-targets`

## [0.9.0] - 2026-04-05

### Release Summary
- Promotes Vigil from MVP-era behavior to production-grade daemon hardening across concurrency, durability, monitoring, and operational safety.
- Delivers a full 15-item production hardening scope with no intentional CLI breaking changes.
- Preserves backward compatibility for existing baseline/audit databases and default configurations through additive, defaulted config fields.

### Compatibility Notes
- No breaking CLI command removals or flag renames.
- No required SQLite schema migration for existing deployments.
- Existing watch groups remain valid; dynamic watch updates now apply on SIGHUP.
- New daemon/database/alert config knobs are additive and have safe defaults.

### Production Hardening Delivery (Items 1-15)

#### 1) Multi-threaded daemon worker pool (`src/lib.rs`, `src/config.rs`)
- Replaced single-thread event processing with coordinator + worker pool architecture.
- Added `daemon.worker_threads` (default `2`, validated range `1..=16`).
- Coordinator thread performs filtering/debounce and forwards accepted events to a bounded internal worker queue.
- Worker threads are named (`vigil-worker-0`, `vigil-worker-1`, ...) and joined cleanly on shutdown.
- Panic isolation and accounting were added with shared `panic_count` tracking.

#### 2) Timeout-based monitor channel sends with drop accounting (`src/monitor/fanotify.rs`, `src/monitor/inotify.rs`, `src/lib.rs`)
- Replaced non-blocking `try_send` patterns with `send_timeout(Duration::from_secs(1))` to apply bounded backpressure.
- Added explicit dropped-event accounting and ERROR-level logging when monitor->daemon queues saturate.
- Increased monitor->coordinator channel capacity to `8192` and worker channel to `2048`.
- Added dropped-event housekeeping checks and recovery scan scheduling logic.

#### 3) O(log n) watched-path lookup in hot paths (`src/watch_index.rs`, `src/monitor/fanotify.rs`)
- Introduced `WatchGroupIndex` B-tree backed prefix lookup for efficient watch-group classification.
- Replaced O(n) linear path-prefix scans with indexed lookups in fanotify processing.
- Added index update and watched-path helper methods to support runtime reuse.

#### 4) Hot-reload watch paths on SIGHUP (`src/lib.rs`, `src/monitor/mod.rs`, `src/monitor/fanotify.rs`, `src/monitor/inotify.rs`)
- Added monitor reconfiguration channel plumbing via `MonitorHandle`.
- SIGHUP now deep-validates and applies watch updates dynamically without daemon restart.
- Fanotify marks are added/removed by mount diffing; inotify watches are rebuilt for the updated path set.
- Shared watch index is guarded with `Arc<RwLock<...>>` and updated atomically during reload.

#### 5) Transaction batching for baseline and daemon writes (`src/baseline/mod.rs`, `src/db/ops.rs`, `src/lib.rs`)
- Wrapped baseline init/refresh loops in explicit transactions with periodic commits every ~1000 entries.
- Added rollback-safe transaction guard behavior for scan failures.
- Added `batch_upsert_baseline()` for grouped baseline writes.
- Daemon worker-side change dispatch now flushes in batches with transaction boundaries.

#### 6) Configurable SQLite synchronous mode (`src/config.rs`, `src/db/mod.rs`)
- Added `database.sync_mode` config field (default `normal`).
- Validation accepts `off|normal|full|extra` (case-insensitive).
- Connection setup now respects configured sync mode instead of hardcoded synchronous behavior.

#### 7) SQLite busy timeout controls (`src/config.rs`, `src/db/mod.rs`)
- Added `database.busy_timeout_ms` config field (default `5000`).
- Applied busy timeout pragma in daemon and CLI connection open paths.
- Reduced lock-contention stalls and improved multi-process DB ergonomics.

#### 8) New-file alerting in daemon event path (`src/lib.rs`, `src/types.rs`)
- Added explicit create/move-in branch for baseline-missing files under watched paths.
- New files are hashed/metadata-enriched and emitted as `ChangeType::Created`.
- Group/severity is resolved through watch index; out-of-scope mount noise is skipped.
- Added race-safe handling for files deleted between event receipt and metadata collection.

#### 9) Explicit deletion alerting (`src/lib.rs`, `src/compare.rs`)
- Added direct handling for `Delete` and `MovedFrom` events.
- Deletion results preserve baseline `old_*` metadata/package fields for high-fidelity alerts.
- Existing compare-layer deleted outcome remains wired and functional for event paths.

#### 10) Rate-limited desktop notification delivery (`src/alert/dbus.rs`, `src/alert/mod.rs`)
- Added desktop notification rate-window controls and burst batching summaries.
- Added in-flight notify-send cap to prevent process storms under event floods.
- Added dedicated child reaper thread to prevent zombie accumulation.
- Excess notifications are dropped with diagnostics instead of unbounded queuing.

#### 11) Graceful degraded mode on disk-full (`src/lib.rs`, `src/types.rs`)
- Added daemon health state model (`Healthy`, `Degraded { reason, since }`).
- Detects disk-full write paths (`ENOSPC`, `SQLITE_FULL`) and transitions to degraded mode.
- Keeps monitoring active while queuing pending DB writes in bounded memory.
- Housekeeping attempts recovery and flushes queued writes when storage health returns.

#### 12) Metrics and observability counters (`src/metrics.rs`, `src/lib.rs`, monitor/filter integration)
- Added daemon-wide `Metrics` counters for event flow, hashing, alerts, DB writes/errors, and panic capture.
- Counters are shared through `Arc<Metrics>` and incremented at monitor, filter, coordinator, and worker stages.
- Added runtime snapshot export (`/run/vigil/metrics.json`) with startup uptime timestamp.

#### 13) Self-protection integrity monitoring (`src/lib.rs`)
- Added startup hashing of daemon binary via `/proc/self/exe`.
- Added periodic self-hash verification in housekeeping with critical alerting on mismatch.
- Added periodic integrity checks for HMAC key and config file when enabled by security settings.
- Self-protection alerts do not terminate daemon monitoring loops.

#### 14) Deep config validation before SIGHUP apply (`src/config.rs`, `src/lib.rs`, `src/cli.rs`)
- Added `validate_config_deep()` for writable path checks, watch path resolution, and HMAC key loadability.
- Reload path now validates before mutating active config state; failed reload keeps prior config live.
- Non-fatal warnings are surfaced without blocking apply.
- Added `vigil config check` command for explicit operator validation.

#### 15) Signal socket access control hardening (`src/alert/socket.rs`)
- Enforced owner-only socket file permissions (`0600`) after bind.
- Added peer credential verification with `SO_PEERCRED` and strict UID allow-listing (root + daemon owner).
- Added connection cap and write-timeout behavior to prevent daemon blocking on slow clients.
- Slow/failing clients are disconnected proactively.

### Additional Notable Changes
- Added `pub mod metrics;` and integrated metrics in daemon/control paths.
- Expanded config diff/reload behavior and dynamic monitor update hooks.
- Added/updated tests around daemon behavior, fixtures, and integration pathways for hardening logic.

### Validation
- `cargo build` passes.
- `cargo test --all-targets -- --test-threads=4` passes.

## [0.8.0] - 2026-04-05

### Release Summary
- Resolves all 17 findings from the critical structural audit in one coordinated release.
- Closes a high-impact file-integrity bypass in the real-time compare path and multiple reliability gaps in daemon event processing.
- Activates previously dormant security/audit capabilities (HMAC signing, package-update handling, scheduled scans, auto-rebaseline).
- Preserves CLI and config compatibility; no schema migration required.

### Compatibility Notes
- No breaking CLI flag or command changes.
- No `vigil.toml` schema changes required.
- No SQLite schema migration required.
- Existing baselines and audit tables remain readable/writable.

### Critical Structural Fixes (Items 1-17)

#### 1) mtime fast-reject security bypass closed (`src/compare.rs`, `src/lib.rs`, `src/scanner.rs`)
- Added `force_hash: bool` and `skip_unchanged: bool` controls to `compare_file_against_baseline()`.
- Real-time event path (`compare_event`) now always sets `force_hash = true`, guaranteeing content hash verification after an event.
- Batch/incremental path (`compare_entry`) uses `force_hash = false` and controlled skip logic.
- Documented threat model/rationale in function docs.

#### 2) package ownership batch misalignment fixed (`src/package.rs`)
- Removed unsafe positional `zip(paths, stdout.lines())` mapping for `pacman` and `rpm` batch paths.
- `batch_query_pacman()` and `batch_query_rpm()` now query per-path to avoid ownership shifts when unowned files are skipped/errored.
- Kept `dpkg` parsing behavior (path-anchored output) unchanged.
- Added regression tests for “unowned file in the middle of batch” scenarios.

#### 3) debounce trailing-edge loss fixed (`src/monitor/filter.rs`, `src/lib.rs`)
- Added `pending_paths: HashSet<PathBuf>` to `EventFilter`.
- Debounced events are now tracked for deferred re-check.
- Added `drain_pending()` to emit paths whose debounce window has elapsed.
- Daemon loop now processes drained pending paths each iteration.
- `prune_debounce()` now clears related pending entries.

#### 4) WatchGroupIndex complexity docs corrected + lookup scan bounded (`src/watch_index.rs`)
- Updated docs to describe real complexity: `O(log n)` seek + `O(k)` backward scan.
- Added early-termination logic in reverse scan when first path component diverges.
- Preserves matching semantics while reducing worst-case backward traversal.

#### 5) inotify now watches newly created subdirectories (`src/monitor/inotify.rs`)
- Detects `IN_CREATE | IN_ISDIR` events.
- Dynamically and recursively adds watches for new directories using existing `add_directory_watches()`.
- Logs newly added dynamic watch paths.

#### 6) `package_update` is no longer hardcoded false (`src/compare.rs`, `src/lib.rs`)
- `deletion_result()` and `change_result()` now accept `package_update` explicitly.
- Daemon path now sets `change.package_update` based on runtime package ownership verification during maintenance state.

#### 7) security context comparison implemented (`src/compare.rs`, `src/types.rs`)
- Added `ChangeType::SecurityContextChanged`.
- Compare path now reads SELinux/AppArmor context via fd-based `/proc/self/fd/<fd>` lookup.
- Security context now participates in both fast/slow comparison paths and emitted metadata.

#### 8) scheduled scanning wired into daemon loop (`src/lib.rs`, `Cargo.toml`)
- Added cron parser dependency (`croner`).
- Daemon now parses scanner schedule and executes scheduled scans in housekeeping window.
- Logs scan start/completion and updates last refresh state.
- Includes schedule parse failure fallback with clear warning.

#### 9) HMAC signing now applied to audit entries (`src/alert/mod.rs`)
- Added `hmac_key: Option<Vec<u8>>` to `AlertEngine`.
- Loads HMAC key at startup when signing is enabled.
- `dispatch()` now computes audit-entry HMAC data and writes signature to DB.
- Keeps operation resilient if key load fails (warn + unsigned fallback).

#### 10) `auto_rebaseline` config now active (`src/lib.rs`)
- After dispatching a qualifying package update, daemon optionally calls `baseline::add_file()` to refresh trusted state.
- Controlled by `package_manager.auto_rebaseline`.
- Emits explicit log on successful auto-rebaseline.

#### 11) cooldown refresh now tracks suppressed burst activity (`src/alert/mod.rs`)
- Cooldown timestamp update moved to occur before suppression return path.
- Prevents stale re-alerts from firing immediately after initial cooldown expiry during ongoing churn.
- Rate counter behavior unchanged (still increments only for dispatched alerts).

#### 12) watch index now rebuilt on SIGHUP reload (`src/lib.rs`)
- `watch_index` made mutable and regenerated from the new config during reload.
- Added log reporting rebuilt index entry count.
- Keeps severity/group classification aligned with live config updates.

#### 13) incremental scan TOCTOU reduced (`src/scanner.rs`, `src/compare.rs`)
- Removed pre-open `metadata(path)` mtime shortcut in scanner loop.
- Moved unchanged-skip decision into compare path after open + fstat on pinned fd.
- Preserves optimization intent while avoiding path-stat race window.

#### 14) baseline metadata double-stat path removed (`src/baseline/mod.rs`)
- `add_file()` now passes `Some(config.scanner.max_file_size)` into `collect_file_metadata()`.
- Ensures size limit enforcement remains inside open/fstat collection flow.

#### 15) maintenance-window DB lookup no longer per-event (`src/lib.rs`)
- Added cached maintenance flag using `AtomicBool`.
- Initialized once at startup and refreshed during housekeeping interval.
- Event path now reads atomic state instead of issuing a SQLite select each change.

#### 16) panic swallowing removed from daemon event hot path (`src/lib.rs`)
- Removed `catch_unwind(AssertUnwindSafe(...))`, panic counters, and threshold logic.
- Event loop now relies on explicit `Result` handling and logging for expected failures.
- True panics now fail fast instead of continuing with potentially inconsistent shared state.

#### 17) per-event full config clone removed (`src/lib.rs`)
- Replaced per-event `active_config.read().clone()` with atomic cache for `max_file_size` (`AtomicU64`).
- Updated value on SIGHUP reload.
- Housekeeping path now uses config read guards without full-struct clone.

### Tests Added/Updated
- Added force-hash bypass regression test in compare module:
  - `force_hash_detects_content_change_despite_matching_metadata`
- Added debounce trailing-edge test:
  - `drain_pending_returns_debounced_paths_after_window_expires`
- Added change-type security-context serde/display coverage:
  - `security_context_changed_serde_roundtrip`
  - `change_type_display` extended for `security_context_changed`
- Added package-owner batch misalignment regressions for pacman/rpm/dpkg parsing behavior.
- Updated integration/security/benchmark callsites for the new compare API signature.

### Validation
- `cargo build` passes.
- `cargo test --all-targets -- --test-threads=4` passes.
- Benchmark target smoke execution succeeds under current test runner invocation.

## [0.7.0] - 2026-04-05

### Release Summary
- Delivers a full performance and efficiency overhaul across Vigil's hot path, baseline lifecycle, SQLite usage, and allocation behavior.
- Implements 17 planned optimizations plus one CI/test-runner compatibility fix for benchmark execution.
- Preserves CLI compatibility, TOML configuration compatibility, and database schema compatibility.

### Compatibility Notes
- No breaking CLI changes.
- No `vigil.toml` format changes.
- No SQLite schema migration required.
- Existing databases remain readable/writable without migration.

### Performance & Efficiency

#### 1) mtime+size fast-reject before hashing (`src/compare.rs`)
- Added a metadata fast path in `compare_file_against_baseline()` after `fstat` and before BLAKE3 hashing.
- When all tracked metadata matches baseline (`mtime`, `size`, `inode`, `device`, `mode`, `uid`, `gid`), hashing is skipped.
- Fast path performs xattr check only; if xattrs are equal returns `CompareOutcome::NoChange`.
- If only xattrs differ, returns `CompareOutcome::Changed(vec![XattrChanged], baseline_hash, file_meta)` without hashing.
- Result: unchanged-event path avoids expensive content hashing in real-time monitoring.

#### 2) Pre-compiled glob exclusions (`src/baseline/mod.rs`)
- Added `CompiledExclusions` with:
  - `patterns: Vec<glob::Pattern>`
  - `system_prefixes: Vec<String>`
- Added `CompiledExclusions::from_config()` to compile patterns once per operation.
- Updated `is_excluded()` to accept `&CompiledExclusions` instead of recompiling globs per path.
- Wired compiled exclusions through `init_baseline`, `refresh_baseline`, `diff_baseline`, `walk_directory`, `scan_path`, `scan_single_file`, and `walk_recursive`.

#### 3) Reduced hot-path string allocations (`src/monitor/filter.rs`, `src/baseline/mod.rs`)
- Changed debounce timer map key type from `HashMap<String, Instant>` to `HashMap<PathBuf, Instant>`.
- Replaced `path_str.into_owned()` key creation with `event.path.clone()`.
- Updated filename extraction in exclusion checks to use `Cow<str>` without forcing owned allocations.

#### 4) Cached home-directory enumeration (`src/config.rs`)
- Added `static HOME_DIRS: OnceLock<Vec<PathBuf>>`.
- Added `cached_home_dirs()` and switched `expand_user_paths()` to read from cache.
- `enumerate_home_dirs()` is now executed once per process lifetime rather than multiple times during startup path expansion.

#### 5) Removed redundant `stat()` syscall (`src/baseline/mod.rs`, `src/baseline/metadata.rs`)
- Reordered `scan_single_file()` to apply exclusions first.
- Moved max-file-size enforcement into `collect_file_metadata(path, config, max_file_size)` after open+fstat.
- Eliminated path-based pre-stat (`std::fs::metadata`) followed by fd-based metadata call.
- New path uses one open and one fstat for metadata collection.

#### 6) Batched package ownership queries (`src/package.rs`, `src/baseline/mod.rs`)
- Added `batch_query_package_owners(paths, config)` returning `HashMap<PathBuf, Option<String>>`.
- Added backend-specific batch implementations for `dpkg`, `pacman`, and `rpm` with chunking (100 paths per batch).
- Reused existing timeout semantics (`PKG_QUERY_TIMEOUT`) for batched calls.
- Updated directory scan flow to gather file paths, batch query once, then scan files using cached package ownership.
- Kept per-file query path for single-file add/update paths.

#### 7) SQLite transaction batching for baseline init/refresh (`src/baseline/mod.rs`)
- Wrapped baseline initialization and refresh writes in explicit transactions (`BEGIN IMMEDIATE` / `COMMIT`).
- Added commit cadence every 1,000 inserts to limit long write-lock windows.
- Immediately starts a new transaction after each periodic commit during ongoing scan work.

#### 8) `WatchGroupIndex` moved to tree-based lookup (`src/watch_index.rs`)
- Replaced vector-based longest-first linear scan with `BTreeMap<PathBuf, (String, Severity)>`.
- Implemented lookup via reverse range walk from `..=path` and first valid prefix match.
- Updated constructors and iterator helpers for the new internal representation.

#### 9) Larger fanotify read buffer (`src/monitor/fanotify.rs`)
- Increased monitor read buffer from `4096` to `262_144` bytes (256KB).
- Reduces read syscall frequency under bursty event conditions.

#### 10) Alert event IDs use atomic counter + timestamp (`src/alert/mod.rs`, `Cargo.toml`)
- Added `static EVENT_COUNTER: AtomicU64`.
- Replaced UUID generation with deterministic format: `vigil_{timestamp_hex}_{seq_hex}`.
- Removed direct `uuid` dependency from `Cargo.toml`.

#### 11) `AlertEngine` stores only needed config fields (`src/alert/mod.rs`)
- Removed full `Config` clone from `AlertEngine` state.
- Added focused fields: `syslog_enabled`, `log_min_severity`, `dbus_min_severity`.
- Updated dispatch paths to reference these stored fields.

#### 12) Single child-reaper thread for desktop notifications (`src/alert/dbus.rs`)
- Added `reaper_tx: crossbeam_channel::Sender<std::process::Child>` to `DbusNotifier`.
- `DbusNotifier::new()` now spawns one long-lived reaper thread (`vigil-reaper`).
- `notify()` now sends child processes to the shared reaper instead of spawning one thread per alert.

#### 13) Reduced `diff_baseline` memory duplication (`src/baseline/mod.rs`, `src/db/ops.rs`)
- Added `get_all_baseline_paths()` query to fetch path set directly (`SELECT path FROM baseline`).
- `diff_baseline()` now uses this path-only query for created-file detection.
- Avoids building a secondary path set from fully loaded baseline rows.

#### 14) Deterministic xattr JSON serialization (`src/compare.rs`, `src/baseline/metadata.rs`)
- Switched xattr collection maps from `HashMap` to `BTreeMap` in both compare and baseline metadata paths.
- Ensures stable JSON key ordering and avoids false-positive xattr-drift detection from map iteration order.

#### 15) Release profile tuned for runtime performance (`Cargo.toml`)
- Changed `[profile.release] opt-level` from `"z"` to `2`.
- Retained `lto = true`, `codegen-units = 1`, and `strip = true`.
- Improves hash-heavy throughput while preserving compact release behavior from existing LTO/strip settings.

#### 16) Prepared-statement caching for repeated SQL (`src/db/ops.rs`)
- Switched loop/hot-path SQL to `prepare_cached()` in:
  - `insert_baseline`
  - `update_baseline`
  - `upsert_baseline`
  - `get_baseline_by_path`
  - `insert_audit_entry`
- Eliminates repeated SQL parse overhead for frequently executed statements.

#### 17) Additional SQLite performance pragmas (`src/db/mod.rs`)
- Added to connection setup (`open_db` and `open_db_at`):
  - `cache_size = -8000`
  - `mmap_size = 268435456`
  - `temp_store = MEMORY`
- Kept existing settings for `journal_mode` (config-driven), `synchronous = NORMAL`, and `foreign_keys = ON`.

### Benchmark/Test Runner Compatibility

#### Criterion bench binaries now tolerate libtest-only flags (`benches/benchmarks.rs`)
- Replaced `criterion_main!` macro entrypoint with explicit `main()`.
- Added libtest-arg detection (`--test-threads`, `--nocapture`, `--show-output`, `--format*`).
- If libtest args are present, runs Criterion with defaults (no CLI parsing) to avoid unknown-arg failures.
- If absent, preserves normal Criterion CLI behavior via `configure_from_args()`.
- Fixes CI failures where benchmark targets were executed with forwarded `--test-threads`.

### Correctness Fixes

#### Config load precedence now matches documented order (`src/config.rs`)
- Fixed `load_config()` iteration order so sources are applied from lowest to highest priority.
- Ensures higher-priority config sources (including `VIGIL_CONFIG` and explicit CLI path) correctly override lower-priority sources (`/etc`, then user config).
- Aligns runtime behavior with the documented search-order contract in the config module docs.

### Tests Added/Updated
- Added fast-reject unit tests in `src/compare.rs`:
  - `fast_reject_skips_hash_when_metadata_unchanged`
  - `fast_reject_detects_size_change`
- Added compiled exclusions tests in `src/baseline/mod.rs`.
- Added baseline path-query tests in `src/db/ops.rs`:
  - `get_all_baseline_paths_returns_all_paths`
  - `get_all_baseline_paths_empty_db`
- Added batch package parsing tests in `src/package.rs` for `dpkg`, `pacman`, and `rpm` output handling.
- Updated integration tests to avoid equal-size/same-second false negatives when validating modified-file detection.

### Validation
- `cargo test --all-targets` passes.
- `cargo clippy --all-targets` passes.
- `cargo fmt` passes.
- `cargo test --bench benchmarks -- --test-threads=4` now executes successfully.

## [0.6.0] - 2026-04-05

### Release Summary
- Addresses 3 security fixes (P0), 2 correctness/reliability improvements (P1), 2 testing expansions (P2), and 1 performance optimization (P3).
- Adds a shared `WatchGroupIndex` for efficient path-to-group resolution, criterion benchmarks, and a daemon lifecycle integration test.
- Preserves backward compatibility with existing CLI commands, configuration format, and SQLite schema.

### Compatibility Notes
- No breaking CLI changes.
- No baseline schema migration required.
- Existing configuration files remain valid.
- SIGHUP reload now applies more config fields at runtime (see "Live Reload" section in `docs/CONFIGURATION.md`).

### Security

#### P0-1: Check flock return values in PID file handling (`src/lib.rs`)
- Both `libc::flock()` calls in `write_pid_file` now check the return value; if `flock` returns `-1`, a `VigilError::Daemon` error is returned with the OS error message
- Extracted `acquire_pid_lock()` helper with `// SAFETY:` comment explaining the invariants
- Added unit tests: `write_pid_file_creates_and_locks` (happy path) and `write_pid_file_detects_held_lock` (error path with a second file handle holding the lock)

#### P0-2: PID file stale detection TOCTOU window (`src/lib.rs`)
- Eliminated the TOCTOU race between `kill(pid, 0)` returning `ESRCH` and `remove_file` + `create_new` by replacing the two-step pattern with a single atomic operation
- Stale recovery now opens the *existing* file with `O_WRONLY | O_TRUNC` (preserving the inode), acquires `flock`, verifies the PID is still stale, then overwrites -- keeping the inode locked throughout
- Added inline comment documenting the race condition mitigation strategy

#### P0-3: HMAC key management documentation and hardening (`src/hmac.rs`, `src/main.rs`, `docs/SECURITY.md`, `docs/CONFIGURATION.md`)
- `load_hmac_key()` now calls `check_hmac_key_permissions()` which emits `log::warn!` if key file mode is more permissive than `0600`
- New `validate_hmac_key_doctor()` public function checks both permissions and ownership (expects root/UID 0) for use by `vigil doctor`
- `cmd_doctor` now reports HMAC key file permission and ownership issues when signing is enabled
- New "HMAC Key Lifecycle" section in `docs/SECURITY.md` covering: key generation (`head -c 32 /dev/urandom | xxd -p -c 64`), file permissions (must be `0400` or `0600`, root-owned), rotation procedure (new epoch vs re-sign), and threat model (key must be on a different trust boundary than monitored files)
- `docs/CONFIGURATION.md` HMAC Signing section updated to reference the new security doc and mention the runtime permission warning
- Added unit tests: `validate_hmac_key_doctor_permissive_mode` and `validate_hmac_key_doctor_strict_mode`

### Changed

#### P1-4: Full config reload on SIGHUP (`src/lib.rs`, `src/alert/mod.rs`, `docs/CONFIGURATION.md`)
- Active config is now held in `Arc<parking_lot::RwLock<Config>>` and swapped atomically on SIGHUP reload
- `AlertEngine` gains `rate_limit: AtomicU32` and `cooldown_secs: AtomicU64` fields; `is_suppressed()` reads from these atomics instead of `self.config`
- New `AlertEngine::update_rate_config()` method resets the rate counter window and stores new values on reload
- The daemon event loop reads `scanner.max_file_size` and `database.audit_retention_days` from the live config snapshot on each cycle
- `diff_config()` output is now computed against the live config (not the startup parameter)
- New "Live Reload (SIGHUP)" section in `docs/CONFIGURATION.md` documenting which fields take effect immediately vs. which require restart:
  - **Immediate**: `exclusions.*`, `alerts.rate_limit`, `alerts.cooldown_seconds`, `scanner.max_file_size`, `database.audit_retention_days`
  - **Restart required**: `daemon.pid_file`, `daemon.db_path`, `daemon.monitor_backend`, `watch.*` paths

### Fixed

#### P1-5: README version badge out of sync
- Updated version badge in `README.md` from `0.4.0` to match `Cargo.toml` (now `0.6.0`)

### Added

#### P2-6: Daemon lifecycle integration test (`tests/integration/daemon_tests.rs`)
- New `daemon_lifecycle_create_modify_delete` test exercising the full event processing pipeline:
  - Creates a temporary directory and config pointing at it
  - Initializes a baseline with test files
  - Starts the inotify monitor in a background thread
  - Spawns an event processing thread that handles comparison and alert dispatch
  - Performs file modification, creation, and deletion
  - Asserts that `modified` audit entries are recorded in the database
  - Verifies WAL checkpoint succeeds on shutdown
- Gated behind `#[ignore]` (requires inotify); run with `cargo test --test integration daemon -- --ignored`
- Registered in `tests/integration.rs` module list

#### P2-7: Criterion benchmarks (`benches/benchmarks.rs`, `Cargo.toml`)
- Added `criterion` to `[dev-dependencies]` with `html_reports` feature
- Added `[[bench]] name = "benchmarks"` section to `Cargo.toml`
- Six benchmark groups:
  - `blake3_hash_file` -- files of 1KB, 1MB, and 100MB
  - `blake3_hash_bytes` -- 1MB in-memory baseline
  - `compare_entry` -- unchanged file, modified file, and deleted file
  - `event_filter_10k_debounce` -- `EventFilter::should_process` with 10K pre-populated debounce entries
  - `full_scan_100_entries` -- end-to-end scan throughput with 100 baseline entries
  - `watch_group_lookup` -- `WatchGroupIndex::lookup` with 100 and 1000 watch paths

#### P3-8: WatchGroupIndex for efficient path lookup (`src/watch_index.rs`, `src/lib.rs`, `src/scanner.rs`)
- New `WatchGroupIndex` struct that sorts expanded watch group entries longest-prefix-first so the first match is always the most-specific
- `from_config()` builds the index from a `Config`; `from_expanded()` builds from pre-expanded entries
- `lookup()` returns `Option<(&str, Severity)>` -- the group name and severity of the best-matching prefix
- Replaced the linear `find_watch_group()` scan in `daemon_run()` with `watch_index.lookup()`
- Replaced the linear `watch_lookup.iter().find()` in `scanner::run_scan()` (both sequential and parallel paths) with `watch_index.lookup()`
- Registered as `pub mod watch_index` in `src/lib.rs`
- Unit tests: `most_specific_prefix_wins`, `overlapping_prefixes_three_levels`, `exact_path_match`, `no_match_returns_none`, `empty_index_returns_none`
- Benchmark: `watch_group_lookup` with 100 and 1000 paths in `benches/benchmarks.rs`

### Validation
- `cargo fmt --all --check` passes
- `cargo clippy --all-targets --all-features -- -D warnings` passes
- `cargo test --all-targets` passes (136 tests: 77 unit + 40 integration + 19 security; 2 intentionally ignored)
- All benchmark smoke tests pass

## [0.5.0] - 2026-04-05

### Release Summary
- Delivers the 12 planned reliability, observability, and test-hardening improvements in one coordinated release.
- Preserves backward compatibility with existing CLI commands, configuration format, and SQLite schema.
- Maintains Vigil principles: deterministic behavior, local-only operation, and no network I/O.

### Compatibility Notes
- No breaking CLI changes were introduced.
- No baseline schema migration is required.
- Existing configuration files remain valid.

### Added

#### Panic Isolation in Daemon Event Loop
- Wrapped comparison and alert dispatch in `std::panic::catch_unwind` so a panic in any single file's processing cannot crash the daemon
- Added panic counter with threshold logging (warns after 10 panics)
- Added unit test verifying panic isolation behavior

#### Structured Scan Warnings
- Added `ScanWarning` type with `WarningSeverity` enum in `src/error.rs`
- `init_baseline()`, `refresh_baseline()`, and `run_scan()` now collect structured warnings alongside results
- `ScanResult` includes `warnings: Vec<ScanWarning>` field
- CLI prints warnings summary after scan operations when warnings are non-empty

#### `PartialEq` on `VigilError`
- Manual `PartialEq` implementation for ergonomic error-path testing
- `Io` and `Database` variants always return false (not structurally comparable)
- String-based variants compare by value; `TomlParse` and `Json` compare by Display output
- Added unit tests for equality semantics

#### Builder Pattern for Library Scan API
- New `CheckBuilder` in `src/check_builder.rs` with fluent API: `.mode()`, `.filter_paths()`, `.on_progress()`, `.quiet()`
- Exported as `vigil::CheckBuilder` from `src/lib.rs`
- Added tests for builder defaults and chaining

#### Progress Callbacks for Long Operations
- Defined `ProgressCallback<'a>` type alias in `src/lib.rs`
- `run_scan()` accepts optional progress callback
- CLI passes TTY-aware progress callback using `eprint!("\r\x1b[K ...")`

#### Optional Parallel Scanning
- Added `parallel` feature flag gating `rayon` dependency
- `run_scan()` uses `par_iter()` for Full mode when `parallel` feature is enabled
- Sequential path remains the default; daemon event loop stays single-threaded
- CI test matrix includes `--features parallel`

#### Snapshot Testing
- Added `insta` (dev-dependency) with JSON feature for snapshot testing
- Three snapshot tests: `baseline_export`, `diff_output`, `alert_json`
- CI includes `cargo insta test --check` step

#### Property-Based Testing
- Added `proptest` and `tempfile` dev-dependencies
- Four property tests: DB roundtrip, BLAKE3 determinism, file/bytes hash equivalence, severity ordering
- Wired into `tests/security/property_tests.rs`

#### SQL-Backed Log Search
- New `search_audit()` function in `src/db/ops.rs` with parameterized SQL WHERE clauses
- Replaces in-memory brute-force search in `cmd_log LogAction::Search`
- Supports path substring filter (`LIKE`) and severity exact match
- Added four unit tests for search scenarios

#### Config Diffing for SIGHUP Reload
- New `diff_config()` function in `src/config.rs` returning human-readable change descriptions
- SIGHUP handler now logs specific config changes instead of generic "reloaded" message
- Logs "Configuration unchanged" when no differences detected
- Warns about fanotify restart requirement only when watch paths actually changed

#### HMAC Audit Log Verification
- New `src/hmac.rs` module with `compute_hmac()`, `verify_hmac()`, `load_hmac_key()`
- Implemented `vigil log verify` command (previously a stub)
- Reports count of valid/invalid/missing HMAC entries
- Added unit tests for HMAC computation and verification roundtrip

#### Expanded Fuzz Targets
- Added four new fuzz targets (7 total): `fuzz_toml_config`, `fuzz_event_filter`, `fuzz_db_roundtrip`, `fuzz_xattr_parsing`
- Made `validate_config()` public for fuzz target access

### Changed

#### Cross-Cutting
- All `unsafe` blocks now have `// SAFETY:` comments explaining invariants
- Updated CI test matrix to include `--features parallel` and `cargo insta test --check`
- Updated `docs/TESTING.md` with snapshot and property-based test documentation
- Updated `CONTRIBUTING.md` with `cargo insta review` workflow
- Updated `CHANGELOG.md` with all improvement entries

### Validation
- `cargo fmt --all --check` passes
- `cargo clippy --all-targets --all-features -- -D warnings` passes
- `cargo test --all-targets --all-features` passes (127 passed, 1 ignored privileged test)

## [0.4.0] - 2026-04-02

### Fixed

#### P0 -- Critical Security & Correctness

##### Fix TOCTOU double-open in comparison engine (`src/compare.rs`)
- Introduced `CompareOutcome` three-state enum (`NoChange`, `Deleted`, `Changed`) so `compare_file_against_baseline` can distinguish all three cases without the caller re-opening the file by path
- Eliminated the nested `match File::open(path)` fallback in both `compare_entry` and `compare_event`
- Deletion is now detected on the first open attempt and returned as `CompareOutcome::Deleted` directly

##### Fix xattr reads using path instead of fd (`src/compare.rs`, `src/baseline/metadata.rs`)
- `read_xattrs_json` and `read_xattrs` now operate via `/proc/self/fd/<fd>` on the already-open file descriptor instead of the filesystem path, closing the TOCTOU window between fstat and xattr reads
- Same fix applied to `read_security_context` in `metadata.rs`

##### Add max_file_size check in real-time monitoring path (`src/compare.rs`)
- `compare_file_against_baseline` now accepts an optional `max_file_size` parameter and skips files exceeding the limit after fstat, preventing the daemon from blocking on large files
- `compare_event` passes `config.scanner.max_file_size` through to the comparison function

#### P1 -- Stability & Reliability

##### Use proper atomic ordering for shutdown flag
- Changed all `shutdown.store(true, Ordering::Relaxed)` to `Ordering::Release`
- Changed all `shutdown.load(Ordering::Relaxed)` to `Ordering::Acquire`
- Applied in `src/lib.rs`, `src/monitor/fanotify.rs`, and `src/monitor/inotify.rs`

##### Fix PID file race condition with atomic creation (`src/lib.rs`)
- Replaced exists-check-then-write pattern with `OpenOptions::create_new(true)` (O_CREAT|O_EXCL)
- Added advisory file lock via `libc::flock(fd, LOCK_EX|LOCK_NB)` for defense-in-depth
- Stale PID files are detected and removed with retry logic

##### Implement audit log rotation (`src/db/ops.rs`, `src/lib.rs`)
- Added `rotate_audit_log(conn, retention_days)` function that deletes entries older than the configured retention period
- Added JSON log file rotation in `src/alert/json_log.rs` via `rotate_if_needed(max_size)` -- renames with timestamp suffix and opens fresh file
- Both rotations run periodically in the daemon's 60-second housekeeping cycle

##### Fix fanotify FD leak on error paths (`src/monitor/fanotify.rs`)
- Created `OwnedFd` RAII wrapper that calls `libc::close` on drop
- Both `fan_fd` and `epoll_fd` are now wrapped in `OwnedFd`, ensuring cleanup on early return or thread exit

##### Check epoll_ctl return value (`src/monitor/fanotify.rs`)
- `epoll_ctl` return value is now checked; logs error and returns from thread if it fails

#### P2 -- Performance

##### Use blake3::Hasher::update_reader() (`src/baseline/hash.rs`)
- Replaced manual 64KB read loop with `hasher.update_reader(&mut reader)` for optimized internal buffering

##### Fix WAL checkpoint counter (`src/lib.rs`)
- Moved `wal_writes` increment inside the `Ok(Some(change))` arm so it only counts actual DB writes, not all events

##### Make notify-send non-blocking (`src/alert/dbus.rs`)
- Changed `.status()` (blocking) to `.spawn()` with a detached reaper thread that calls `child.wait()` to avoid zombies without blocking the alert path

##### Pass severity into compare_entry (`src/compare.rs`, `src/scanner.rs`, `src/baseline/mod.rs`)
- `compare_entry` now accepts `severity: Severity` and `group_name: &str` parameters instead of hardcoding `Severity::Medium`
- Both `diff_baseline` and `run_scan` build a watch-group lookup table and pass the correct severity/group for each entry

#### P3 -- Robustness

##### Standardize on parking_lot::Mutex everywhere
- Replaced `std::sync::Mutex` with `parking_lot::Mutex` in `src/alert/json_log.rs` and `src/alert/socket.rs`
- Removed `if let Ok(...)` patterns -- `parking_lot::Mutex::lock()` returns the guard directly

##### Add timeout to package manager subprocess calls (`src/package.rs`)
- Added `run_with_timeout` helper that spawns the child process and polls with `try_wait` in a loop
- 5-second timeout; kills child process on timeout and returns None
- Applied to `query_pacman`, `query_dpkg`, and `query_rpm`

##### Bound the debounce map (`src/monitor/filter.rs`)
- Added `MAX_DEBOUNCE_ENTRIES` (50,000) capacity check before inserting
- Triggers emergency `prune_debounce()` when exceeded, with a warning log

##### Add SIGHUP handler for config reload (`src/lib.rs`)
- Added `SIGHUP` to the blocked signal set
- Signal handler thread now loops: SIGHUP sets a reload flag, SIGINT/SIGTERM triggers shutdown
- Housekeeping section checks reload flag -- reloads config and rebuilds EventFilter
- Logs warning that fanotify/inotify marks require a daemon restart to update

##### Validate log_level config value (`src/config.rs`)
- `validate_config` now rejects log_level values other than error/warn/info/debug/trace (case-insensitive)

##### Validate hash_algorithm config value (`src/config.rs`)
- Rejects any value other than "blake3" with a clear error message

##### Validate cron schedule expression (`src/config.rs`)
- Validates that `scanner.schedule` has exactly 5 whitespace-separated fields (standard cron format)

### Added

#### New Tests
- `validate_rejects_invalid_log_level` -- invalid log level rejected
- `validate_accepts_valid_log_levels` -- all valid levels accepted (case-insensitive)
- `validate_rejects_unsupported_hash_algorithm` -- non-blake3 algorithm rejected
- `validate_accepts_blake3_hash_algorithm` -- blake3 accepted
- `validate_rejects_invalid_cron_schedule` -- malformed cron rejected
- `validate_accepts_valid_cron_schedule` -- standard cron accepted
- `audit_log_rotation_deletes_old_entries` -- rotation removes entries older than retention
- `audit_log_rotation_preserves_recent_entries` -- rotation preserves recent entries

### Notes
- All 103 tests pass (up from 95 in v0.3.1)
- Zero clippy warnings
- `compare_entry` signature changed: now requires `severity: Severity` and `group_name: &str` parameters
- `compare_event` signature changed: now requires `max_file_size: u64` parameter

## [0.3.1] - 2026-04-02

### Fixed

#### README License Section
- License section now shows the complete licensing model in a structured table: GPL-3.0-only for source code, CC BY 4.0 for documentation, and CLA for contributor submissions
- Previously only stated "Licensed under the GNU General Public License v3.0 only" without mentioning the documentation license or contributor terms
- Added references to `licenses/DEPENDENCY-AUDIT.md` and `licenses/CONTRIBUTOR-LICENSE.md` in the license section

#### Version Badge
- Updated version badge from `0.2.1` to `0.3.1` (was stale since v0.2.1 release)

#### Formatting
- Fixed `rustfmt` issues in `src/compare.rs` (match arm brace removal), `src/lib.rs` (method chain wrapping), and `src/package.rs` (closure simplification)

### Changed

#### License Framework Cross-References
- Added references to `NOTICE`, `TRADEMARKS.md`, and `licenses/LICENSE-COMMERCIAL.md` in `README.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, and `docs/README.md`
- Added trademark usage note in `CONTRIBUTING.md` contributor terms section

#### License Framework Adoption
- Adopted comprehensive open-source license framework (adapted from Shroud project) with full legal document set
- Created `NOTICE` file with identity mapping, project info, license summary, and trademark notice
- Created `TRADEMARKS.md` with trademark ownership, permitted/prohibited uses, fork requirements, and reporting
- Created `licenses/LICENSE-COMMERCIAL.md` as commercial licensing inquiry pathway (Vigil is GPL-3.0-only; no commercial license currently exists)
- Replaced `licenses/LICENSING.md` with comprehensive file-type coverage map, SPDX header formats, and verification scripts -- all references updated from dual-license to GPL-3.0-only
- Replaced `licenses/CONTRIBUTOR-LICENSE.md` with full CLA including patent grant, future licensing clause, and governing law
- Replaced `licenses/DEPENDENCY-AUDIT.md` with compatibility tables covering 20+ license types, Vigil's actual 20 dependencies, and audit process
- Replaced `licenses/LICENSE-DOCS.md` with detailed CC BY 4.0 scope and exclusions matching Vigil's file structure
- Replaced `licenses/THIRD-PARTY-LICENSES` with Vigil's actual dependency list (20 direct dependencies)
- Updated `licenses/README.md` to index all legal documents including root-level files

## [0.3.0] - 2026-04-02

### Fixed

#### P0 -- Critical Bugs

##### Signal handler doesn't work -- graceful shutdown broken (`src/lib.rs`)
- The `ctrlc_handler` function previously spawned a thread that called `sigset.thread_block()` internally -- this only blocked signals on the spawned thread while the main thread still received SIGINT/SIGTERM and was hard-killed by the OS before `sigset.wait()` could fire
- PID file was never cleaned up and WAL checkpoint never ran on shutdown
- Fixed by blocking SIGINT and SIGTERM on the main thread **before** spawning any child threads (so all threads inherit the signal mask), then passing the pre-blocked `SigSet` to the dedicated signal thread which calls `sigset.wait()`
- `ctrlc_handler` now accepts `SigSet` as a parameter instead of constructing its own

##### `try_send` silently drops security events (`src/monitor/fanotify.rs`, `src/monitor/inotify.rs`)
- Both fanotify and inotify monitors used `let _ = event_tx.try_send(...)`, silently discarding filesystem events when the channel buffer (1024) was full -- unacceptable for a security monitor
- Replaced with explicit `match` on `TrySendError`: logs `warn!` on `Full` (with the affected path) and logs `error!` + breaks the event loop on `Disconnected`

##### TOCTOU race in `path.exists()` before `File::open()` (`src/compare.rs`)
- Both `compare_entry` and `compare_event` checked `if !path.exists()` to detect deletions, then later called `File::open()` -- an attacker could exploit the gap between these two calls
- Removed the `path.exists()` pre-check entirely; now attempts `File::open()` directly and matches on `ErrorKind::NotFound` to detect deletions

##### Hash file doesn't seek to position 0 (`src/baseline/hash.rs`)
- `blake3_hash_file` called `file.try_clone()` and read from the current file offset; if the file descriptor's cursor was moved by prior reads (e.g., metadata collection), the hash would be computed from the wrong position
- Added `reader.seek(std::io::SeekFrom::Start(0))` immediately after `try_clone()` and before the read loop
- Added `std::io::Seek` to imports

#### P1 -- Important Fixes

##### `compare_event` skips xattr checking (`src/compare.rs`)
- `compare_entry` checked xattrs but `compare_event` did not -- real-time monitoring missed xattr/SELinux context changes
- Extracted shared comparison logic into a private `compare_file_against_baseline()` helper that handles: open file → fstat → hash → compare all fields including xattrs → return change types
- Both `compare_entry` and `compare_event` are now thin wrappers over this shared helper (see Code Quality section)

##### Database file permissions not restricted (`src/db/mod.rs`)
- `open_db` created the SQLite database with default umask permissions, potentially leaving baseline data world-readable
- After creating the database file, permissions are now explicitly set to `0o600` (owner read/write only)

##### No stale PID file detection (`src/lib.rs`)
- `write_pid_file` blindly overwrote any existing PID file, allowing two daemon instances to run simultaneously
- Now checks if a process with the existing PID is still alive via `libc::kill(pid, 0)` before writing
- Returns `VigilError::Config` if another instance is running; removes stale PID files from dead processes

##### Inotify busy-wait polling loop (`src/monitor/inotify.rs`)
- Used `IN_NONBLOCK` + `sleep(100ms)` in a tight loop, wasting CPU cycles and adding event latency
- Replaced with `nix::poll::poll()` on the inotify fd with a 500ms timeout (matching the fanotify pattern)
- Removed the `IN_NONBLOCK` flag from inotify fd initialization since blocking is now handled by poll
- Added `poll` feature to the `nix` dependency in `Cargo.toml`

##### Mutex poisoning silently disables rate limiting (`src/alert/mod.rs`)
- All `Mutex::lock()` calls used `if let Ok(...)`, silently ignoring poisoned mutexes -- if any code panicked while holding a lock, rate limiting and cooldowns would permanently stop working
- Switched from `std::sync::Mutex` to `parking_lot::Mutex`, which does not poison and returns the guard directly
- All `if let Ok(mut x) = self.mutex.lock()` patterns replaced with direct `self.mutex.lock()` calls
- Added `parking_lot = "0.12"` to `Cargo.toml`

#### P2 -- Performance

##### `find_watch_group` re-expands paths every event (`src/lib.rs`)
- Every filesystem event triggered `expand_user_paths()` for every watch group, re-reading `/etc/passwd` and doing filesystem I/O on each event
- Pre-compute expanded paths at daemon startup into a `Vec<(PathBuf, String, Severity)>` of `(expanded_path, group_name, severity)` tuples
- `find_watch_group` now takes the precomputed list instead of the raw config
- Removed unused `let _path_str = path.to_string_lossy()` binding

##### `hostname()` reads from disk on every alert (`src/alert/mod.rs`)
- `/etc/hostname` was read on every call to `build_alert`
- Hostname is now read once in `AlertEngine::new()` and stored as a `String` field on the struct
- `build_alert` references `self.hostname` instead of calling the function

##### Change type dedup uses `format!("{:?}")` (`src/compare.rs`, `src/types.rs`)
- `change_types.sort_by_key(|c| format!("{:?}", c))` allocated a `String` per element per comparison during sorting
- Derived `PartialOrd` and `Ord` on `ChangeType` in `src/types.rs`
- Replaced with `change_types.sort()` / `change_types.dedup()` (zero-allocation)

##### `mtime_changed` is hardcoded to `true` (`src/alert/mod.rs`, `src/types.rs`, `src/compare.rs`)
- `AlertFileInfo.mtime_changed` was unconditionally set to `true` regardless of actual mtime state
- Added `old_mtime: Option<i64>` and `new_mtime: Option<i64>` fields to `ChangeResult`
- Both fields are populated from baseline and fstat metadata in `compare_file_against_baseline`
- `build_alert` now computes `mtime_changed: change.old_mtime != change.new_mtime`

##### Duplicate `OwnerChanged` when both UID and GID change (`src/compare.rs`)
- Separate `if` checks for UID and GID each pushed `ChangeType::OwnerChanged`, producing duplicates
- Combined into a single `if meta.uid() != baseline.owner_uid || meta.gid() != baseline.owner_gid` check

##### `integrity_check` returns misleading error (`src/db/mod.rs`)
- Returned `VigilError::Database(rusqlite::Error::QueryReturnedNoRows)` -- a misleading error type that hid the actual integrity failure reason
- Now returns `VigilError::Config(format!("database integrity check failed: {}", result))` with the actual SQLite integrity check output

### Changed

#### Code Quality

##### Extracted shared comparison logic (`src/compare.rs`)
- `compare_entry` and `compare_event` were ~90% identical code
- Created private `compare_file_against_baseline()` helper: open file → fstat → hash → compare all fields (inode, permissions, owner, content hash, xattrs) → return change types with file metadata
- Created `deletion_result()` and `change_result()` helper functions to eliminate duplicated `ChangeResult` construction
- `compare_entry` and `compare_event` are now thin wrappers that call the shared helper and add severity/group context

##### `notify-send` zombie process accumulation (`src/alert/dbus.rs`)
- Used `.spawn()` without reaping children, accumulating zombie processes over daemon lifetime
- Changed `.spawn()` to `.status()` which waits for the child process to complete
- Added comment noting that the long-term fix is to use `zbus` for native D-Bus integration

##### `which` command may not exist (`src/package.rs`)
- `command_exists` shelled out to `which` -- not available on all systems (e.g., minimal containers, some Debian installations)
- Replaced with direct `PATH` directory scan: splits `$PATH`, checks each directory for the target binary via `is_file()`

### Dependencies
- Added `parking_lot = "0.12"` (non-poisoning mutex)
- Added `poll` feature to `nix = "0.28"`

### Notes
- All 52 existing tests pass (37 unit/integration + 15 security)
- Zero clippy warnings
- No public API signature changes except the addition of `old_mtime`/`new_mtime` fields to `ChangeResult` (struct field addition)
- Version bumped from `0.2.1` → `0.3.0` (minor bump: new struct fields are a compatible but meaningful change)

## [0.2.1] - 2026-04-02

### Added

#### Complete Project Documentation Suite
- Replaced one-line project README with full operational guide covering philosophy, architecture summary, quick start, command basics, configuration overview, requirements, and licensing references
- Added full documentation index (`docs/README.md`) organized by onboarding, operations, architecture, security, and development
- Added architecture deep dive (`docs/ARCHITECTURE.md`) with full module tree, data-flow diagrams, backend behavior, TOCTOU comparison model, database schema, config precedence, and design decisions
- Added full CLI reference (`docs/CLI.md`) documenting global flags, all top-level commands, nested subcommands, arguments, output modes, and exit-code behavior
- Added full configuration reference (`docs/CONFIGURATION.md`) with precedence rules, annotated example config, option tables, watch-group guidance, exclusion behavior, alert tuning, HMAC configuration notes, and validation rules
- Added installation guide (`docs/INSTALL.md`) for source builds, distro dependencies, binary install, systemd setup, hooks setup, permissions model, first-run, and uninstall flow
- Added security policy and model (`docs/SECURITY.md`) with reporting process, timeline targets, supported-version policy, trust boundaries, threat scope, privilege model, DB/signal-socket/HMAC notes, and direct dependency justification
- Added focused threat model (`docs/THREAT_MODEL.md`) covering detection boundaries, non-goals, trust boundaries, attack surface, and evasion considerations
- Added testing guide (`docs/TESTING.md`) mapping unit/integration/security/fuzz coverage to local commands and CI workflows
- Added development guide (`docs/DEVELOPMENT.md`) with build/run/test/lint workflows, local daemon workflows, fuzz setup, and commit conventions
- Added troubleshooting guide (`docs/TROUBLESHOOTING.md`) for fanotify fallback, package-update alert storms, DB integrity issues, socket issues, inotify limits, and service failures
- Added FAQ (`docs/FAQ.md`) for core operator questions and expected behavior
- Added resilience guide (`docs/RESILIENCE.md`) for failure-mode handling, fallback behavior, and operator recovery paths
- Added release process guide (`docs/RELEASING.md`) with API-surface checklist, quality gates, tagging, and rollback policy
- Added contribution guide (`CONTRIBUTING.md`) with principles mapping, scope boundaries, workflow, testing expectations, and contributor terms reference
- Added governance document (`GOVERNANCE.md`) describing decision model, succession scenarios, and GPL continuity guarantees
- Added version policy (`VERSIONING.md`) with SemVer expectations, pre-1.0 rules, public API definitions, and dependency/toolchain policy
- Added third-party notices (`THIRD_PARTY_NOTICES.md`) for dependency policy and attribution handling

#### Licensing Documentation Framework
- Added root GPL text file (`LICENSE`) and integrated references across project docs
- Added dedicated licensing directory (`licenses/`) with:
	- `licenses/README.md` (legal docs index)
	- `licenses/LICENSING.md` (file-level license coverage map)
	- `licenses/LICENSE-DOCS.md` (documentation license scope and terms)
	- `licenses/CONTRIBUTOR-LICENSE.md` (contributor license terms)
	- `licenses/DEPENDENCY-AUDIT.md` (dependency license audit framework)
	- `licenses/THIRD-PARTY-LICENSES` (direct dependency license attribution list)

### Changed

#### Tone and Voice Consistency Pass
- Performed consistency pass across operational, governance, and licensing docs to align style with concise, direct, operator-first language
- Tightened intros/outros and policy phrasing to reduce ambiguity while preserving technical/legal meaning

#### Release Metadata
- Bumped crate version from `0.2.0` to `0.2.1` in `Cargo.toml`
- Updated version references in README badge and CLI/versioning examples

### Compliance and Hygiene

#### Repository-Term and Tooling Constraint Pass
- Removed references to disallowed terms/tooling from documentation and helper scripts
- Updated project links and wording to remain repository-local and tool-agnostic where required
- Updated `scripts/test-all.sh` output calls to `printf`

#### Documentation Cross-Linking
- Added explicit legal and licensing links from root README and documentation index
- Linked contributor workflow to contributor-license and licensing-policy files for clear submission terms

### Notes
- No source-code runtime behavior changes were introduced in this release
- This release focuses on documentation completeness, legal clarity, repository policy alignment, and release-readiness

## [0.2.0] - 2026-04-02

### Added

#### CI/CD Pipeline (`.github/workflows/ci.yml`)
- Full GitHub Actions CI pipeline triggered on push to `main`/`develop` and pull requests to `main`
- **Check & Lint** job: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo doc` with `-D warnings` via `RUSTDOCFLAGS`
- **Security Audit** job: `cargo audit --deny warnings` and `cargo deny check` for comprehensive supply-chain security
- **Test** job: matrix strategy testing both default features and `--all-features`, with `--test-threads=4` for parallelism; includes doc-test pass
- **Coverage** job: `cargo-tarpaulin` generating XML + HTML reports, uploaded to Codecov via `codecov/codecov-action@v4` and as build artifacts
- **MSRV Check** job: verifies compilation against Rust 1.75 (edition 2021 minimum)
- **CI Success** gate job: single required status check for branch protection, fails if any upstream job fails
- Concurrency groups with `cancel-in-progress: true` to avoid stale CI runs
- `Swatinem/rust-cache@v2` on all jobs for Cargo build caching
- `timeout-minutes` on every job to prevent runaway costs

#### Fuzz Testing Infrastructure
- **Fuzz smoke test** (`.github/workflows/fuzz-smoke.yml`): 60-second per-target fuzz on every push/PR touching `src/`, `fuzz/`, `Cargo.toml`, or `Cargo.lock`; uploads crash artifacts on failure
- **Fuzz MOAB** (`.github/workflows/fuzz-moab.yml`): manual-dispatch multi-hour sharded fuzz campaign (3 targets × 4 shards, up to 5 hours per shard); uses `-seed` per shard and `-use_value_profile=1` for diversity; uploads corpus (30-day retention) and crash artifacts (90-day retention); report job summarizes proven properties
- **Weekly Fuzz** (`.github/workflows/weekly-fuzz.yml`): scheduled Sunday 04:00 UTC extended fuzz (5 minutes per target, configurable via `max_total_time` input); shared Cargo cache across weekly runs

#### Fuzz Targets (`fuzz/`)
- Fuzz package scaffolding (`fuzz/Cargo.toml`) with `libfuzzer-sys`, `arbitrary`, and vigil library dependency
- **`fuzz_config_parse`**: fuzzes `toml::from_str::<Config>()` -- proves TOML config parsing never panics on arbitrary input
- **`fuzz_baseline_compare`**: fuzzes JSON deserialization of `BaselineEntry`, `ChangeType`, and `Severity::from_str` -- proves baseline comparison types handle malformed input safely
- **`fuzz_scanner`**: fuzzes JSON deserialization of `ScanMode`, `MonitorBackend`, `PackageBackend`, `BaselineSource`, and `Severity::from_str` -- proves scanner-related type parsing is robust

#### Scheduled Security & Coverage (`.github/workflows/scheduled.yml`)
- Weekly Monday 03:00 UTC security audit using both `cargo audit` and `cargo deny check`
- Automatic GitHub issue creation (labeled `security`, `automated`) when vulnerabilities are found
- Scheduled coverage with `--engine llvm`, `--verbose`, and 300-second timeout; uploaded to Codecov with 30-day artifact retention

#### Supply-Chain Policy (`deny.toml`)
- `cargo-deny` configuration for automated supply-chain checks
- Advisory policy: deny known vulnerabilities, warn on unmaintained crates
- License policy: deny unlicensed; allow MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-DFS-2016, GPL-3.0
- Ban policy: warn on multiple versions of the same crate
- Source policy: deny unknown registries and unknown git sources

## [0.1.0] - 2026-04-01

### Added

#### Project Principles (`docs/PRINCIPLES.md`)
- 15 engineering principles derived from the Quiet System Manifesto
- Emotional core: "No one tiptoes through your system without leaving footprints behind"
- Compass question: "Does this make Vigil quieter or noisier?"
- Key principles: Watch Don't Act, Silence Is Default, Determinism Over Heuristics, The Baseline Is Sacred, The Audit Trail Never Lies

#### Test Suite (95 tests)
- Shared test infrastructure: `TempDir` helper, config/baseline builders, custom assertions (`tests/common/`)
- Test decision tree and documentation (`tests/README.md`)
- Test runner script (`scripts/test-all.sh`): format, clippy, unit, integration, security stages

#### Unit Tests (43 tests, inline in `src/`)
- Type serialization roundtrips: `Severity`, `ChangeType`, `BaselineSource`, `MonitorBackend`, `PackageBackend`
- Severity ordering, case-insensitive parsing, serde JSON roundtrip
- BLAKE3 hashing: determinism, known values, empty files, hex format, file-vs-bytes equivalence
- Config parsing: minimal/full TOML, defaults, validation rejection (no watch groups, zero rate limit, zero max file size, invalid globs)
- Default config: four watch groups, correct severity levels, valid exclusion patterns
- Database CRUD: insert, upsert, query by path, get all (ordered), remove, count
- Audit log: always-written entries, suppression flags, maintenance window recording
- Config state: set/get, upsert, missing key

#### Integration Tests (37 tests, `tests/integration/`)
- **baseline_tests**: init scans files, records correct hashes, diff detects modified/deleted/new files, add/remove single file, refresh updates hashes, stats accuracy, exclusion patterns respected, unchanged file produces no diff
- **comparison_tests**: unchanged returns None, content modification detected, deletion detected, permission change detected, file replacement via inode, event comparison with group severity, old/new hash pairs provided
- **config_tests**: TOML file loading, invalid TOML rejected, missing watch groups rejected, invalid glob rejected, zero rate limit rejected, absolute path expansion
- **db_tests**: schema creation, integrity check, WAL checkpoint, maintenance window state, audit trail never suppressed, unique constraint enforcement
- **filter_tests**: system path exclusion, glob pattern exclusion, monitored file allowance, self-exclusion (DB/log paths), debounce suppression, per-path debounce independence, debounce pruning

#### Security Tests (15 passed + 1 ignored, `tests/security/`)
- **integrity_tests**: hash determinism (Principle III), distinct hashes for different content, inode tracking in baseline, file replacement attack detection via inode change, database unique constraint prevents silent overwrite, audit log records suppressed entries (Principle XIII), metadata captures permissions and ownership
- **permission_tests**: setuid permission escalation detection, world-writable detection, database file not world-writable, ownership change detection (ignored: requires root)
- **race_tests**: concurrent baseline writes, rapid file changes during comparison, file deleted between event and hash, empty file handling, deeply nested path handling

#### Core Infrastructure
- Project scaffolding with Cargo.toml and dependency manifest
- Core domain types (`Severity`, `ChangeType`, `BaselineEntry`, `FileMetadata`, `ChangeResult`, `Alert`, `FsEvent`, etc.) in `src/types.rs`
- Central error type with `thiserror` in `src/error.rs`
- `.gitignore` for build artifacts

#### Configuration (`src/config.rs`)
- TOML-based configuration with serde deserialization
- Layered config loading: `/etc/vigil/vigil.toml` → `~/.config/vigil/vigil.toml` → `$VIGIL_CONFIG` → CLI `--config`
- Config validation (watch groups, glob patterns, rate limits, HMAC key, paths)
- Home directory expansion via `/etc/passwd` enumeration (UID 1000–65533)
- Default config with four watch groups: `system_critical`, `persistence`, `user_space`, `network`
- Default configuration file at `config/vigil.toml`

#### Database Layer (`src/db/`)
- SQLite database with WAL mode, schema auto-creation
- `baseline` table with UNIQUE constraint on `(path, device, inode)` for inode-change detection
- `audit_log` table for tamper-evident change history
- `config_state` key-value table for daemon metadata
- Full CRUD operations: insert, upsert, update, query by path, query all, remove
- Audit log insertion with suppression/maintenance tracking
- Database integrity check (`PRAGMA integrity_check`) and WAL checkpoint

#### Baseline Engine (`src/baseline/`)
- BLAKE3 hashing via open file descriptors (TOCTOU-hardened)
- File metadata collection: permissions, ownership, mtime, inode, device, xattrs, SELinux/AppArmor context
- `vigil init` -- full baseline generation across all watch groups
- `vigil baseline refresh` -- re-scan with optional path filtering
- `vigil baseline add/remove` -- single-file baseline management
- `vigil baseline diff` -- compare current state vs. baseline without updating
- `vigil baseline stats` -- entry counts by source, last refresh time
- `vigil baseline export` -- JSON export of all baseline entries
- Recursive directory walking with configurable depth limit (max 20)
- Exclusion pattern matching (glob + system prefix)
- Automatic package manager ownership query during baseline generation

#### Comparison Engine (`src/compare.rs`)
- TOCTOU-hardened comparison: open file → fstat(fd) → hash(fd) → compare
- Inode + device verification to detect file replacement attacks
- Detection of: content modification, deletion, permission changes, ownership changes, inode replacement, xattr changes
- Separate `compare_entry` (for scheduled scans) and `compare_event` (for real-time monitor) functions

#### Real-Time Monitor (`src/monitor/`)
- **fanotify backend** (`src/monitor/fanotify.rs`): mount-wide monitoring via direct `libc::syscall`, epoll-based event loop, `/proc/self/fd` path resolution, automatic mount point detection from `/proc/self/mountinfo`
- **inotify backend** (`src/monitor/inotify.rs`): per-directory recursive watches, graceful degradation with explicit blind-spot warnings
- Automatic fallback from fanotify → inotify when `CAP_SYS_ADMIN` is unavailable
- **Event filter** (`src/monitor/filter.rs`): per-path 100ms debounce, glob exclusion patterns, system path exclusion, self-exclusion (Vigil's own DB/logs), periodic debounce map pruning

#### Alert Engine (`src/alert/`)
- Multi-channel alert dispatch: D-Bus, journald, JSON log, signal socket
- Per-path cooldown (default 300s) to suppress duplicate alerts
- Rate limiting (default 10 alerts/minute) with automatic window reset
- Maintenance window awareness: suppress package-managed path alerts, always fire HIGH/CRITICAL for non-package paths
- Audit log always written regardless of suppression
- **D-Bus notifications** (`src/alert/dbus.rs`): via `notify-send` with urgency mapping (critical/normal/low)
- **Journald logging** (`src/alert/journal.rs`): severity-mapped log levels (error/warn/info)
- **JSON log** (`src/alert/json_log.rs`): append-only structured log file with directory auto-creation
- **Signal socket** (`src/alert/socket.rs`): Unix domain socket for external tool integration, silent drop if no listener

#### Scheduled Scanner (`src/scanner.rs`)
- Incremental mode: only re-hash files with changed mtime
- Full mode: re-hash every baselined file
- I/O priority set to idle class via `ioprio_set` syscall
- CPU nice set to 19 via `setpriority` syscall

#### Package Manager Integration (`src/package.rs`)
- Auto-detection of pacman, dpkg, or rpm
- Package ownership queries (`pacman -Qo`, `dpkg -S`, `rpm -qf`)
- Maintenance window enter/exit commands for package manager hooks

#### CLI Interface (`src/cli.rs`, `src/main.rs`)
- Full command tree: `init`, `baseline {init,refresh,diff,add,remove,stats,export}`, `watch`, `check`, `maintenance {enter,exit,status}`, `log {show,search,stats,verify}`, `status`, `config {show,validate}`, `doctor`, `version`
- `--config` flag for explicit config path
- `--format` flag (`human`, `json`, `table`)
- `vigil doctor` -- self-diagnostics (fanotify, root, config, DB, HMAC, D-Bus, package manager, signal socket)

#### Daemon (`src/daemon.rs`, `src/lib.rs`)
- Event loop: receive → filter → lookup baseline → compare → classify → dispatch
- PID file management with cleanup on shutdown
- Signal handling (SIGINT/SIGTERM) via `nix::sys::signal`
- WAL checkpoint every 1000 writes
- Periodic debounce map pruning (60s interval)
- Watch group lookup for severity classification

#### Systemd Integration (`systemd/`)
- `vigild.service`: hardened with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `MemoryMax=50M`, `CAP_SYS_ADMIN` + `CAP_DAC_READ_SEARCH`
- `vigil-scan.timer`: daily at 03:00 with 15-minute random delay, persistent
- `vigil-scan.service`: one-shot full integrity scan at idle I/O + nice 19

#### Package Manager Hooks (`hooks/`)
- pacman pre/post-transaction hooks (`hooks/pacman/vigil-pre.hook`, `hooks/pacman/vigil-post.hook`)
- apt pre/post-invoke config (`hooks/apt/99vigil`)
