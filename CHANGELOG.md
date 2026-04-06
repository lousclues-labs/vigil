# Changelog

All notable changes to Vigil will be documented in this file.

## [Unreleased]

- No entries yet.

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
- `CaptureOpts` now carries optional `baseline_mtime` and `baseline_hash` fields. When `force_hash` is false and the file's current mtime matches the baseline, the stored hash is reused — eliminating redundant I/O and computation for unchanged files.
- Files changed: `src/types/snapshot.rs`, `src/scanner.rs`, `src/worker.rs`.

#### Bulk package ownership cache
- `build_initial_baseline()` previously spawned a subprocess (`pacman -Qo` / `dpkg -S` / `rpm -qf`) for every single file — up to 59,000+ fork+exec calls.
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
- `BloomFilter` contains only `Vec<u8>`, `usize`, and `u32` — all inherently `Send + Sync`. The manual unsafe impls were unnecessary and would mask safety issues if the struct ever gained a non-Sync field.
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
- Stale recovery now opens the *existing* file with `O_WRONLY | O_TRUNC` (preserving the inode), acquires `flock`, verifies the PID is still stale, then overwrites — keeping the inode locked throughout
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
  - `blake3_hash_file` — files of 1KB, 1MB, and 100MB
  - `blake3_hash_bytes` — 1MB in-memory baseline
  - `compare_entry` — unchanged file, modified file, and deleted file
  - `event_filter_10k_debounce` — `EventFilter::should_process` with 10K pre-populated debounce entries
  - `full_scan_100_entries` — end-to-end scan throughput with 100 baseline entries
  - `watch_group_lookup` — `WatchGroupIndex::lookup` with 100 and 1000 watch paths

#### P3-8: WatchGroupIndex for efficient path lookup (`src/watch_index.rs`, `src/lib.rs`, `src/scanner.rs`)
- New `WatchGroupIndex` struct that sorts expanded watch group entries longest-prefix-first so the first match is always the most-specific
- `from_config()` builds the index from a `Config`; `from_expanded()` builds from pre-expanded entries
- `lookup()` returns `Option<(&str, Severity)>` — the group name and severity of the best-matching prefix
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

#### P0 — Critical Security & Correctness

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

#### P1 — Stability & Reliability

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
- Added JSON log file rotation in `src/alert/json_log.rs` via `rotate_if_needed(max_size)` — renames with timestamp suffix and opens fresh file
- Both rotations run periodically in the daemon's 60-second housekeeping cycle

##### Fix fanotify FD leak on error paths (`src/monitor/fanotify.rs`)
- Created `OwnedFd` RAII wrapper that calls `libc::close` on drop
- Both `fan_fd` and `epoll_fd` are now wrapped in `OwnedFd`, ensuring cleanup on early return or thread exit

##### Check epoll_ctl return value (`src/monitor/fanotify.rs`)
- `epoll_ctl` return value is now checked; logs error and returns from thread if it fails

#### P2 — Performance

##### Use blake3::Hasher::update_reader() (`src/baseline/hash.rs`)
- Replaced manual 64KB read loop with `hasher.update_reader(&mut reader)` for optimized internal buffering

##### Fix WAL checkpoint counter (`src/lib.rs`)
- Moved `wal_writes` increment inside the `Ok(Some(change))` arm so it only counts actual DB writes, not all events

##### Make notify-send non-blocking (`src/alert/dbus.rs`)
- Changed `.status()` (blocking) to `.spawn()` with a detached reaper thread that calls `child.wait()` to avoid zombies without blocking the alert path

##### Pass severity into compare_entry (`src/compare.rs`, `src/scanner.rs`, `src/baseline/mod.rs`)
- `compare_entry` now accepts `severity: Severity` and `group_name: &str` parameters instead of hardcoding `Severity::Medium`
- Both `diff_baseline` and `run_scan` build a watch-group lookup table and pass the correct severity/group for each entry

#### P3 — Robustness

##### Standardize on parking_lot::Mutex everywhere
- Replaced `std::sync::Mutex` with `parking_lot::Mutex` in `src/alert/json_log.rs` and `src/alert/socket.rs`
- Removed `if let Ok(...)` patterns — `parking_lot::Mutex::lock()` returns the guard directly

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
- Housekeeping section checks reload flag — reloads config and rebuilds EventFilter
- Logs warning that fanotify/inotify marks require a daemon restart to update

##### Validate log_level config value (`src/config.rs`)
- `validate_config` now rejects log_level values other than error/warn/info/debug/trace (case-insensitive)

##### Validate hash_algorithm config value (`src/config.rs`)
- Rejects any value other than "blake3" with a clear error message

##### Validate cron schedule expression (`src/config.rs`)
- Validates that `scanner.schedule` has exactly 5 whitespace-separated fields (standard cron format)

### Added

#### New Tests
- `validate_rejects_invalid_log_level` — invalid log level rejected
- `validate_accepts_valid_log_levels` — all valid levels accepted (case-insensitive)
- `validate_rejects_unsupported_hash_algorithm` — non-blake3 algorithm rejected
- `validate_accepts_blake3_hash_algorithm` — blake3 accepted
- `validate_rejects_invalid_cron_schedule` — malformed cron rejected
- `validate_accepts_valid_cron_schedule` — standard cron accepted
- `audit_log_rotation_deletes_old_entries` — rotation removes entries older than retention
- `audit_log_rotation_preserves_recent_entries` — rotation preserves recent entries

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
- Replaced `licenses/LICENSING.md` with comprehensive file-type coverage map, SPDX header formats, and verification scripts — all references updated from dual-license to GPL-3.0-only
- Replaced `licenses/CONTRIBUTOR-LICENSE.md` with full CLA including patent grant, future licensing clause, and governing law
- Replaced `licenses/DEPENDENCY-AUDIT.md` with compatibility tables covering 20+ license types, Vigil's actual 20 dependencies, and audit process
- Replaced `licenses/LICENSE-DOCS.md` with detailed CC BY 4.0 scope and exclusions matching Vigil's file structure
- Replaced `licenses/THIRD-PARTY-LICENSES` with Vigil's actual dependency list (20 direct dependencies)
- Updated `licenses/README.md` to index all legal documents including root-level files

## [0.3.0] - 2026-04-02

### Fixed

#### P0 — Critical Bugs

##### Signal handler doesn't work — graceful shutdown broken (`src/lib.rs`)
- The `ctrlc_handler` function previously spawned a thread that called `sigset.thread_block()` internally — this only blocked signals on the spawned thread while the main thread still received SIGINT/SIGTERM and was hard-killed by the OS before `sigset.wait()` could fire
- PID file was never cleaned up and WAL checkpoint never ran on shutdown
- Fixed by blocking SIGINT and SIGTERM on the main thread **before** spawning any child threads (so all threads inherit the signal mask), then passing the pre-blocked `SigSet` to the dedicated signal thread which calls `sigset.wait()`
- `ctrlc_handler` now accepts `SigSet` as a parameter instead of constructing its own

##### `try_send` silently drops security events (`src/monitor/fanotify.rs`, `src/monitor/inotify.rs`)
- Both fanotify and inotify monitors used `let _ = event_tx.try_send(...)`, silently discarding filesystem events when the channel buffer (1024) was full — unacceptable for a security monitor
- Replaced with explicit `match` on `TrySendError`: logs `warn!` on `Full` (with the affected path) and logs `error!` + breaks the event loop on `Disconnected`

##### TOCTOU race in `path.exists()` before `File::open()` (`src/compare.rs`)
- Both `compare_entry` and `compare_event` checked `if !path.exists()` to detect deletions, then later called `File::open()` — an attacker could exploit the gap between these two calls
- Removed the `path.exists()` pre-check entirely; now attempts `File::open()` directly and matches on `ErrorKind::NotFound` to detect deletions

##### Hash file doesn't seek to position 0 (`src/baseline/hash.rs`)
- `blake3_hash_file` called `file.try_clone()` and read from the current file offset; if the file descriptor's cursor was moved by prior reads (e.g., metadata collection), the hash would be computed from the wrong position
- Added `reader.seek(std::io::SeekFrom::Start(0))` immediately after `try_clone()` and before the read loop
- Added `std::io::Seek` to imports

#### P1 — Important Fixes

##### `compare_event` skips xattr checking (`src/compare.rs`)
- `compare_entry` checked xattrs but `compare_event` did not — real-time monitoring missed xattr/SELinux context changes
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
- All `Mutex::lock()` calls used `if let Ok(...)`, silently ignoring poisoned mutexes — if any code panicked while holding a lock, rate limiting and cooldowns would permanently stop working
- Switched from `std::sync::Mutex` to `parking_lot::Mutex`, which does not poison and returns the guard directly
- All `if let Ok(mut x) = self.mutex.lock()` patterns replaced with direct `self.mutex.lock()` calls
- Added `parking_lot = "0.12"` to `Cargo.toml`

#### P2 — Performance

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
- Returned `VigilError::Database(rusqlite::Error::QueryReturnedNoRows)` — a misleading error type that hid the actual integrity failure reason
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
- `command_exists` shelled out to `which` — not available on all systems (e.g., minimal containers, some Debian installations)
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
- **`fuzz_config_parse`**: fuzzes `toml::from_str::<Config>()` — proves TOML config parsing never panics on arbitrary input
- **`fuzz_baseline_compare`**: fuzzes JSON deserialization of `BaselineEntry`, `ChangeType`, and `Severity::from_str` — proves baseline comparison types handle malformed input safely
- **`fuzz_scanner`**: fuzzes JSON deserialization of `ScanMode`, `MonitorBackend`, `PackageBackend`, `BaselineSource`, and `Severity::from_str` — proves scanner-related type parsing is robust

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
- `vigil init` — full baseline generation across all watch groups
- `vigil baseline refresh` — re-scan with optional path filtering
- `vigil baseline add/remove` — single-file baseline management
- `vigil baseline diff` — compare current state vs. baseline without updating
- `vigil baseline stats` — entry counts by source, last refresh time
- `vigil baseline export` — JSON export of all baseline entries
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
- `vigil doctor` — self-diagnostics (fanotify, root, config, DB, HMAC, D-Bus, package manager, signal socket)

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
