# Architecture

VigilBaseline has one job. Detect filesystem boundary changes and record them.

---

## Big Picture

```
+------------------------------------------------------------------------------------+
|                                      VIGILBASELINE                                |
|                                                                                    |
|  +-----------------------------+            +----------------------------------+   |
|  | CLI process: vigil          |            | Daemon process: vigild           |   |
|  | init, check, diff, status,  |            | long-running monitor             |   |
|  | doctor, audit, log, config  |            |                                  |   |
|  +-------------+---------------+            +----------------+-----------------+   |
|                |                                           |                      |
|                | one-shot commands                         | event loop            |
|                v                                           v                      |
|      +----------------------+                   +----------------------------+     |
|      | scanner.rs           |                   | monitor backend            |     |
|      | baseline scans       |                   | fanotify or inotify        |     |
|      +----------+-----------+                   +-------------+--------------+     |
|                 |                                             |                    |
|                 |                                             v                    |
|                 |                                +----------------------------+     |
|                 |                                | worker pool                |     |
|                 |                                | filter + compare + classify|     |
|                 |                                +-------------+--------------+     |
|                 |                                              |                    |
|                 |                                              v                    |
|                 |                                +----------------------------+     |
|                 |                                | Detection WAL              |     |
|                 |                                | detections.wal             |     |
|                 |                                | crash-safe binary log      |     |
|                 |                                +------+----------+----------+     |
|                 |                                       |          |                |
|                 |                              +--------+--+  +---+----------+     |
|                 |                              | AuditWriter|  | SinkRunner   |     |
|                 |                              | -> audit DB |  | -> sinks     |     |
|                 v                              +------+------+  +--+--+--+----+     |
|      +----------------------+                        |             |  |  |          |
|      | baseline.db          |                        |             |  |  +--> socket |
|      | trusted file state   |                        |             |  +-----> JSON   |
|      +----------+-----------+                        |             +-------> journal |
|                 |                                    |                        + DBus |
|                 v                                    v                              |
|      +----------------------+              +----------------------+                 |
|      | audit.db             |              | (fallback: alert_tx  |                 |
|      | append-only changes  |              |  when WAL disabled   |                 |
|      +----------------------+              |  or append fails)    |                 |
|                                            +----------------------+                 |
|                                                                                    |
|  +------------------------------- control plane ----------------------------------+ |
|  | control.rs listens on daemon.control_socket (default /run/vigil/control.sock)  | |
|  | methods: status, baseline_count, reload, scan, metrics_prometheus              | |
|  | authentication: challenge-response with HMAC key when hmac_signing = true      | |
|  | audit: logs peer PID/UID/GID via SO_PEERCRED; counts control_commands metric   | |
|  +--------------------------------------------------------------------------------+ |
+------------------------------------------------------------------------------------+
```

---

## Runtime Threads

`vigild` runs a small fixed set of threads, all owned by `DaemonRuntime` (in `src/lib.rs`).

- monitor thread in `src/monitor/fanotify.rs` or `src/monitor/inotify.rs`
- worker thread pool in `src/worker.rs` — each worker holds a `WorkerContext` struct
- WAL audit writer thread (`vigil-wal-audit`) in `src/wal/audit_writer.rs` — drains WAL to audit DB (when WAL enabled)
- WAL sink runner thread (`vigil-wal-sinks`) in `src/wal/sink_runner.rs` — dispatches alerts from WAL to sinks (when WAL enabled)
- alert dispatcher thread in `src/alert/mod.rs` — runs `AlertDispatcher::run()` (handles fallback alerts; skips audit writes when WAL active)
- baseline writer thread in `src/lib.rs` — batches auto-rebaseline writes
- coordinator thread in `src/coordinator.rs` — runs a `Coordinator` struct's tick loop
- scan scheduler thread in `src/scan_scheduler.rs`
- control socket thread in `src/control.rs` — dispatches via a `ControlHandler` struct

The `DaemonRuntime` owns all `JoinHandle`s, channel senders, and shutdown state.
The coordinator owns lifecycle coordination and periodic housekeeping.

---

## Module Structure

```
src/
|-- alert/
|   |-- mod.rs              # Alert engine. Suppression and channel dispatch.
|   |-- dbus.rs             # Desktop notifications via notify-send with urgency mapping.
|   |-- journal.rs          # journald/syslog logging.
|   |-- json_log.rs         # Append-only JSON alert file.
|   |-- remote_syslog.rs    # Remote syslog forwarding over TCP or UDP.
|   `-- socket.rs           # Unix signal socket event writer.
|
|-- config/
|   |-- mod.rs              # Config model, loading, validation, defaults.
|   `-- diff.rs             # Config diff for SIGHUP reload logging.
|
|-- db/
|   |-- mod.rs              # SQLite open, pragma setup, integrity, checkpoint.
|   |-- schema.rs           # Schema creation: baseline, audit_log, config_state.
|   |-- baseline_ops.rs     # Baseline CRUD operations.
|   |-- audit_ops.rs        # Audit queries, chain verification, statistics.
|   `-- migrate.rs          # Baseline migration v1 JSON blobs to v2 flat columns.
|
|-- filter/
|   |-- mod.rs              # Event filter: debounce, self-exclusion, path matching.
|   `-- exclusion.rs        # globset-based exclusion engine.
|
|-- monitor/
|   |-- mod.rs              # Backend selection and fallback logic.
|   |-- fanotify.rs         # fanotify monitor thread and event decoding.
|   `-- inotify.rs          # inotify fallback monitor and recursive watches.
|
|-- types/
|   |-- mod.rs              # Re-exports.
|   |-- alert.rs            # Alert struct.
|   |-- baseline.rs         # BaselineEntry and BaselineSource.
|   |-- change.rs           # Change enum.
|   |-- config_types.rs     # OutputFormat, ScanMode, MonitorBackend, and others.
|   |-- content.rs          # ContentInfo.
|   |-- event.rs            # File event structs.
|   |-- identity.rs         # FileIdentity.
|   |-- permissions.rs      # PermissionInfo.
|   |-- security.rs         # SecurityInfo.
|   `-- snapshot.rs         # FileSnapshot capture and diff logic.
|
|-- wal/
|   |-- mod.rs              # Detection WAL: file format, DetectionWal, DetectionRecord.
|   |-- audit_writer.rs     # AuditWriter: WAL -> audit DB consumer thread.
|   `-- sink_runner.rs      # SinkRunner: WAL -> alert sink dispatch thread.
|
|-- bloom.rs                # Bloom filter for fast path membership reject.
|-- cli.rs                  # clap command tree and flags.
|-- control.rs              # Unix control socket. ControlHandler struct dispatches methods.
|-- coordinator.rs          # Coordinator struct with tick loop and named housekeeping methods.
|-- daemon.rs               # vigild binary entrypoint.
|-- doctor.rs               # System health diagnostics and health snapshot.
|-- error.rs                # Central error type.
|-- hash.rs                 # BLAKE3 hashing helpers.
|-- hmac.rs                 # HMAC signing and verification helpers.
|-- lib.rs                  # Daemon struct + DaemonRuntime (start/wait/drain lifecycle).
|-- main.rs                 # CLI entrypoint and command dispatch.
|-- metrics.rs              # Runtime counters and snapshot serialization.
|-- package.rs              # Package manager detection and ownership query.
|-- scan_scheduler.rs       # Cron-based scan scheduling with croner.
|-- scanner.rs              # Scheduled scans and baseline refresh work.
|-- watch_index.rs          # Path to watch-group lookup index.
`-- worker.rs               # WorkerContext struct: evaluate, process_safe, drain_debounced.
```

---

## Component Notes

These modules are easy to miss. They are core to the runtime.

- `src/lib.rs` defines `Daemon` (config, connections, startup) and `DaemonRuntime` (thread ownership, channel lifecycle). `Daemon::run()` is ~11 lines: harden, record binary hash, start runtime, wait, drain. `DaemonRuntime::start()` wires all channels, spawns all threads (including WAL AuditWriter and SinkRunner when `detection_wal = true`), runs WAL self-test, calls `AuditWriter::recover()`, emits `sd_notify(Ready)`. `DaemonRuntime::drain()` joins threads in dependency order: workers → baseline_writer → audit_writer → sink_runner → alert → coordinator → scan_scheduler → final WAL truncation. A `send_watchdog_heartbeat()` helper sends `sd_notify(Watchdog)` guarded by `is_notify_socket_safe()` and is called throughout pre-flight and startup to prevent systemd from killing the daemon before the coordinator thread exists.
- `src/wal/mod.rs` defines `DetectionWal` — the crash-safe binary WAL for detection records. The WAL decouples detection output from audit persistence and alert dispatch. Workers, scan scheduler, and debounce write `DetectionRecord` entries via `append()` (pwrite + fdatasync). Two independent consumer threads read entries via `iter_unconsumed()` with gap-scanning recovery: the AuditWriter persists to the audit DB with priority ordering; the SinkRunner dispatches to alert sinks with bounded cooldowns. Entries have independent `audit_done` / `sink_done` flags — flag updates via `mark_flag()` are non-atomic read-modify-write operations protected by the global `write_lock` to prevent concurrent flag overwrites. The WAL uses CRC32 checksums for crash recovery and optional per-entry HMAC-SHA256 for tamper detection. Gap scanning is bounded by `MAX_GAP_BYTES` (64KB) to prevent adversarial DoS via large zeroed regions. File permissions are enforced at 0o600. When the WAL is disabled or full, detections fall back to the pre-WAL `alert_tx` channel.
- `src/wal/audit_writer.rs` defines `AuditWriter` — the `vigil-wal-audit` background thread. Consumes WAL entries sorted by severity (Critical first), writes to audit DB with HMAC chain integrity. Features: sequence gap detection (`detections_wal_gaps` metric), crash recovery with deduplication, DB connection reopen after 3 consecutive failures, periodic compaction every 60s. On shutdown, drains completely before exiting — no entries can be lost.
- `src/wal/sink_runner.rs` defines `SinkRunner` — the `vigil-wal-sinks` background thread. Consumes WAL entries sorted by sequence, dispatches to configured alert sinks. Uses an `LruCache<String, Instant>` bounded to 10,000 entries for path cooldowns. Suppressed entries are marked `sink_done` immediately (no infinite retry). Operates independently of AuditWriter.
- `src/control.rs` defines `ControlHandler` — a struct holding metrics, state, reload flag, scan trigger, DB path, HMAC key, and auth flag. Methods: `handle_connection` (auth-or-read, dispatch, write), `authenticate_and_read` (challenge-response), `read_request`, `write_response`, `dispatch`. When HMAC signing is enabled, connections are authenticated via nonce-based challenge-response. All `reload` and `scan` commands are logged with peer credentials.
- `src/coordinator.rs` defines `CoordinatorConfig` (spawn arguments) and `Coordinator` (runtime state). The main loop calls `handle_reload()` on flag and `tick()` every 60 seconds. `tick()` sequences: `check_baseline_db_identity`, `check_audit_db_identity`, `check_mount_evasion`, `notify_watchdog`, `detect_clock_anomaly`, `rotate_audit_log`, `notify_watchdog`, `write_snapshots`, `notify_watchdog`, `check_backpressure`, `check_event_drops`, `maybe_checkpoint_wal`. Watchdog pings are interleaved between expensive sub-methods within `tick()` and also sent on every loop iteration (~1s) via `notify_watchdog()`.
- `src/worker.rs` defines `WorkerSpawnArgs` (spawn arguments) and `WorkerContext` (per-worker state: connection, config, watch index, metrics, filter, LRU cache, generation tracker). Key methods: `evaluate` (cache lookup + baseline + snapshot + diff + classify), `process_safe` (catch_unwind wrapper), `drain_debounced` (debounced re-check). Logs self-protection warnings when config or HMAC key files are modified.
- `src/alert/mod.rs` defines `AlertDispatcher` with extracted methods: `record_audit` (DB write + error recovery + retry buffer + DB reopen) and `dispatch_to_sinks` (sink iteration). `run()` is ~17 lines.
- `src/scan_scheduler.rs` parses cron strings with `croner` and executes scheduled scans.
- `src/bloom.rs` provides fast probabilistic reject for unrelated paths.
- `src/watch_index.rs` maps a path to the most specific watch group.
- `src/metrics.rs` stores counters. Coordinator writes `metrics.json`. Doctor writes `health.json`.
- `src/hmac.rs` signs and verifies audit entries with HMAC-SHA256. Audit HMAC data includes the previous chain hash for deletion detection.
- `src/config/diff.rs` reports config changes on SIGHUP reload.
- `src/db/migrate.rs` migrates baseline schema from v1 blobs to v2 flattened columns.
- `src/alert/remote_syslog.rs` sends RFC5424 alerts to remote syslog.

---

## Data Flow

### 1) Baseline Creation (`vigil init`)

```
vigil init
  -> load config
  -> open baseline.db and create schema
  -> walk watched paths
  -> FileSnapshot::from_path()
  -> baseline_ops::upsert()
```

Result: `baseline` table is populated with trusted file state.

### 2) Real-time Event Pipeline (`vigild`)

```
filesystem event
  -> monitor backend (fanotify or inotify)
  -> WorkerContext::process_safe(event)
  -> WorkerContext::evaluate(event)
     -> cache lookup or baseline_ops::get_by_path()
     -> process_event_inner()
     -> FileSnapshot::from_fd() or FileSnapshot::from_path()
     -> FileSnapshot::diff(&baseline_entry)
  -> try_auto_rebaseline() (if package update detected)
  -> DetectionWal::append() (when WAL enabled)
     |
     +-> AuditWriter thread (vigil-wal-audit)
     |   -> priority sort (Critical first)
     |   -> insert_audit_entry() with HMAC chain
     |   -> mark_audit_done()
     |
     +-> SinkRunner thread (vigil-wal-sinks)
         -> suppression check (cooldown + rate limit)
         -> dispatch_to_sinks() (journal, JSON, desktop, socket)
         -> mark_sink_done()

  [fallback when WAL disabled or append fails]:
  -> alert_tx.send(AlertPayload)
  -> AlertDispatcher::record_audit() + dispatch_to_sinks()
```

Comparison and classification run in `src/worker.rs` (`WorkerContext`) and `src/types/snapshot.rs`.
The WAL decouples detection from persistence — a blocked audit DB write cannot delay alert delivery.

### 3) Scheduled Scan Pipeline

```
scan_scheduler::spawn()
  -> parse scanner.schedule with croner
  -> scanner::run_scan()
  -> diff against baseline
  -> DetectionWal::append() with DetectionSource::ScheduledScan (when WAL enabled)
  -> fallback: alert_tx.send(AlertPayload)
```

On-demand scans (via control socket) use `DetectionSource::OnDemandScan`.
Scheduled scans use `scanner.scheduled_mode`.

### 4) Control Socket Pipeline

```
control socket request
  -> ControlHandler::handle_connection(stream)
  -> log peer credentials (PID, UID, GID)
  -> ControlHandler::authenticate_and_read() or read_request()
  -> ControlHandler::dispatch(method, request)
  -> handle_status | handle_baseline_count | handle_reload | handle_scan | handle_metrics_prometheus
  -> log_control_action() for reload/scan
  -> ControlHandler::write_response()
```

`vigil check --now` and status queries use this path when daemon mode is active.

---

## Comparison Model

VigilBaseline compares current state to baseline with a file-descriptor-first pipeline.

```
open(path)
  -> fstat(fd)
  -> hash(fd)
  -> collect xattrs and security context
  -> diff snapshot against baseline
```

This lives in `FileSnapshot::from_fd`, `FileSnapshot::from_path`, and `FileSnapshot::diff`.
`WorkerContext::evaluate` → `process_event_inner` drives the call sequence.

This model reduces TOCTOU exposure because metadata and hash come from the same opened object.

---

## Database Schema

VigilBaseline uses two SQLite files in practice.

- baseline data in `baseline.db`
- audit data in `audit.db`

### `baseline` table (v2 flattened)

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | autoincrement |
| `path` | TEXT NOT NULL UNIQUE | absolute path |
| `inode` | INTEGER NOT NULL | inode number |
| `device` | INTEGER NOT NULL | device number |
| `file_type` | TEXT NOT NULL | default `regular` |
| `symlink_target` | TEXT | nullable |
| `hash` | TEXT NOT NULL | BLAKE3 hex |
| `size` | INTEGER NOT NULL | bytes |
| `mode` | INTEGER NOT NULL | permission bits |
| `owner_uid` | INTEGER NOT NULL | owner uid |
| `owner_gid` | INTEGER NOT NULL | owner gid |
| `capabilities` | TEXT | nullable |
| `xattrs_json` | TEXT NOT NULL | default `{}` |
| `security_context` | TEXT NOT NULL | default empty string |
| `mtime` | INTEGER NOT NULL | unix timestamp |
| `package` | TEXT | nullable owning package |
| `source` | TEXT NOT NULL | `package_manager`, `manual`, `auto_scan` |
| `added_at` | INTEGER NOT NULL | unix timestamp |
| `updated_at` | INTEGER NOT NULL | unix timestamp |

Constraints and indexes:
- `UNIQUE(path)`
- `CHECK(source IN ('package_manager', 'manual', 'auto_scan'))`
- index `idx_baseline_path` on `path`

### `audit_log` table

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | autoincrement |
| `timestamp` | INTEGER NOT NULL | unix epoch |
| `path` | TEXT NOT NULL | changed path |
| `changes_json` | TEXT NOT NULL | serialized change array |
| `severity` | TEXT NOT NULL | low, medium, high, critical |
| `monitored_group` | TEXT | nullable watch group name |
| `process_json` | TEXT | nullable process metadata |
| `package` | TEXT | nullable package metadata |
| `maintenance` | INTEGER NOT NULL | boolean, default 0 |
| `suppressed` | INTEGER NOT NULL | boolean, default 0 |
| `hmac` | TEXT | nullable HMAC signature |
| `chain_hash` | TEXT NOT NULL | BLAKE3 chain hash |

Indexes:
- `idx_audit_ts` on `timestamp`
- `idx_audit_path` on `path`
- `idx_audit_severity` on `severity`
- `idx_audit_group` on `monitored_group`

### `config_state` table

`config_state` is a small key value table.
Columns are `key`, `value`, and `updated_at`.

Known keys:

| Key | Purpose |
|-----|---------|
| `last_baseline_refresh` | timestamp of last baseline build |
| `baseline_initialized` | `"true"` after first successful init; prevents silent auto-reinit on empty baseline |
| `baseline_hmac` | HMAC of all baseline entries for at-rest tamper detection |
| `config_file_hmac` | HMAC of config file contents for reload integrity verification |
| `wal_instance_nonce` | hex-encoded 32-byte nonce from the current WAL file; used by AuditWriter crash recovery to prevent cross-instance replay |

---

## Design Decisions

### 1) `globset` for exclusions

`globset` compiles glob patterns once and matches fast at runtime.
This avoids repeated parse cost in hot paths.

### 2) `croner` for schedules

`croner` parses cron expressions used by scheduled scans.
This keeps scheduling simple and explicit.

### 3) `lru` for baseline cache

Workers use an LRU cache for baseline lookups.
This reduces repeated DB reads on noisy paths.

### 4) `arc-swap` for config

`ArcSwap<Config>` provides lock-free reads in hot paths.
Reload swaps the whole config atomically.

### 5) `parking_lot` for mutex and rwlock

`parking_lot` gives lower overhead locks for high-frequency paths.
It is used in alert suppression state and daemon state.

### 6) `crossbeam-channel` for thread boundaries

Channels carry events and scan triggers between threads.
The flow stays explicit and easy to trace.

### 7) Detection WAL for crash-safe detection output

The Detection WAL (`src/wal/mod.rs`) decouples detection writes from audit DB persistence and alert dispatch. Workers write `DetectionRecord` entries to a binary log with CRC32 checksums and optional per-entry HMAC. Two independent background threads consume entries: AuditWriter (priority-ordered audit persistence with crash recovery) and SinkRunner (alert dispatch with bounded cooldowns). This architecture eliminates the single-threaded bottleneck where a blocked audit write could delay alerts, and ensures zero detection loss across daemon crashes, DB failures, and transient I/O stalls.

### 8) `rmp-serde` for WAL payload serialization

MessagePack is compact, fast, and schema-flexible. WAL entries use `rmp_serde::to_vec()` for serialization and `rmp_serde::from_slice()` for deserialization. This keeps entries small and parsing fast during gap-scanning recovery.

### 9) `crc32fast` for WAL entry integrity

CRC32 (ISO 3309) with hardware acceleration. Each WAL entry includes a trailing CRC32 over all preceding bytes. Gap-scanning recovery uses CRC validation to skip corrupted entries and find the next valid entry by advancing byte-by-byte. Gap scanning is bounded by `MAX_GAP_BYTES` (64KB) — if the scanner advances more than 64KB without finding a valid entry, it stops and returns entries recovered so far, preventing adversarial DoS via large corrupted regions.

---

## File Locations

| Purpose | Default Path |
|---------|--------------|
| System config | `/etc/vigil/vigil.toml` |
| User config | `~/.config/vigil/vigil.toml` |
| Baseline database | `/var/lib/vigil/baseline.db` |
| Audit database | `/var/lib/vigil/audit.db` |
| Detection WAL (non-persistent) | `/run/vigil/detections.wal` |
| Detection WAL (persistent) | `/var/lib/vigil/detections.wal` |
| Runtime dir | `/run/vigil` |
| PID file | `/run/vigil/vigild.pid` |
| Control socket | `/run/vigil/control.sock` |
| Health snapshot | `/run/vigil/health.json` |
| Metrics snapshot | `/run/vigil/metrics.json` |
| State snapshot | `/run/vigil/state.json` |
| JSON alert log | `/var/log/vigil/alerts.json` |

---

## Startup Sequence

The daemon startup path follows two stages: `Daemon::run()` handles pre-flight checks, then delegates to `DaemonRuntime`.

**`Daemon::run()` (pre-flight):**

1. `harden_process()` — sets umask, disables ptrace, locks privileges
2. `raise_nofile_limit()` — attempts to raise `RLIMIT_NOFILE`
3. `send_watchdog_heartbeat()` — keep systemd alive before slow binary hash
4. `record_binary_hash()` — BLAKE3 hash of `/proc/self/exe`
5. `send_watchdog_heartbeat()` — keep systemd alive before baseline health check
6. `log_startup_diagnostics()` — log baseline DB path, existence, file size, readability, and HMAC signing status
7. `ensure_baseline_health()` — integrity check, emptiness check (with version-upgrade recovery), HMAC verification. Sends watchdog heartbeats before and after each `build_initial_baseline()` call. The scanner itself sends heartbeats every 5,000 files, after transaction COMMIT, and after HMAC computation.
8. `send_watchdog_heartbeat()` — keep systemd alive before thread wiring

**`DaemonRuntime::start()` (thread wiring):**

9. Set up signal mask and spawn signal thread
10. Start monitor backend (fanotify with inotify fallback) + watchdog heartbeat
11. Open Detection WAL (when `detection_wal = true`): create file with 0o600 perms, write header, store instance nonce in baseline DB, run self-test (append sentinel, read back, verify, mark consumed) + watchdog heartbeat
12. Spawn AuditWriter: open audit DB connection, call `recover()` (nonce verification + dedup replay) + watchdog heartbeat
13. Spawn SinkRunner with configured alert sinks
14. Spawn worker pool (`WorkerSpawnArgs` with WAL handle), baseline writer, alert dispatcher (with `wal_active` flag) + watchdog heartbeat
15. Spawn coordinator (`CoordinatorConfig` with WAL identity for TOCTOU checking) + watchdog heartbeat
16. `send_watchdog_heartbeat()` + `sd_notify(Ready)` — signal systemd that startup is complete
17. Spawn control socket (`ControlHandler`)

**`DaemonRuntime::wait_for_shutdown()` + `DaemonRuntime::drain()`:**

18. Block on shutdown signal
19. Send `sd_notify(Stopping)`, signal scan scheduler
20. Drop event_tx → join workers (no more WAL appends after this)
21. Drop alert_tx → join baseline writer
22. Join AuditWriter (drains all remaining WAL entries to audit DB)
23. Join SinkRunner (dispatches all remaining WAL entries to sinks)
24. Join alert dispatcher, coordinator, scan scheduler
25. Final `wal.truncate_consumed()` — compact or reset WAL file
26. Cleanup PID file

If any step before `sd_notify(Ready)` fails, the daemon exits with the error printed to both tracing and stderr.

---

## Desktop Notifications

`notify_desktop()` checks for `notify-send` availability once using `OnceLock<bool>`. If the binary is not found in `PATH` (common on headless servers), all future notification calls are skipped and a single debug-level log message is emitted. The `vigil doctor` command also checks for `notify-send` availability and suggests the correct package for the detected distribution.

---

VigilBaseline architecture is intentionally small. You should be able to trace any alert from event source to audit row.
