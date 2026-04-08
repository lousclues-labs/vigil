# Architecture

Vigil has one job. Detect filesystem boundary changes and record them.

---

## Big Picture

```
+--------------------------------------------------------------------------------+
|                                    VIGIL                                       |
|                                                                                |
|  +-----------------------------+          +----------------------------------+ |
|  | CLI process: vigil          |          | Daemon process: vigild           | |
|  | init, check, diff, status,  |          | long-running monitor             | |
|  | doctor, audit, log, config  |          |                                  | |
|  +-------------+---------------+          +----------------+-----------------+ |
|                |                                         |                    |
|                | one-shot commands                       | event loop          |
|                v                                         v                    |
|      +----------------------+                 +----------------------------+   |
|      | scanner.rs           |                 | monitor backend            |   |
|      | baseline scans       |                 | fanotify or inotify        |   |
|      +----------+-----------+                 +-------------+--------------+   |
|                 |                                           |                  |
|                 |                                           v                  |
|                 |                              +----------------------------+   |
|                 |                              | worker pool                |   |
|                 |                              | filter + compare + classify|   |
|                 |                              +-------------+--------------+   |
|                 |                                            |                  |
|                 v                                            v                  |
|      +----------------------+                 +----------------------------+   |
|      | baseline.db          |                 | alert dispatcher           |   |
|      | trusted file state   |                 | audit write + sinks        |   |
|      +----------+-----------+                 +------+------+------+-------+   |
|                 |                                     |      |      |          |
|                 |                                     |      |      +--> socket |
|                 |                                     |      +---------> JSON   |
|                 |                                     +---------------> journal |
|                 v                                                        + DBus |
|      +----------------------+                                                     |
|      | audit.db             |                                                     |
|      | append-only changes  |                                                     |
|      +----------------------+                                                     |
|                                                                                |
|  +------------------------------ control plane --------------------------------+ |
|  | control.rs listens on daemon.control_socket (default /run/vigil/control.sock) |
|  | methods: status, baseline_count, reload, scan, metrics_prometheus            |
|  | authentication: challenge-response with HMAC key when hmac_signing = true    |
|  | audit: logs peer PID/UID/GID via SO_PEERCRED; counts control_commands metric |
|  +-------------------------------------------------------------------------------+ |
+--------------------------------------------------------------------------------+
```

---

## Runtime Threads

`vigild` runs a small fixed set of threads.

- monitor thread in `src/monitor/fanotify.rs` or `src/monitor/inotify.rs`
- worker thread pool in `src/worker.rs`
- alert dispatcher thread in `src/alert/mod.rs`
- coordinator thread in `src/coordinator.rs`
- scan scheduler thread in `src/scan_scheduler.rs`
- control socket thread in `src/control.rs`

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
|-- bloom.rs                # Bloom filter for fast path membership reject.
|-- cli.rs                  # clap command tree and flags.
|-- control.rs              # Unix control socket command server.
|-- coordinator.rs          # Thread lifecycle and periodic coordinator loop.
|-- daemon.rs               # vigild binary entrypoint.
|-- doctor.rs               # System health diagnostics and health snapshot.
|-- error.rs                # Central error type.
|-- hash.rs                 # BLAKE3 hashing helpers.
|-- hmac.rs                 # HMAC signing and verification helpers.
|-- lib.rs                  # Daemon runtime orchestration.
|-- main.rs                 # CLI entrypoint and command dispatch.
|-- metrics.rs              # Runtime counters and snapshot serialization.
|-- package.rs              # Package manager detection and ownership query.
|-- scan_scheduler.rs       # Cron-based scan scheduling with croner.
|-- scanner.rs              # Scheduled scans and baseline refresh work.
|-- watch_index.rs          # Path to watch-group lookup index.
`-- worker.rs               # Event processing worker pipeline.
```

---

## Component Notes

These modules are easy to miss. They are core to the runtime.

- `src/control.rs` handles daemon RPC over Unix socket for `status`, `scan`, and reload actions. When HMAC signing is enabled, connections are authenticated via nonce-based challenge-response. All `reload` and `scan` commands are logged with peer credentials.
- `src/coordinator.rs` coordinates reload, snapshot writing, retention rotation, and watchdog heartbeats. Watchdog pings systemd on every loop iteration (~1s) independently of the 60-second housekeeping tick. Detects sustained event drops and logs evasion warnings. Verifies config file integrity on reload.
- `src/scan_scheduler.rs` parses cron strings with `croner` and executes scheduled scans.
- `src/worker.rs` processes monitor events and runs snapshot comparison. Debounced paths are re-checked via synthetic events. Logs self-protection warnings when config or HMAC key files are modified.
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
  -> worker::process_event()
  -> worker::process_event_inner()
  -> FileSnapshot::from_fd() or FileSnapshot::from_path()
  -> FileSnapshot::diff(&baseline_entry)
  -> alert dispatcher
  -> audit write always
  -> notification sinks if not suppressed
```

Comparison and classification run in `src/worker.rs` and `src/types/snapshot.rs`.

### 3) Scheduled Scan Pipeline

```
scan_scheduler::spawn()
  -> parse scanner.schedule with croner
  -> scanner::run_scan()
  -> diff against baseline
  -> enqueue alert payloads
```

Scheduled scans use `scanner.scheduled_mode`.

### 4) Control Socket Pipeline

```
control socket request
  -> challenge-response auth (if hmac_signing enabled)
  -> log peer credentials (PID, UID, GID)
  -> control::dispatch()
  -> status | baseline_count | reload | scan | metrics_prometheus
  -> log_control_action() for reload/scan
  -> JSON response
```

`vigil check --now` and status queries use this path when daemon mode is active.

---

## Comparison Model

Vigil compares current state to baseline with a file-descriptor-first pipeline.

```
open(path)
  -> fstat(fd)
  -> hash(fd)
  -> collect xattrs and security context
  -> diff snapshot against baseline
```

This lives in `FileSnapshot::from_fd`, `FileSnapshot::from_path`, and `FileSnapshot::diff`.
`worker::process_event_inner` drives the call sequence.

This model reduces TOCTOU exposure because metadata and hash come from the same opened object.

---

## Database Schema

Vigil uses two SQLite files in practice.

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

---

## File Locations

| Purpose | Default Path |
|---------|--------------|
| System config | `/etc/vigil/vigil.toml` |
| User config | `~/.config/vigil/vigil.toml` |
| Baseline database | `/var/lib/vigil/baseline.db` |
| Audit database | `/var/lib/vigil/audit.db` |
| Runtime dir | `/run/vigil` |
| PID file | `/run/vigil/vigild.pid` |
| Control socket | `/run/vigil/control.sock` |
| Health snapshot | `/run/vigil/health.json` |
| Metrics snapshot | `/run/vigil/metrics.json` |
| State snapshot | `/run/vigil/state.json` |
| JSON alert log | `/var/log/vigil/alerts.json` |

---

Vigil architecture is intentionally small. You should be able to trace any alert from event source to audit row.
