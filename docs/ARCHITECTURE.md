# Architecture

How Vigil is built. The actual structure, not the marketing version.

---

## Big Picture

```
+------------------------------------------------------------------------+
|                                  VIGIL                                 |
|                                                                        |
|  +-------------------+                    +--------------------------+  |
|  |   vigil (CLI)     |                    |     vigild (daemon)      |  |
|  | one-shot commands |                    | long-running event loop  |  |
|  +---------+---------+                    +-------------+------------+  |
|            |                                              |             |
|            | init/check/baseline/log/config               | watch       |
|            v                                              v             |
|  +----------------------+                      +---------------------+  |
|  |   Baseline Engine    |<-------------------->|   Monitor Backend   |  |
|  | hash + metadata      |                      | fanotify / inotify  |  |
|  +----------+-----------+                      +----------+----------+  |
|             |                                             |             |
|             v                                             v             |
|  +----------------------+                      +---------------------+  |
|  |  SQLite (WAL mode)   |<-------------------->| Comparison Engine   |  |
|  | baseline/audit/state |                      | open->fstat->hash   |  |
|  +----------+-----------+                      +----------+----------+  |
|             ^                                             |             |
|             |                                             v             |
|             |                                  +---------------------+  |
|             |                                  |   Alert Pipeline    |  |
|             |                                  | cooldown/rate-limit |  |
|             |                                  +----+----+----+-----+  |
|             |                                       |    |    |        |
|             |                                       |    |    +------> Unix signal socket
|             |                                       |    +-----------> JSON alert log
|             |                                       +---------------> journald/syslog
|             |                                                      -> desktop notification (notify-send)
+------------------------------------------------------------------------+
```

Vigil has one purpose: detect structural filesystem changes and report them.
This is Principle I (Watch, Don't Act) and Principle VII (Boundaries, Not Intelligence).

---

## Two Binaries, One Purpose

```
+-----------------------------------------------------------------------+
| $ vigil <command>                     $ vigild                         |
| one-shot CLI                          daemon entrypoint               |
|                                                                       |
| +----------------------+             +------------------------------+  |
| | Parse args (clap)    |             | Load config + open DB        |  |
| | Execute command      |             | Start monitor backend         |  |
| | Exit                 |             | Event loop until signal       |  |
| +----------+-----------+             +---------------+--------------+  |
|            |                                         |                 |
|            +------------- both use same core library +                 |
|                               (src/lib.rs)                             |
+-----------------------------------------------------------------------+
```

- `vigil` is the operator-facing CLI for init, checks, baseline updates, log queries, diagnostics.
- `vigild` is the daemon entrypoint used by systemd for real-time monitoring.
- Both use the same modules and same database schema.

This is Principle VIII (Vigil Stands Alone): small pieces, explicit behavior.

---

## Module Structure

```
src/
|-- main.rs                  # CLI entrypoint, command dispatch
|-- daemon.rs                # Daemon binary entrypoint (vigild)
|-- lib.rs                   # Daemon runtime loop and orchestration
|-- cli.rs                   # clap command tree and flags
|-- config.rs                # TOML config types, defaults, loading, validation
|-- types.rs                 # Domain types: severity, change, baseline, alert
|-- error.rs                 # Central error type (thiserror)
|-- compare.rs               # TOCTOU-hardened compare pipeline
|-- scanner.rs               # Scheduled scans (incremental/full)
|-- package.rs               # Package manager detection and ownership query
|
|-- baseline/
|   |-- mod.rs               # Baseline lifecycle: init/refresh/diff/add/remove/stats
|   |-- hash.rs              # BLAKE3 hashing helpers
|   `-- metadata.rs          # File metadata + xattr collection
|
|-- db/
|   |-- mod.rs               # SQLite open/configure/checkpoint/integrity
|   |-- schema.rs            # Schema creation (baseline, audit_log, config_state)
|   `-- ops.rs               # Baseline/audit/config_state CRUD ops
|
|-- monitor/
|   |-- mod.rs               # Backend selection + fallback logic
|   |-- fanotify.rs          # fanotify monitor thread and event decoding
|   |-- inotify.rs           # inotify fallback monitor and recursive watches
|   `-- filter.rs            # Exclusions, self-filtering, per-path debounce
|
`-- alert/
    |-- mod.rs               # Alert engine: suppression + channel dispatch
    |-- dbus.rs              # notify-send desktop notifications
    |-- journal.rs           # journald/syslog logging
    |-- json_log.rs          # append-only JSON alert file
    `-- socket.rs            # Unix signal socket event writer
```

---

## Data Flow

### 1) `vigil init` Baseline Creation

```
operator runs: vigil init
        |
        v
+------------------------+
| load config layers     |
+-----------+------------+
            |
            v
+------------------------+
| open SQLite (WAL)      |
| create schema if needed|
+-----------+------------+
            |
            v
+------------------------+
| expand watch groups    |
| walk files             |
+-----------+------------+
            |
            v
+------------------------+
| open file descriptor   |
| fstat(fd)              |
| blake3 hash(fd)        |
| read xattrs/context    |
+-----------+------------+
            |
            v
+------------------------+
| upsert baseline rows   |
| record refresh state   |
+------------------------+
```

### 2) Real-Time Monitoring

```
filesystem event
      |
      v
+------------------------+
| fanotify or inotify    |
+-----------+------------+
            |
            v
+------------------------+
| event filter           |
| - exclusions           |
| - self-exclusion       |
| - per-path debounce    |
+-----------+------------+
            |
            v
+------------------------+
| baseline lookup        |
| path -> baseline row   |
+-----------+------------+
            |
            v
+------------------------+
| compare_event()        |
| open -> fstat -> hash  |
| classify change types  |
+-----------+------------+
            |
            v
+------------------------+
| alert engine           |
| audit log ALWAYS write |
| suppression for notify |
+----+----+----+----+----+
     |    |    |    |
     |    |    |    +--> signal socket
     |    |    +-------> JSON log
     |    +------------> desktop notify
     +-----------------> journald/syslog
```

### 3) Scheduled Scan (`vigil check`)

```
operator/systemd timer
        |
        v
+------------------------+
| choose mode            |
| incremental or full    |
+-----------+------------+
            |
            v
+------------------------+
| lower process priority |
| ioprio=idle, nice=19   |
+-----------+------------+
            |
            v
+------------------------+
| iterate baseline rows  |
| if incremental: mtime  |
| unchanged -> skip hash |
+-----------+------------+
            |
            v
+------------------------+
| compare_entry()        |
| dispatch alerts        |
| collect scan counters  |
+------------------------+
```

---

## Comparison Model (TOCTOU-Hardened)

Vigil compares files with an open-first pipeline:

```
1) open(path)            -> pins inode/device for this fd
2) fstat(fd)             -> metadata from pinned object
3) blake3_hash_file(fd)  -> hash from same pinned object
4) compare with baseline -> classify changed fields
```

Why this matters:
- Path-based reopen introduces race windows.
- fd-based stat+hash keeps metadata and content tied to the same object.
- Inode/device changes are explicit first-class signals.

This is Principle III (Determinism Over Heuristics) and Principle XII (The Baseline Is Sacred).

---

## Monitor Backends

| Backend | Strengths | Limits | When Used |
|---------|-----------|--------|-----------|
| `fanotify` | mount-wide visibility, broad coverage | requires `CAP_SYS_ADMIN` | default backend |
| `inotify` | works without `CAP_SYS_ADMIN`, widely available | limited by watch count, reduced cross-user visibility, recursive watch complexity | automatic fallback |

Fallback logic:
1. Start selected backend from config (`fanotify` by default).
2. If fanotify init/mark fails, log warning and fall back to inotify.
3. Continue monitoring with explicit warnings about blind spots.

Blind spots during fallback are surfaced intentionally. That is Principle X (Fail Open, Fail Loud).

---

## Alert Pipeline

```
change result
   |
   v
+-----------------------------+
| is_suppressed()?            |
| - maintenance window        |
| - per-path cooldown         |
| - per-minute rate limit     |
+---------------+-------------+
                |
                v
+-----------------------------+
| insert_audit_entry() ALWAYS |
| (suppressed or not)         |
+---------------+-------------+
                |
         +------+------+
         | not suppressed?
         v
+-----------------------------+
| dispatch channels           |
| journald, JSON, desktop,    |
| signal socket               |
+-----------------------------+
```

Important invariant: suppression affects notifications, not truth.
Audit rows are always written. This is Principle XIII (The Audit Trail Never Lies).

---

## Database Schema

Vigil uses SQLite with WAL mode (`journal_mode=WAL`) and three tables.

### `baseline`

Stores trusted state per file.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | autoincrement |
| `path` | TEXT NOT NULL | absolute path |
| `hash` | TEXT NOT NULL | BLAKE3 hex |
| `size` | INTEGER NOT NULL | bytes |
| `permissions` | INTEGER NOT NULL | mode bits |
| `owner_uid`/`owner_gid` | INTEGER NOT NULL | ownership |
| `mtime` | INTEGER NOT NULL | unix timestamp |
| `inode`/`device` | INTEGER NOT NULL | replacement detection |
| `xattrs` | TEXT NOT NULL | serialized xattrs |
| `security_context` | TEXT NOT NULL | SELinux/AppArmor context |
| `package` | TEXT | package owner if known |
| `source` | TEXT NOT NULL | `package_manager|manual|auto_scan` |
| `added_at`/`updated_at` | INTEGER NOT NULL | timestamps |

Constraints and indexes:
- `UNIQUE(path, device, inode)`
- `CHECK(source IN ('package_manager','manual','auto_scan'))`
- indexes on `path`, `hash`, `package`, `(device,inode)`

### `audit_log`

Append-only change history.

| Column | Purpose |
|--------|---------|
| `timestamp`, `event_type`, `path`, `change_type`, `severity` | core event identity |
| old/new hash, perms, owner, inode | forensic diff fields |
| `package`, `package_update` | package context |
| `maintenance_window`, `suppressed` | suppression metadata |
| `monitored_group` | watch group source |
| `hmac` | optional integrity tag |

### `config_state`

Small state KV store (`key`, `value`, `updated_at`) for runtime markers:
- `last_baseline_refresh`
- `maintenance_window_active`
- `maintenance_window_started`
- daemon metadata

---

## Config Loading Order

Layered precedence (highest wins):

```
+-------------------------------+
| CLI --config /path/file.toml  |  highest
+-------------------------------+
| $VIGIL_CONFIG                 |
+-------------------------------+
| ~/.config/vigil/vigil.toml    |
+-------------------------------+
| /etc/vigil/vigil.toml         |  lowest
+-------------------------------+
```

Load order in code is lowest-to-highest so later files override earlier ones.
This is Principle IX (No Configuration Required for Correct Operation): if no file exists,
Vigil uses built-in defaults with default watch groups.

---

## Design Decisions

These are not accidents. They are choices.

### 1) BLAKE3 over SHA-256

Why:
- Faster hashing for large tree scans.
- Strong cryptographic properties for integrity use.
- Smaller runtime cost for frequent compare operations.

Why not SHA-256:
- Slower for this workload.
- No practical gain for Vigil's change-detection model.

Principle reference: Principle XI (Complexity Is a Vulnerability), Principle III.

### 2) SQLite over flat files

Why:
- Atomic updates, constraints, indexed queries, WAL durability.
- Reliable audit trail and state management.

Why not flat JSON/TOML files:
- No constraints, brittle concurrent writes, poor query performance.
- Harder integrity and recovery behavior.

Principle reference: Principle XIII (Audit Trail), Principle X.

### 3) fanotify with inotify fallback

Why:
- fanotify gives better coverage when privileges allow.
- inotify keeps Vigil usable without elevated capabilities.

Why not fanotify-only:
- Hard failure on systems without `CAP_SYS_ADMIN` violates usability.

Why not inotify-only:
- Reduced coverage where fanotify is available.

Principle reference: Principle X (Fail Open, Fail Loud).

### 4) `notify-send` wrapper over direct D-Bus library

Why:
- Simpler desktop integration with less moving parts.
- Easy runtime availability check.

Why not direct D-Bus crate now:
- More complexity in threaded daemon path for little functional gain.

Principle reference: Principle XI.

### 5) crossbeam-channel over async runtime

Why:
- Synchronous event pipeline is straightforward and explicit.
- Low overhead for bounded producer/consumer queue.

Why not full async runtime:
- Added runtime complexity for a workload that does not need it yet.

Principle reference: Principle XI, Principle III.

### 6) Per-path debounce over global debounce

Why:
- Noisy path gets suppressed without hiding unrelated paths.
- Preserves signal quality in busy systems.

Why not global debounce:
- A single noisy file could suppress critical events elsewhere.

Principle reference: Principle V (alerts must be rare, clear, actionable).

---

## File Locations

| Purpose | Path |
|---------|------|
| System config | `/etc/vigil/vigil.toml` |
| User config | `~/.config/vigil/vigil.toml` |
| Database | `/var/lib/vigil/baseline.db` |
| JSON alerts log | `/var/log/vigil/alerts.json` |
| PID file | `/run/vigil/vigild.pid` |
| Signal socket (optional) | configured via `hooks.signal_socket` |
| systemd daemon unit | `systemd/vigild.service` |
| systemd scan timer | `systemd/vigil-scan.timer` |

---

## Philosophy

Architecture should be boring. Predictable. Explainable.

If you cannot trace an alert from source event to audit row, architecture failed.
If you cannot explain a fallback in one sentence, architecture got too clever.

*Vigil is small on purpose. Trust follows from clarity.*
