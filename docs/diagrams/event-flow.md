# Event Flow

The hot path at architectural altitude: kernel event through
to audit record and alert. This diagram names the
architectural components, not the specific functions. A
function rename does not invalidate this diagram; a redesign
of the event pipeline does.

```
╭────────────────────────────────────────────────────╮
│                    Kernel                           │
│                                                    │
│  filesystem write / create / delete / rename /     │
│  chmod / chown                                     │
╰───────────────────────┬────────────────────────────╯
                        │
                        ▼
╭──── Monitor ──────────────────────────────────────╮
│                                                    │
│  fanotify fd (preferred)  or  inotify fd           │
│                                                    │
│  Reads kernel events, resolves paths.              │
│  FID mode: open_by_handle_at for path resolution.  │
│  Legacy mode: /proc/self/fd/N for path.            │
│                                                    │
╰───────────────────────┬────────────────────────────╯
                        │ FsEvent (bounded channel)
                        ▼
╭──── Bloom Filter ─────────────────────────────────╮
│                                                    │
│  Fast-reject paths not in any watch group.         │
│  Probabilistic: false positives pass through,      │
│  false negatives impossible.                       │
│                                                    │
╰───────────────────────┬────────────────────────────╯
                        │ (pass)
                        ▼
╭──── Exclusion Filter ─────────────────────────────╮
│                                                    │
│  Glob-based exclusion patterns from config.        │
│  System exclusions (package manager caches, etc.)  │
│  Per-path debounce (coalesce rapid-fire events).   │
│                                                    │
╰───────────────────────┬────────────────────────────╯
                        │ (pass)
                        ▼
╭──── Worker (one of N) ────────────────────────────╮
│                                                    │
│  1. Look up path in WatchGroupIndex → group +      │
│     severity                                       │
│  2. Open file by fd (TOCTOU-safe)                  │
│  3. Snapshot: hash (BLAKE3), stat, xattrs,         │
│     security context                               │
│  4. Compare snapshot against baseline entry         │
│  5. If changed: build ChangeResult                 │
│                                                    │
╰───────────────────────┬────────────────────────────╯
                        │ ChangeResult (if deviation)
                        ▼
╭──── Detection Dispatch ───────────────────────────╮
│                                                    │
│  WAL available?                                    │
│  ├── yes → append DetectionRecord to WAL           │
│  ╰── no  → send AlertPayload to alert channel     │
│                                                    │
╰──────────┬─────────────────────┬───────────────────╯
           │                     │
     (WAL path)            (direct path)
           ▼                     ▼
╭──── WAL ──────╮     ╭──── Alert Dispatch ────────╮
│               │     │                            │
│  append-only  │     │  Insert into audit.db      │
│  detection    │     │  Dispatch to alert sinks   │
│  log          │     │                            │
╰───┬───────┬───╯     ╰────────────────────────────╯
    │       │
    ▼       ▼
╭────────╮ ╭──────────╮
│ audit  │ │  sink    │
│ writer │ │  runner  │
╰───┬────╯ ╰────┬─────╯
    │            │
    ▼            ▼
╭────────╮ ╭──────────────╮
│audit.db│ │ alert sinks  │
│        │ │ (journal,    │
│        │ │  dbus, json, │
│        │ │  syslog,     │
│        │ │  socket)     │
╰────────╯ ╰──────────────╯
```

## Walkthrough

**Kernel to monitor.** The monitor thread reads events
from a fanotify or inotify file descriptor. On FID-capable
kernels (5.1+), fanotify provides filesystem-scoped events
including creates, deletes, renames, and attribute changes.
On older kernels, mount-mark mode covers modifies and
close-writes; a periodic scan backstops the missing event
types.

**Fast-reject filter.** The bloom filter rejects paths
that are not in any watch group, before any file I/O. It
is populated at startup from watch group paths and rebuilt
on config reload. False positives are harmless (the worker
will find no baseline entry and skip); false negatives are
structurally impossible.

**Exclusion and debounce.** The exclusion filter applies
glob patterns from config plus system exclusions (package
manager caches, compiler outputs, etc.). The debounce
window coalesces rapid-fire events on the same path into a
single processing pass.

**Worker comparison.** Each worker opens the file by its
fd (not path) for TOCTOU safety, captures a full snapshot
(BLAKE3 hash, stat metadata, extended attributes, SELinux
context), and compares against the baseline entry. If any
attribute differs, a `ChangeResult` is built with the
specific changes, severity (from the watch group config),
process attribution (when available), and package
ownership.

**Detection dispatch.** If the WAL is active, the
detection is appended as a `DetectionRecord`. Two
independent consumers — audit writer and sink runner —
process it asynchronously. If the WAL is not active (e.g.,
CLI scan mode), the detection goes directly to the alert
channel.

**Audit and alert.** The audit writer persists detections
to `audit.db` with chain hashes and HMACs. The sink
runner dispatches to configured alert sinks (systemd
journal, D-Bus desktop notifications, JSON log file,
remote syslog, Unix socket). Rate limiting and per-path
cooldowns suppress notification storms without affecting
the audit trail.

This diagram shows the architectural shape of the event
path. It does NOT show the specific call sequence within
the worker (which evolves with each release; see code
comments in `src/worker.rs`), the bloom filter's internal
hash mechanics (see `src/bloom.rs` docstring), or the
error recovery paths (see code comments at each fallible
call site).

## Related diagrams

- [system-overview.md](system-overview.md) — where these
  components live in the full system
- [wal-consumers.md](wal-consumers.md) — audit writer and
  sink runner detail
- [thread-topology.md](thread-topology.md) — which threads
  own which stages
