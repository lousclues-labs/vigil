# Thread Topology

Every thread the daemon spawns, what it owns, what it shares,
and what it sends and receives. This diagram focuses on
concurrency: which threads exist, how they communicate, and
what state they access.

```
╭─ vigild (main thread) ─────────────────────────────╮
│  Spawns all threads, then waits for shutdown signal │
╰──────────────────────────┬──────────────────────────╯
                           │ spawns
     ┌──────────┬──────────┼──────────┬──────────┐
     ▼          ▼          ▼          ▼          ▼
╭─────────╮╭────────╮╭──────────╮╭────────╮╭────────╮
│ vigil-  ││ vigil- ││  vigil-  ││ vigil- ││ vigil- │
│ monitor ││worker-N││  coord   ││ scan   ││control │
╰────┬────╯╰───┬────╯╰────┬─────╯╰───┬────╯╰───┬────╯
     │         │          │          │          │
     │         │     ╭────┴─────╮   │          │
     │         │     │ spawns 2 │   │          │
     │         │     │  loops   │   │          │
     │         │     ▼          ▼   │          │
     │         │ ╭────────╮╭──────╮ │          │
     │         │ │guardian││maint.│ │          │
     │         │ │  (1s)  ││(60s) │ │          │
     │         │ ╰────────╯╰──────╯ │          │
     │         │                     │          │
     ▼         ▼                     ▼          ▼
╭────────╮╭────────╮╭────────╮╭──────────╮╭────────╮
│ vigil- ││baseline││ vigil- ││  vigil-  ││ vigil- │
│ signal ││ writer ││ audit- ││  sink-   ││ alert  │
│        ││        ││ writer ││  runner  ││        │
╰────────╯╰────────╯╰────────╯╰──────────╯╰────────╯


 Thread          Owns (exclusive)     Reads (shared)
╭──────────────┬────────────────────┬──────────────────╮
│ monitor      │ fanotify/inotify   │ config, bloom,   │
│              │ fd, mount fds      │ shutdown         │
├──────────────┼────────────────────┼──────────────────┤
│ worker (×N)  │ baseline DB conn   │ config, watch    │
│              │ (read-only),       │ index, metrics,  │
│              │ file hash cache    │ shutdown, WAL    │
├──────────────┼────────────────────┼──────────────────┤
│ guardian     │ guardian.json       │ config, metrics, │
│ (coord)      │ writer             │ state, identity, │
│              │                    │ backpressure     │
├──────────────┼────────────────────┼──────────────────┤
│ maintenance  │ baseline DB conn,  │ config, metrics, │
│ (coord)      │ audit DB conn,     │ state, watch     │
│              │ state.json,        │ index, WAL       │
│              │ metrics.json,      │                  │
│              │ health.json        │                  │
├──────────────┼────────────────────┼──────────────────┤
│ scan sched   │ baseline DB conn   │ config, metrics, │
│              │                    │ shutdown         │
├──────────────┼────────────────────┼──────────────────┤
│ control      │ Unix listener,     │ config, metrics, │
│              │ baseline DB conn   │ state, WAL,      │
│              │ (via Mutex)        │ identity         │
├──────────────┼────────────────────┼──────────────────┤
│ audit writer │ audit DB conn      │ WAL, metrics,    │
│              │                    │ shutdown         │
├──────────────┼────────────────────┼──────────────────┤
│ sink runner  │ alert sinks,       │ WAL, config,     │
│              │ cooldown LRU       │ metrics,         │
│              │                    │ shutdown         │
├──────────────┼────────────────────┼──────────────────┤
│ baseline     │ baseline DB conn   │ shutdown         │
│ writer       │ (write)            │                  │
├──────────────┼────────────────────┼──────────────────┤
│ alert        │ audit DB conn,     │ metrics,         │
│              │ alert sinks        │ shutdown         │
├──────────────┼────────────────────┼──────────────────┤
│ signal       │ signal fd          │ shutdown         │
╰──────────────┴────────────────────┴──────────────────╯


              Channel Map
╭────────────────┬──────────┬───────────┬──────────╮
│ Channel        │ Sender   │ Receiver  │ Capacity │
├────────────────┼──────────┼───────────┼──────────┤
│ events         │ monitor  │ coord →   │ config   │
│                │          │ workers   │          │
├────────────────┼──────────┼───────────┼──────────┤
│ alerts         │ workers, │ alert     │ 512      │
│                │ scanner  │ dispatch  │          │
├────────────────┼──────────┼───────────┼──────────┤
│ scan_trigger   │ control, │ scan      │ 4        │
│                │ coord    │ scheduler │          │
├────────────────┼──────────┼───────────┼──────────┤
│ baseline_update│ workers  │ baseline  │ bounded  │
│                │          │ writer    │          │
├────────────────┼──────────┼───────────┼──────────┤
│ shutdown       │ signal   │ main      │ 1        │
╰────────────────┴──────────┴───────────┴──────────╯
```

## Walkthrough

**Thread naming.** Every thread is named (`vigil-monitor`,
`vigil-worker-0`, `vigil-coordinator`, etc.) for visibility
in `htop`, `ps`, and tracing output.

**Ownership rule.** SQLite connections are never shared across
threads. Each thread that needs database access opens its own
connection. This avoids connection pooling complexity and
ensures WAL-mode readers never block writers.

**Shared state.** All cross-thread shared state uses lock-free
or read-mostly patterns. `ArcSwap` provides wait-free reads
for config and watch index (updated only on reload). `Metrics`
uses `Relaxed` atomics for counters. The daemon state `RwLock`
is read-heavy with rare transitions. Boolean flags use
`Acquire`/`Release` ordering.

**Coordinator split.** The coordinator spawns two internal
loops on the same thread: the guardian (1s cadence) handles
fast checks (watchdog, backpressure, identity), and the
maintenance loop (60s cadence) handles heavy work (DB
identity checks, mount evasion detection, audit rotation,
state file writes).

**WAL consumers.** The audit writer and sink runner both read
from the WAL independently. Each maintains its own cursor and
marks entries consumed via separate flag bits. Neither blocks
the other.

This diagram shows thread ownership and communication. It
does NOT show the internal state machines within each thread
(see code comments on each thread's entry function), error
recovery (see `src/supervised_thread.rs`), or the specific
shutdown drain sequence (see `DaemonRuntime::drain()`).

## Related diagrams

- [system-overview.md](system-overview.md) — static view of
  the same runtime
- [coordinator-split.md](coordinator-split.md) — guardian vs
  maintenance detail
- [wal-consumers.md](wal-consumers.md) — audit writer and
  sink runner consumption pattern
