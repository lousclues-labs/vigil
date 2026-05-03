# System Overview

Vigild as it runs: every long-lived thread, every channel,
every shared state structure, and every persistent file it
touches. This is the single most important diagram. If a
contributor reads only one diagram, this is it.

```
╭─────────────────────────────────────────────────────────╮
│                       vigild                            │
│                                                         │
│  ╭─────────╮    events     ╭───────────╮                │
│  │ monitor ├──────────────►│coordinator│                │
│  │(fanotify│  (bounded ch) │  (2 loops)│                │
│  │/inotify)│               ╰─────┬─────╯                │
│  ╰─────────╯                     │                      │
│       │                          │ events                │
│       │ events              ╭────▼────╮                  │
│       │ (bounded ch)        │ workers │                  │
│       ╰────────────────────►│  (N×)   │                  │
│                             ╰────┬────╯                  │
│                                  │ detections            │
│                             ╭────▼────╮                  │
│                             │   WAL   │                  │
│                             │(append) │                  │
│                             ╰──┬───┬──╯                  │
│                      ┌─────────┘   └──────────┐          │
│                 ╭────▼─────╮           ╭──────▼──────╮   │
│                 │  audit   │           │    sink     │   │
│                 │  writer  │           │   runner    │   │
│                 ╰────┬─────╯           ╰──────┬─────╯   │
│                      │                        │          │
│                      ▼                        ▼          │
│               ╭────────────╮          ╭──────────────╮   │
│               │  audit.db  │          │  alert sinks │   │
│               │(chain+HMAC)│          │(journal,dbus,│   │
│               ╰────────────╯          │ syslog, etc) │   │
│                                       ╰──────────────╯   │
│                                                          │
│  ╭──────────╮  ╭─────────╮  ╭──────────╮  ╭──────────╮  │
│  │  scan    │  │ control │  │ baseline │  │  signal  │  │
│  │scheduler │  │ socket  │  │  writer  │  │ handler  │  │
│  ╰──────────╯  ╰─────────╯  ╰──────────╯  ╰──────────╯  │
╰──────────────────────────────────────────────────────────╯

             Shared State (lock-free / read-mostly)
╭──────────────────────────────────────────────────────────╮
│  Arc<ArcSwap<Config>>        config (lock-free reads)    │
│  Arc<ArcSwap<WatchGroupIndex>>  watch paths              │
│  Arc<Metrics>                atomic counters (~50)        │
│  Arc<RwLock<DaemonState>>    Healthy / Degraded          │
│  Arc<AtomicBool>             shutdown flag                │
│  Arc<AtomicBool>             reload flag                  │
│  Arc<AtomicBool>             backpressure flag            │
│  Arc<AtomicBool>             maintenance_active           │
╰──────────────────────────────────────────────────────────╯

                    Persistent Files
╭──────────────────────────────────────────────────────────╮
│  baseline.db       known-good filesystem state (SQLite)  │
│  audit.db          HMAC-chained detection log (SQLite)   │
│  detection.wal     append-only detection log (custom)    │
│  /run/vigil/       runtime state directory:              │
│    control.sock      CLI ↔ daemon Unix socket            │
│    metrics.json      Prometheus-compatible metrics        │
│    state.json        maintenance thread state             │
│    health.json       health summary                       │
│    guardian.json     guardian thread state                 │
│  vigild.pid        PID file                              │
╰──────────────────────────────────────────────────────────╯
```

## Walkthrough

**Threads.** Vigild spawns these long-lived threads: the
filesystem monitor (fanotify or inotify), N worker threads
(default matches CPU count), the coordinator (two internal
loops: guardian at 1s and maintenance at 60s), the scan
scheduler, the control socket listener, the baseline writer,
the signal handler, and — when the WAL is enabled — the
audit writer and sink runner.

**Channels.** Events flow through bounded crossbeam channels.
The monitor sends `FsEvent` values to the coordinator, which
forwards them to workers. Workers send detections to the WAL.
The WAL feeds two independent consumers: the audit writer
(persists to `audit.db`) and the sink runner (dispatches to
alert sinks). The scan scheduler and control socket both use
a `ScanRequest` channel to trigger on-demand scans.

**Shared state.** Configuration and watch paths use `ArcSwap`
for lock-free reads during hot-path event processing. Metrics
are atomic counters. Daemon state uses a `RwLock` (read-heavy,
writes only on state transitions). Boolean flags coordinate
shutdown, reload, backpressure, and maintenance windows.

**Persistent files.** The baseline DB holds known-good
filesystem state. The audit DB holds the HMAC-chained
detection log. The WAL bridges the gap between detection and
persistence. Runtime state files under `/run/vigil/` expose
daemon health to the CLI and monitoring tools.

This diagram shows the architectural shape of the running
daemon. It does NOT show the specific startup sequence (see
code comments in `src/daemon/mod.rs`), the shutdown drain
order (see `DaemonRuntime::drain()`), or the config reload
mechanics (see code comments in `src/coordinator/mod.rs`).

## Related diagrams

- [thread-topology.md](thread-topology.md) — concurrency
  detail for each thread
- [event-flow.md](event-flow.md) — the hot path in detail
- [wal-consumers.md](wal-consumers.md) — the WAL's two
  consumer pattern
