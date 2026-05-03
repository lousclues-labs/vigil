# Coordinator Split

The coordinator thread runs two loops at different
cadences: the guardian (1 Hz, fast checks) and the
maintenance loop (60s, heavy work). This split is an
architectural decision from v1.6.0 that defines how the
daemon's self-monitoring works.

Both loops run on the same thread, spawned from
`src/coordinator/mod.rs::spawn`.

```
╭────── vigil-coordinator thread ───────────────────╮
│                                                    │
│  ╭──── Guardian Loop (1s cadence) ──────────────╮ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Systemd watchdog heartbeat            │    │ │
│  │  │   sd_notify(WATCHDOG=1)               │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Backpressure check                    │    │ │
│  │  │   event channel full? → Degraded      │    │ │
│  │  │   channel drained? → Healthy          │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Baseline identity check               │    │ │
│  │  │   inode/device changed?               │    │ │
│  │  │   authorized replacement window?      │    │ │
│  │  │   → accept or Degraded                │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ User-space drop detection             │    │ │
│  │  │   sliding window threshold check      │    │ │
│  │  │   → compensating scan + Degraded      │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  Writes: guardian.json                        │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
│  ╭──── Maintenance Loop (60s cadence) ──────────╮ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ DB identity checks (TOCTOU)           │    │ │
│  │  │   baseline.db inode/device            │    │ │
│  │  │   audit.db inode/device               │    │ │
│  │  │   detection.wal inode/device           │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Mount evasion detection               │    │ │
│  │  │   check /proc/self/mountinfo          │    │ │
│  │  │   new overlapping mounts? → re-mark   │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Clock anomaly detection               │    │ │
│  │  │   monotonic vs wall clock skew        │    │ │
│  │  │   → Degraded if beyond threshold      │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Audit retention sweep                 │    │ │
│  │  │   prune entries beyond retention_days │    │ │
│  │  │   insert checkpoint for chain bridge  │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ WAL checkpoint                        │    │ │
│  │  │   trigger truncation of consumed      │    │ │
│  │  │   entries                              │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Config reload (if flagged)            │    │ │
│  │  │   re-read vigil.toml                  │    │ │
│  │  │   diff and apply changes              │    │ │
│  │  │   update ArcSwap<Config>              │    │ │
│  │  │   rebuild watch index + bloom filter  │    │ │
│  │  │   reconfigure monitor marks           │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  ╭───────────────────────────────────────╮    │ │
│  │  │ Maintenance window timeout            │    │ │
│  │  │   enforce max_window_seconds          │    │ │
│  │  ╰───────────────────────────────────────╯    │ │
│  │                                               │ │
│  │  Writes: state.json, metrics.json,            │ │
│  │          health.json                          │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
╰────────────────────────────────────────────────────╯


╭──── File Ownership ───────────────────────────────╮
│                                                    │
│  guardian.json     written by guardian loop (1s)    │
│                    lightweight health snapshot      │
│                                                    │
│  state.json        written by maintenance loop     │
│                    (60s) full daemon state          │
│                                                    │
│  metrics.json      written by maintenance loop     │
│                    (60s) Prometheus metrics         │
│                                                    │
│  health.json       written by maintenance loop     │
│                    (60s) operator-facing summary    │
│                                                    │
│  All writes use atomic_write (temp + rename)       │
│  to prevent partial reads by the CLI.              │
│                                                    │
╰────────────────────────────────────────────────────╯
```

## Walkthrough

**Why two loops.** The guardian loop runs every second to
catch time-sensitive conditions: backpressure that could
cause event loss, identity changes that could indicate an
active attack, and systemd watchdog heartbeats that prove
the daemon is alive. These checks are cheap (atomic reads,
single stat calls).

The maintenance loop runs every 60 seconds for expensive
operations: full DB identity verification, mount table
parsing, clock anomaly detection, audit retention sweeps,
WAL checkpoint/truncation, config reload application, and
runtime state file writes. These operations involve file
I/O and database queries that would be wasteful at 1 Hz.

**File split.** The guardian writes `guardian.json` at its
own cadence, separate from the maintenance state files.
This prevents a slow maintenance tick from delaying the
watchdog heartbeat. The `vigil status` command reads from
the maintenance files; the systemd watchdog reads the
heartbeat.

**Atomic writes.** All runtime state files are written
atomically via temp-file-then-rename. This ensures the CLI
never reads a partially written state file, even if it
queries during a maintenance tick.

**Shared state.** Both loops share `Arc<ArcSwap<Config>>`,
`Arc<Metrics>`, and `Arc<RwLock<DaemonState>>`. The
guardian reads atomics; the maintenance loop does heavier
work with owned DB connections. Neither loop blocks the
other except via the shared daemon state RwLock (held
briefly during state transitions).

This diagram shows the guardian/maintenance split and their
responsibilities. It does NOT show the specific timing
logic (see `time_phase()` in coordinator code), the mount
evasion detection algorithm (see code comments on the
mount-check method), or the config diff/apply mechanics
(see `src/config/diff.rs`).

## Related diagrams

- [daemon-state-machine.md](daemon-state-machine.md) —
  the state transitions these loops trigger
- [thread-topology.md](thread-topology.md) — where the
  coordinator sits among all threads
- [system-overview.md](system-overview.md) — the runtime
  files the coordinator writes
