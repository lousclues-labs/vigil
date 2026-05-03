# Daemon State Machine

The daemon operates in two states: Healthy and Degraded.
Every `DegradedReason` variant is an architectural
commitment — adding a new reason means adding a new class
of failure that the daemon recognizes and surfaces. The
state machine itself is architectural; specific recovery
paths within each transition are implementation and live
in code.

The state is managed via `Arc<RwLock<DaemonState>>` in the
coordinator thread.

```
                    ╭────────────────╮
                    │    Healthy     │
                    │                │
                    │  All systems   │
                    │  nominal       │
                    ╰───────┬────────╯
                            │
          any DegradedReason│triggers
                            │
                    ╭───────▼────────╮
                    │   Degraded     │
                    │                │
                    │  reason:       │
                    │  DegradedReason│
                    ╰───────┬────────╯
                            │
          condition clears  │
                            │
                    ╭───────▼────────╮
                    │    Healthy     │
                    ╰────────────────╯


╭──── DegradedReason Variants ──────────────────────╮
│                                                    │
│  Database Identity                                 │
│  ─────────────────                                 │
│  BaselineDbReplaced   baseline.db inode/device     │
│                       changed (TOCTOU attack or    │
│                       unauthorized replacement)    │
│                                                    │
│  AuditDbReplaced      audit.db inode/device        │
│                       changed                      │
│                                                    │
│  WalFileReplaced      detection.wal inode/device   │
│                       changed                      │
│                                                    │
│  Flow Pressure                                     │
│  ─────────────                                     │
│  EventBackpressure    event channel full; workers   │
│                       cannot keep up. Auto-recovers │
│                       when channel drains.          │
│                                                    │
│  EventLossDetected    kernel reports events were    │
│  { drop_delta,        dropped (FAN_Q_OVERFLOW).    │
│    threshold }        Triggers compensating scan.   │
│                                                    │
│  UserspaceEventDrops  user-space event drops        │
│  { dropped,           exceed sliding-window         │
│    window_secs }      threshold. Triggers scan.     │
│                                                    │
│  FanotifyQueueOverflow  kernel queue overflow       │
│                         detected                    │
│                                                    │
│  Infrastructure                                    │
│  ──────────────                                    │
│  FanotifyMarkFailed   fanotify_mark(2) rejected    │
│  { mount }            for a mount point             │
│                                                    │
│  FanotifyReadFailed   fanotify read loop failed     │
│                                                    │
│  WorkerDbUnrecoverable  worker DB reconnect failed  │
│                         after max retries           │
│                                                    │
│  Integrity                                         │
│  ─────────                                         │
│  BaselineHmacMismatch  baseline HMAC does not match │
│                        stored value at startup      │
│                                                    │
│  Capacity                                          │
│  ────────                                          │
│  AuditLogFull         audit.db exceeds configured   │
│                       max_size_mb                   │
│                                                    │
│  RetentionPolicyMismatch  retention sweep skipped   │
│  { skipped_count,         too many times            │
│    retention_days,                                  │
│    would_delete_pct }                               │
│                                                    │
│  Time                                              │
│  ────                                              │
│  ClockSkewDetected    system clock jumped beyond    │
│  { skew_secs }        configured threshold          │
│                                                    │
╰────────────────────────────────────────────────────╯


╭──── State Transitions ────────────────────────────╮
│                                                    │
│  Healthy → Degraded                                │
│  ────────────────────                              │
│  Guardian thread (1s):                             │
│    - checks backpressure flag                      │
│    - checks DB identity (inode/device)             │
│    - checks userspace drop counters                │
│                                                    │
│  Maintenance thread (60s):                         │
│    - checks DB file identity                       │
│    - checks clock skew                             │
│    - checks audit log size                         │
│    - checks retention sweep status                 │
│                                                    │
│  Worker thread:                                    │
│    - reports unrecoverable DB errors               │
│                                                    │
│  Monitor thread:                                   │
│    - reports mark failures, read failures          │
│    - reports queue overflows                       │
│                                                    │
│  Degraded → Healthy                                │
│  ────────────────────                              │
│  EventBackpressure: auto-clears when channel       │
│    drains                                          │
│  ClockSkewDetected: auto-clears after recovery     │
│    window (default 300s)                           │
│  EventLossDetected / UserspaceEventDrops:          │
│    auto-clears after compensating scan completes   │
│  Other reasons: require operator intervention      │
│    (restart, baseline refresh, etc.)               │
│                                                    │
╰────────────────────────────────────────────────────╯
```

## Walkthrough

**Two states.** The daemon is either Healthy (all systems
nominal) or Degraded (a specific reason is active). There
is no third state. Degraded carries a `DegradedReason`
enum variant that identifies exactly what went wrong.

**Reason categories.** DegradedReason variants fall into
five categories:

- **Database identity:** The baseline DB, audit DB, or WAL
  file was replaced on disk (inode/device changed). This
  could indicate a TOCTOU attack or an unauthorized
  replacement.

- **Flow pressure:** The event pipeline is overloaded.
  EventBackpressure means workers can't keep up.
  EventLossDetected means the kernel dropped events.
  UserspaceEventDrops means user-space processing dropped
  events. FanotifyQueueOverflow means the kernel queue
  overflowed.

- **Infrastructure:** A kernel interface failed
  (fanotify_mark rejected, fanotify read failed) or a
  worker's database connection is unrecoverable.

- **Integrity:** The baseline's stored HMAC doesn't match
  the computed HMAC at startup, indicating possible
  tampering.

- **Capacity/Time:** The audit log is full, retention
  sweeps are failing, or the system clock jumped.

**Auto-recovery.** Some degraded states auto-clear:
backpressure clears when the channel drains, clock skew
clears after a recovery window, event loss clears after a
compensating scan. Others require operator intervention.

**Visibility.** The current state is visible via
`vigil status`, `vigil doctor`, and the runtime state
files (`state.json`, `health.json`). The degraded reason
is always surfaced with enough context for the operator to
diagnose.

This diagram shows the state machine and reason taxonomy.
It does NOT show the specific check implementations (see
code comments in `src/coordinator/mod.rs`), the
compensating scan mechanics (see `scan_scheduler`), or the
clock skew detection thresholds (see config documentation).

## Related diagrams

- [coordinator-split.md](coordinator-split.md) — which
  loop checks which conditions
- [system-overview.md](system-overview.md) — where
  DaemonState sits in shared state
