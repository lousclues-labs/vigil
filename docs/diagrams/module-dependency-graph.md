# Module Dependency Graph

The layered module structure: leaf modules at the bottom,
composition modules in the middle, binaries at the top. The
no-back-edge invariant means lower layers never import from
higher layers.

```
                        Binaries
╭──────────────────────────────────────────────────╮
│                                                  │
│     ╭───────╮                   ╭────────╮       │
│     │ vigil │                   │ vigild │       │
│     │(CLI)  │                   │(daemon)│       │
│     ╰───┬───╯                   ╰───┬────╯       │
│         │                           │            │
╰─────────┼───────────────────────────┼────────────╯
          │                           │
          ▼                           ▼
╭──────────────────────────────────────────────────╮
│                  Commands / Daemon                │
│                                                  │
│  ╭──────────╮ ╭────────╮ ╭──────────╮ ╭───────╮ │
│  │ commands │ │ daemon │ │  doctor  │ │display│ │
│  │  (CLI    │ │(orches-│ │(diagnos- │ │(render│ │
│  │ dispatch)│ │tration)│ │  tics)   │ │  +UI) │ │
│  ╰────┬─────╯ ╰───┬────╯ ╰─────┬────╯ ╰───┬───╯ │
╰───────┼────────────┼────────────┼───────────┼────╯
        │            │            │           │
        ▼            ▼            ▼           ▼
╭──────────────────────────────────────────────────╮
│              Composition Modules                  │
│                                                  │
│  ╭────────────╮  ╭─────────╮  ╭──────────────╮   │
│  │coordinator │  │ scanner │  │ scan_scheduler│  │
│  │(maintenance│  │(walk +  │  │ (cron + on-  │   │
│  │ + health)  │  │compare) │  │  demand)     │   │
│  ╰─────┬──────╯  ╰────┬────╯  ╰──────┬───────╯  │
│        │              │              │           │
│  ╭─────┴──╮  ╭────────┴──╮  ╭────────┴────╮     │
│  │ worker │  │  control  │  │    alert    │     │
│  │(event  │  │ (socket   │  │(dispatcher  │     │
│  │process)│  │  handler) │  │ + sinks)    │     │
│  ╰────┬───╯  ╰─────┬─────╯  ╰──────┬──────╯    │
╰───────┼────────────┼───────────────┼────────────╯
        │            │               │
        ▼            ▼               ▼
╭──────────────────────────────────────────────────╮
│              Infrastructure Modules               │
│                                                  │
│  ╭─────────╮  ╭───────╮  ╭──────────╮            │
│  │ monitor │  │  wal  │  │    db    │            │
│  │(fanotify│  │(detect│  │(baseline │            │
│  │/inotify)│  │  log) │  │ + audit) │            │
│  ╰────┬────╯  ╰───┬───╯  ╰─────┬────╯           │
│       │           │             │                │
│  ╭────┴─────╮  ╭──┴───╮  ╭─────┴──────╮         │
│  │  filter  │  │ bloom │  │ watch_index│         │
│  │(exclusion│  │(fast  │  │(path→group │         │
│  │+debounce)│  │reject)│  │  mapping)  │         │
│  ╰──────────╯  ╰──────╯  ╰────────────╯         │
╰──────────────────────────────────────────────────╯
        │            │               │
        ▼            ▼               ▼
╭──────────────────────────────────────────────────╮
│                  Leaf Modules                     │
│                                                  │
│  ╭──────╮ ╭──────╮ ╭───────╮ ╭───────╮ ╭──────╮ │
│  │ hash │ │ hmac │ │ types │ │config │ │error │ │
│  │(BLAKE│ │(SHA- │ │(domain│ │(load +│ │(Vigil│ │
│  │  3)  │ │ 256) │ │model) │ │valid) │ │Error)│ │
│  ╰──────╯ ╰──────╯ ╰───────╯ ╰───────╯ ╰──────╯ │
│                                                  │
│  ╭─────────╮ ╭──────────╮ ╭───────────╮          │
│  │ metrics │ │detection │ │supervised │          │
│  │(atomic  │ │(dispatch │ │  _thread  │          │
│  │counters)│ │ helper)  │ │(restarts) │          │
│  ╰─────────╯ ╰──────────╯ ╰───────────╯         │
│                                                  │
│  ╭──────────╮ ╭─────────╮ ╭─────────╮            │
│  │ package  │ │  util   │ │receipt  │            │
│  │(pkg mgr │ │(fs,sys, │ │(install │            │
│  │ queries)│ │process) │ │ verify) │            │
│  ╰──────────╯ ╰─────────╯ ╰─────────╯           │
╰──────────────────────────────────────────────────╯
```

## Walkthrough

The module graph has four layers. Dependencies flow
strictly downward; no module in a lower layer imports from
a higher layer.

**Binaries.** `vigil` (the CLI) and `vigild` (the daemon)
are the two entry points. The CLI dispatches to command
modules. The daemon delegates to `daemon::Daemon` for
lifecycle orchestration.

**Commands / Daemon.** Command modules implement CLI
subcommands (init, check, status, doctor, update, etc.).
The daemon module owns startup, thread spawning, and
shutdown. Doctor runs diagnostics. Display renders output.

**Composition modules.** These compose leaf modules into
subsystems. The coordinator runs periodic maintenance. The
scanner walks the filesystem and compares against baseline.
Workers process real-time events. The control socket handles
CLI-to-daemon communication. The alert dispatcher routes
detections to configured sinks.

**Infrastructure modules.** The monitor provides the kernel
event source (fanotify/inotify). The WAL provides the
detection log. The DB layer manages SQLite connections. The
filter, bloom filter, and watch index support event routing.

**Leaf modules.** These have no intra-crate dependencies
beyond `types`, `error`, and `config`. Hash provides BLAKE3.
HMAC provides SHA-256 signing. Types defines the domain model.
Config handles loading and validation. Metrics holds atomic
counters. Detection provides the dispatch helper. The
supervised thread module wraps fallible threads with bounded
restarts.

This diagram shows the module layering and dependency
direction. It does NOT show every `use` statement (those
change with refactors) or the specific public API surface of
each module (see module-level docstrings in each file).

## Related diagrams

- [system-overview.md](system-overview.md) — runtime view
  of the same components
- [event-flow.md](event-flow.md) — how events traverse
  these layers
