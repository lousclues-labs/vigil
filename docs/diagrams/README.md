# Architectural Diagrams

These diagrams capture vigil's architectural decisions — the
structural choices that don't change release-to-release.
Specific implementation details (function call sequences,
internal state machines, recovery mechanics) are documented
in code comments next to the code they describe.

If you're reading vigil for the first time, start with
`system-overview.md`. If you're investigating a specific
behavior, the code comment on the relevant function is
usually a better answer than these diagrams.

---

## System and Structure

- [system-overview.md](system-overview.md) — every long-lived
  thread, channel, shared state, and persistent file
- [module-dependency-graph.md](module-dependency-graph.md) —
  layered module structure and no-back-edge invariant
- [thread-topology.md](thread-topology.md) — thread
  ownership, shared state, and message passing

## Persistence and Chain

- [wal-format.md](wal-format.md) — on-disk byte layout of
  the detection WAL
- [wal-consumers.md](wal-consumers.md) — two-consumer
  pattern with independent cursors
- [audit-chain.md](audit-chain.md) — chain hash composition,
  HMAC separation, retention checkpoints
- [baseline-schema.md](baseline-schema.md) — SQLite tables,
  columns, and relationships

## Operational Shape

- [event-flow.md](event-flow.md) — hot path from kernel
  event to audit + alert
- [daemon-state-machine.md](daemon-state-machine.md) —
  Healthy / Degraded states and every DegradedReason
- [coordinator-split.md](coordinator-split.md) — guardian
  (1s) and maintenance (60s) loop responsibilities

## Boundaries

- [trust-boundaries.md](trust-boundaries.md) — what vigil
  trusts, what it doesn't, where HMAC and audit sit
- [control-socket.md](control-socket.md) — daemon-CLI
  protocol shape and request dispatch
