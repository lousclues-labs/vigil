# WAL Consumers

The two-consumer pattern: audit_writer and sink_runner each
maintain a cursor over unconsumed entries, flag bits track
per-consumer consumption, and truncation requires both
consumers to be done. This is an architectural pattern, not
an implementation detail.

The audit writer is spawned from
`src/wal/audit_writer.rs::AuditWriter::spawn`.
The sink runner is spawned from
`src/wal/sink_runner.rs::SinkRunner::spawn`.

```
╭─────────────── Detection WAL ──────────────────────╮
│                                                    │
│  Entry 1   Entry 2   Entry 3   Entry 4   Entry 5   │
│  ╭──────╮  ╭──────╮  ╭──────╮  ╭──────╮  ╭──────╮ │
│  │flags:│  │flags:│  │flags:│  │flags:│  │flags:│ │
│  │ A+S  │  │ A+S  │  │  A   │  │  S   │  │ none │ │
│  ╰──────╯  ╰──────╯  ╰──────╯  ╰──────╯  ╰──────╯ │
│  fully     fully       audit     sink               │
│  consumed  consumed    only      only               │
│                                                    │
│  ◄── truncatable ──►  ◄── not yet truncatable ──►  │
│                                                    │
╰────────────────────────────────────────────────────╯

    A = FLAG_AUDIT_DONE (bit 0)
    S = FLAG_SINK_DONE  (bit 1)

            ╭────────────────────╮
            │   audit_writer     │
            │                    │
            │  Reads entries     │
            │  where bit 0 = 0   │
            │                    │
            │  ╭──────────────╮  │
            │  │ Insert into  │  │
            │  │ audit.db     │  │
            │  │ (chain hash  │  │
            │  │  + HMAC)     │  │
            │  ╰──────┬───────╯  │
            │         │          │
            │  ╭──────▼───────╮  │
            │  │ Set bit 0    │  │
            │  │ (mark audit  │  │
            │  │  done)       │  │
            │  ╰──────────────╯  │
            ╰────────────────────╯

            ╭────────────────────╮
            │   sink_runner      │
            │                    │
            │  Reads entries     │
            │  where bit 1 = 0   │
            │                    │
            │  ╭──────────────╮  │
            │  │ Apply rate   │  │
            │  │ limit +      │  │
            │  │ cooldown     │  │
            │  ╰──────┬───────╯  │
            │         │          │
            │  ╭──────▼───────╮  │
            │  │ Dispatch to  │  │
            │  │ alert sinks  │  │
            │  │ (or suppress)│  │
            │  ╰──────┬───────╯  │
            │         │          │
            │  ╭──────▼───────╮  │
            │  │ Set bit 1    │  │
            │  │ (mark sink   │  │
            │  │  done)       │  │
            │  ╰──────────────╯  │
            ╰────────────────────╯

╭───────────── Truncation ──────────────────────────╮
│                                                    │
│  Precondition: both bits set on contiguous         │
│  entries from WAL head                             │
│                                                    │
│  Before:                                           │
│  ╭──┬──┬──┬──┬──┬──╮                               │
│  │AS│AS│AS│ A│  │  │  (3 fully consumed)           │
│  ╰──┴──┴──┴──┴──┴──╯                               │
│                                                    │
│  After:                                            │
│  ╭──┬──┬──╮                                        │
│  │ A│  │  │  (3 entries removed, file rewritten)   │
│  ╰──┴──┴──╯                                        │
│                                                    │
│  Method: open replacement file, copy surviving     │
│  entries, fsync, rename over original.             │
│  Replacement file opened BEFORE rename to prevent  │
│  data loss if open fails.                          │
│                                                    │
╰────────────────────────────────────────────────────╯
```

## Walkthrough

**Independent consumers.** The WAL has exactly two
consumers, each responsible for a different purpose:

1. **audit_writer** reads unprocessed entries, inserts
   them into the audit database with chain hashes and
   HMACs, then sets `FLAG_AUDIT_DONE` (bit 0).

2. **sink_runner** reads unprocessed entries, applies
   per-path cooldown and per-minute rate limiting,
   dispatches to configured alert sinks (journal, D-Bus,
   syslog, etc.), then sets `FLAG_SINK_DONE` (bit 1).
   Suppressed entries are still marked consumed.

Neither consumer blocks the other. An entry can be
audit-written before it is sink-dispatched, or vice versa.
The order depends on which consumer polls first.

**Flag-based coordination.** Each entry's 16-bit flags
field tracks which consumers have processed it. Setting a
flag is a single 2-byte write at a known offset (flags are
inside the CRC-covered region, so the entry CRC is
recomputed and rewritten alongside the flag update).

**Truncation.** The WAL periodically truncates fully
consumed entries from the head. An entry is fully consumed
only when BOTH flag bits are set. Truncation creates a
replacement file with surviving entries, syncs it, then
atomically renames it over the original. The replacement
file is opened before the rename to prevent data loss if
the open syscall fails.

**Sequence continuity.** Sequence numbers are never
reused. After truncation, the next appended entry
continues from the last sequence number, not from zero.
This ensures the audit writer can deduplicate against
rows already present in the audit DB after crash recovery.

This diagram shows the two-consumer architectural pattern.
It does NOT show the internal polling loops of each
consumer (see code comments in `src/wal/audit_writer.rs`
and `src/wal/sink_runner.rs`), the retry logic for failed
audit writes (see `AlertDispatcher::audit_retry_buffer`),
or the CRC recomputation mechanics on flag updates.

## Related diagrams

- [wal-format.md](wal-format.md) — on-disk byte layout
  that the flag bits live in
- [audit-chain.md](audit-chain.md) — what audit_writer
  does with each entry
- [event-flow.md](event-flow.md) — how entries reach
  the WAL in the first place
