# Audit Chain

Chain hash composition, HMAC field separation, and retention
checkpoint structure. The audit chain is vigil's tamper
evidence mechanism: each entry's chain hash depends on the
previous entry, forming a hash chain that an attacker cannot
modify without detection.

The chain hash is computed in
`src/db/audit_ops.rs::compute_chain_hash`.
The HMAC is computed in `src/hmac.rs::build_audit_hmac_data`.

```
╭──────── Audit Entry N-1 ──────────────────────────╮
│                                                    │
│  chain_hash(N-1) = BLAKE3(                         │
│    chain_hash(N-2) │ timestamp │ path │            │
│    changes_json │ severity                         │
│  )                                                 │
│                                                    │
│  hmac(N-1) = HMAC-SHA256(key,                      │
│    timestamp │ path │ change_type │ severity │     │
│    old_hash │ new_hash │ chain_hash(N-2)           │
│  )                                                 │
│                                                    │
╰────────────────────────┬───────────────────────────╯
                         │
                chain_hash(N-1) feeds into ▼
                         │
╭──────── Audit Entry N ────────────────────────────╮
│                                                    │
│  chain_hash(N) = BLAKE3(                           │
│    chain_hash(N-1) │ timestamp │ path │            │
│    changes_json │ severity                         │
│  )                                                 │
│                                                    │
│  hmac(N) = HMAC-SHA256(key,                        │
│    timestamp │ path │ change_type │ severity │     │
│    old_hash │ new_hash │ chain_hash(N-1)           │
│  )                                                 │
╰────────────────────────┬───────────────────────────╯
                         │
                chain_hash(N) feeds into ▼
                         │
╭──────── Audit Entry N+1 ──────────────────────────╮
│  ...                                               │
╰────────────────────────────────────────────────────╯


  Chain Hash Inputs          HMAC Inputs
╭───────────────────╮  ╭────────────────────────╮
│ ✓ previous_chain  │  │ ✓ timestamp            │
│   _hash           │  │ ✓ path                 │
│ ✓ timestamp       │  │ ✓ change_type          │
│ ✓ path            │  │ ✓ severity             │
│ ✓ changes_json    │  │ ✓ old_hash             │
│ ✓ severity        │  │ ✓ new_hash             │
│                   │  │ ✓ previous_chain_hash  │
│ ✗ hmac            │  │                        │
│ ✗ process_json    │  │ ✗ chain_hash (this     │
│ ✗ package         │  │   entry's own)         │
│ ✗ maintenance     │  │                        │
│ ✗ disambiguation  │  │                        │
╰───────────────────╯  ╰────────────────────────╯


╭──── Retention Checkpoint ─────────────────────────╮
│                                                    │
│  When bounded retention prunes old entries:        │
│                                                    │
│  Before pruning:                                   │
│  ╭───╮ ╭───╮ ╭───╮ ╭───╮ ╭───╮ ╭───╮ ╭───╮       │
│  │ 1 │→│ 2 │→│ 3 │→│ 4 │→│ 5 │→│ 6 │→│ 7 │      │
│  ╰───╯ ╰───╯ ╰───╯ ╰───╯ ╰───╯ ╰───╯ ╰───╯      │
│                                                    │
│  Prune entries 1-4, insert checkpoint:             │
│  ╭──────────────╮ ╭───╮ ╭───╮ ╭───╮               │
│  │ checkpoint   │→│ 5 │→│ 6 │→│ 7 │               │
│  │              │ ╰───╯ ╰───╯ ╰───╯               │
│  │ record_type: │                                  │
│  │  'checkpoint'│                                  │
│  │ first_seq: 1 │                                  │
│  │ last_seq: 4  │                                  │
│  │ entry_count:4│                                  │
│  │ bridge_chain │                                  │
│  │  _hash:      │                                  │
│  │  chain_hash  │                                  │
│  │  of entry 4  │                                  │
│  │ hmac: HMAC of│                                  │
│  │  checkpoint  │                                  │
│  ╰──────────────╯                                  │
│                                                    │
│  The bridge_chain_hash preserves chain continuity: │
│  entry 5's chain_hash was computed from entry 4's  │
│  chain_hash, which the checkpoint records. Chain   │
│  verification walks the checkpoint to bridge the   │
│  gap.                                              │
│                                                    │
╰────────────────────────────────────────────────────╯
```

## Walkthrough

**Chain hash.** Each audit entry's `chain_hash` is the
BLAKE3 hash of a pipe-delimited string containing the
previous entry's chain hash, the timestamp, path,
changes_json, and severity. This creates a hash chain:
modifying any entry invalidates every subsequent entry's
chain hash. The first entry in the chain uses a
well-known initial hash (empty string hash).

**HMAC separation.** The HMAC is intentionally NOT part of
the chain hash. The HMAC proves that a specific entry was
written by a process holding the HMAC key. The chain hash
proves ordering and integrity. They serve different
purposes: the HMAC authenticates origin; the chain hash
detects tampering or reordering. Including the HMAC in the
chain hash would create a circular dependency.

**HMAC versioning.** v1 uses pipe-delimited plaintext
fields. v2 (VIGIL-VULN-076) uses deterministic CBOR
encoding to prevent delimiter collision attacks. The
`encoding_version` column in the audit DB identifies which
format each entry uses. Mixed v1/v2 chains verify
correctly.

**Retention checkpoints.** When bounded retention prunes
old entries, an `AuditCheckpoint` record replaces the
pruned range. The checkpoint's `bridge_chain_hash` field
records the last pruned entry's chain hash, preserving
chain continuity. Chain verification recognizes checkpoint
records and uses the bridge hash to validate entries that
follow. The checkpoint itself is authenticated by its own
HMAC, not by chain hash recomputation.

**Out-of-band columns.** Some audit columns are
intentionally excluded from chain hash and HMAC
computation: `process_json`, `package`, `maintenance`,
`suppressed`, `disambiguation`. These columns carry
metadata that may be enriched after initial recording
without invalidating the chain.

This diagram shows the chain composition rules. It does
NOT show the SQL insert path (see code comments in
`src/db/audit_ops.rs::insert_audit_entry`), the chain
verification algorithm (see `verify_chain_detail`), or the
CBOR encoding details (see `src/util/canonical_cbor.rs`).

## Related diagrams

- [wal-consumers.md](wal-consumers.md) — how entries
  reach the audit DB via the audit writer
- [trust-boundaries.md](trust-boundaries.md) — where
  HMAC sits in the trust model
- [baseline-schema.md](baseline-schema.md) — the other
  persistent store
