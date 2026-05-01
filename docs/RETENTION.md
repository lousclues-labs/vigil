# Audit Retention

Vigil bounds its audit log automatically. The daemon prunes old entries on
a daily cadence, replacing each pruned range with a cryptographically-sealed
checkpoint record. The HMAC chain extends across every checkpoint without
break. The operator never has to manually prune in normal operation.

## How it works

1. The daemon runs a retention sweep once per `audit.retention_check_interval`
   (default: every 24 hours).
2. Entries older than `audit.retention_days` (default: 365 days) are
   identified for pruning.
3. A pruned-range HMAC is computed over the original entries' canonical
   chain-hash encodings, seeded with the preceding chain hash.
4. An `AuditCheckpoint` record replaces the pruned range. It stores:
   - The sequence range and timestamp range covered.
   - The entry count.
   - The pruned-range HMAC.
   - The checkpoint's own chain hash (bridging the gap in the chain).
   - The checkpoint's own HMAC (proving the checkpoint's integrity).
5. The original entries are deleted atomically with the checkpoint insertion.
6. The chain remains unbroken: `vigil audit verify` succeeds across any
   number of checkpoints.

```
live entries (within retention window)         pruned ranges (older)
─────────────────────────────────────         ─────────────────────
E_n → E_n+1 → E_n+2 → ... → E_latest         CHK_2 → CHK_1
                                                ↑       ↑
                                               HMAC    HMAC
chain links (previous_chain_hash):              ↑       ↑
E_n.previous_chain_hash = CHK_2.chain_hmac    [E_998..E_2001]
CHK_2.previous_chain_hash = CHK_1.chain_hmac  [E_1..E_997]
```

## Configuration

All keys live in the `[audit]` section of `vigil.toml`.

| Key | Default | Range | Description |
|-----|---------|-------|-------------|
| `retention_days` | 365 | >= 7 | Entries older than this are pruned |
| `retention_check_interval` | `"24h"` | 1h -- 7d | How often the sweep runs |
| `max_size_mb` | 1024 | >= 64 | Hard cap on audit DB file size |
| `min_entries_to_keep` | 1000 | any | Sweep refuses to leave fewer than this |

Example:

```toml
[audit]
retention_days = 365
retention_check_interval = "24h"
max_size_mb = 1024
min_entries_to_keep = 1000
```

## Defaults

The defaults are chosen so that a fresh install runs for years without
operator intervention:

- **365 days of full forensic detail.** Every detection, every attribution,
  every HMAC -- available for a full year.
- **1 GB cap as defense-in-depth.** At the typical desktop rate of ~5 MB/month,
  the audit DB reaches ~60 MB/year. The 1 GB cap is a safety net, not a
  normal operating boundary.
- **1000 minimum entries.** Prevents catastrophic misconfiguration from
  deleting the entire audit history.

## Cap behavior

The `audit.max_size_mb` cap operates independently of the retention sweep:

- **90% of cap:** doctor row warns (`⚠ approaching cap`), info-level audit
  record written.
- **100% of cap:** daemon enters `Degraded { reason: AuditLogFull }`, refuses
  new audit writes, high-severity audit record and desktop notification.
  Recovery: `vigil audit prune --before <date> --confirm` or
  `vigil recover --reason audit_log_full`.

## Manual pruning

```
# Dry run (shows what would be pruned):
vigil audit prune --before 2025-01-01

# Execute:
vigil audit prune --before 2025-01-01 --confirm
```

Manual prunes follow the same algorithm as the daily sweep. They are
audited: the operator's UID, PID, exe path, and argv are recorded in the
audit log.

## Verification

```
$ sudo vigil audit verify
audit log: 329,329 entries verified, chain intact
checkpoints: 2 present, covering 145,210 entries dating back to 2024-04-23
```

Checkpoints are verified by their HMAC (when the HMAC key is available).
The original pruned entries cannot be individually verified (they are gone),
but the checkpoint proves they existed and produced a specific cryptographic
hash.

## Longer retention

If you need more than 365 days of full forensic detail:

1. Set `audit.retention_days` higher (e.g., 1825 for 5 years).
2. Increase `audit.max_size_mb` to match the expected growth.
3. Optionally, archive the audit DB externally on a schedule.

Vigil does not provide an archival subsystem. Operators who need long-term
forensic recovery beyond the retention window are responsible for their own
archival strategy. See `docs/THREAT_MODEL.md` for the rationale.

## Trade-offs

- **Pruned entries are gone.** The checkpoint proves they existed, but does
  not contain their content. If you need to investigate a specific old entry,
  archive first.
- **The pruned-range HMAC cannot be independently verified** without the
  original entries. It serves as proof-of-existence, not proof-of-content.
- **Per-severity retention is not supported.** The chain integrity model
  assumes uniform retention. If you need to keep critical alerts forever,
  archive externally.
