# Baseline Schema

SQLite tables and their relationships. The schema is stable
because changing it requires a migration story. Baseline and
audit live in separate database files.

Schema definitions live in `src/db/schema.rs`.

```
╭────────────── baseline.db ─────────────────────────╮
│                                                    │
│  ╭──── baseline ──────────────────────────────╮    │
│  │                                            │    │
│  │  id             INTEGER PK AUTOINCREMENT   │    │
│  │                                            │    │
│  │  ── path ──                                │    │
│  │  path           TEXT NOT NULL UNIQUE        │    │
│  │                                            │    │
│  │  ── identity ──                            │    │
│  │  inode          INTEGER NOT NULL            │    │
│  │  device         INTEGER NOT NULL            │    │
│  │  file_type      TEXT NOT NULL  'regular'    │    │
│  │  symlink_target TEXT                        │    │
│  │                                            │    │
│  │  ── content ──                             │    │
│  │  hash           TEXT NOT NULL               │    │
│  │  size           INTEGER NOT NULL            │    │
│  │                                            │    │
│  │  ── permissions ──                         │    │
│  │  mode           INTEGER NOT NULL            │    │
│  │  owner_uid      INTEGER NOT NULL            │    │
│  │  owner_gid      INTEGER NOT NULL            │    │
│  │  capabilities   TEXT                        │    │
│  │                                            │    │
│  │  ── security ──                            │    │
│  │  xattrs_json    TEXT NOT NULL  '{}'         │    │
│  │  security_context TEXT NOT NULL  ''         │    │
│  │                                            │    │
│  │  ── metadata ──                            │    │
│  │  mtime          INTEGER NOT NULL            │    │
│  │  package        TEXT                        │    │
│  │  source         TEXT NOT NULL  'auto_scan'  │    │
│  │  added_at       INTEGER NOT NULL            │    │
│  │  updated_at     INTEGER NOT NULL            │    │
│  │                                            │    │
│  │  CHECK(source IN ('package_manager',       │    │
│  │    'manual', 'auto_scan'))                  │    │
│  │                                            │    │
│  │  INDEX idx_baseline_path ON (path)         │    │
│  ╰────────────────────────────────────────────╯    │
│                                                    │
│  ╭──── config_state ─────────────────────────╮     │
│  │                                            │    │
│  │  key          TEXT PRIMARY KEY              │    │
│  │  value        TEXT NOT NULL                 │    │
│  │  updated_at   INTEGER NOT NULL              │    │
│  │                                            │    │
│  │  Known keys:                               │    │
│  │    baseline_hmac        baseline integrity  │    │
│  │    config_file_hmac     config integrity    │    │
│  │    baseline_initialized init flag           │    │
│  │    last_check_at        last check time     │    │
│  │    last_check_changes   last check count    │    │
│  ╰────────────────────────────────────────────╯    │
│                                                    │
╰────────────────────────────────────────────────────╯


╭────────────── audit.db ────────────────────────────╮
│                                                    │
│  ╭──── audit_log ────────────────────────────╮     │
│  │                                            │    │
│  │  id              INTEGER PK AUTOINCREMENT  │    │
│  │  timestamp       INTEGER NOT NULL           │    │
│  │  path            TEXT NOT NULL              │    │
│  │  changes_json    TEXT NOT NULL              │    │
│  │  severity        TEXT NOT NULL              │    │
│  │  monitored_group TEXT                       │    │
│  │  process_json    TEXT                       │    │
│  │  package         TEXT                       │    │
│  │  maintenance     INTEGER NOT NULL  0        │    │
│  │  suppressed      INTEGER NOT NULL  0        │    │
│  │  hmac            TEXT                       │    │
│  │  chain_hash      TEXT NOT NULL              │    │
│  │  encoding_version INTEGER NOT NULL 1        │    │
│  │                                            │    │
│  │  ── retention checkpoint columns ──        │    │
│  │  record_type     TEXT NOT NULL 'detection'  │    │
│  │  first_sequence  INTEGER                    │    │
│  │  last_sequence   INTEGER                    │    │
│  │  first_timestamp INTEGER                    │    │
│  │  last_timestamp  INTEGER                    │    │
│  │  entry_count     INTEGER                    │    │
│  │  pruned_range_hmac TEXT                     │    │
│  │                                            │    │
│  │  ── out-of-band columns ──                 │    │
│  │  disambiguation  TEXT                       │    │
│  │                                            │    │
│  │  INDEX idx_audit_ts ON (timestamp)         │    │
│  │  INDEX idx_audit_path ON (path)            │    │
│  │  INDEX idx_audit_path_id ON (path, id)     │    │
│  │  INDEX idx_audit_severity ON (severity)    │    │
│  │  INDEX idx_audit_group ON (monitored_group)│    │
│  ╰────────────────────────────────────────────╯    │
│                                                    │
│  ╭──── audit_segments ───────────────────────╮     │
│  │                                            │    │
│  │  id                INTEGER PK              │    │
│  │  first_sequence    INTEGER NOT NULL         │    │
│  │  last_sequence     INTEGER NOT NULL         │    │
│  │  first_timestamp   INTEGER NOT NULL         │    │
│  │  last_timestamp    INTEGER NOT NULL         │    │
│  │  first_chain_hash  TEXT NOT NULL            │    │
│  │  sealed_chain_hash TEXT NOT NULL            │    │
│  │  seal_hmac         TEXT NOT NULL            │    │
│  │  sealed_at         INTEGER NOT NULL         │    │
│  │  archive_path      TEXT                     │    │
│  ╰────────────────────────────────────────────╯    │
│                                                    │
╰────────────────────────────────────────────────────╯
```

## Walkthrough

**Split databases.** Baseline and audit live in separate
SQLite files. This is an architectural decision: the
baseline is read-heavy (workers read on every event), while
the audit DB is write-heavy (every detection appends). WAL
mode and separate files prevent readers from blocking
writers across the two workloads.

**Baseline table.** The v2 flattened schema stores each
file attribute as a direct column (replacing the v1 JSON
blob format). Twenty columns capture path, identity (inode,
device, file_type, symlink_target), content (hash, size),
permissions (mode, uid, gid, capabilities), security
(xattrs_json, security_context), and metadata (mtime,
package, source, timestamps). The `source` CHECK constraint
limits values to three known origins.

**config_state table.** Key-value store for integrity and
operational state. The `baseline_hmac` key holds the HMAC
of the entire baseline (13 fields per entry). The
`baseline_initialized` flag prevents silent re-init of a
cleared baseline. The `config_file_hmac` tracks config
integrity.

**audit_log table.** Each detection record includes the
path, changes (JSON), severity, chain hash, and optional
HMAC. The `encoding_version` column distinguishes v1
(pipe-delimited) from v2 (CBOR) HMAC encoding.
Checkpoint columns (`record_type`, `first_sequence`,
etc.) support bounded retention: when old entries are
pruned, a checkpoint record preserves chain continuity.
The `disambiguation` column stores forensic analysis
results (out-of-band, not in chain hash).

**audit_segments table.** Records sealed audit segments
with their chain hash range and HMAC seal, enabling
segment-level verification and archival.

This diagram shows the table structure and column layout.
It does NOT show the SQL query patterns (see code comments
in `src/db/baseline_ops.rs` and `src/db/audit_ops.rs`),
the migration logic (see `src/db/schema.rs`), or the HMAC
field coverage (see [audit-chain.md](audit-chain.md)).

## Related diagrams

- [audit-chain.md](audit-chain.md) — which columns feed
  into chain hash and HMAC
- [trust-boundaries.md](trust-boundaries.md) — HMAC
  protection model
