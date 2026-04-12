# Testing

VigilBaseline tests deterministic behavior. Claims need runnable checks.

---

## Test Layout

Integration-style tests live as flat files under `tests/`.
The chaos engineering suite lives under `tests/chaos/`.

```
tests/
|-- alert_dispatcher_tests.rs
|-- audit_chain_tests.rs
|-- baseline_json_tests.rs
|-- baseline_tamper_tests.rs
|-- chaos.rs                          # entry point for chaos suite
|-- chaos/
|   |-- chaos_common.rs               # shared helpers, record factories
|   |-- harness.rs                    # seeded RNG, clock, fault injectors, invariant engine
|   |-- mod.rs
|   `-- scenarios/
|       |-- clock_warfare.rs           # Scenario 7: time anomaly resilience
|       |-- config_reload_storm.rs     # Scenario 5: atomic reload under load
|       |-- coordinated_attack.rs      # Scenario 8: full-system compound stress
|       |-- coordinator_adversarial_tick.rs  # Scenario 3: inode swap + state transitions
|       |-- mod.rs
|       |-- pipeline_recovery.rs       # Scenario 2: crash recovery durability
|       |-- sink_determinism.rs        # Scenario 6: suppression determinism
|       |-- wal_concurrency.rs         # Scenario 1: concurrent WAL operations
|       `-- worker_pool_chaos.rs       # Scenario 4: filesystem race safety
|-- daemon_smoke_tests.rs
|-- exclusion_filter_tests.rs
|-- filter_self_paths_tests.rs
|-- hmac_chain_tamper_tests.rs
|-- scan_deleted_file_tests.rs
|-- security_hardening_v3_tests.rs
|-- self_monitoring_tests.rs
|-- snapshot_diff_tests.rs
|-- version_upgrade_tests.rs
|-- wal_integration.rs
`-- worker_tests.rs
```

There is no `tests/common/`, `tests/integration/`, `tests/security/`, or `tests/README.md` in this repository.

---

## Quick Commands

Run the full suite:

```bash
cargo test --all-targets
```

Run one test file:

```bash
cargo test --test audit_chain_tests
cargo test --test hmac_chain_tamper_tests
cargo test --test snapshot_diff_tests
cargo test --test worker_tests
cargo test --test wal_integration
```

Run WAL-specific unit tests:

```bash
cargo test wal::tests::
cargo test wal::audit_writer::tests::
cargo test wal::sink_runner::tests::
```

Run chaos engineering suite:

```bash
cargo test --test chaos                          # default (Tier A, seed 42)
cargo test --test chaos -- --nocapture            # with output
CHAOS_SEED=12345 cargo test --test chaos          # specific seed
CHAOS_TIER=B cargo test --test chaos              # nightly tier (10 seeds)
CHAOS_TIER=C cargo test --test chaos              # full sweep (100 seeds)
cargo test --test chaos wal_concurrency           # single scenario
```

Format and lint gates:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

---

## Snapshot Coverage

Snapshot and diff behavior is tested in:
- `tests/snapshot_diff_tests.rs`

Use that file as the source of truth for snapshot-related behavior.

---

## Fuzz Targets

Current fuzz targets in `fuzz/fuzz_targets/`:
- `fuzz_config_parse`
- `fuzz_baseline_compare`
- `fuzz_scanner`
- `fuzz_toml_config`
- `fuzz_event_filter`
- `fuzz_db_roundtrip`
- `fuzz_xattr_parsing`
- `fuzz_wal_recovery`

Run them from the `fuzz/` workspace:

```bash
cd fuzz
cargo +nightly fuzz build
cargo +nightly fuzz list
```

---

## scripts/test-all.sh Notes

`./scripts/test-all.sh` currently runs these stages:
1. `cargo fmt -- --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --bins`
4. `cargo test --test integration`
5. `cargo test --test security`

Stages 4 and 5 do not match the current flat `tests/` layout.
Use `cargo test --all-targets` or explicit `--test <file_name>` commands for reliable local verification.

---

## Where to Add New Tests

Use this rule of thumb:

- single function behavior: unit test in the same `src/*` module
- cross-module behavior: new file in `tests/` named for behavior
- integrity and tamper behavior: new file in `tests/` with explicit scope in the filename

Prefer descriptive names like `audit_chain_tests.rs` over generic buckets.

---

## WAL Test Coverage

The Detection WAL has three layers of testing:

**Unit tests (in-module):**
- `src/wal/mod.rs` — 14 tests covering WAL format, append/read, CRC corruption, gap scanning, gap limit enforcement (MAX_GAP_BYTES DoS prevention), HMAC verification, truncation, concurrency (8 threads × 1,000 entries), and sentinel roundtrip
- `src/wal/audit_writer.rs` — 5 tests covering drain-to-audit-DB, crash recovery deduplication, sequence gap detection, priority ordering (Critical first), and audit DB failure/reopen
- `src/wal/sink_runner.rs` — 3 tests covering bounded cooldown LRU, independent sink dispatch, and suppressed entries marked consumed

**Integration tests:**
- `tests/wal_integration.rs` — 2 tests: `panic_produces_detection_record` (panic handler WAL roundtrip), `wal_disabled_uses_current_path` (fallback to alert channel when WAL disabled)

**Fuzz target:**
- `fuzz/fuzz_targets/fuzz_wal_recovery.rs` — feeds arbitrary bytes as WAL file, exercises `iter_unconsumed()` gap-scanning

---

## Chaos Engineering Suite (since v0.29.0)

The chaos suite validates resilience under real environmental faults: filesystem churn, time anomalies, resource starvation, and crash recovery. It is deterministic and seed-reproducible.

### Architecture

- **Harness** (`tests/chaos/harness.rs`): seeded xoshiro256** PRNG, `InjectedClock` (forward/backward/freeze/jitter), `FsMutator` (8 filesystem mutation types), `DbPermissionToggler`, `InvariantEngine` (13 invariants), `ArtifactWriter` (forensic replay bundle)
- **Common** (`tests/chaos/chaos_common.rs`): factory functions for `DetectionRecord`, WAL/DB helpers, config defaults
- **Scenarios** (`tests/chaos/scenarios/`): 8 scenario files exercising different subsystems

### Scenarios

| # | Scenario | File | What it tests |
|---|----------|------|---------------|
| 1 | WAL Concurrency and Recovery | `wal_concurrency.rs` | N threads racing append/mark/iter/truncate + reopen recovery |
| 2 | Detection Pipeline Crash Recovery | `pipeline_recovery.rs` | Repeated AuditWriter crash-restart cycles, HMAC chain verification |
| 3 | Coordinator Adversarial Tick | `coordinator_adversarial_tick.rs` | DbFileIdentity inode-swap detection, Degraded transitions |
| 4 | Worker Pool Filesystem Chaos | `worker_pool_chaos.rs` | Workers under filesystem races, panic containment |
| 5 | Config Reload Storm | `config_reload_storm.rs` | Rapid valid/invalid config alternation, atomic rejection |
| 6 | Sink Suppression Determinism | `sink_determinism.rs` | Two SinkRunners fed identical streams produce identical decisions |
| 7 | Clock Warfare | `clock_warfare.rs` | Forward/backward jumps, freeze, jitter across WAL + coordinator |
| 8 | Coordinated Attack | `coordinated_attack.rs` | All subsystems under compound stress (fs warfare + DB flapping + reload + scan) |

### Invariants Checked

| ID | Invariant |
|----|-----------|
| I1 | Every appended WAL entry has a unique, monotonically increasing sequence number |
| I2 | `iter_unconsumed()` never returns fully consumed entries |
| I3 | After recovery, each non-sentinel WAL entry is durably present in audit DB or still pending |
| I4 | `truncate_consumed()` never increases file size |
| I5 | `mark_audit_done` and `mark_sink_done` are idempotent |
| I6 | `DetectionSource::Sentinel` entries are excluded from audit DB durability counts |
| I7 | Audit DB HMAC chain has no gaps and verifies end-to-end |
| I8 | `process_safe` panic detections have `Severity::Critical` and empty `changes` |
| I9 | With `wal_active=true`, audit persistence path remains WAL-mediated |
| I10 | WAL permissions remain `0600` |
| I11 | `pending_count()` equals `count(!(audit_done && sink_done))` |
| I12 | Coordinator transitions to Degraded on DB/WAL inode change |
| I13 | Invalid config reload leaves effective runtime config unchanged |

### CI Tiers

| Tier | When | Seeds | Duration | Scale |
|------|------|-------|----------|-------|
| A | Default CI (`cargo test`) | 1 | ~6s | 4 threads, 100 iterations |
| B | Nightly (`CHAOS_TIER=B`) | 10 | ~5 min | 8 threads, 1000 iterations |
| C | Manual (`CHAOS_TIER=C`) | 100 | Extended | 16 threads, 10000 iterations |

### Failure Artifacts

When an invariant fails, the suite writes an artifact file containing:
- Seed (for exact replay)
- Scenario config and timeline of injected faults with elapsed timestamps
- WAL summary (file size, pending count, appends)
- Audit DB summary (entry count, chain validity, chain breaks)
- Failed invariant details with context

A test is flaky only if failure is not seed-reproducible. Any seed-reproducible failure is a bug until root-caused.
