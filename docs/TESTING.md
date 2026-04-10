# Testing

Vigil tests deterministic behavior. Claims need runnable checks.

---

## Test Layout

Integration-style tests live as flat files under `tests/`.

```
tests/
|-- alert_dispatcher_tests.rs
|-- audit_chain_tests.rs
|-- baseline_json_tests.rs
|-- baseline_tamper_tests.rs
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
- `src/wal/mod.rs` — 13 tests covering WAL format, append/read, CRC corruption, gap scanning, HMAC verification, truncation, concurrency (8 threads × 1,000 entries), and sentinel roundtrip
- `src/wal/audit_writer.rs` — 5 tests covering drain-to-audit-DB, crash recovery deduplication, sequence gap detection, priority ordering (Critical first), and audit DB failure/reopen
- `src/wal/sink_runner.rs` — 3 tests covering bounded cooldown LRU, independent sink dispatch, and suppressed entries marked consumed

**Integration tests:**
- `tests/wal_integration.rs` — 2 tests: `panic_produces_detection_record` (panic handler WAL roundtrip), `wal_disabled_uses_current_path` (fallback to alert channel when WAL disabled)

**Fuzz target:**
- `fuzz/fuzz_targets/fuzz_wal_recovery.rs` — feeds arbitrary bytes as WAL file, exercises `iter_unconsumed()` gap-scanning
