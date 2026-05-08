# Development Setup

This page covers local build, run, test, and fuzz workflows.

---

## Prerequisites

- Linux
- Rust stable toolchain
- build tools (`gcc`, `make`, `pkg-config`)

### Arch

```bash
sudo pacman -S --needed rust base-devel pkgconf
```

### Debian or Ubuntu

```bash
sudo apt update
sudo apt install -y rustc cargo build-essential pkg-config
```

### Fedora

```bash
sudo dnf install -y rust cargo gcc make pkgconf-pkg-config
```

Optional runtime tools:
- `notify-send`
- systemd for service and timer tests

---

## Clone and Build

```bash
git clone https://github.com/lousclues-labs/vigil.git
cd vigil
cargo build
cargo build --release
```

Binaries:
- `target/debug/vigil`
- `target/debug/vigild`

---

## Core Commands

| Task | Command |
|------|---------|
| format | `cargo fmt --all` |
| lint | `cargo clippy --all-targets --all-features -- -D warnings` |
| tests | `cargo test --all-targets` |
| docs | `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` |

---

## Run Locally

### One-shot CLI

```bash
cargo run -- init
cargo run -- status
cargo run -- check
cargo run -- audit stats
```

### Watch mode

```bash
RUST_LOG=debug cargo run -- watch
```

### Daemon binary

```bash
RUST_LOG=debug cargo run --bin vigild
```

### Explicit config

```bash
RUST_LOG=debug cargo run -- --config ./config/vigil.toml watch
```

---

## Project Structure

```
src/
|-- alert/
|   |-- mod.rs
|   |-- dbus.rs
|   |-- journal.rs
|   |-- json_log.rs
|   |-- remote_syslog.rs
|   `-- socket.rs
|-- attest/
|   |-- mod.rs
|   |-- create.rs
|   |-- verify.rs
|   |-- diff.rs
|   |-- show.rs
|   |-- list.rs
|   |-- format.rs
|   |-- key.rs
|   `-- error.rs
|-- commands/
|   |-- mod.rs
|   |-- common.rs
|   |-- init.rs
|   |-- check.rs
|   |-- watch.rs
|   |-- diff.rs
|   |-- status.rs
|   |-- explain.rs
|   |-- why_silent.rs
|   |-- inspect.rs
|   |-- test_alert.rs
|   |-- doctor.rs
|   |-- audit.rs
|   |-- config.rs
|   |-- setup.rs
|   |-- attest.rs
|   |-- log.rs
|   |-- maintenance.rs
|   |-- baseline.rs
|   `-- update.rs
|-- config/
|   |-- mod.rs
|   `-- diff.rs
|-- db/
|   |-- mod.rs
|   |-- schema.rs
|   |-- baseline_ops.rs
|   |-- audit_ops.rs
|   `-- migrate.rs
|-- display/
|   |-- mod.rs
|   |-- check.rs
|   |-- explain.rs
|   |-- format.rs
|   |-- term.rs
|   `-- widgets.rs
|-- filter/
|   |-- mod.rs
|   `-- exclusion.rs
|-- monitor/
|   |-- mod.rs
|   |-- fanotify.rs
|   `-- inotify.rs
|-- types/
|   |-- mod.rs
|   |-- alert.rs
|   |-- baseline.rs
|   |-- change.rs
|   |-- config_types.rs
|   |-- content.rs
|   |-- event.rs
|   |-- identity.rs
|   |-- permissions.rs
|   |-- security.rs
|   `-- snapshot.rs
|-- ui/
|   |-- mod.rs
|   `-- progress.rs
|-- wal/
|   |-- mod.rs
|   |-- audit_writer.rs
|   `-- sink_runner.rs
|-- bloom.rs
|-- cli.rs
|-- control.rs
|-- coordinator.rs
|-- daemon.rs
|-- detection.rs
|-- doctor.rs
|-- error.rs
|-- hash.rs
|-- hmac.rs
|-- lib.rs
|-- main.rs
|-- metrics.rs
|-- package.rs
|-- receipt.rs
|-- scan_scheduler.rs
|-- scanner.rs
|-- watch_index.rs
`-- worker.rs

tests/
|-- alert_dispatcher_tests.rs
|-- attest_tests.rs
|-- audit_chain_tests.rs
|-- baseline_json_tests.rs
|-- baseline_tamper_tests.rs
|-- chaos.rs                     # chaos engineering entry point
|-- chaos/                       # chaos test suite (~2,800 lines)
|   |-- chaos_common.rs
|   |-- harness.rs
|   `-- scenarios/
|       |-- wal_concurrency.rs
|       |-- pipeline_recovery.rs
|       |-- coordinator_adversarial_tick.rs
|       |-- worker_pool_chaos.rs
|       |-- config_reload_storm.rs
|       |-- sink_determinism.rs
|       |-- clock_warfare.rs
|       `-- coordinated_attack.rs
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

fuzz/
`-- fuzz_targets/
    |-- fuzz_config_parse.rs
    |-- fuzz_baseline_compare.rs
    |-- fuzz_scanner.rs
    |-- fuzz_toml_config.rs
    |-- fuzz_event_filter.rs
    |-- fuzz_db_roundtrip.rs
    |-- fuzz_xattr_parsing.rs
    |-- fuzz_wal_recovery.rs
    |-- fuzz_attest_file.rs
    `-- fuzz_attest_verify.rs
```

---

## Test Flow

Primary commands:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Run specific integration files:

```bash
cargo test --test audit_chain_tests
cargo test --test hmac_chain_tamper_tests
cargo test --test snapshot_diff_tests
```

Run chaos engineering suite:

```bash
cargo test --test chaos                          # default tier (Tier A)
CHAOS_SEED=12345 cargo test --test chaos         # specific seed
CHAOS_TIER=B cargo test --test chaos             # nightly tier (10 seeds)
```

---

## Fuzzing

Install toolchain and cargo-fuzz:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Build and list targets:

```bash
cd fuzz
cargo +nightly fuzz build
cargo +nightly fuzz list
```

This workspace has ten fuzz targets:
- `fuzz_config_parse`
- `fuzz_baseline_compare`
- `fuzz_scanner`
- `fuzz_toml_config`
- `fuzz_event_filter`
- `fuzz_db_roundtrip`
- `fuzz_xattr_parsing`
- `fuzz_wal_recovery`
- `fuzz_attest_file`
- `fuzz_attest_verify`

Run one target:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_config_parse -- -max_total_time=120
```

---

## Release profile

`Cargo.toml` pins `[profile.release]` to:

```toml
opt-level = 2
lto = true
codegen-units = 1
strip = true
```

`opt-level = 2` was kept after measurement, not by default.

### Methodology

Bench the BLAKE3 hot path and the exclusion filter under each
candidate `opt-level`. Single-codegen-unit + LTO is held constant.

```bash
cargo bench --bench benchmarks -- --warm-up-time 1 --measurement-time 3
cargo build --release && ls -l target/release/{vigil,vigild}
```

`benches/benchmarks.rs` covers BLAKE3 at 64 KiB / 1 MiB / 16 MiB
(captures cold, warm, and large-mmap regimes) plus a 10k-path
exclusion filter pass.

### Results (v1.11.2, x86_64 reference machine)

| Metric                   | opt-level 2          | opt-level 3          | Delta   |
|--------------------------|----------------------|----------------------|---------|
| BLAKE3 64 KiB throughput | 3.40 GiB/s           | (within noise)       | flat    |
| BLAKE3 1 MiB throughput  | 3.46 GiB/s           | 3.18 GiB/s           | -6.4%   |
| BLAKE3 16 MiB throughput | 3.12 GiB/s           | 3.03 GiB/s           | -2.8%   |
| event_filter_10k         | 776 us               | 981 us               | +19% slower |
| `vigil` binary           | 8.59 MB              | 9.35 MB              | +8.9% bigger |
| `vigild` binary          | 5.63 MB              | 6.28 MB              | +11.6% bigger |

`opt-level = 3` was slower *and* larger on this codebase. The hot path
is already SIMD-vectorised inside the `blake3` crate, so aggressive
inlining at `-O3` did not unlock new SIMD codegen. Once LTO collapses
crate boundaries, `-O3` inliner heuristics produced cache-unfriendly
code in the exclusion filter. `opt-level = "s"` was not pursued after
this finding: there is no throughput pressure to trade off against.

### When to revisit

Re-run the benchmark suite if any of the following changes:

- `blake3` crate major version bump.
- Significant rewrite of the worker, scanner, or filter hot path.
- Toolchain MSRV bump that changes the LLVM version.
- Migration to a different default codegen backend (e.g. `cranelift`).

Record the new numbers in this section. Do not change the profile
silently.

---

## Before Opening a PR

Run the full gate:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Optional dependency checks:

```bash
cargo install cargo-audit --locked
cargo audit --deny warnings
cargo install cargo-deny --locked
cargo deny check
```
