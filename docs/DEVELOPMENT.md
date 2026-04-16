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
|-- config/
|   |-- mod.rs
|   `-- diff.rs
|-- db/
|   |-- mod.rs
|   |-- schema.rs
|   |-- baseline_ops.rs
|   |-- audit_ops.rs
|   `-- migrate.rs
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
|-- bloom.rs
|-- cli.rs
|-- control.rs
|-- coordinator.rs
|-- daemon.rs
|-- doctor.rs
|-- error.rs
|-- hash.rs
|-- hmac.rs
|-- lib.rs
|-- main.rs
|-- metrics.rs
|-- package.rs
|-- scan_scheduler.rs
|-- scanner.rs
|-- watch_index.rs
`-- worker.rs

tests/
|-- alert_dispatcher_tests.rs
|-- audit_chain_tests.rs
|-- baseline_json_tests.rs
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
|-- snapshot_diff_tests.rs
`-- worker_tests.rs

fuzz/
`-- fuzz_targets/
    |-- fuzz_config_parse.rs
    |-- fuzz_baseline_compare.rs
    |-- fuzz_scanner.rs
    |-- fuzz_toml_config.rs
    |-- fuzz_event_filter.rs
    |-- fuzz_db_roundtrip.rs
    `-- fuzz_xattr_parsing.rs
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

This workspace has seven fuzz targets:
- `fuzz_config_parse`
- `fuzz_baseline_compare`
- `fuzz_scanner`
- `fuzz_toml_config`
- `fuzz_event_filter`
- `fuzz_db_roundtrip`
- `fuzz_xattr_parsing`

Run one target:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_config_parse -- -max_total_time=120
```

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
