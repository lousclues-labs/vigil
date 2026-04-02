# Development Setup

How to build, run, and test Vigil locally.

---

## Prerequisites

- Linux environment
- Rust toolchain (stable)
- build tools (`gcc`, `make`, `pkg-config`)

### Arch

```bash
sudo pacman -S --needed rust base-devel pkgconf
```

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y rustc cargo build-essential pkg-config
```

### Fedora

```bash
sudo dnf install -y rust cargo gcc make pkgconf-pkg-config
```

Optional local runtime tooling:
- `notify-send` (`libnotify-bin` / `libnotify`)
- systemd for service/timer tests

---

## Clone and Build

```bash
git clone https://github.com/<org>/vigil.git
cd vigil

# debug build
cargo build

# release build
cargo build --release
```

Binaries:
- `target/debug/vigil`
- `target/debug/vigild`

---

## Core Dev Commands

| Task | Command |
|------|---------|
| format | `cargo fmt --all` |
| lint | `cargo clippy --all-targets --all-features -- -D warnings` |
| unit+integration+security | `cargo test --all-targets` |
| docs | `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` |
| full local gate | `./scripts/test-all.sh` |

---

## Running Locally

### One-shot CLI checks

```bash
cargo run -- init
cargo run -- status
cargo run -- check
```

### Daemon in foreground

```bash
RUST_LOG=debug cargo run -- watch
```

Or run daemon binary directly:

```bash
RUST_LOG=debug cargo run --bin vigild
```

Use explicit config when needed:

```bash
RUST_LOG=debug cargo run -- --config ./config/vigil.toml watch
```

---

## Project Structure Walkthrough

```
src/
|-- main.rs             # CLI dispatch
|-- daemon.rs           # vigild entrypoint
|-- lib.rs              # daemon loop orchestration
|-- cli.rs              # clap surface
|-- config.rs           # config model + validation
|-- compare.rs          # TOCTOU compare
|-- scanner.rs          # incremental/full scans
|-- package.rs          # package ownership backends
|-- types.rs            # shared domain types
|-- error.rs            # error taxonomy
|-- baseline/           # baseline lifecycle
|-- db/                 # sqlite schema + ops
|-- monitor/            # fanotify/inotify + filter
`-- alert/              # notify channels + suppression

tests/
|-- common/             # fixtures + assertions
|-- integration/        # cross-module behavior
`-- security/           # security property tests

fuzz/
`-- fuzz_targets/       # three libfuzzer targets
```

---

## Test Infrastructure

Primary local script:

```bash
./scripts/test-all.sh
```

Stages in script:
1. `cargo fmt -- --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --bins`
4. `cargo test --test integration`
5. `cargo test --test security`

Privileged security tests:

```bash
sudo -E cargo test --test security -- --ignored
```

---

## Fuzz Development

Install tooling:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Build and list targets:

```bash
cargo +nightly fuzz build
cargo +nightly fuzz list
```

Run targets:

```bash
cargo +nightly fuzz run fuzz_config_parse -- -max_total_time=120
cargo +nightly fuzz run fuzz_baseline_compare -- -max_total_time=120
cargo +nightly fuzz run fuzz_scanner -- -max_total_time=120
```

Artifacts:
- crashes: `fuzz/artifacts/<target>/`
- corpus: `fuzz/corpus/<target>/`

---

## Logging and Diagnostics

Useful commands while developing:

```bash
RUST_LOG=debug cargo run -- doctor
cargo run -- status
cargo run -- log stats
```

What `doctor` checks:
- fanotify availability
- privilege context
- config validity
- DB write + integrity
- baseline count
- HMAC key presence (if enabled)
- notify-send availability
- package backend detection
- signal socket config

---

## Commit Message Convention

Use conventional commits.

Format:

```text
type: short summary

optional body with what/why
```

Types:
- `feat` new feature
- `fix` bug fix
- `docs` documentation
- `refactor` code restructuring
- `test` test additions/changes
- `chore` tooling/build/ci

Examples:

```text
fix: preserve inode/device checks in compare path
docs: expand security model and threat boundaries
test: add regression for debounce suppression edge case
```

---

## Development Rules That Matter

- no `unwrap()` in production paths unless failure is impossible and justified
- propagate errors with context
- prefer deterministic behavior over heuristic behavior
- keep dependencies minimal and justified
- update docs when behavior changes

---

## Before Opening a PR

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Recommended:

```bash
cargo install cargo-audit --locked
cargo audit --deny warnings
cargo install cargo-deny --locked
cargo deny check
```

---

*Small codebase. Sharp boundaries. No hidden magic.*
