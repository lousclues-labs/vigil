# Testing

Vigil tests deterministic behavior, not vibes.
If a security claim cannot be tested, it is not a claim.

---

## Test Categories

| Category | Count | Location | Purpose |
|----------|-------|----------|---------|
| Unit | 43 | inline in `src/**/*.rs` | validate isolated functions/types |
| Integration | 37 | `tests/integration/` | cross-module behavior |
| Security | 15 + 1 ignored privileged | `tests/security/` | security properties and race resilience |
| Fuzz | 3 targets | `fuzz/fuzz_targets/` | panic/crash resistance under arbitrary input |

Reference: `tests/README.md` is the canonical test-layout guide.

---

## Quick Commands

```bash
# Full suite helper
./scripts/test-all.sh

# Standard test run
cargo test

# Unit tests only
cargo test --bins

# Integration tests only
cargo test --test integration

# Security tests (non-privileged)
cargo test --test security

# Privileged ignored tests
sudo -E cargo test --test security -- --ignored
```

---

## Detailed Commands

### Formatting and Linting

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

### Rustdoc checks

```bash
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
cargo test --doc
```

### Targeted filtering

```bash
cargo test baseline
cargo test compare
cargo test filter
cargo test race
```

---

## Fuzz Testing

Vigil includes three fuzz targets:

| Target | File | Property Tested |
|--------|------|-----------------|
| `fuzz_config_parse` | `fuzz/fuzz_targets/fuzz_config_parse.rs` | TOML config parsing does not panic on arbitrary input |
| `fuzz_baseline_compare` | `fuzz/fuzz_targets/fuzz_baseline_compare.rs` | baseline compare pipeline handles arbitrary metadata safely |
| `fuzz_scanner` | `fuzz/fuzz_targets/fuzz_scanner.rs` | scanner path handles malformed/edge file states without crashes |

Setup:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Run all targets quickly:

```bash
cargo +nightly fuzz build
for t in $(cargo +nightly fuzz list); do
  cargo +nightly fuzz run "$t" -- -max_total_time=60 -max_len=65536
done
```

Run one target longer:

```bash
cargo +nightly fuzz run fuzz_baseline_compare -- \
  -max_total_time=1800 \
  -print_final_stats=1 \
  -use_value_profile=1
```

---

## CI Pipeline Mapping

### Primary CI (`.github/workflows/ci.yml`)

| Job | Purpose | Command Class |
|-----|---------|---------------|
| `check` | format/lint/docs gate | `fmt`, `clippy`, `cargo doc` |
| `audit` | dependency risk gate | `cargo audit`, `cargo deny` |
| `test` | unit/integration/doc tests | `cargo test --all-targets`, doc tests |
| `coverage` | coverage generation + upload | `cargo tarpaulin`, Codecov |
| `msrv` | minimum supported Rust check | `cargo check --all-features` on 1.85 |

### Scheduled CI (`.github/workflows/scheduled.yml`)

| Job | Purpose |
|-----|---------|
| `security-audit` | weekly `cargo audit` + `cargo deny` |
| `coverage` | weekly coverage artifacts |

### Fuzz CI

| Workflow | Purpose |
|----------|---------|
| `fuzz-smoke.yml` | 60-second per-target smoke fuzz on push/PR |
| `weekly-fuzz.yml` | scheduled weekly fuzz run |
| `fuzz-moab.yml` | manual long fuzz shards across all targets |

---

## Coverage

Coverage is generated with `cargo-tarpaulin` in CI.

Local run:

```bash
cargo install cargo-tarpaulin --locked
mkdir -p coverage
cargo tarpaulin \
  --all-features \
  --skip-clean \
  --out xml --out html \
  --output-dir coverage \
  --timeout 240 \
  --jobs 1 \
  -- --test-threads=2
```

Outputs:
- `coverage/cobertura.xml`
- `coverage/tarpaulin-report.html` (and related files)

In CI:
- uploaded to Codecov
- stored as workflow artifact (`coverage` or `scheduled-coverage`)

---

## Adding New Tests

Decision rule (expanded from `tests/README.md`):

```
Does it test one function/type in isolation?
|- yes -> unit test in src module
`- no
   Does it cross module boundaries?
   |- yes -> integration test in tests/integration/
   `- no
      Is it a security property or adversarial behavior?
      |- yes -> tests/security/
      `- no -> usually integration unless benchmark/fuzz-specific
```

Placement guidance:
- baseline lifecycle behavior -> `tests/integration/baseline_tests.rs`
- compare/TOCTOU behavior -> `tests/integration/comparison_tests.rs`
- filter/exclusion/debounce -> `tests/integration/filter_tests.rs`
- permission/race/integrity guarantees -> `tests/security/*`

When adding new behavior:
1. add positive path tests
2. add failure path tests
3. add regression test for bug fixed
4. update docs if behavior changed

---

## Privileged Tests

Some security scenarios require root capabilities (ownership changes, certain monitor conditions).
Mark these `#[ignore]` and run explicitly under sudo in controlled environments.

Do not make privileged paths mandatory for default CI.

---

## Testing Philosophy

- Determinism over heuristics
- Reproducible failures over flaky checks
- Security claims backed by runnable tests

*If a test flakes, fix the test or the design. Do not normalize noise.*
