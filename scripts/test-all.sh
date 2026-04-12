#!/usr/bin/env bash
# Run the complete Vigil Baseline test suite.
set -euo pipefail

printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf '%s\n' "  Vigil Baseline Test Suite"
printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf '\n'

printf '%s\n' "▶ Stage 1: Format check"
cargo fmt -- --check || { printf '%s\n' "✗ Format check failed"; exit 1; }
printf '%s\n' "✓ Format OK"
printf '\n'

printf '%s\n' "▶ Stage 2: Clippy"
cargo clippy --all-targets -- -D warnings 2>/dev/null || { printf '%s\n' "✗ Clippy failed"; exit 1; }
printf '%s\n' "✓ Clippy OK"
printf '\n'

printf '%s\n' "▶ Stage 3: Unit tests"
cargo test --bins 2>&1
printf '%s\n' "✓ Unit tests OK"
printf '\n'

printf '%s\n' "▶ Stage 4: Integration tests"
cargo test --test integration 2>&1
printf '%s\n' "✓ Integration tests OK"
printf '\n'

printf '%s\n' "▶ Stage 5: Security tests (non-privileged)"
cargo test --test security 2>&1
printf '%s\n' "✓ Security tests OK"
printf '\n'

printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf '%s\n' "  All tests passed."
printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
