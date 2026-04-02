#!/usr/bin/env bash
# Run the complete Vigil test suite.
set -euo pipefail

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Vigil Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "▶ Stage 1: Format check"
cargo fmt -- --check || { echo "✗ Format check failed"; exit 1; }
echo "✓ Format OK"
echo

echo "▶ Stage 2: Clippy"
cargo clippy --all-targets -- -D warnings 2>/dev/null || { echo "✗ Clippy failed"; exit 1; }
echo "✓ Clippy OK"
echo

echo "▶ Stage 3: Unit tests"
cargo test --bins 2>&1
echo "✓ Unit tests OK"
echo

echo "▶ Stage 4: Integration tests"
cargo test --test integration 2>&1
echo "✓ Integration tests OK"
echo

echo "▶ Stage 5: Security tests (non-privileged)"
cargo test --test security 2>&1
echo "✓ Security tests OK"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  All tests passed."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
