# Vigil Test Suite

Every test, organized by type and purpose.

## Test Categories

| Category    | Location              | Command                              | Purpose                               |
|-------------|-----------------------|--------------------------------------|---------------------------------------|
| Unit        | `src/**/*.rs`         | `cargo test --bins`                  | Inline tests for individual functions |
| Integration | `tests/integration/`  | `cargo test --test integration`      | Module interaction tests              |
| Security    | `tests/security/`     | `cargo test --test security`         | Security property verification        |

## Directory Structure

```
tests/
├── README.md                      # This file
│
├── common/                        # Shared test utilities
│   ├── mod.rs                     # Module root
│   ├── fixtures.rs                # TempDir, config builders, baseline builders
│   └── assertions.rs              # Custom assertions for changes, severity, counts
│
├── integration.rs                 # Integration test binary
├── integration/                   # Integration tests (Rust)
│   ├── mod.rs                     # Test module root
│   ├── baseline_tests.rs          # Baseline init, refresh, diff, add, remove
│   ├── comparison_tests.rs        # TOCTOU-hardened file comparison
│   ├── config_tests.rs            # Configuration parsing and validation
│   ├── db_tests.rs                # Database operations and state management
│   └── filter_tests.rs            # Event filter: exclusion, debounce, self-exclusion
│
├── security.rs                    # Security test binary
└── security/                      # Security tests (Rust)
    ├── mod.rs                     # Test module root
    ├── integrity_tests.rs         # Hash determinism, inode tracking, audit trail
    ├── permission_tests.rs        # Permission escalation, world-writable detection
    └── race_tests.rs              # TOCTOU resilience, concurrent writes, edge cases
```

## Running Tests

### Quick Commands

```bash
# Run all tests
cargo test

# Unit tests only (fast)
cargo test --bins

# Integration tests
cargo test --test integration

# Security tests (non-privileged)
cargo test --test security

# Security tests (privileged — requires sudo)
sudo -E cargo test --test security -- --ignored

# Run tests matching a pattern
cargo test baseline
cargo test compare
cargo test filter
```

## Decision Tree: Where Should This Test Go?

```
Does it test a single function/struct in isolation?
├── YES → Unit test (inline in src/)
└── NO
    ↓
Does it test multiple modules working together?
├── YES → Integration test (tests/integration/)
└── NO
    ↓
Does it test a security property?
├── YES → Security test (tests/security/)
└── NO
    ↓
Does it need the full binary running?
├── YES → E2E test (tests/e2e/ — future)
└── NO
    ↓
Does it need privileged access (root, CAP_SYS_ADMIN)?
├── YES → Security test with #[ignore]
└── NO → Probably integration test
```

## What Each Test Category Covers

### Unit Tests (`src/`)
- Type serialization roundtrips (Severity, ChangeType, BaselineSource)
- BLAKE3 hashing: determinism, known values, empty files, hex format
- Config parsing: defaults, validation, rejection of invalid input
- Database CRUD: insert, upsert, query, delete, audit log, config state

### Integration Tests (`tests/integration/`)
- **baseline_tests**: Full init/refresh/diff lifecycle, exclusion patterns, stats
- **comparison_tests**: Content modification, deletion, permission changes, inode replacement, hash verification
- **config_tests**: TOML loading, validation rules, path expansion
- **db_tests**: Schema creation, integrity checks, WAL, maintenance window state, constraint enforcement
- **filter_tests**: System exclusions, glob patterns, self-exclusion, debounce timing

### Security Tests (`tests/security/`)
- **integrity_tests**: Hash determinism (Principle III), inode tracking for file replacement attacks, audit trail completeness (Principle XIII)
- **permission_tests**: Setuid detection, world-writable detection, database file permissions
- **race_tests**: Concurrent DB writes, rapid file changes during comparison, file deletion between event and hash, edge cases (empty files, deep paths)

## Test Requirements

### Unit & Integration Tests
- No root privileges required
- No daemon running required
- No network access required
- Temp directories cleaned up automatically

### Security Tests
Non-privileged tests:
- Hash determinism
- Permission change detection
- Database integrity
- Race condition resilience

Privileged tests (marked with `#[ignore]`):
- Ownership change detection (requires `chown`)
- fanotify availability check
