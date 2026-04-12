# Contributing to VigilBaseline

You want to help. Good.
Read the principles first, then ship clean changes.

---

## Short Version

1. Read [docs/PRINCIPLES.md](docs/PRINCIPLES.md)
2. Fork the repo
3. Create a branch from `main`
4. Make focused changes
5. Run checks
6. Open a PR

## Contributor Terms

By submitting a contribution, you agree to:
- [licenses/CONTRIBUTOR-LICENSE.md](licenses/CONTRIBUTOR-LICENSE.md)
- [licenses/LICENSING.md](licenses/LICENSING.md)

Trademark usage (the "VigilBaseline" and "lousclues" names) is governed separately by [TRADEMARKS.md](TRADEMARKS.md).

This keeps source licensing, documentation licensing, and trademark rights explicit.

---

## Principles, Summarized

These are not decoration. They are contribution filters.

| Principle | What It Means For Contributions |
|-----------|---------------------------------|
| I. Watch, Don't Act | no auto-remediation/quarantine/kill behavior |
| II. Silence Is the Default | reduce false positives, avoid noisy output |
| III. Determinism Over Heuristics | no ML/heuristic scoring logic |
| IV. Structure Over Behavior | file-state facts, not behavior interpretation |
| V. Alerts Must Be Actionable | clear path/severity/change-type in outputs |
| VIII. VigilBaseline Stands Alone | avoid unnecessary external coupling |
| X. Fail Open, Fail Loud | explicit fallback and degradation signals |
| XI. Complexity Is a Vulnerability | justify every dependency and feature |
| XIII. Audit Trail Never Lies | suppression must not hide audit truth |
| XIV. No Network I/O | no telemetry, no hidden outbound behavior |

Full context: [docs/PRINCIPLES.md](docs/PRINCIPLES.md).

---

## Development Setup

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for full details.

Quick start:

```bash
git clone https://github.com/loujr/vigil.git
cd vigil
cargo build
cargo test
```

---

## Before You Submit

All PRs should pass locally:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Recommended security gates:

```bash
cargo install cargo-audit --locked
cargo audit --deny warnings
cargo install cargo-deny --locked
cargo deny check
```

---

## What Makes A Good Contribution

### Great Contributions

- bug fixes with regression tests
- test coverage for edge cases and races
- docs clarity improvements
- performance improvements with evidence
- cross-distro install/runtime fixes

### Discuss First

Open an issue before implementing:
- new top-level CLI commands
- new config sections/options
- new direct dependencies
- architecture changes in daemon/monitor/alert pipeline
- schema changes in baseline/audit tables

### Out Of Scope

These are intentional non-goals.

| Feature Request | Why Rejected |
|-----------------|--------------|
| GUI frontend | VigilBaseline is CLI/systemd-first |
| cloud integration/telemetry | violates Principle XIV |
| behavioral analysis/ML scoring | violates Principles III and IV |
| auto-remediation/quarantine | violates Principle I |

---

## PR Process

1. Fork repository
2. Branch from `main`
3. Implement change
4. Add or update tests
5. Update docs when behavior changes
6. Run required checks
7. Commit with conventional message
8. Push and open pull request

Suggested branch naming:

```bash
git checkout -b fix/short-description
git checkout -b feat/short-description
git checkout -b docs/short-description
```

---

## Commit Messages

Use conventional commits:

```text
type: short summary

optional body with what and why
```

Types:
- `feat`
- `fix`
- `docs`
- `refactor`
- `test`
- `chore`

Examples:

```text
fix: keep audit entries when alert channel suppressed
docs: clarify fanotify fallback blind spots
test: add race regression for delete-between-open-and-hash
```

---

## Code Style

### Error Handling

- no silent failures
- avoid `unwrap()` in production paths
- return typed errors with context

### Logging

- use level-appropriate logs (`error`, `warn`, `info`, `debug`)
- log fallback/degradation events explicitly
- avoid noisy informational spam in healthy steady state

### Scope Discipline

- prefer small diffs
- do not reformat unrelated files
- keep behavior deterministic

---

## Testing Requirements

Reference: [docs/TESTING.md](docs/TESTING.md).

Decision guide:

```
Single function behavior?
|- yes -> unit test in src module
`- no
   Cross-module behavior?
   |- yes -> tests/<behavior>_tests.rs
   `- no
      Security property/race?
      |- yes -> tests/<security_scope>_tests.rs
      `- no -> tests/<feature_scope>_tests.rs
```

If behavior changes, add tests in same PR.

### Snapshot Tests

VigilBaseline uses [insta](https://insta.rs/) for snapshot testing of critical output formats.
When a snapshot changes:

```bash
cargo insta test       # Run tests and capture new snapshots
cargo insta review     # Interactively review and accept/reject changes
```

Snapshot behavior coverage currently lives in `tests/snapshot_diff_tests.rs`.
Review snapshot changes carefully. They indicate a change in alert, baseline export, or diff output format.

---

## AI Transparency

VigilBaseline is built with AI.
Contributions are reviewed with the same standards regardless of tooling: tests, lint, review, and clear reasoning.

---

## Questions

- bug report: open an issue with reproduction details
- feature idea: open issue first for scope fit
- docs confusion: open docs issue or PR directly

Be direct. Be respectful. Keep it technical.

*Good contributions make VigilBaseline quieter and more truthful.*
