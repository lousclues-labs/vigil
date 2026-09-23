# Contributing to Vigil Baseline

You want to help. Good.
Read the principles first, then ship clean changes.

---

## Short Version

1. Read [docs/PRINCIPLES.md](docs/PRINCIPLES.md) and [PROMISES.md](PROMISES.md)
2. Fork the repo
3. Create a branch from `main`
4. Make focused changes
5. Run checks, including `cargo test --test pdd_canaries`
6. Open a PR

## Contributor Terms

By submitting a contribution, you agree to:
- [licenses/CONTRIBUTOR-LICENSE.md](licenses/CONTRIBUTOR-LICENSE.md)
- [licenses/LICENSING.md](licenses/LICENSING.md)

Trademark usage (the "Vigil Baseline" and "lousclues" names) is governed separately by [TRADEMARKS.md](TRADEMARKS.md).

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
| VIII. Vigil Baseline Stands Alone | avoid unnecessary external coupling |
| X. Fail Open, Fail Loud | explicit fallback and degradation signals |
| XI. Complexity Is a Vulnerability | justify every dependency and feature |
| XIII. Audit Trail Never Lies | suppression must not hide audit truth |
| XIV. No Network I/O | no telemetry, no hidden outbound behavior |

Full context: [docs/PRINCIPLES.md](docs/PRINCIPLES.md).

---

## Promises And Canaries

Vigil is built on Promise Driven Development. The principles above are the
values layer; [PROMISES.md](PROMISES.md) is the part we can prove. Every
promise there is narrow, falsifiable, and guarded by a canary that fails
loudly when the promise stops being true.

Three rules apply to contributions:

1. **A new self-claim needs a promise and a canary.** If your change makes the
   tool claim something about itself (in the README, in `--help`, in the docs),
   either add a promise to [PROMISES.md](PROMISES.md) with a canary that fails
   when the claim breaks, or state it as an aspiration at the bottom of that
   file. A claim with no guard is the one failure mode this project will not
   accept.
2. **A canary must live where the promise lives.** A promise about the source
   tree is a source scan. A promise about behavior is a behavioral test driving
   the real types. A cross-cutting promise that no unit test can see belongs in
   [.github/workflows/pdd-canaries.yml](.github/workflows/pdd-canaries.yml) as a
   gate job.
3. **Drift gets recorded, not just fixed.** If you find a case where a stated
   claim had stopped being true, add a numbered finding to
   [AUDIT_FINDINGS.md](AUDIT_FINDINGS.md): what drifted, why it mattered, the
   closing change, and the canary that prevents recurrence. A finding closed
   without a canary is not closed.

Before opening a PR that touches a promise:

```bash
cargo test --test pdd_canaries
bash scripts/verify-canary-drift.sh   # proves each canary fails on a real breach
```

Enable the pre-push guard once per clone, so a red canary cannot leave your
machine by accident:

```bash
git config core.hooksPath scripts/git-hooks
```

That same setting enables the sign-off hook described below.

A red canary is not a flaky test. It is the tool telling you a claim this
project makes about itself stopped being true. Fix the drift, or if the claim
itself changed, update [PROMISES.md](PROMISES.md) and record a finding.

---

## Sign-off

Every commit carries a `Signed-off-by:` trailer. It is an assertion under the
[Developer Certificate of Origin](https://developercertificate.org/): you are
stating you have the right to submit the work under this project's license.
The release tooling gates on the tagged commit carrying one.

Enabling `core.hooksPath` above installs
[scripts/git-hooks/prepare-commit-msg](scripts/git-hooks/prepare-commit-msg),
which adds the trailer using the identity git is already committing as. It
never adds a second one, so `git commit -s` and cherry-picks are unaffected.

If you would rather add it yourself:

```bash
git commit -s
```

The trailer is added at commit time deliberately. A sign-off that is only
noticed at release time is discovered long after the author who could make
the assertion has moved on, which turns the gate into something to override
rather than something to satisfy.

Note that `git commit --no-verify` does *not* skip this hook: that flag
bypasses `pre-commit` and `commit-msg` only. To commit without a sign-off,
disable hooks for the single command with
`git -c core.hooksPath=/dev/null commit`.

---

## Development Setup

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for full details.

Quick start:

```bash
git clone https://github.com/lousclues-labs/vigil.git
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
cargo test --test pdd_canaries
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
| GUI frontend | Vigil Baseline is CLI/systemd-first |
| cloud integration/telemetry | violates Principle XIV, breaks PR11 and PR12 |
| behavioral analysis/ML scoring | violates Principles III and IV, breaks PR3 and PR4 |
| auto-remediation/quarantine | violates Principle I, breaks PR1 and PR2 |

Each row on the right names the canary that will fail if the change is
attempted, not just the principle it offends. See [PROMISES.md](PROMISES.md).

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

### Architectural Diagrams

Vigil's architectural diagrams in `docs/diagrams/` cover
structural decisions that change rarely. If your PR
changes one of those structures (adds a new long-lived
thread, changes the WAL format, adds a new persistent
file, changes the trust model), update the corresponding
diagram in the same PR.

If your PR changes implementation details (function
internals, call sequences, recovery mechanics), update
the relevant code comments. The diagrams should NOT need
updating for implementation changes; if they do, the
diagram was drawn at too fine a grain and should be
revised.

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

Vigil Baseline uses [insta](https://insta.rs/) for snapshot testing of critical output formats.
When a snapshot changes:

```bash
cargo insta test       # Run tests and capture new snapshots
cargo insta review     # Interactively review and accept/reject changes
```

Snapshot behavior coverage currently lives in `tests/snapshot_diff_tests.rs`.
Review snapshot changes carefully. They indicate a change in alert, baseline export, or diff output format.

---

## AI Transparency

Vigil Baseline is built with AI.
Contributions are reviewed with the same standards regardless of tooling: tests, lint, review, and clear reasoning.

---

## Questions

- bug report: open an issue with reproduction details
- feature idea: open issue first for scope fit
- docs confusion: open docs issue or PR directly

Be direct. Be respectful. Keep it technical.

*Good contributions make Vigil Baseline quieter and more truthful.*
