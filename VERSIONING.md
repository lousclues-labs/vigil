# Versioning Policy

Version numbers are behavior contracts.
VigilBaseline uses Semantic Versioning with explicit pre-1.0 rules.

---

## SemVer Baseline

Format: `MAJOR.MINOR.PATCH`

- `PATCH`: backward-compatible bug fixes
- `MINOR`: new features and, while `<1.0.0`, may include breaking changes
- `MAJOR`: breaking changes after `1.0.0`

---

## Pre-1.0 Rules (`0.y.z`)

Before `1.0.0`, the project is still stabilizing.

Rules:
- `0.y+1.0` may break compatibility
- breaking changes must be documented in `CHANGELOG.md`
- migrations must be documented in docs for affected surfaces
- avoid unnecessary breakage; "can break" is never a free pass

---

## What Counts As Public API

The following are treated as public compatibility surfaces:

| Surface | Compatibility Expectation |
|---------|---------------------------|
| CLI commands and flags | stable within a minor series unless documented otherwise |
| output formats used for automation | changes require docs/changelog callout |
| config schema (`vigil.toml`) | additive changes preferred; breaking changes documented |
| database schema | migration notes required for structural changes |
| alert event JSON semantics | downstream parser impact must be documented |

Not public API:
- internal module layout
- private helper functions
- non-contract log wording

---

## Compatibility Signals

A change should trigger at least a minor bump when it:
- removes/renames CLI commands or flags
- changes config meaning or defaults in behaviorally significant ways
- changes DB schema in non-additive ways
- changes alert payload semantics consumed downstream

Patch bump is appropriate for:
- bug fixes with no contract changes
- internal refactors
- docs-only updates

---

## Commit Message Convention

Use conventional commits for clear changelog generation and review flow.

Format:

```text
type: short summary
```

Types:
- `feat`
- `fix`
- `docs`
- `refactor`
- `test`
- `chore`

Optional scope style:

```text
feat(cli): add baseline export output controls
fix(compare): preserve inode change classification
```

---

## Toolchain and Dependency Policy

### Rust Toolchain

- MSRV is enforced in CI
- bumps to MSRV must be documented in changelog
- avoid unnecessary MSRV churn

### Dependencies

- new direct dependencies require explicit justification
- security/license checks must pass (`cargo audit`, `cargo deny`)
- dependency updates that alter behavior should be treated as release-significant

---

## Documentation Sync Rule

When a compatibility surface changes, update docs in the same PR:
- [docs/CLI.md](docs/CLI.md)
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) when model changes
- [CHANGELOG.md](CHANGELOG.md)

---

*Version numbers are promises. Keep them honest.*
