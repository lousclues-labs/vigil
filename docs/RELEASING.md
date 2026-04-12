# Releasing VigilBaseline

Release process for maintainers.
Keep it boring, repeatable, and verifiable.

---

## Version Format

VigilBaseline uses Semantic Versioning (`MAJOR.MINOR.PATCH`).

Examples:
- `0.18.0`
- `0.18.1`
- `0.19.0`

While major version is `0`, minor bumps may include breaking changes.
See [VERSIONING.md](../VERSIONING.md).

---

## Public API Surface

Treat these as compatibility-sensitive:

| Surface | Why It Is Public |
|---------|------------------|
| CLI commands/flags/output contracts | user automation/scripts rely on it |
| config format (`vigil.toml`) | user/system config management relies on schema |
| database schema (`baseline`, `audit_log`, `config_state`) | operators and forensic tooling depend on it |
| alert event shape (JSON log + signal socket payload intent) | downstream consumers parse it |

Changes to these require clear changelog and migration notes.

---

## Release Checklist

### 1) Prepare

```bash
git checkout main
git pull --ff-only
```

Verify version and changelog targets:
- `Cargo.toml` version
- `CHANGELOG.md` release section

### 2) Quality Gates

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --doc
```

Security gates:

```bash
cargo install cargo-audit --locked
cargo audit --deny warnings
cargo install cargo-deny --locked
cargo deny check
```

Optional extended gate:

```bash
./scripts/test-all.sh
```

### 3) Build Release Artifacts

```bash
cargo build --release
```

Validate binaries:

```bash
./target/release/vigil version
./target/release/vigild --help || true
```

### 4) Tag

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --tags
```

### 5) Publish Release Notes

- copy finalized section from `CHANGELOG.md`
- include highlights, breaking changes, migration notes
- link relevant docs for changed surfaces

---

## Breaking Change Discipline

If release changes any public API surface:
1. document exactly what changed
2. include migration path
3. update docs in same release
4. call out operational risk clearly

Do not hide breaking behavior behind vague notes.

---

## Commit Message Convention

Use conventional commits throughout release cycle:
- `feat`
- `fix`
- `docs`
- `refactor`
- `test`
- `chore`

Examples:

```text
chore: release v0.19.0
docs: add migration notes for baseline schema update
fix: preserve audit write on suppression path
```

---

## Post-Release Verification

After tag push:
- CI for release commit passes
- security audit workflow green
- coverage workflow green
- docs links resolve
- install instructions still work on clean machine

---

## Rollback Policy

If severe regression is found:
1. publish hotfix branch
2. release patch version (`0.x.(y+1)`)
3. document issue and remediation in changelog

Do not rewrite tags for published releases.

---

*Releases are trust events. Treat them like it.*
