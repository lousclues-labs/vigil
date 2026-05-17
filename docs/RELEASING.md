# Releasing Vigil Baseline

Release process for maintainers.
Keep it boring, repeatable, and verifiable.

---

## Version Format

Vigil Baseline uses Semantic Versioning (`MAJOR.MINOR.PATCH`).

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

## Packaging Gate

`.github/workflows/pkg-build.yml` is the merge-blocking gate for any
change under `pkg/`, `systemd/`, `config/`, `contrib/`, `hooks/`, or
the top-level `Cargo.toml` / `Cargo.lock`. The aggregate check
`pkg-success` is the single required status set in branch protection.

The gate proves, for every distro in the matrix (`noble`, `jammy`,
`bookworm`, `el9`, `fedora`):

1. `pkg/build.sh` rejects every documented bad input shape.
2. `pkg/build.sh` produces exactly one artifact per invocation.
3. The artifact is reproducible — two builds with the same
   `SOURCE_DATE_EPOCH` are byte-identical (sha256 match). This
   underpins [ATTEST.md](ATTEST.md): signed attestations are only
   meaningful over reproducible outputs.
4. The artifact installs cleanly via `dpkg` / `rpm`.
5. Every file Vigil claims to ship is at the claimed path, with
   the claimed mode and ownership.
6. Regression guards hold (no dev-paths in unit, correct
   capability surface, correct file modes).
7. Both binaries run their `--help` / `--version` paths without
   requiring runtime deps.

Signing and publishing are not this gate's job — those belong to
`lousclues-labs/lousclues-pkg`. This gate only proves that what is
fed to the signer is correct.

### Wiring `pkg-success` into branch protection

The aggregate check is named `pkg-success`. To make it the single
required status (rather than wiring all four jobs individually,
which is brittle as the workflow evolves):

1. GitHub → repo → **Settings → Branches → Branch protection rules**.
2. Edit (or create) the rule for `main`.
3. Tick **Require status checks to pass before merging**, then
   **Require branches to be up to date before merging**.
4. In the *Search for status checks* box, type `pkg-success` and
   select it. Do **not** also select `lint`, `input-tests`, or any
   `build (…)` matrix child — `pkg-success` already gates on all of
   them via `needs: [lint, input-tests, build]` and runs with
   `if: always()`. Selecting the children individually means a
   matrix-cardinality change to the workflow silently bypasses the
   gate.
5. Save.

For the same reason, the workflow's `pkg-success` job is *not*
inside the `build` matrix and does *not* use `success()` — it
explicitly inspects each `needs.<job>.result` and fails if any is
not `success`. This shape survives workflow refactors.

---

*Releases are trust events. Treat them like it.*
