# Third-Party Notices

VigilBaseline depends on third-party open source crates.
This file states policy and attribution. No guesswork.

---

## License Policy

Dependency license policy is enforced by `cargo-deny` using [deny.toml](deny.toml).

Allowed license families (current policy):
- MIT
- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- ISC
- Unicode-3.0
- Unicode-DFS-2016
- GPL-3.0-only

Unknown registries and unknown git sources are denied by policy.

---

## Source of Truth

The authoritative dependency set is:
- [Cargo.lock](Cargo.lock) for exact resolved versions
- [Cargo.toml](Cargo.toml) for direct dependency declarations
- [licenses/THIRD-PARTY-LICENSES](licenses/THIRD-PARTY-LICENSES) for direct attribution records
- [licenses/DEPENDENCY-AUDIT.md](licenses/DEPENDENCY-AUDIT.md) for policy and audit process

For release-time license/security checks, run:

```bash
cargo install cargo-deny --locked
cargo deny check

cargo install cargo-audit --locked
cargo audit --deny warnings
```

---

## Attribution and Compliance

VigilBaseline includes and distributes third-party software under their respective licenses.

Compliance rules:
1. keep dependency graph auditable (`Cargo.lock` committed)
2. enforce policy in CI (`cargo deny`, `cargo audit`)
3. avoid unreviewed dependency additions
4. preserve required notices and license obligations

When adding a dependency:
- justify need in PR description
- verify license compatibility with policy
- ensure CI license checks pass

---

## Warranty Boundary

Third-party components are provided under their own licenses and warranty terms.
VigilBaseline does not override those upstream terms.

---

*Every dependency is borrowed trust. Track it like a liability.*
