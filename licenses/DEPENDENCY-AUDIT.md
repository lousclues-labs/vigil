# Dependency License Audit Framework

Last updated: April 2026

How Vigil evaluates dependency license compatibility.

## Purpose

Every dependency is a legal and supply-chain risk surface.
This framework keeps dependency decisions auditable and repeatable.

## Repository Policy

Vigil source is GPL-3.0-only.
Dependency allow-list policy is enforced by `deny.toml`.

Allowed SPDX identifiers in current policy:
- MIT
- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- ISC
- Unicode-3.0
- Unicode-DFS-2016
- GPL-3.0-only

Registry policy:
- unknown registries: denied
- unknown git sources: denied

## Compatibility Table

| License Type | GPL-3.0-only Compatibility | Policy Status |
|--------------|-----------------------------|---------------|
| MIT / Apache-2.0 / BSD / ISC | compatible | allowed |
| Unicode-* data licenses | compatible for relevant crates | allowed |
| GPL-3.0-only | compatible | allowed |
| GPL-2.0-only | incompatible | denied |
| AGPL / SSPL / proprietary | outside policy | denied |

## Direct Dependency Audit

Source of truth: `Cargo.toml` + `Cargo.lock` + `cargo metadata`.

| Dependency | License Expression |
|------------|--------------------|
| blake3 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| chrono | MIT OR Apache-2.0 |
| clap | MIT OR Apache-2.0 |
| crossbeam-channel | MIT OR Apache-2.0 |
| env_logger | MIT OR Apache-2.0 |
| glob | MIT OR Apache-2.0 |
| hex | MIT OR Apache-2.0 |
| hmac | MIT OR Apache-2.0 |
| libc | MIT OR Apache-2.0 |
| log | MIT OR Apache-2.0 |
| nix | MIT |
| rusqlite | MIT |
| serde | MIT OR Apache-2.0 |
| serde_json | MIT OR Apache-2.0 |
| sha2 | MIT OR Apache-2.0 |
| thiserror | MIT OR Apache-2.0 |
| toml | MIT OR Apache-2.0 |
| uuid | Apache-2.0 OR MIT |
| xattr | MIT OR Apache-2.0 |

Note:
- Multi-license crates are acceptable when at least one compatible path exists and policy checks pass.

## Audit Process

Before adding a dependency:
1. identify the license expression
2. verify compatibility against policy
3. run automated checks
4. document the decision in PR notes

Commands:

```bash
cargo install cargo-deny --locked
cargo deny check

cargo install cargo-audit --locked
cargo audit --deny warnings

cargo metadata --format-version 1 > /tmp/vigil-metadata.json
```

Optional visibility helpers:

```bash
cargo tree
cargo tree --duplicates
```

## Attribution Maintenance

When dependencies change:
- update [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES)
- re-run policy checks in CI/local
- call out license-impacting changes in changelog

*Dependency approvals are design decisions, not package-manager side effects.*
