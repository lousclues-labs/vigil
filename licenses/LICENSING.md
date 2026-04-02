# Licensing Guide

Last updated: April 2026

Canonical license coverage map for Vigil.

## Copyright Holder

Original project work is copyright Louis Nelson Jr., unless stated otherwise.

## License Summary

| License | SPDX | Applies To |
|---------|------|------------|
| GNU GPL v3.0 only | `GPL-3.0-only` | source code, scripts, tests, configuration, build files |
| Creative Commons Attribution 4.0 | `CC-BY-4.0` | documentation files in scope of [LICENSE-DOCS.md](LICENSE-DOCS.md) |

Root license text:
- [../LICENSE](../LICENSE)

## Coverage Map

### Source and Code-Adjacent Files

| Pattern | License |
|---------|---------|
| `src/**/*.rs` | GPL-3.0-only |
| `tests/**/*.rs` | GPL-3.0-only |
| `fuzz/**/*.rs` | GPL-3.0-only |
| `scripts/*.sh` | GPL-3.0-only |
| `hooks/**` | GPL-3.0-only |
| `systemd/**` | GPL-3.0-only |
| `Cargo.toml`, `Cargo.lock`, `deny.toml` | GPL-3.0-only |
| `.github/workflows/**` | GPL-3.0-only |

### Documentation Files

| Pattern | License |
|---------|---------|
| `docs/*.md` | CC-BY-4.0 (except legal docs if added under docs/) |
| `README.md` | CC-BY-4.0 |
| `CONTRIBUTING.md` | CC-BY-4.0 |
| `CHANGELOG.md` | CC-BY-4.0 |
| `tests/README.md` | CC-BY-4.0 |

### Legal and Administrative Files

| File | Role |
|------|------|
| `LICENSE` | GPL-3.0-only full text |
| `licenses/LICENSING.md` | this coverage guide |
| `licenses/LICENSE-DOCS.md` | docs license terms |
| `licenses/CONTRIBUTOR-LICENSE.md` | contribution terms |
| `licenses/DEPENDENCY-AUDIT.md` | dependency license policy |
| `licenses/THIRD-PARTY-LICENSES` | dependency attributions |

## SPDX Header Guidance

Use this SPDX header for source files:

```text
SPDX-License-Identifier: GPL-3.0-only
```

Use this SPDX header for documentation files (optional when repo-level policy is already explicit):

```text
SPDX-License-Identifier: CC-BY-4.0
```

## Dependency Compliance

Dependency license policy and audit process:
- [DEPENDENCY-AUDIT.md](DEPENDENCY-AUDIT.md)
- [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES)

## Contribution Terms

By submitting contributions, contributors agree to terms in:
- [CONTRIBUTOR-LICENSE.md](CONTRIBUTOR-LICENSE.md)

*Licensing should be explicit enough that nobody has to guess.*
