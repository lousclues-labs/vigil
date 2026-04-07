# Licensing Guide

*Last updated: April 2026*

This document provides a comprehensive overview of how licensing applies to every file and file type in the Vigil project. It serves as the canonical reference for contributors, users, and anyone evaluating Vigil's licensing for compatibility or compliance.

## Copyright Holder

All original work in this repository is copyright **Louis Nelson Jr.** unless otherwise noted.

See the [NOTICE](../NOTICE) file for the full identity mapping (Louis Nelson Jr. ↔ loujr ↔ lousclues).

## License Summary

| License | SPDX Identifier | Applies To | Full Text |
|---------|-----------------|------------|-----------|
| GNU GPL v3.0 only **or** Commercial License | `GPL-3.0-only` | Source code, scripts, build files, tests, configs | [LICENSE](../LICENSE), [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) |
| CC BY 4.0 | `CC-BY-4.0` | Documentation | [LICENSE-DOCS.md](LICENSE-DOCS.md) |

Vigil is dual-licensed. A Commercial License is available for organizations whose use cases are incompatible with the GPL. See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for full terms.

---

## File-Type License Coverage Map

### Source Code

| File Pattern | License | SPDX Header Required | Notes |
|-------------|---------|---------------------|-------|
| `src/**/*.rs` | GPL-3.0-only | Yes | All Rust source files |
| `tests/**/*.rs` | GPL-3.0-only | Yes | All test files |
| `fuzz/**/*.rs` | GPL-3.0-only | Yes | All fuzz target files |

### Scripts

| File Pattern | License | SPDX Header Required | Notes |
|-------------|---------|---------------------|-------|
| `scripts/*.sh` | GPL-3.0-only | Yes | Development/CI scripts |
| `hooks/**` | GPL-3.0-only | Recommended | Git/package-manager hooks |

### Build & Configuration Files

| File Pattern | License | SPDX Header Required | Notes |
|-------------|---------|---------------------|-------|
| `Cargo.toml` | GPL-3.0-only | No (metadata file) | `license` field covers this |
| `Cargo.lock` | GPL-3.0-only | No (generated) | Auto-generated |
| `deny.toml` | GPL-3.0-only | No | cargo-deny policy |
| `.github/workflows/*.yml` | GPL-3.0-only | Recommended | CI/CD pipelines |

### Systemd Service Files

| File Pattern | License | SPDX Header Required | Notes |
|-------------|---------|---------------------|-------|
| `systemd/**` | GPL-3.0-only | Recommended | systemd service/timer units |

### Configuration Templates

| File Pattern | License | SPDX Header Required | Notes |
|-------------|---------|---------------------|-------|
| `config/**` | GPL-3.0-only | No | Configuration templates/examples |

### Documentation

| File Pattern | License | SPDX Header Required | Notes |
|-------------|---------|---------------------|-------|
| `docs/*.md` | CC-BY-4.0 | No | User and developer documentation |
| `README.md` | CC-BY-4.0 | No | Project README |
| `CONTRIBUTING.md` | CC-BY-4.0 | No | Contribution guide |
| `CHANGELOG.md` | CC-BY-4.0 | No | Release history |
| `VERSIONING.md` | CC-BY-4.0 | No | Version policy |

### Legal & Administrative Documents

| File Pattern | License | Notes |
|-------------|---------|-------|
| `LICENSE` | N/A (is the license) | GPL-3.0 full text |
| `licenses/LICENSE-COMMERCIAL.md` | N/A (is the license) | Commercial license terms |
| `licenses/LICENSE-DOCS.md` | N/A (is the license) | Documentation license terms |
| `licenses/LICENSING.md` | N/A (this file) | License coverage guide |
| `licenses/CONTRIBUTOR-LICENSE.md` | N/A (is the CLA) | Contributor license agreement |
| `licenses/DEPENDENCY-AUDIT.md` | N/A (is the framework) | Dependency audit framework |
| `licenses/THIRD-PARTY-LICENSES` | N/A (is attribution) | Third-party license list |
| `licenses/README.md` | N/A (is an index) | License directory index |
| `TRADEMARKS.md` | N/A (is the policy) | Trademark usage policy |
| `GOVERNANCE.md` | N/A (is the policy) | Succession and governance |
| `NOTICE` | N/A (is the notice) | Attribution and identity |
| `THIRD_PARTY_NOTICES.md` | N/A (is the policy) | Third-party notice policy |

### Generated & Temporary Files

| File Pattern | License | Notes |
|-------------|---------|-------|
| `target/` | N/A | Build artifacts (not distributed) |
| `coverage/` | N/A | Generated reports (not distributed) |

---

## Canonical SPDX Header Formats

### Rust Source Files (`.rs`)

```rust
// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Louis Nelson Jr. <https://lousclues.com>
```

### Shell Scripts (`.sh`)

```bash
#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Louis Nelson Jr. <https://lousclues.com>
```

Place the SPDX header immediately after the shebang line.

### TOML Configuration Files

```toml
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Louis Nelson Jr. <https://lousclues.com>
```

> **Note:** For `Cargo.toml`, the `license` field in `[package]` serves as the SPDX declaration. An additional comment header is optional but not required.

### YAML Configuration Files (`.yml`, `.yaml`)

```yaml
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Louis Nelson Jr. <https://lousclues.com>
```

### Markdown Documentation (`.md` in `docs/`)

Markdown documentation files are covered by CC-BY-4.0 as declared in [LICENSE-DOCS.md](LICENSE-DOCS.md). No per-file header is required. The repository-level license declaration covers all documentation files.

If a per-file header is desired (e.g., for standalone distribution), use an HTML comment:

```markdown
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright (C) 2026 Louis Nelson Jr. <https://lousclues.com> -->
```

---

## Header Verification

To verify that all source files have correct SPDX headers, use the following approach:

### Quick Check (grep)

```bash
# Find .rs files missing SPDX headers
find src/ tests/ fuzz/ -name '*.rs' -exec grep -L 'SPDX-License-Identifier' {} \;

# Find .sh files missing SPDX headers
find . -name '*.sh' -not -path './target/*' -exec grep -L 'SPDX-License-Identifier' {} \;

# Verify copyright line format
grep -rn 'Copyright (C)' src/ tests/ fuzz/ scripts/ | grep -v 'Louis Nelson Jr.'
```

### Automated Check (CI)

A CI step can enforce header compliance:

```bash
#!/bin/bash
# check-headers.sh -- Verify SPDX headers in source files
set -euo pipefail

ERRORS=0

# Check Rust files
while IFS= read -r file; do
    if ! head -1 "$file" | grep -q 'SPDX-License-Identifier: GPL-3.0-only'; then
        echo "MISSING SPDX header: $file"
        ERRORS=$((ERRORS + 1))
    fi
    if ! head -2 "$file" | grep -q 'Copyright (C) .* Louis Nelson Jr.'; then
        echo "MISSING/INCORRECT copyright: $file"
        ERRORS=$((ERRORS + 1))
    fi
done < <(find src/ tests/ fuzz/ -name '*.rs')

# Check shell scripts
while IFS= read -r file; do
    if ! head -3 "$file" | grep -q 'SPDX-License-Identifier'; then
        echo "MISSING SPDX header: $file"
        ERRORS=$((ERRORS + 1))
    fi
done < <(find . -name '*.sh' -not -path './target/*')

if [ "$ERRORS" -gt 0 ]; then
    echo "Found $ERRORS header issues."
    exit 1
fi

echo "All headers OK."
```

---

## Dependency License Compatibility

All third-party dependencies must be compatible with the GPL-3.0-only license. See [DEPENDENCY-AUDIT.md](DEPENDENCY-AUDIT.md) for the full compatibility framework and audit process.

---

## Questions

For licensing questions, see the [README](../README.md) or contact Louis Nelson Jr.:

- **GitHub:** [@loujr](https://github.com/loujr)
- **Website:** [lousclues.com](https://lousclues.com)
