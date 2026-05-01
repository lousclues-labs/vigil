# Vigil Baseline

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-success)](.github/workflows/ci.yml)
[![Security Audit](https://img.shields.io/badge/Security-Audit-success)](.github/workflows/scheduled.yml)
[![Version](https://img.shields.io/badge/version-1.8.2-blue)](CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://www.rust-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

**Your filesystem. Your baseline. Your witness.**

> *No one tiptoes through your system without leaving footprints behind.*

---

A file integrity monitor for Linux. You tell it what to watch.
It records exactly what those files look like. Then it watches
them. When something changes, it tells you.

That's all it does. No machine learning. No risk score. No
threat feed. No opinion about whether a change is "suspicious."
Hashes match or they don't. Permissions changed or they didn't.
There is no "maybe."

```
$ vigil check
Vigil Baseline — Integrity Check
═════════════════════════════════

  Baseline   5a7b·6009·f26f·e08c   established 24 Apr 18:52 (44m ago)
  Scanned    7,624 files in 0.1s    mode: incremental · HMAC ● signed
  Coverage   7,624 baseline entries · 0 scan errors

  ╭──────────────────────────────────────────────╮
  │  ● Boundaries intact                       │
  ╰──────────────────────────────────────────────╯
```

That's a healthy system. When files change, the box fills with
one square per change, severity-colored, and the changed files
are listed below.

## Try it

```bash
sudo vigil welcome                    # configure (about 90s, idempotent)
sudo vigil init                       # establish baseline
sudo vigil check                      # verify
sudo systemctl enable --now vigild    # run continuously
```

If you'd rather configure by hand, see
[Installation](docs/INSTALL.md) and
[Configuration](docs/CONFIGURATION.md).

## What it is

Vigil records a known-good snapshot of every watched file: hash,
permissions, ownership, inode, capabilities, xattrs, and
SELinux/AppArmor context. The daemon watches via fanotify
(falling back to inotify) and compares every event against that
snapshot. Deviations are written to a crash-safe WAL and an
HMAC-chained audit log. Notifications are storm-suppressed,
per-path-cooldowned, and written once.

The principles that drive every design decision are in
[PRINCIPLES.md](docs/PRINCIPLES.md). Worth reading before you
decide whether vigil is the right tool for your situation.

## CVE-2026-31431 (copy.fail) detection

Vigil hashes file content through the kernel page cache. That means it
observes what readers observe, including page-cache-layer tampering.

In `v1.8.1`, `vigil check --disambiguate-cause` adds mismatch
classification to help triage copy.fail-class signatures:

- `page_cache_only` — cached view changed, on-disk view re-hashes to baseline
- `disk_modification` — cached and on-disk views match each other, both differ from baseline
- `active_modification` — baseline, cached, and post-eviction views all differ
- `inconclusive` — cache eviction did not complete

For end-to-end reproducible evidence, see:

- `tests/exploits/copy_fail/` (Tier 1 and optional Tier 2 harness)
- `docs/COPY_FAIL_VERIFICATION_REPORT.md`
- `docs/COPY_FAIL_EXECUTIVE_SUMMARY.md`

## What it isn't

It isn't an EDR. It doesn't kill processes, quarantine files,
or block execution. There is no web UI, no plugin system, no
telemetry, no auto-updates, no network calls of any kind. The
signal socket and webhook are the only integration points; both
are off by default and outbound-only when enabled.

If you need more, vigil is probably not the right fit.

## How it's built

Every release was driven by a written prompt that named the
problem, the principle being applied, and the constraints. The
[CHANGELOG](CHANGELOG.md) records each architectural decision,
each correction, and the reasoning behind both. Vigil is built
with AI assistance; the changelog is the honest record of that
work.

If you want to see how vigil came to be the way it is, that's
where to start.

## Documentation

| Document | What's Inside |
|----------|---------------|
| [Docs Index](docs/README.md) | Documentation map by topic |
| [Quickstart](docs/QUICKSTART.md) | From install to monitoring in 5 minutes |
| [Cookbook](docs/COOKBOOK.md) | Common scenarios with exact commands |
| [Installation](docs/INSTALL.md) | Building, dependencies, systemd setup |
| [CLI Reference](docs/CLI.md) | Every command, every flag |
| [Configuration](docs/CONFIGURATION.md) | The config file explained |
| [Notifications](docs/NOTIFICATIONS.md) | Routing policy, coalescing, storm suppression, webhook |
| [Architecture](docs/ARCHITECTURE.md) | How it's built |
| [Security](docs/SECURITY.md) | Security model, dependency justification |
| [Vulnerabilities](docs/VULNERABILITIES.md) | All remediated vulnerabilities with tracking IDs |
| [Attestation](docs/ATTEST.md) | Portable signed attestations and offline verification |
| [Threat Model](docs/THREAT_MODEL.md) | What Vigil Baseline detects and what it doesn't |
| [Testing](docs/TESTING.md) | Test suite, fuzz targets, coverage |
| [Development](docs/DEVELOPMENT.md) | Dev setup, building, debugging |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | When things go wrong |
| [FAQ](docs/FAQ.md) | Common questions answered |
| [Resilience](docs/RESILIENCE.md) | Failure modes and recovery |
| [Minimum Viable Trust](docs/MINIMUM_VIABLE.md) | Smallest deployment, what it provides |
| [Forensics](docs/FORENSICS.md) | Offline comparison workflows |
| [Principles](docs/PRINCIPLES.md) | Why it's built this way |
| [Releasing](docs/RELEASING.md) | Release process and versioning |
| [Licensing Guide](licenses/LICENSING.md) | File-level license coverage and policy |
| [Dependency Audit](licenses/DEPENDENCY-AUDIT.md) | Dependency license compatibility framework |
| [Third-Party Licenses](licenses/THIRD-PARTY-LICENSES) | Direct dependency attributions |
| [Documentation License](licenses/LICENSE-DOCS.md) | License terms for project docs |
| [Commercial Licensing](licenses/LICENSE-COMMERCIAL.md) | Commercial license terms |
| [NOTICE](NOTICE) | Project identity and attribution |
| [Trademarks](TRADEMARKS.md) | Trademark usage policy |
| [Contributing](CONTRIBUTING.md) | How to help |

## Requirements

Linux. Optional `CAP_SYS_ADMIN` for fanotify (inotify fallback
otherwise). Optional `notify-send` for desktop notifications.
SQLite is bundled.

## License

Copyright (C) 2026 **Louis Nelson Jr.** — a [lousclues](https://lousclues.com) project.

Vigil Baseline is dual-licensed:

| Component | License | File |
|-----------|---------|------|
| Source Code | GNU GPL v3.0 only **or** Commercial License | [LICENSE](LICENSE), [LICENSE-COMMERCIAL.md](licenses/LICENSE-COMMERCIAL.md) |
| Documentation | Creative Commons Attribution 4.0 (CC BY 4.0) | [LICENSE-DOCS.md](licenses/LICENSE-DOCS.md) |
| Third-Party Dependencies | MIT, Apache-2.0, and other permissive licenses | [THIRD-PARTY-LICENSES](licenses/THIRD-PARTY-LICENSES) |

**For most users:** The GPL covers you completely. Use Vigil Baseline, monitor your files, run the daemon. No restrictions beyond the GPL.

**For proprietary/commercial use:** If you need to embed Vigil Baseline in closed-source products or redistribute without GPL obligations, a [commercial license](licenses/LICENSE-COMMERCIAL.md) is available.

**For contributors:** By submitting a pull request, you agree to the [Contributor License Agreement](licenses/CONTRIBUTOR-LICENSE.md). You keep your copyright. You grant the project permission to use the contribution under both licenses.

**Trademarks:** "Vigil Baseline" and "lousclues" are the project name and publisher mark respectively. See [TRADEMARKS.md](TRADEMARKS.md). Neither "Vigil" nor "Baseline" is individually claimed as a trademark.

For the complete licensing framework, see [LICENSING.md](licenses/LICENSING.md). For project governance and succession planning, see [GOVERNANCE.md](GOVERNANCE.md).
