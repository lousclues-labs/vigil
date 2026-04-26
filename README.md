# Vigil Baseline

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-success)](.github/workflows/ci.yml)
[![Security Audit](https://img.shields.io/badge/Security-Audit-success)](.github/workflows/scheduled.yml)
[![Version](https://img.shields.io/badge/version-1.7.0-blue)](CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://www.rust-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

**Your filesystem. Your baseline. Your witness.**

> *No one tiptoes through your system without leaving footprints behind.*

---

## What Is This

Vigil Baseline is a file integrity monitor for Linux. You tell it what to watch. It records exactly what those files look like. Then it watches them. When something changes, it tells you. That's it.

No risk scores. No threat intelligence feeds. No behavioral analysis. No machine learning. Vigil compares the filesystem against a known-good snapshot and reports the difference. Hashes match or they don't. Permissions changed or they didn't. The inode is the same or it was replaced.

There is no "maybe."

### The rules

**Vigil compares. Vigil does not judge.** Severity comes from your watch group configuration. Not from an internal heuristic. Not from a hardcoded list of "dangerous" things. You decide what's critical.

**A healthy system produces zero alerts.** When the baseline matches reality, Vigil says nothing. When reality deviates, Vigil speaks. Once. Clearly.

**Everything stays local.** No telemetry. No cloud lookups. No outbound connections. Disconnect the network cable. Vigil works identically.

**Vigil watches. Vigil does not act.** It is a witness. Not a guard. What you do about a change is your decision.

**The baseline protects itself.** If the baseline database is tampered with, emptied, or replaced, Vigil detects it and refuses to operate on a compromised foundation.

**Every threshold you hit is a threshold you control.** Clock skew tolerance, alert rates, retention policy, scan schedules. If Vigil has a number in it that affects your experience, you can change it.

Read the full [Principles](docs/PRINCIPLES.md).

---

## How It Gets Built

Rust. Because the compiler enforces the kind of promises security tools need to keep. Memory safety is not optional when the tool's job is to prove filesystem integrity.

Built with AI. Every line held to the same standard as my own. Every decision is in the [CHANGELOG](CHANGELOG.md).

42,000 lines of source across 118 files. 536 tests. 10 fuzz targets. 8 chaos engineering scenarios with 13 machine-checked invariants. Zero `unsafe` blocks without documented SAFETY justification.

---

## What You Get

**Establish the baseline.**
- `vigil init` walks your watched paths and records the known-good state
- BLAKE3 hashing with full metadata capture (permissions, ownership, inode, capabilities, xattrs, SELinux/AppArmor context)
- HMAC signing available for tamper-evident baselines

**Watch the filesystem.**
- Real-time kernel-level monitoring via fanotify with poll(2) event loop (inotify fallback)
- TOCTOU-hardened comparison pipeline: open fd, fstat(fd), hash(fd), compare
- Package-aware monitoring distinguishes system updates from suspicious changes

**Detect deviations.**
- Every deviation compared against the baseline you established
- Crash-safe detection WAL ensures no detection is silently lost
- Severity determined by watch group configuration. No internal heuristics.

**Prove what happened.**
- HMAC-chained audit trail. Delete an entry and the chain breaks.
- Suppression affects notifications. It never affects the audit trail.
- `vigil audit verify` proves the chain is intact (and warns you honestly when HMAC is disabled).
- `vigil attest` creates signed portable attestations (`.vatt`) for offline verification.
- `vigil inspect` compares files against a baseline on a different machine. No daemon required.

**Stay informed.**
- Desktop notifications, journald, JSON log, Unix signal socket, webhook
- Storm suppression and per-path cooldowns keep alerting actionable under heavy churn
- `vigil doctor` runs seventeen self-diagnostics with typed recovery actions
- `vigil why <path>` explains a single change. Facts only.
- `vigil diff` compares any file against baseline and audit history

**Know when something is wrong with Vigil itself.**
- Daemon self-monitors for DB tampering, clock manipulation, event loss, WAL corruption
- Every degradation is loud. Silent failures become `Degraded` state with operator-visible recovery.
- Audit retention that can't execute surfaces as a Doctor warning, not a silent skip.

---

## First Time?

    sudo vigil welcome

Configures Vigil in 90 seconds. Idempotent. Safe to re-run.

If you prefer to configure by hand, skip to Quick Start.

---

## Quick Start

```bash
vigil init                  # establish your baseline
vigil check                 # verify the filesystem against it
vigil status                # see what you are protecting
vigil doctor                # make sure everything is healthy
vigil watch                 # start watching in real time
```

The baseline is your source of truth. Everything starts there.

---

## The Basics

### Setup

```bash
vigil welcome                      # first-run configuration (interactive, idempotent)
vigil init                         # create baseline from configured watch paths
vigil init --force                 # overwrite existing baseline without asking
vigil status                       # show baseline stats and daemon health
vigil doctor                       # run self-diagnostics (compact; --verbose for full)
vigil selftest                     # end-to-end verification on this machine
```

### Real-Time Monitoring

```bash
vigil watch                        # start monitoring (foreground, Ctrl+C to stop)
sudo systemctl start vigild        # start as systemd daemon
```

### Integrity Checks

```bash
vigil check                        # incremental check (mtime-changed files only)
vigil check --full                 # full scan (re-hash everything)
vigil check --now                  # trigger scan on running daemon via control socket
vigil check --since 24h            # show only changes with recent audit evidence
vigil check --brief                # single-line summary output
vigil diff /etc/passwd             # compare file against baseline + audit history
vigil why /etc/resolv.conf         # explain a single change (facts only)
vigil why                          # explain the most recent change
```

### Accepting Changes

```bash
vigil check --accept               # show changes, then update baseline to current state
vigil check --accept --path '/etc/*'  # accept only changes matching a glob
vigil check --accept --dry-run     # preview what would be accepted without mutating
vigil check --accept --accept-severity low  # accept only low-severity changes
```

After package updates, `vigil check --accept` tells Vigil "yes, I know these files changed, that's fine." The pacman/apt hooks in `hooks/` do this automatically.

### Audit Log

```bash
vigil audit show                   # show recent audit entries (default: last 50)
vigil audit show -n 100            # show last 100 entries
vigil audit show --severity high   # filter by severity
vigil audit show --path '/etc/*'   # filter by path glob
vigil audit show --since 2026-04-01  # filter by date
vigil audit show --group system_critical  # filter by watch group
vigil audit show -v                # show full change details
vigil audit stats                  # severity and count breakdown
vigil audit stats --period 30d     # stats for last 30 days
vigil audit verify                 # verify audit chain integrity
```

### Configuration

```bash
vigil config show                  # display active configuration as TOML
vigil config validate              # validate configuration file
```

### HMAC and Socket Setup

```bash
vigil setup hmac                   # generate HMAC signing key at default path
vigil setup hmac --key-path /custom/path --force  # custom path, overwrite existing
vigil setup socket --path /run/vigil/alert.sock   # configure alert socket
vigil setup socket --disable       # disable alert socket
```

---

## Configuration

Config lives at `/etc/vigil/vigil.toml` (system) or `~/.config/vigil/vigil.toml` (user).

```toml
[daemon]
monitor_backend = "fanotify"       # "fanotify" or "inotify"
log_level = "info"                 # error/warn/info/debug/trace
control_socket = "/run/vigil/control.sock"

[scanner]
schedule = "0 3 * * *"             # cron schedule for scheduled scans
mode = "incremental"               # incremental or full
hash_algorithm = "blake3"
max_file_size = 2147483648         # 2 GB

[alerts]
desktop_notifications = true       # D-Bus via notify-send
webhook_url = ""                   # optional HTTP POST endpoint
webhook_bearer_token = ""          # optional Bearer token
storm_threshold = 50               # events before storm suppression activates
cooldown_seconds = 300             # per-path alert cooldown (5 min)
rate_limit = 10                    # max alerts per minute

[security]
hmac_signing = false               # enable HMAC signing for audit entries
hmac_key_path = "/etc/vigil/hmac.key"
clock_skew_threshold_seconds = 60  # skew above this prevents audit rotation
clock_skew_recovery_window = 300   # seconds before clock-skew degradation self-clears

[watch.system_critical]
severity = "critical"
paths = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/usr/bin/", "/usr/sbin/", "/boot/",
]

[watch.user_space]
severity = "high"
paths = [
    "~/.bashrc", "~/.ssh/", "~/.gnupg/",
]
```

See [Configuration](docs/CONFIGURATION.md) for the full reference.
See [Notifications](docs/NOTIFICATIONS.md) for routing, coalescing, and escalation behavior.

---

## Documentation

| Document | What's Inside |
|----------|---------------|
| [Docs Index](docs/README.md) | Documentation map by topic |
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

---

## What Vigil will never do

- No TUI. No web UI. The terminal is the interface.
- No rule engine. No plugin system.
- No telemetry, opt-in or otherwise.
- No auto-updates.
- No machine learning, no Bayesian inference, no adaptive thresholds.
- No heuristic severity escalation. Severity comes from your config.
- No anthropomorphized daemon name.

The signal socket is the integration point for anyone who needs more.

---

## Requirements

- Linux (Arch, Debian/Ubuntu, Fedora, etc.)
- Rust toolchain (edition 2021, MSRV 1.85)
- Optional: `CAP_SYS_ADMIN` for fanotify (falls back to inotify without it)
- Optional: `notify-send` for desktop notifications

That's it. SQLite is bundled. No system libraries required.

---

## License

Copyright (C) 2026 **Louis Nelson Jr.** -- a [lousclues](https://lousclues.com) project.

Vigil Baseline is dual-licensed:

| Component | License | File |
|-----------|---------|------|
| Source Code | GNU GPL v3.0 only **or** Commercial License | [LICENSE](LICENSE), [LICENSE-COMMERCIAL.md](licenses/LICENSE-COMMERCIAL.md) |
| Documentation | Creative Commons Attribution 4.0 (CC BY 4.0) | [LICENSE-DOCS.md](licenses/LICENSE-DOCS.md) |
| Third-Party Dependencies | MIT, Apache-2.0, and other permissive licenses | [THIRD-PARTY-LICENSES](licenses/THIRD-PARTY-LICENSES) |

**For most users:** The GPL covers you completely. Use Vigil Baseline, monitor your files, run the daemon. No restrictions beyond the GPL.

**For proprietary/commercial use:** If you need to embed Vigil Baseline in closed-source products or redistribute without GPL obligations, a [commercial license](licenses/LICENSE-COMMERCIAL.md) is available. Contact [@loujr](https://github.com/loujr) for terms.

**For contributors:** By submitting a pull request, you agree to the [Contributor License Agreement](licenses/CONTRIBUTOR-LICENSE.md). You keep your copyright. You grant the project permission to use your contribution under both licenses.

**Trademarks:** "Vigil Baseline" and "lousclues" are the project name and publisher mark respectively. See [TRADEMARKS.md](TRADEMARKS.md). Neither "Vigil" nor "Baseline" is individually claimed as a trademark.

For the complete licensing framework, see [LICENSING.md](licenses/LICENSING.md). For project governance and succession planning, see [GOVERNANCE.md](GOVERNANCE.md).

---

*Your filesystem has a witness.*