# Vigil Baseline

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-success)](.github/workflows/ci.yml)
[![Security Audit](https://img.shields.io/badge/Security-Audit-success)](.github/workflows/scheduled.yml)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://www.rust-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

**Your filesystem. Your baseline. Your witness.**

> *No one tiptoes through your system without leaving footprints behind.*

---

## The Baseline

You run `vigil init` on a clean system. Vigil walks every path you told it to watch and records exactly what it sees. Hash. Permissions. Ownership. Inode. Extended attributes. That snapshot is the baseline. It is the truth about what your system looks like when you trust it.

From that moment forward, every change is measured against the baseline. A file's hash changes. A permission shifts. An inode is replaced. An entry disappears. Vigil sees it because the baseline remembers what was there before.

The baseline is not a database you query. It is a declaration you made about what "correct" looks like. Everything Vigil does flows from that declaration.

**We compare. We do not guess.** Hashes match or they don't. Permissions changed or they didn't. The inode is the same or it was replaced. There is no "maybe." There is no gradient. There is no risk score that fades into ambiguity.

**We are silent by default.** A healthy system produces zero alerts. When the baseline matches reality, Vigil says nothing. When reality deviates, Vigil speaks. Once. Clearly.

**We stay local.** No telemetry. No cloud lookups. No outbound connections. Disconnect the network cable. Vigil works identically.

**We watch. We do not act.** Vigil is a witness. Not a guard. When something changes that shouldn't have, Vigil tells you. What you do about it is your decision.

**The baseline protects itself.** If the baseline database is tampered with, emptied, or replaced, Vigil detects it and refuses to operate silently on a compromised foundation. A tool that trusts its own data without verifying it is a tool that can be blinded.

Read the full [Principles](docs/PRINCIPLES.md) if you want to understand
what we're about.

---

## How It Gets Built

Rust. Because the compiler enforces the kind of promises security tools need to keep. Memory safety is not optional when the tool's job is to prove filesystem integrity.

Built with AI. Every line held to the same standard as my own. Every decision is in the [CHANGELOG](CHANGELOG.md).

---

## What You Get

**Establish the baseline.**
- `vigil init` walks your watched paths and records the known-good state
- BLAKE3 hashing with full metadata capture (permissions, ownership, inode, xattrs)
- HMAC signing available for tamper-evident baselines

**Watch the filesystem.**
- Real-time kernel-level monitoring via fanotify (inotify fallback)
- TOCTOU-hardened comparison pipeline: open, fstat(fd), hash(fd), compare
- Bloom filter rejects 99% of irrelevant events before they reach workers

**Detect deviations.**
- Every deviation compared against the baseline you established
- Crash-safe detection WAL ensures no detection is silently lost
- Package-aware monitoring distinguishes system updates from suspicious changes

**Prove what happened.**
- HMAC-chained audit trail. Delete an entry and the chain breaks.
- Suppression affects notifications. It never affects the audit trail.
- `vigil audit verify` proves the chain is intact.
- `vigil attest` creates signed portable attestations (`.vatt`) for offline verification.
- `vigil inspect` compares files against a baseline on a different machine. No daemon required.

**Stay informed.**
- Policy-based notification routing supports immediate, coalesced, and digest delivery modes
- Storm suppression and critical escalation tracking keep alerting actionable under heavy churn
- Desktop notifications, journald, JSON log, Unix signal socket
- Optional webhook delivery for external incident pipelines
- `vigil doctor` runs twelve self-diagnostics
- `vigil diff` compares any file against baseline and audit history

---

## First time?

    sudo vigil welcome

Configures vigil in 90 seconds. Idempotent: safe to re-run.

Operators who prefer to configure by hand can skip ahead to Quick Start.

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
vigil welcome                      # First-run configuration (interactive, idempotent)
vigil init                         # Create baseline from configured watch paths
vigil init --force                 # Overwrite existing baseline without asking
vigil status                       # Show baseline stats and daemon health
vigil doctor                       # Run self-diagnostics (compact; --verbose for full)
vigil selftest                     # End-to-end verification on this machine
```

### Real-Time Monitoring

```bash
vigil watch                        # Start monitoring (foreground, Ctrl+C to stop)
sudo systemctl start vigild        # Start as systemd daemon
```

### Integrity Checks

```bash
vigil check                        # Incremental check (mtime-changed files only)
vigil check --full                 # Full scan (re-hash everything)
vigil check --now                  # Trigger scan on running daemon via control socket
vigil check --since 24h            # Show only changes with recent audit evidence
vigil check --brief                # Single-line summary output
vigil diff /etc/passwd             # Compare file against baseline + audit history
vigil why /etc/resolv.conf         # Explain a single change (facts only)
vigil why                          # Explain the most recent change
```

### Accepting Changes

```bash
vigil check --accept               # Show changes, then update baseline to current state
vigil check --accept --path '/etc/*'  # Accept only changes matching a glob
vigil check --accept --dry-run     # Preview what would be accepted without mutating
vigil check --accept --accept-severity low  # Accept only low-severity changes
```

After package updates, `vigil check --accept` is the way to tell Vigil Baseline
"yes, I know these files changed, that's fine." The pacman/apt hooks in
`hooks/` do this automatically.

### Audit Log

```bash
vigil audit show                   # Show recent audit entries (default: last 50)
vigil audit show -n 100            # Show last 100 entries
vigil audit show --severity high   # Filter by severity
vigil audit show --path '/etc/*'   # Filter by path glob
vigil audit show --since 2026-04-01  # Filter by date
vigil audit show --group system_critical  # Filter by watch group
vigil audit show -v                # Show full change details
vigil audit stats                  # Severity and count breakdown
vigil audit stats --period 30d     # Stats for last 30 days
vigil audit verify                 # Verify audit chain integrity
```

### Configuration

```bash
vigil config show                  # Display active configuration as TOML
vigil config validate              # Validate configuration file
```

### HMAC and Socket Setup

```bash
vigil setup hmac                   # Generate HMAC signing key at default path
vigil setup hmac --key-path /custom/path --force  # Custom path, overwrite existing
vigil setup socket --path /run/vigil/alert.sock   # Configure alert socket
vigil setup socket --disable       # Disable alert socket
```

---

## Configuration

Vigil Baseline keeps its config in `/etc/vigil/vigil.toml` (system) or
`~/.config/vigil/vigil.toml` (user). Here's what matters:

```toml
[daemon]
monitor_backend = "fanotify"       # "fanotify" or "inotify"
log_level = "info"                 # error/warn/info/debug/trace
control_socket = "/run/vigil/control.sock"

[scanner]
schedule = "0 3 * * *"             # cron schedule for scheduled scans
mode = "incremental"               # incremental or full
hash_algorithm = "blake3"          # the only option that makes sense
max_file_size = 2147483648         # 2 GB -- skip larger files

[alerts]
desktop_notifications = true       # D-Bus via notify-send (with --app-name=Vigil Baseline and urgency mapping)
webhook_url = ""                  # optional HTTP endpoint for alert delivery
webhook_bearer_token = ""         # optional Authorization: Bearer token
storm_threshold = 50               # events before storm suppression activates
storm_window_secs = 60             # rolling window (seconds) for storm detection
cooldown_seconds = 300             # per-path alert cooldown (5 min)
rate_limit = 10                    # max alerts per minute

[security]
hmac_signing = false               # enable HMAC signing for audit entries
hmac_key_path = "/etc/vigil/hmac.key"

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

## What 1.0 doesn't have, and won't

- No TUI. No web UI.
- No rule engine. No plugin system.
- No telemetry, opt-in or otherwise.
- No auto-updates.
- No anthropomorphized daemon name.
- No webhook or MQTT notification channels.
- No machine learning, no Bayesian inference, no adaptive thresholds.

The signal socket is the integration point for anyone who needs more.

---

## Requirements

- Linux (Arch, Debian/Ubuntu, Fedora, etc.)
- Rust toolchain (edition 2021)
- Optional: `CAP_SYS_ADMIN` for fanotify (falls back to inotify without it)
- Optional: `notify-send` for desktop notifications

That's really it. SQLite is bundled. No system libraries required.

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

*Vigil Baseline: Your filesystem has a witness. It never looks away.*