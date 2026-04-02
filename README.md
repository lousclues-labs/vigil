# Vigil

[![CI](https://img.shields.io/badge/CI-GitHub_Actions-success)](.github/workflows/ci.yml)
[![Security Audit](https://img.shields.io/badge/Security-Audit-success)](.github/workflows/scheduled.yml)
[![Version](https://img.shields.io/badge/version-0.4.0-blue)](CHANGELOG.md)
[![Rust](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://www.rust-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

**A lightweight file integrity monitor for Linux desktops.**

> *No one tiptoes through your system without leaving footprints behind.*

---

## The Philosophy

Most security tools want to be smart. They scan your files, apply heuristics,
consult cloud databases, compute risk scores, and then tell you something
is "potentially suspicious." You nod. You ignore it. You move on.

Vigil doesn't do any of that.

**We watch, we don't act.** Vigil compares hashes. Hashes match or they
don't. Permissions changed or they didn't. The inode is the same or it was
replaced. There is no "maybe." There is no gradient.

**We are silent by default.** A healthy system produces zero alerts. If
Vigil is making noise during a normal day, either your system is compromised
or your configuration is wrong. Fix the configuration first.

**We stay local.** No telemetry. No update checks. No cloud lookups. No
DNS queries. No outbound connections. Disconnect the network cable. Vigil
works identically.

**We don't quarantine. We don't execute. We don't remediate.** Vigil is a
witness, not a guard. When something changes that shouldn't have, Vigil
tells you -- immediately, clearly, and only once. What you do about it is
your decision.

Read the full [Principles](docs/PRINCIPLES.md) if you want to understand
what we're about.

---

## How It Gets Built

I chose Rust because the compiler enforces the kind of promises security
tools need to keep. I built Vigil with AI. I'm not going to pretend
otherwise, because pretending would violate the same principles this tool
is built on.

I broke the code, found the bugs, and fixed them. Every decision is in the
[CHANGELOG](CHANGELOG.md). That's where the real work lives.

---

## What You Get

```
+--------------------------------------------------------------------+
| [x] Filesystem monitoring                                          |
|     fanotify (mount-wide) with inotify fallback                   |
|                                                                    |
| [x] BLAKE3 integrity baselines                                     |
|     hash + permissions + ownership + inode + xattrs               |
|                                                                    |
| [x] TOCTOU-hardened comparison                                     |
|     open -> fstat(fd) -> hash(fd) -> compare                      |
|                                                                    |
| [x] Multi-channel alerting                                         |
|     desktop notify, journald, JSON log, Unix signal socket        |
|                                                                    |
| [x] systemd + package-manager integration                          |
|     hardened daemon unit, scan timer, pacman/apt hook support     |
|                                                                    |
| [x] Zero network I/O                                               |
|     no telemetry, no cloud lookups, no phoning home               |
|                                                                    |
| [x] Single-purpose design                                          |
|     two binaries, one job: file integrity monitoring              |
+--------------------------------------------------------------------+
```

---

## Quick Start

```bash
vigil init                  # create baseline of monitored paths
vigil check                 # one-shot integrity scan
vigil status                # verify backend and baseline counts
vigil doctor                # run environment diagnostics
vigil watch                 # foreground real-time monitor
```

You're protected.

---

## The Basics

### Initialization

```bash
vigil init                         # Create baseline from configured watch paths
vigil status                       # Show baseline stats and daemon health
vigil doctor                       # Run self-diagnostics
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
vigil baseline diff                # Show changes since last baseline
```

### Baseline Management

```bash
vigil baseline init                # Create initial baseline
vigil baseline refresh             # Re-scan and update all entries
vigil baseline refresh --paths /etc # Refresh only paths under /etc
vigil baseline add /path/to/file   # Add a single file
vigil baseline remove /path/to/file # Remove a single file
vigil baseline stats               # Show entry counts by source
vigil baseline export              # Export baseline as JSON
```

### Maintenance Windows

```bash
vigil maintenance enter            # Suppress alerts for package-managed paths
vigil maintenance exit             # Resume normal alerting
vigil maintenance status           # Check maintenance window state
```

Package manager hooks handle this automatically during `pacman -Syu` and
`apt upgrade`.

### Alert History

```bash
vigil log show                     # Show recent alerts
vigil log show --severity critical # Filter by severity
vigil log show --last 50           # Show last 50 entries
vigil log search --path /etc/passwd # Search by path
vigil log search --severity high   # Search by severity
vigil log stats                    # Alert count breakdown
vigil log verify                   # Verify HMAC integrity of audit log
```

### Configuration

```bash
vigil config show                  # Display active configuration
vigil config validate              # Validate configuration file
```

---

## Configuration

Vigil keeps its config in `/etc/vigil/vigil.toml` (system) or
`~/.config/vigil/vigil.toml` (user). Here's what matters:

```toml
[daemon]
monitor_backend = "fanotify"       # "fanotify" or "inotify"

[scanner]
hash_algorithm = "blake3"          # The only option that makes sense
max_file_size = 2147483648         # 2 GB -- skip larger files

[alerts]
desktop_notifications = true       # D-Bus via notify-send
cooldown_seconds = 300             # Per-path alert cooldown (5 min)
rate_limit = 10                    # Max alerts per minute

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

---

## Documentation

| Document | What's Inside |
|----------|---------------|
| [Docs Index](docs/README.md) | Documentation map by topic |
| [Installation](docs/INSTALL.md) | Building, dependencies, systemd setup |
| [CLI Reference](docs/CLI.md) | Every command, every flag |
| [Configuration](docs/CONFIGURATION.md) | The config file explained |
| [Architecture](docs/ARCHITECTURE.md) | How it's built |
| [Security](docs/SECURITY.md) | Security model, dependency justification |
| [Threat Model](docs/THREAT_MODEL.md) | What Vigil detects and what it doesn't |
| [Testing](docs/TESTING.md) | Test suite, fuzz targets, coverage |
| [Development](docs/DEVELOPMENT.md) | Dev setup, building, debugging |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | When things go wrong |
| [FAQ](docs/FAQ.md) | Common questions answered |
| [Resilience](docs/RESILIENCE.md) | Failure modes and recovery |
| [Principles](docs/PRINCIPLES.md) | Why it's built this way |
| [Releasing](docs/RELEASING.md) | Release process and versioning |
| [Licensing Guide](licenses/LICENSING.md) | File-level license coverage and policy |
| [Dependency Audit](licenses/DEPENDENCY-AUDIT.md) | Dependency license compatibility framework |
| [Third-Party Licenses](licenses/THIRD-PARTY-LICENSES) | Direct dependency attributions |
| [Documentation License](licenses/LICENSE-DOCS.md) | License terms for project docs |
| [Commercial Licensing](licenses/LICENSE-COMMERCIAL.md) | Commercial licensing inquiry pathway |
| [NOTICE](NOTICE) | Project identity and attribution |
| [Trademarks](TRADEMARKS.md) | Trademark usage policy |
| [Contributing](CONTRIBUTING.md) | How to help |

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

Vigil is dual-licensed:

| Component | License | File |
|-----------|---------|------|
| Source Code | GNU GPL v3.0 only **or** Commercial License | [LICENSE](LICENSE), [LICENSE-COMMERCIAL.md](licenses/LICENSE-COMMERCIAL.md) |
| Documentation | Creative Commons Attribution 4.0 (CC BY 4.0) | [LICENSE-DOCS.md](licenses/LICENSE-DOCS.md) |
| Third-Party Dependencies | MIT, Apache-2.0, and other permissive licenses | [THIRD-PARTY-LICENSES](licenses/THIRD-PARTY-LICENSES) |

**For most users:** The GPL covers you fully. Use Vigil, monitor your files, run the daemon. No restrictions beyond the GPL.

**For proprietary/commercial use:** If you need to embed Vigil in closed-source products or redistribute without GPL obligations, a [commercial license](licenses/LICENSE-COMMERCIAL.md) is available for inquiry. No commercial license is currently active — Vigil is single-licensed under GPL-3.0-only at this time.

**For contributors:** By submitting a pull request, you agree to the [Contributor License Agreement](licenses/CONTRIBUTOR-LICENSE.md). You keep your copyright; you grant the project permission to include your contribution under the current and any future licenses.

**Trademarks:** "Vigil" and "lousclues" are trademarks of Louis Nelson Jr. See [TRADEMARKS.md](TRADEMARKS.md) for usage guidelines. The GPL does not grant trademark rights.

For the complete licensing framework, see [LICENSING.md](licenses/LICENSING.md). For project governance and succession planning, see [GOVERNANCE.md](GOVERNANCE.md).

---

*Vigil: Your filesystem has a witness. It never looks away.*