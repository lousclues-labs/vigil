# Security Policy

This document defines how to report issues and what security guarantees VigilBaseline does and does not make.

---

## Reporting

Do not open a public issue for a vulnerability.

Preferred path:
1. Open the GitHub Security tab.
2. Select Report a vulnerability.
3. Include exact reproduction steps and impact.

Fallback path:
- Contact the maintainer on GitHub if Security Advisories are unavailable.

---

## Report Checklist

Include these items.

| Item | Why |
|------|-----|
| issue description | states what failed |
| impact | states attacker outcome |
| reproduction | makes triage fast |
| affected versions | scopes patch effort |
| mitigation ideas | reduces risk before patch |

---

## Response Targets

| Step | Target |
|------|--------|
| acknowledgement | 72 hours |
| first triage pass | 7 days |
| fix or mitigation plan | 14 days |
| public disclosure | after patch or clear mitigation |

These are targets. They are not an SLA.

---

## Supported Versions

Security fixes target the latest release.

---

## Dependency Justification

This list matches direct dependencies in `Cargo.toml`.

### Hashing and Integrity

| Crate | Purpose in VigilBaseline |
|-------|------------------|
| `blake3` | baseline and chain hash computation |
| `hmac` | keyed signing of audit records |
| `sha2` | SHA-256 backend used by HMAC |
| `hex` | stable hex encoding for hashes |

### Database and Data Model

| Crate | Purpose in VigilBaseline |
|-------|------------------|
| `rusqlite` | baseline and audit persistence |
| `serde` | typed serialization and deserialization |
| `serde_json` | JSON alerts and payloads |
| `toml` | parse configuration files |
| `toml_edit` | update and render TOML in config commands |

### CLI and Logging

| Crate | Purpose in VigilBaseline |
|-------|------------------|
| `clap` | command parsing and help output |
| `tracing` | structured logging facade |
| `tracing-subscriber` | log backend with env filtering and JSON output |

### Linux Integration

| Crate | Purpose in VigilBaseline |
|-------|------------------|
| `nix` | fanotify and inotify wrappers and signal helpers |
| `libc` | low-level syscalls |
| `xattr` | extended attribute reads |
| `sd-notify` | systemd readiness and watchdog notifications |

### Matching, Concurrency, and Runtime State

| Crate | Purpose in VigilBaseline |
|-------|------------------|
| `globset` | compiled glob matching for exclusions |
| `crossbeam-channel` | thread communication |
| `parking_lot` | low-overhead mutex and rwlock |
| `arc-swap` | lock-free config pointer swap on reload |
| `lru` | baseline lookup cache in workers |
| `croner` | cron expression parsing for scheduled scans |
| `rayon` | optional parallel scanning feature |

### Utility

| Crate | Purpose in VigilBaseline |
|-------|------------------|
| `chrono` | timestamps and UTC handling |
| `thiserror` | typed error definitions |

### WAL Serialization and Integrity

| Crate | Purpose in VigilBaseline |
|-------|------------------|
| `rmp-serde` | MessagePack serialization for WAL entry payloads |
| `crc32fast` | CRC32 checksums for WAL entry crash recovery |

Removed from this table because they are not direct dependencies:
- `log`
- `env_logger`
- `uuid`
- `glob`

---

## Security Model

VigilBaseline is a local integrity monitor.

It does:
- detect filesystem state changes against baseline
- record changes in append-only audit history
- expose explicit degraded states

It does not:
- block processes
- quarantine files
- perform malware classification
- provide kernel attestation

---

## Threat Scope

### In scope

| Threat | Coverage |
|--------|----------|
| unauthorized file modification | baseline comparison |
| inode replacement attacks | inode and device checks |
| race between event and read | fd-first snapshot pipeline |
| notification suppression hiding evidence | audit rows still written |
| audit tamper attempts | chain hash verification, chained HMAC with previous hash, and optional HMAC |
| baseline deletion/truncation | `baseline_initialized` flag prevents silent auto-reinitialize |
| baseline at-rest tampering | baseline HMAC verification on startup |
| config file poisoning | config HMAC verification on reload when HMAC signing enabled |
| control socket abuse | challenge-response auth, peer credential logging, command audit trail |
| mtime-reset evasion | scheduled scans default to full mode (rehash regardless of mtime) |
| event channel flooding | event drop detection with coordinator-level alerting |
| persistence via `/run/` | `/run/*` not blanket-excluded; targeted exclusions only |
| detection loss during daemon crash | Detection WAL provides crash-safe buffering; AuditWriter replays on restart with deduplication |
| WAL entry tampering | per-entry HMAC-SHA256 when HMAC signing enabled; entries with invalid HMAC are skipped |
| WAL file replacement | coordinator periodic TOCTOU check on WAL inode/device; Degraded state on replacement |
| WAL gap scanning DoS | `MAX_GAP_BYTES` (64KB) bounds gap scanning; scanner stops after limit, preventing adversarial CPU exhaustion via large zeroed regions |

### Out of scope

| Threat | Why out of scope |
|--------|------------------|
| kernel compromise | user-space observer loses trust base |
| physical device compromise | not a physical control |
| process behavior analytics | VigilBaseline tracks structure, not behavior |
| exploit prevention | VigilBaseline reports, it does not block |

---

## Audit Chain Verification

Audit verification is implemented.

Use:

```bash
vigil audit verify
```

What it checks:
- each `chain_hash` links to the previous entry
- chain ordering and continuity across the audit log
- when HMAC key is available, HMAC signatures are verified (including previous chain hash linkage)

When HMAC is enabled, signatures add a second integrity layer. The HMAC data includes the previous chain hash, so deleting entries from the middle of the chain is detectable even if the attacker can recompute BLAKE3 chain hashes.

---

## HMAC Key Lifecycle

If `security.hmac_signing = true`, key management quality defines integrity quality.

Generate a 32-byte key:

```bash
openssl rand -hex 32 > /etc/vigil/hmac.key
```

Set strict ownership and mode:

```bash
sudo chown root:root /etc/vigil/hmac.key
sudo chmod 0400 /etc/vigil/hmac.key
```

Recommended rotation flow:
1. create new key
2. archive current audit context and key
3. restart daemon
4. verify new audit chain

If attacker can read the key and edit the audit database, HMAC cannot protect integrity.

The HMAC key is also used for:
- baseline tamper detection: baseline HMAC is computed and verified on daemon startup
- config file integrity: config HMAC is verified on reload to reject tampering
- control socket authentication: challenge-response protocol uses the HMAC key

---

## Control Socket Security

The daemon control socket (`/run/vigil/control.sock`) accepts commands for `status`, `reload`, `scan`, and other operations.

Protections:
- socket permissions set to `0600` on creation
- when `security.hmac_signing = true` and `security.control_socket_auth = true` (default), connections require challenge-response authentication using the HMAC key
- peer credentials (PID, UID, GID) are logged via `SO_PEERCRED` on every connection
- `reload` and `scan` commands are logged at `warn` level with a `control_commands` metric counter
- without HMAC signing, the socket falls back to unauthenticated mode with a warning on every connection

---

## Socket Security

`hooks.signal_socket` uses Unix domain sockets for alert forwarding.

- keep socket directory private
- use restrictive permissions
- treat this channel as local host only

If socket delivery fails, other channels keep working.

---

## Unsafe Code Policy

The crate root declares `#![deny(unsafe_code)]`.

All `unsafe` usage must be annotated with `#[allow(unsafe_code)]` on the specific function, impl block, or module that requires it. Each `unsafe` block must include a `// SAFETY:` comment explaining why the invariants hold.

Current allowed locations:

| Location | Reason |
|----------|--------|
| `src/lib.rs` — `harden_process()` | prctl, umask syscalls |
| `src/lib.rs` — `raise_nofile_limit()` | getrlimit/setrlimit syscalls |
| `src/hash.rs` — `MmapGuard` | mmap/munmap/from_raw_parts |
| `src/hash.rs` — `blake3_hash_fd()` | calls MmapGuard::new |
| `src/worker.rs` — `dup_to_file()` | libc::dup, File::from_raw_fd |
| `src/control.rs` — `log_peer_credentials()` | getsockopt SO_PEERCRED |
| `src/doctor.rs` — `is_pid_alive()` | libc::kill signal 0 probe |
| `src/monitor/fanotify.rs` | module-level allow (fanotify syscalls) |
| `src/types/event.rs` — `impl Send for FsEvent` | OwnedFd thread transfer |

Adding new `unsafe` code without updating this table and providing a `// SAFETY:` comment will be caught by `cargo clippy` and CI.

---

## Operational Checks

Run these commands during hardening and incident response.

```bash
vigil doctor
vigil status
vigil audit stats
vigil audit verify
```

---

Security claims must map to code paths. If a claim cannot be tested, remove it.
