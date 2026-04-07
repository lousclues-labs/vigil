# Security Policy

This document defines how to report issues and what security guarantees Vigil does and does not make.

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

| Crate | Purpose in Vigil |
|-------|------------------|
| `blake3` | baseline and chain hash computation |
| `hmac` | keyed signing of audit records |
| `sha2` | SHA-256 backend used by HMAC |
| `hex` | stable hex encoding for hashes |

### Database and Data Model

| Crate | Purpose in Vigil |
|-------|------------------|
| `rusqlite` | baseline and audit persistence |
| `serde` | typed serialization and deserialization |
| `serde_json` | JSON alerts and payloads |
| `toml` | parse configuration files |
| `toml_edit` | update and render TOML in config commands |

### CLI and Logging

| Crate | Purpose in Vigil |
|-------|------------------|
| `clap` | command parsing and help output |
| `tracing` | structured logging facade |
| `tracing-subscriber` | log backend with env filtering and JSON output |

### Linux Integration

| Crate | Purpose in Vigil |
|-------|------------------|
| `nix` | fanotify and inotify wrappers and signal helpers |
| `libc` | low-level syscalls |
| `xattr` | extended attribute reads |
| `sd-notify` | systemd readiness and watchdog notifications |

### Matching, Concurrency, and Runtime State

| Crate | Purpose in Vigil |
|-------|------------------|
| `globset` | compiled glob matching for exclusions |
| `crossbeam-channel` | thread communication |
| `parking_lot` | low-overhead mutex and rwlock |
| `arc-swap` | lock-free config pointer swap on reload |
| `lru` | baseline lookup cache in workers |
| `croner` | cron expression parsing for scheduled scans |
| `rayon` | optional parallel scanning feature |

### Utility

| Crate | Purpose in Vigil |
|-------|------------------|
| `chrono` | timestamps and UTC handling |
| `thiserror` | typed error definitions |

Removed from this table because they are not direct dependencies:
- `log`
- `env_logger`
- `uuid`
- `glob`

---

## Security Model

Vigil is a local integrity monitor.

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
| audit tamper attempts | chain hash verification and optional HMAC |

### Out of scope

| Threat | Why out of scope |
|--------|------------------|
| kernel compromise | user-space observer loses trust base |
| physical device compromise | not a physical control |
| process behavior analytics | Vigil tracks structure, not behavior |
| exploit prevention | Vigil reports, it does not block |

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

When HMAC is enabled, signatures add a second integrity layer.

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

---

## Socket Security

`hooks.signal_socket` uses Unix domain sockets.

- keep socket directory private
- use restrictive permissions
- treat this channel as local host only

If socket delivery fails, other channels keep working.

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
