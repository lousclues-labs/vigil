# Security Policy

You found a vulnerability. Thank you. Here is how to report it and what security model Vigil actually claims.

---

## Reporting

Do not open a public issue for security bugs.

### Preferred: GitHub Security Advisories

1. Open the repository Security tab.
2. Click "Report a vulnerability".
3. Include reproduction details and impact.

### Fallback: Maintainer Contact

If advisories are unavailable, contact the maintainer through GitHub directly.

---

## What To Include

| Field | Why It Matters |
|-------|----------------|
| Description | what is wrong |
| Impact | what attacker can do |
| Reproduction | exact steps and environment |
| Affected versions | release range |
| Mitigation ideas | short-term safety options |

---

## Response Timeline

| Step | Target |
|------|--------|
| Acknowledge report | 72 hours |
| Initial triage | 7 days |
| Fix or mitigation plan | 14 days |
| Public disclosure | after patch or clear mitigation |

This timeline is a goal, not a legal SLA.

---

## Supported Versions

Security fixes are provided for the latest released version only.

If you run an older version, update first.

---

## Dependency Justification

Every dependency is a liability.
These are the direct dependencies from `Cargo.toml`, why they exist, and compromise impact.

### Hashing and Integrity

| Crate | What It Does In Vigil | Why It Is Here | Compromise Impact |
|-------|------------------------|----------------|-------------------|
| `blake3` | content hashing for baseline and compare pipeline | fast deterministic hashing for large scans | forged or mismatched hash outcomes; high integrity risk |
| `hmac` | integrity plumbing for signed audit/baseline workflows | keyed tamper-evidence primitive | signature bypass or false verification; high integrity risk |
| `sha2` | SHA-2 backend for HMAC workflows | standard digest primitive paired with HMAC | same as above when signing enabled |
| `hex` | hex encoding of hashes/xattrs | stable text serialization for logs/db | data representation corruption; low-to-medium risk |

### Database

| Crate | What It Does In Vigil | Why It Is Here | Compromise Impact |
|-------|------------------------|----------------|-------------------|
| `rusqlite` | baseline/audit/config_state persistence | safe SQLite access with WAL support | tampered reads/writes, audit loss, state corruption; high risk |

### Config and Serialization

| Crate | What It Does In Vigil | Why It Is Here | Compromise Impact |
|-------|------------------------|----------------|-------------------|
| `serde` | (de)serialize config and domain structs | standard typed serialization framework | malformed config/object parsing; medium-to-high risk |
| `serde_json` | JSON alert output and baseline export | machine-readable output format | forged/invalid JSON logs or exports; medium risk |
| `toml` | parse Vigil config files | native parser for declared config format | malicious parse behavior or silent coercion; medium-to-high risk |

### CLI

| Crate | What It Does In Vigil | Why It Is Here | Compromise Impact |
|-------|------------------------|----------------|-------------------|
| `clap` | command tree, flags, help/version handling | robust argument parsing and validation | incorrect command parsing or flag handling; medium risk |

### Linux and Filesystem Integration

| Crate | What It Does In Vigil | Why It Is Here | Compromise Impact |
|-------|------------------------|----------------|-------------------|
| `nix` | inotify/fanotify helpers, signal/setuid wrappers | idiomatic bindings for Linux primitives | monitor/signal misbehavior; high risk |
| `libc` | raw syscalls (fanotify, ioprio, setpriority) | required for low-level kernel interfaces | full syscall surface compromise; critical risk |
| `xattr` | read extended attributes/security labels | xattr change detection and context capture | hidden metadata tampering; medium risk |
| `glob` | exclusion pattern parsing/matching | predictable path filtering semantics | bypass or over-filtering of monitored paths; medium risk |

### Concurrency and Flow Control

| Crate | What It Does In Vigil | Why It Is Here | Compromise Impact |
|-------|------------------------|----------------|-------------------|
| `crossbeam-channel` | event transport between monitor and daemon loop | bounded channel with simple semantics | dropped/reordered/blocked events; high detection risk |

### Logging, Time, Identity, Errors

| Crate | What It Does In Vigil | Why It Is Here | Compromise Impact |
|-------|------------------------|----------------|-------------------|
| `log` | structured severity logging | common log facade for daemon + CLI | hidden or falsified operational logs; medium risk |
| `env_logger` | log backend and `RUST_LOG` filtering | runtime log control without heavy stack | log visibility degradation; low-to-medium risk |
| `chrono` | timestamps for alerts/audit records | consistent UTC timestamp handling | timeline distortion in forensic records; medium risk |
| `uuid` | event IDs for alerts | stable unique event correlation | ID collisions/spoofing in downstream systems; low-to-medium risk |
| `thiserror` | error type derives | explicit error taxonomy with less boilerplate | mostly compile-time; low runtime risk |

---

## Security Model

Vigil is a local integrity observer. It does not claim host hardening, malware removal, or runtime behavior analysis.

### Trust / Do Not Trust

| Trust | Do Not Trust |
|-------|--------------|
| local filesystem metadata APIs | file contents before hashing |
| configured watch boundaries | paths not in watch scope |
| package manager ownership metadata (`pacman -Qo`, `dpkg -S`, `rpm -qf`) | network-fed intelligence sources |
| SQLite transactional guarantees | unvalidated config input |
| kernel-enforced file permissions | desktop notification delivery success |

Principle alignment:
- Principle VI: Filesystem is source of truth.
- Principle XIV: No network I/O.

---

## Threat Model (Security Scope)

### In Scope

| Threat | Covered By |
|--------|------------|
| unauthorized file modification | hash + metadata compare against baseline |
| persistence mechanism tampering | default watch groups (`persistence`, `system_critical`) |
| inode replacement attacks | inode/device comparison |
| TOCTOU race conditions during compare | open -> fstat(fd) -> hash(fd) pipeline |
| alert suppression visibility | audit log writes even when notification suppressed |
| audit trail tampering attempts | append-only audit strategy + optional HMAC fields |

### Out Of Scope

| Threat | Why Out Of Scope |
|--------|------------------|
| kernel compromise / rootkit in kernel space | if kernel lies, user-space observer loses trust base |
| physical device access attacks | not a physical security control |
| in-memory process behavior monitoring | Vigil is structural, not behavioral (Principle IV) |
| exploit prevention / process containment | Vigil does not block, quarantine, or kill (Principle I) |

---

## HMAC Key Lifecycle

The optional HMAC signing feature (`security.hmac_signing = true`) provides
tamper-evidence for audit log entries. Its value depends entirely on proper
key management. If an attacker who can modify monitored files can also read
the HMAC key, the signed audit trail offers no additional protection.

### Key Generation

Generate a 32-byte (256-bit) random key:

```bash
head -c 32 /dev/urandom | xxd -p -c 64 > /etc/vigil/hmac.key
```

Or equivalently:

```bash
openssl rand -hex 32 > /etc/vigil/hmac.key
```

### File Permissions

The key file **must** be readable only by root:

```bash
sudo chown root:root /etc/vigil/hmac.key
sudo chmod 0400 /etc/vigil/hmac.key
```

Acceptable modes are `0400` (read-only) or `0600` (read-write for rotation).
Vigil warns at runtime if the key file is more permissive than `0600`, and
`vigil doctor` flags both permission and ownership issues.

### Rotation Procedure

1. Generate a new key file (see above).
2. Existing audit entries signed with the old key remain verifiable only
   with the old key. You have two options:
   - **New audit epoch**: archive the current audit log and database,
     start fresh with `vigil init`. Previous entries can be verified
     offline using the archived key.
   - **Re-sign**: export audit entries, re-compute HMACs with the new key,
     and re-import. This is not yet automated.
3. Restart the daemon (`systemctl restart vigild`) to pick up the new key.

### Threat Model

The HMAC key **must** reside on a different trust boundary than the files
being monitored:

| Placement | Tamper-Evidence |
|-----------|-----------------|
| Root-owned file on the same partition | protects against non-root attackers |
| Separate partition mounted read-only | protects against root-level file writes (attacker must remount) |
| External/HSM-backed key (future) | protects against full disk compromise |

If an attacker has root access **and** can read the key, they can forge
audit entries. In that scenario, the HMAC provides no additional guarantee
beyond what the filesystem permissions already offer.

---

## HMAC Baseline Integrity

Current state:
- config supports `security.hmac_signing` and `security.hmac_key_path`
- config validation enforces key existence when signing is enabled
- schema includes `audit_log.hmac`
- `vigil log verify` CLI entry exists, with current command path not fully implemented

What this protects (when fully enabled in your deployment path):
- tamper-evident integrity metadata for baseline/audit records

What this does not protect:
- root attacker who can replace binary, key, and database together
- kernel-level attacker that can forge filesystem/system call behavior

---

## Signal Socket Security

Vigil can send JSON alert events to an optional Unix socket path (`hooks.signal_socket`).

Security boundary:
- local host only (Unix domain socket)
- access control is determined by socket path ownership and permissions

Behavior details:
- if no listener is present, events are dropped silently for this channel
- other channels (journald/JSON log/desktop) still operate
- no extra encryption layer is added at this boundary

Operational guidance:
- place socket in a directory owned by the intended consumer
- use restrictive permissions (`0700` directory, `0600` socket)
- avoid world-writable directories

---

## Database Security

Vigil database defaults to `/var/lib/vigil/baseline.db` with WAL enabled.

Controls in code:
- schema constraints (`UNIQUE(path, device, inode)`, source `CHECK`)
- `PRAGMA foreign_keys=ON`
- startup integrity check (`integrity_check`)
- periodic WAL checkpointing

Operational controls you should enforce:
- root-owned DB and parent directory
- least-write access (daemon user only)
- backup baseline/audit data before major upgrades

Quick checks:

```bash
vigil doctor
vigil status
```

---

## Privilege Model

### fanotify path

- fanotify monitoring typically needs `CAP_SYS_ADMIN`
- systemd unit grants bounded capabilities (`CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`)

### fallback path

- if fanotify initialization fails, Vigil falls back to inotify
- fallback reduces coverage but keeps monitor alive
- warnings are explicit (Principle X: Fail Open, Fail Loud)

Systemd hardening defaults include:
- `NoNewPrivileges=yes`
- `ProtectSystem=strict`
- bounded writable paths
- memory limits

---

## Local Attacker Limitations

A same-user attacker can often:
- modify user-owned config files
- read user-owned logs
- disable user-level processes

Vigil is designed for boundary change visibility, not local account isolation.
If attacker already owns your user session, incident response scope is broader than a file monitor.

---

## Disclosure Philosophy

Security through clarity beats security theater.
Small, deterministic, auditable behavior is safer than opaque "smart" detection claims.

*If Vigil speaks, it should be because something real changed.*
