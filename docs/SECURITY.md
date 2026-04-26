# Security Policy

This document defines how to report issues and what security guarantees Vigil Baseline does and does not make.

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

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `blake3` | baseline and chain hash computation |
| `hmac` | keyed signing of audit records |
| `sha2` | SHA-256 backend used by HMAC |
| `hex` | stable hex encoding for hashes |
| `constant_time_eq` | constant-time HMAC comparison (pinned below 0.4.3 for MSRV 1.85 compatibility) |
| `zeroize` | explicit key material memory clearing |

### Database and Data Model

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `rusqlite` | baseline and audit persistence |
| `serde` | typed serialization and deserialization |
| `serde_json` | JSON alerts and payloads |
| `toml` | parse configuration files |
| `toml_edit` | update and render TOML in config commands |

### CLI and Logging

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `clap` | command parsing and help output |
| `tracing` | structured logging facade |
| `tracing-subscriber` | log backend with env filtering and JSON output |

### Linux Integration

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `nix` | fanotify and inotify wrappers and signal helpers |
| `libc` | low-level syscalls |
| `xattr` | extended attribute reads |
| `sd-notify` | systemd readiness and watchdog notifications |

### Matching, Concurrency, and Runtime State

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `globset` | compiled glob matching for exclusions |
| `crossbeam-channel` | thread communication |
| `parking_lot` | low-overhead mutex and rwlock |
| `arc-swap` | lock-free config pointer swap on reload |
| `lru` | baseline lookup cache in workers |
| `croner` | cron expression parsing for scheduled scans |

### Utility

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `chrono` | timestamps and UTC handling |
| `thiserror` | typed error definitions |

### WAL Serialization and Integrity

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `rmp-serde` | MessagePack serialization for WAL entry payloads |
| `crc32fast` | CRC32 checksums for WAL entry crash recovery |

### Attestation Serialization

| Crate | Purpose in Vigil Baseline |
|-------|------------------|
| `ciborium` | deterministic CBOR (RFC 8949) serialization for `.vatt` attestation envelopes |

**Sticky-HMAC behavior (v0.35.0, VIGIL-VULN-067):** Once a WAL file is initialized with an HMAC key, the 16-byte BLAKE3 fingerprint of the key is stored in the header (offset 16..32). On subsequent opens:
- If the header fingerprint is non-zero and the caller passes no key, the WAL refuses to open.
- If the header fingerprint is non-zero and the caller passes a different key, the WAL refuses to open.
- During entry scanning, entries with all-zero HMAC fields are rejected when the header demands HMAC.
This prevents both security downgrades and zero-HMAC injection attacks.

Removed from this table because they are not direct dependencies:
- `log`
- `env_logger`
- `uuid`
- `glob`

---

## Security Model

Vigil Baseline is a local integrity monitor.

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
| WAL entry tampering | per-entry HMAC-SHA256 over `(instance_nonce \|\| sequence \|\| payload)` when HMAC signing enabled; entries with invalid HMAC are skipped. Instance nonce binding prevents cross-host WAL replay. |
| WAL file replacement | coordinator periodic TOCTOU check on WAL inode/device; Degraded state on replacement |
| WAL header fingerprint downgrade | header fingerprint cached in memory at open time; not re-read from disk on subsequent scans. An attacker with WAL write access cannot zero the fingerprint to downgrade HMAC policy. |
| WAL truncate data loss | replacement file opened BEFORE rename; if open fails, old WAL remains canonical and no entries are lost |
| WAL gap scanning DoS | `MAX_GAP_BYTES` (64KB) bounds gap scanning; scanner stops after limit, preventing adversarial CPU exhaustion via large zeroed regions |
| baseline HMAC auto-recompute bypass | HMAC mismatch on startup enters Degraded state unless `trust_baseline_on_hmac_mismatch` is explicitly set |
| control socket config bypass via baseline_refresh | `baseline_refresh` uses the daemon's live (HMAC-verified) config, not a fresh disk read |
| control socket OOM via unbounded read | `read_line` bounded to 64KB; oversized requests rejected |
| HMAC key world-readable | `check_hmac_key_permissions()` returns hard error in release builds when key has group/other permissions |
| sudo privilege escalation via user-owned repo | `vigil update` skips $HOME-relative candidates when running as root (unless $HOME=/root); `validate_vigil_repo()` checks directory ownership |
| baseline refresh during degraded state | `baseline_refresh` control socket command refuses execution when daemon is in Degraded state |
| PID recycling in process attribution | Process attribution detects exited processes (exe readlink failure) and marks attribution as stale; best-effort by design |

### Out of scope

| Threat | Why out of scope |
|--------|------------------|
| kernel compromise | user-space observer loses trust base |
| physical device compromise | not a physical control |
| process behavior analytics | Vigil Baseline tracks structure, not behavior |
| exploit prevention | Vigil Baseline reports, it does not block |

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

## Chain Integrity vs Authenticity

The audit chain provides two distinct protections. Operators should understand
which applies to their deployment.

**Chain integrity** (always active, HMAC not required):
Each audit entry's `chain_hash` is a BLAKE3 hash of
`previous_chain_hash | timestamp | path | changes_json | severity`.
Modifying any entry breaks the chain for all subsequent entries. This is
verifiable by anyone with read access to the audit database.

**Chain authenticity** (requires HMAC signing):
When `security.hmac_signing = true`, each entry also carries an HMAC-SHA256
signature computed with the operator's secret key. An attacker with write
access to `audit.db` but without the HMAC key cannot forge entries that
pass HMAC verification. The HMAC data includes the previous chain hash,
making mid-chain deletion detectable even if the attacker recomputes
BLAKE3 hashes.

**When HMAC signing is disabled**, an attacker with write access to the
audit database can recompute `chain_hash` values for every affected row
using the public BLAKE3 algorithm, producing a self-consistent forged
chain. The chain still detects accidental corruption and unsophisticated
tampering, but it does not provide cryptographic authenticity.

`vigil audit verify` displays a prominent warning when HMAC is disabled.
`vigil doctor` surfaces HMAC-disabled status as a Warning with a recovery
command (`sudo vigil setup hmac`).

**Recommendation:** Enable HMAC signing for any deployment where the audit
database could be reached by an adversary you want protection from. The
cost is key management; the benefit is cryptographic proof that every
audit entry was produced by the vigil daemon holding the key.

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

## Attestation Signing Key Lifecycle

The attestation signing key is intentionally separate from `/etc/vigil/hmac.key`.

Key separation rationale:

- audit HMAC key signs live on-host audit entries,
- attestation key signs portable `.vatt` evidence artifacts,
- compromise of one key does not automatically compromise the other trust domain,
- operators can rotate each key independently to match operational risk.

Generate key with Vigil:

```bash
sudo vigil setup attest
```

Defaults:

- path: `/etc/vigil/attest.key`
- mode: `0600`
- file format: `0x01 || 32 random bytes`

Key ID derivation (`signing_key_id`):

- first 8 bytes of `BLAKE3("vigil-attest-key-id-v1" || key)`

Rotation recommendations:

1. generate new attestation key,
2. archive prior key with historical attestation set,
3. verify current artifacts with new key,
4. document key epoch boundaries in evidence records.

Loss of attestation key means HMAC signatures on prior attestations cannot be
re-verified, so key backup quality directly affects long-term evidentiary value.

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

## Baseline Refresh Integrity

`vigil baseline refresh` builds the new baseline in a temp file
(`baseline.db.refresh`) alongside the live database. The live database
continues to serve reads during the build. Events that occur during
refresh are evaluated against the old baseline and recorded in the
audit log normally.

On completion, the daemon atomically renames the temp file over the
live database and reopens its connection. The swap window is
milliseconds; the build window is minutes.

If the build fails (disk full, I/O error), the temp file is deleted
and the live database is untouched. The daemon remains healthy.

An attacker who modifies a file during the refresh window does not get
their change absorbed silently. The modification is recorded in the
audit log against the old baseline before the swap. After the swap,
the new baseline reflects the attacker's change; but the audit log
entry survives.

The daemon refuses refresh while in a Degraded state. A refresh during
Degraded state could cement compromised filesystem state as the new
baseline.

---

## Unsafe Code Policy

The crate root declares `#![deny(unsafe_code)]`.

All `unsafe` usage must be annotated with `#[allow(unsafe_code)]` on the specific function, impl block, or module that requires it. Each `unsafe` block must include a `// SAFETY:` comment explaining why the invariants hold.

Current allowed locations:

| Location | Reason |
|----------|--------|
| `src/lib.rs` -- `harden_process()` | prctl, umask syscalls |
| `src/lib.rs` -- `raise_nofile_limit()` | getrlimit/setrlimit syscalls |
| `src/hash.rs` -- `MmapGuard` | mmap/munmap/from_raw_parts |
| `src/hash.rs` -- `blake3_hash_fd()` | calls MmapGuard::new |
| `src/worker.rs` -- `dup_to_file()` | libc::fcntl(F_DUPFD_CLOEXEC), File::from_raw_fd |
| `src/display/term.rs` -- `TermInfo::ioctl_size()` | ioctl TIOCGWINSZ for terminal dimensions |
| `src/control.rs` -- `log_peer_credentials()` | getsockopt SO_PEERCRED |
| `src/control.rs` -- `current_euid()` | libc::geteuid (cached in OnceLock) |
| `src/doctor.rs` -- `is_pid_alive()` | libc::kill signal 0 probe |
| `src/monitor/fanotify.rs` | module-level allow (fanotify syscalls) |
| `src/types/event.rs` -- `impl Send for FsEvent` | OwnedFd thread transfer |
| `src/wal/mod.rs` -- `random_nonce()` | libc::getrandom syscall |

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

## Release Integrity

Each release from v0.35.0 onward produces the following artifacts:

1. **Binary tarball** (`vigil-baseline-<version>-linux-x86_64.tar.gz`) -- stripped release binaries, README, LICENSE.
2. **SHA256 checksum** (`.tar.gz.sha256`) -- verify with `sha256sum -c`.
3. **Build provenance attestation** (`.intoto.jsonl`) -- generated by `actions/attest-build-provenance@v1` using cosign-keyless signing. Verify with `gh attestation verify`.
4. **SBOM** (`release-sbom*.json`) -- CycloneDX JSON generated by `cargo-cyclonedx`. Lists all transitive dependencies.

The release workflow:
- Runs `cargo test --all-features` and `cargo test --release` before publishing.
- Publishes to crates.io with `--locked` (no dependency resolution drift).
- Does not use `--allow-dirty` (clean working tree required).

To verify a release tarball:
```bash
# Verify checksum
sha256sum -c vigil-baseline-<version>-linux-x86_64.tar.gz.sha256

# Verify provenance (requires GitHub CLI)
gh attestation verify vigil-baseline-<version>-linux-x86_64.tar.gz \
  --owner lousclues-labs
```

---

Security claims must map to code paths. If a claim cannot be tested, remove it.
