# Threat Model

Vigil is a filesystem integrity witness.
It detects structural changes. It does not interpret intent.

---

## What Vigil Detects

| Detection | Example |
|-----------|---------|
| content modification | `/usr/bin/sudo` hash no longer matches baseline |
| deletion | `/etc/shadow` missing |
| permission drift | `/etc/sudoers` mode changed unexpectedly |
| owner/group changes | critical file ownership changed |
| inode replacement | file replaced in-place with same path |
| xattr changes | security labels/attributes changed |

How it does this:
- open file descriptor first
- fstat on descriptor
- hash same descriptor
- compare against baseline row

---

## What Vigil Does NOT Detect

| Not Detected | Why |
|--------------|-----|
| kernel rootkits that forge syscall output | user-space monitor depends on kernel truth |
| memory-only process tampering | Vigil is file integrity, not process introspection |
| runtime behavior anomalies | no heuristics, no ML, no behavior scoring |
| attacks outside watch scope | Vigil only sees configured paths |
| physical tampering while host offline | outside runtime software boundary |

---

## Adversary Assumptions

Assumed adversary capabilities:
- can modify files on disk
- may attempt to replace files atomically
- may try to hide changes during package updates

Not assumed as defendable by Vigil alone:
- kernel-level compromise
- full root control of host with binary/key replacement

---

## Trust Boundaries

```
+-----------------------------+
|         Trusted-ish         |
|-----------------------------|
| kernel file metadata APIs   |
| local package DB ownership  |
| SQLite transactional rules  |
+--------------+--------------+
               |
               | compare boundary
               v
+-----------------------------+
|        Untrusted            |
|-----------------------------|
| file contents before hash   |
| paths outside watch groups  |
| unvalidated config input    |
| optional external consumers |
+-----------------------------+
```

Key boundaries:
- filesystem state
- package manager metadata
- kernel syscall responses

---

## Attack Surface

| Surface | Risk |
|---------|------|
| config files (`/etc/vigil/vigil.toml`, user override) | scope manipulation or suppression settings. Mitigated: vigil_self watch group monitors config at Critical severity; config HMAC verification rejects tampered reloads when HMAC signing is enabled. |
| SQLite DB (`/var/lib/vigil/baseline.db`) | baseline/audit tampering. Mitigated: baseline HMAC verification on startup; `baseline_initialized` flag prevents silent recovery from empty baseline. |
| JSON alert log (`/var/log/vigil/alerts.json`) | forensic record tampering |
| signal socket path (`hooks.signal_socket`) | local IPC misuse if path permissions weak |
| control socket (`/run/vigil/control.sock`) | privileged command injection. Mitigated: 0600 permissions, challenge-response authentication, peer credential logging, control command audit trail. |
| Detection WAL (`/run/vigil/detections.wal` or `/var/lib/vigil/detections.wal`) | WAL entry tampering or deletion. Mitigated: per-entry HMAC-SHA256 when HMAC signing enabled; CRC32 checksums for crash recovery; file permissions 0600; periodic TOCTOU identity check by coordinator; instance nonce prevents cross-instance replay. |
| monitor backend interfaces (fanotify/inotify) | dropped events or reduced coverage under fallback. Mitigated: event drop detection with coordinator-level alerting. |

---

## Evasion Considerations

Possible bypass/evasion routes:
- in-memory-only malware that avoids disk writes
- kernel-level attacker spoofing file metadata/events
- modifications in paths never added to watch groups
- alert flooding to trigger suppression windows (still audited)
- direct tampering with logs/db by privileged attacker
- mtime-reset attacks (file modified, mtime restored to original)
- baseline deletion/truncation followed by daemon restart
- config file poisoning to add exclusions or disable alerting
- control socket abuse to trigger reload of tampered config
- event channel flooding to cause event drops
- persistence via transient systemd units in `/run/systemd/transient/`

Mitigations in design:
- deterministic structural comparison
- inode/device checks for replacement attacks
- audit entries written even when notifications suppressed
- explicit fallback warnings when fanotify is unavailable
- scheduled scans default to full mode (rehash regardless of mtime)
- baseline HMAC verification on startup detects at-rest tampering
- `baseline_initialized` flag prevents silent auto-reinitialize of empty baselines
- config file HMAC verification on reload rejects tampered configs when HMAC signing is enabled
- control socket challenge-response authentication when HMAC signing is enabled
- all control socket commands logged with peer PID/UID/GID via SO_PEERCRED
- event drops detected and logged as possible evasion by coordinator
- `/run/*` not blanket-excluded; targeted exclusions preserve visibility into `/run/systemd/`
- vigil self-monitoring: config and HMAC key files watched at Critical severity
- HMAC chain includes previous chain hash to detect mid-chain audit entry deletion
- Detection WAL ensures zero detection loss across daemon crashes, audit DB failures, and I/O stalls
- WAL entries protected by per-entry HMAC-SHA256 when HMAC signing enabled; tampered entries are skipped
- WAL file identity (inode/device) checked periodically by coordinator; replacement triggers Degraded state
- WAL instance nonce stored in baseline DB; prevents cross-instance replay attacks on crash recovery
- WAL gap scanning bounded by `MAX_GAP_BYTES` (64KB); prevents adversarial DoS via large zeroed/corrupted regions

---

## Operational Reality

Vigil is strongest when:
- watch groups are scoped to high-value paths
- baseline is initialized on known-good system state
- package hooks are installed
- alert channels are monitored and audit log is retained

Vigil is not a silver bullet.
It is a high-signal boundary witness.

*No heuristics. No guessing. Changed or unchanged.*
