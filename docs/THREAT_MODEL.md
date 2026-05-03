# Threat Model

Vigil Baseline is a filesystem integrity witness.
It detects structural changes. It does not interpret intent.

---

## What Vigil Baseline Detects

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

## What Vigil Baseline Does NOT Detect

| Not Detected | Why |
|--------------|-----|
| kernel rootkits that forge syscall output | user-space monitor depends on kernel truth |
| memory-only process tampering | Vigil Baseline is file integrity, not process introspection |
| runtime behavior anomalies | no heuristics, no ML, no behavior scoring |
| attacks outside watch scope | Vigil Baseline only sees configured paths |
| physical tampering while host offline | outside runtime software boundary |

---

## Adversary Assumptions

Assumed adversary capabilities:
- can modify files on disk
- may attempt to replace files atomically
- may try to hide changes during package updates

Not assumed as defendable by Vigil Baseline alone:
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

## Network Posture

**Vigil opens no listening network sockets.** Vigil's only network egress
is the optional remote-syslog sink (`[alerts.remote_syslog]`), which is
outbound-only and disabled by default. The webhook sink (`[alerts].webhook_url`)
is also outbound-only. The control socket is a Unix domain socket at
`/run/vigil/control.sock`, accessible only to local processes with
appropriate uid/permissions. There is no TCP/UDP listener, no HTTP server,
and no inbound network surface. This property is load-bearing for security
evaluation: Vigil cannot be attacked from the network.

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
| monitor backend interfaces (fanotify/inotify) | dropped events or reduced coverage under fallback. Mitigated: event drop detection with coordinator-level alerting; FID-tier event loop on supported kernels (5.1+) restores full real-time coverage; `vigil doctor` surfaces degraded coverage when present. |

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
- slow clock drift to bypass audit retention cutoff (mitigated in v0.35.0 via monotonic-time comparison)

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
- WAL HMAC is sticky per-file: once the header is initialized with an HMAC key fingerprint, entries with zero-HMAC are rejected and the WAL refuses to open without a key (VIGIL-VULN-067)
- WAL file identity (inode/device) checked periodically by coordinator; replacement triggers Degraded state
- WAL instance nonce stored in baseline DB; prevents cross-instance replay attacks on crash recovery
- WAL gap scanning bounded by `MAX_GAP_BYTES` (64KB); prevents adversarial DoS via large zeroed/corrupted regions
- Race-deleted files (unlinked between fanotify event and fd→path resolution) are detected as deletions via kernel ` (deleted)` suffix stripping (VIGIL-VULN-068)
- New mounts overlapping watched paths receive dynamic fanotify marks; modifications under new mounts are monitored in real-time (VIGIL-VULN-069, fanotify backend only; inotify detects and logs but cannot mark)
- Clock anomaly detection compares wall-clock delta against monotonic time; skew exceeding `security.clock_skew_threshold_seconds` (default 60s) prevents audit rotation; daemon degradation requires skew above 2× threshold (default 120s). Transient skew self-clears after `clock_skew_recovery_window` seconds of clean ticks (VIGIL-VULN-070)
- Audit rotation refused when max audit timestamp exceeds current wall-clock time (clock rollback detection)
- Baseline refresh records unattributed changes to the detection WAL with `DetectionSource::BaselineRefresh` and `Severity::High`. An attacker who modifies files and then triggers a baseline refresh cannot use the refresh to silently absorb the modifications; the audit trail will contain a record of every path whose hash changed without package attribution. Diff computation failures do not suppress this recording; the refresh proceeds and the `complete` event reports `diff_unavailable: true`.
- Baseline refresh coordinates with the TOCTOU tamper detector via `SharedBaselineIdentity`. The control handler signals an authorized replacement deadline before the atomic `rename(2)`, and the guardian thread accepts the inode change only within the 30-second window (`BASELINE_REPLACEMENT_WINDOW`). Unauthorized replacements (no deadline set, or deadline expired) still trigger `BaselineDbReplaced` degradation. This prevents a legitimate refresh from being misidentified as tampering while preserving the tamper detector's ability to catch real attacks. The window is fail-closed: if the rename does not complete within 30 seconds, the authorization expires and the next inode check degrades normally.
- Package manager hooks (pacman, apt) always exit 0 regardless of refresh outcome. A failed refresh is logged to journald and surfaces a desktop notification, but never blocks the package transaction. An attacker who causes refresh failures cannot use the hook to deny package updates to the operator.

---

## Operational Reality

Vigil Baseline is strongest when:
- watch groups are scoped to high-value paths
- baseline is initialized on known-good system state
- package hooks are installed
- alert channels are monitored and audit log is retained

## Audit Log Segmentation

Audit log segmentation preserves chain integrity across rotation boundaries. When a segment is sealed, its HMAC covers the chain from first to last entry. The next live entry uses the sealed segment's chain hash as its `previous_chain_hash`, extending the chain across segments without a break.

Sealed segments can be moved to cold storage without breaking verification. The `vigil audit verify` command warns when an archived segment file is missing but does not treat it as a chain break -- the operator may have intentionally moved it to offline storage. If the file is present, its seal HMAC and internal chain are verified.

Pruning sealed segments is irreversible and audited. The `vigil audit prune --confirm` command records a `DetectionSource::AuditPrune` entry in the live audit log before deleting archived data. Operators should retain at least one full chain from baseline establishment to current for forensic purposes.

Vigil Baseline is not a silver bullet.
It is a high-signal boundary witness.

*No heuristics. No guessing. Changed or unchanged.*

---

## Closed-Set Directory Watches

Closed-set mode (`mode = "closed_set"`) detects persistence via unknown
filenames. The per-file baseline cannot detect a new file in a watched
directory unless the operator predicted its name. Closed-set declares:
"this directory's set of entries is fixed; any addition or removal is a
structural deviation."

Default closed-set directories: `~/.ssh/`, `/etc/cron.d/`, `/etc/cron.daily/`,
`/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`,
`/etc/sudoers.d/`.

### Per-Tier Coverage (VIGIL-VULN-077)

Real-time detection of closed-set violations depends on the fanotify
capability tier resolved at daemon startup:

| Tier | Kernel | Coverage |
|------|--------|----------|
| `fid_dfid_name` | Linux 5.9+ | Full: `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_TO`, `FAN_ATTRIB` events delivered in real time via `FAN_MARK_FILESYSTEM`. Directory FID + filename resolution via `open_by_handle_at(2)`. Ideal for closed-set watches. |
| `fid` | Linux 5.1+ | Full: FID-mode events with `FAN_MARK_FILESYSTEM` deliver the full event mask in real time. File handles resolved via `open_by_handle_at(2)`. |
| `legacy_fd` | Linux <5.1 | Partial: uses `FAN_MARK_MOUNT`, which does not support `FAN_CREATE`/`FAN_DELETE`/`FAN_MOVED_*`/`FAN_ATTRIB`. On strict kernels (6.18+), falls back to `FAN_MODIFY | FAN_CLOSE_WRITE` only. Scheduled scans compensate for missing event classes. |
| `inotify` | any | Partial: inotify backend has no mount-scoped coverage; relies on per-directory watches with limited scalability. |

The detected tier is logged at `info` at startup, exposed in `vigil status`
JSON as `metrics.fanotify_tier`, and surfaced in `vigil doctor`. Operators
can pin a tier via `monitor.fanotify_tier` in the config for testing.

---

## Absence of Receipts

When `vigil check --reason` is used, each check records a `check_completed`
entry in the audit chain. The absence of receipts over a period is itself
a detection signal: it means either Vigil was not running checks, or an
attacker suppressed Vigil during that window.

Operators can query receipts:
```
vigil audit show --path 'vigil:check_completed'
```

---

## Attestation Threat Model

Attestations address a different question than runtime detection:

> Can an operator prove what Vigil's baseline and audit chain looked like at a
> specific past time, even if the original host is no longer trustworthy?

### Scenario

The source host may later be seized, coerced, silently modified, or otherwise
unable to serve as a trustworthy witness to its own historical state.

### Security Objective

`vigil attest` creates a signed, portable artifact (`.vatt`) that can be verified
offline using only:

- a Vigil binary,
- the attestation file,
- and the attestation signing key (for HMAC-BLAKE3 signatures).

Verification does not require:

- daemon runtime,
- baseline DB presence,
- network access,
- cloud trust anchors,
- package manager state.

### Guarantees

- Tampering with header/body after creation is detected by content-hash mismatch.
- Signature mismatch or wrong key is detected during verification.
- Embedded audit chain link breaks are detected when audit entries are present.
- `attest diff --against current` can detect live-chain divergence (fork/rewrites)
    relative to an attested chain head.

### Non-Goals (Attestation)

- It is not a recovery mechanism.
- It does not rebuild host state.
- It does not prove runtime behavior; it proves declared structural state.

---

## Alert Delivery Degradation

Per-channel delivery status is recorded with every alert. Historical
delivery failures are queryable:
```
vigil audit show --path 'vigil:test_alert'
```

An attacker who degrades alert channels (e.g., kills the notification daemon)
leaves a trail in the audit log showing that alerts were generated but
delivery partially failed.

---

## Acknowledgments and No-Suppression Rule

Acknowledgments are scoped to doctor presentation and operator context.
They do not alter detection classification, alert dispatch, or audit chain
verification.

Security properties:

- `vigil ack` writes chain-extending audit records with operator context.
- `vigil ack revoke` is also chain-audited, so accidental or malicious
  acknowledgment state changes are visible and reversible.
- Acknowledging one event does not silence future events of the same kind
  (recurrence remains actionable).
- Blanket diagnostic suppression flags are intentionally absent. There is
  no `--suppress-future` equivalent that could silently reduce doctor signal.

Threat-model consequence:

- An attacker with command execution cannot covertly downgrade doctor by
  setting hidden suppressors; any acknowledgment is explicit, audited,
  and tied to a specific event reference.

---

## Audit Log Retention

Vigil's audit log is bounded by configuration. By default, entries older
than 365 days are pruned automatically. Each pruned range is replaced with
a single `AuditCheckpoint` record containing a cryptographic HMAC over the
original entries. The chain extends across the checkpoint without break.

**What this preserves:**

- Full forensic detail for entries within the retention window.
- Tamper-evidence forward from any checkpoint: an attacker cannot modify a
  post-checkpoint entry without breaking the chain.
- Tamper-evidence of the prune itself: an attacker cannot fabricate,
  modify, or delete a checkpoint without the audit HMAC key.
- Proof-of-existence for pruned entries: each checkpoint records the
  sequence range, timestamp range, and entry count it covered.

**What this does not preserve:**

- The bytes of pruned entries. After a prune sweep, the original entries
  are deleted. The checkpoint proves they existed and produced a specific
  HMAC, but does not contain their content.
- The ability to verify a specific old entry's HMAC, since the entry
  itself is gone.

**Operator options for longer retention:**

- Configure `audit.retention_days` to a longer value (e.g., 1825 for 5
  years). The audit DB grows accordingly; ensure `audit.max_size_mb` is
  sized appropriately.
- Archive the audit DB externally on a schedule (e.g., monthly `cp` to a
  secondary storage location) before the retention sweep prunes entries.
  The exported DB remains independently verifiable with the audit HMAC
  key.
- Both: configure longer retention AND archive externally for
  defense-in-depth.

**Non-goal:** vigil does not provide an archival subsystem. Operators who
need long-term forensic recovery beyond the retention window are
responsible for their own archival strategy. This is documented and
intentional: archival is a separable concern with diverse operator
requirements (encryption-at-rest, off-site replication, write-once media,
compliance attestation), and bundling it into vigil would expand the
attack surface and the operator-facing complexity for a need that varies
widely between deployments.

---

## Page-cache-layer attacks

A class of kernel-side vulnerabilities — exemplified by **CVE-2026-31431
/ copy.fail** — allows an attacker to mutate file contents *as observed
by reading processes* without modifying the on-disk inode. The
modification lives in the kernel's page cache and is invisible to any
integrity tool that hashes the file via the on-disk view (e.g., raw
block-device reads, `O_DIRECT`, or any path that bypasses the cache).

### How vigil interacts with this class

Vigil's hash path is a standard buffered read (`std::fs::File` →
`read`-based BLAKE3) or, for files above `scanner.mmap_threshold`, a
`mmap`-based BLAKE3. Both paths read **through the page cache**. This
means:

- A modification visible in the page cache is visible to vigil. Vigil
  detects it as a content mismatch on the next scan, regardless of
  whether the mutation has been (or ever will be) written through to the
  on-disk inode.
- The forensic disambiguation pass (1.8.1+) classifies the mismatch as
  `page_cache_only` when the on-disk inode rehashes back to the
  baseline after `POSIX_FADV_DONTNEED`. This is the operator-facing
  signal that distinguishes a page-cache-layer attack from an ordinary
  on-disk modification.

### Honest detection limits

Vigil does **not** claim to defeat page-cache-layer attacks at the
kernel layer. It claims, and now demonstrates with a reproducible
harness, the strictly weaker property: **any modification that is
visible to a normal reading process is also visible to vigil**. If the
exploit can hide the bytes from `read()` *and* from `mmap`, it can hide
them from vigil too — but in that case it has also hidden them from the
process it was supposedly attacking, which is a different problem.

Specific limits worth stating plainly:

- **`mlock` / `MAP_LOCKED` pages.** If the attacker can lock pages such
  that `POSIX_FADV_DONTNEED` cannot evict them, disambiguation returns
  `Inconclusive` rather than misclassifying. Detection (the mismatch
  itself) still works.
- **Files smaller than one page or with the entire range pinned.**
  Disambiguation may be `Inconclusive`; detection is unaffected.
- **Kernel rootkits that hook `read`/`mmap`.** Out of scope; vigil
  inherits the syscall integrity it is run on top of.

### Evidence

A standalone, in-repo harness at
[`tests/exploits/copy_fail/`](../tests/exploits/copy_fail/) reproduces a
Tier-1 (mmap-based, dirty-page) page-cache modification end-to-end and
generates a markdown report attestable to a specific kernel version.
This is the evidentiary backing for the claims above.
