# Remediated Vulnerabilities

This document lists all security vulnerabilities identified and fixed in Vigil, organized by tracking ID. Each entry includes the severity, the release that shipped the fix, and a description of the issue and remediation.

Use this as a reference when assessing Vigil's security posture or auditing specific fixes.

---

## Severity Definitions

| Severity | Meaning |
|----------|---------|
| Critical | Attacker can bypass core integrity guarantees, suppress critical alerts, or tamper with baseline/audit data without detection |
| High | Attacker can evade detection for specific attack classes or exploit trust boundaries |
| Medium | Detection gaps or information leaks that weaken monitoring fidelity but do not directly enable undetected tampering |
| Low | Noise, usability, or hardening issues with minimal direct security impact |

---

## Vulnerability Index

| ID | Severity | Fixed In | Summary |
|----|----------|----------|---------|
| VIGIL-VULN-001 | Critical | 0.21.0 | Config/HMAC key file changes were unmonitored |
| VIGIL-VULN-002 | Critical | 0.21.0 | Baseline could be silently replaced without detection |
| VIGIL-VULN-003 | Medium | 0.21.0 | Debounced paths were silently dropped without re-check |
| VIGIL-VULN-004 | High | 0.21.0 | Audit entries could be deleted from the middle of the chain without HMAC detection |
| VIGIL-VULN-005 | High | 0.21.0 | Incremental scan default allowed mtime-reset evasion |
| VIGIL-VULN-006 | Critical | 0.21.0 | Control socket accepted unauthenticated commands |
| VIGIL-VULN-007 | Medium | 0.21.0 | Control socket commands were unlogged with no peer credential capture |
| VIGIL-VULN-008 | Medium | 0.21.0 | Sustained event drops were silent, no evasion alert |
| VIGIL-VULN-009 | Low | 0.21.0 | Hardcoded event channel capacity was not tunable for high-load environments |
| VIGIL-VULN-010 | High | 0.21.0 | Blanket `/run/*` exclusion created monitoring blind spot for transient systemd units |
| VIGIL-VULN-011 | Critical | 0.21.0 | Empty baseline after initialization could be silently auto-reinitialized |
| VIGIL-VULN-012 | High | 0.21.0 | Config file modifications between restarts were undetected |
| VIGIL-VULN-013 | Critical | 0.22.0 | `has_dangerous_capabilities()` always returned false on real binaries |
| VIGIL-VULN-014 | High | 0.22.0 | Critical/High alerts fully suppressed during maintenance windows |
| VIGIL-VULN-015 | High | 0.22.0 | `from_fd()` followed symlinks, could not classify symlink paths |
| VIGIL-VULN-016 | High | 0.22.0 | Hash computation re-opened file by path, introducing TOCTOU window |
| VIGIL-VULN-017 | High | 0.22.0 | Package manager invocation trusted PATH, allowing command hijacking |
| VIGIL-VULN-018 | High | 0.22.0 | Clock-forward attack could destroy audit evidence via rotation |
| VIGIL-VULN-019 | Medium | 0.22.0 | File size changes were invisible to the diff engine |
| VIGIL-VULN-020 | Medium | 0.22.0 | Device (st_dev) changes were invisible, missing cross-filesystem swaps |
| VIGIL-VULN-021 | Low | 0.22.0 | `security.*` xattrs duplicated in generic map, producing noisy change entries |
| VIGIL-VULN-022 | Medium | 0.22.0 | fanotify relied on `FAN_MODIFY` only, missing completed writes |
| VIGIL-VULN-023 | High | 0.22.0 | Worker baseline cache could remain stale after baseline commits |
| VIGIL-VULN-024 | Medium | 0.22.0 | Intermediate HMAC key material persisted in heap memory |

---

## Detailed Descriptions

### VIGIL-VULN-001 — Config/HMAC key file changes unmonitored (Critical)

**Fixed in:** 0.21.0

Vigil did not monitor its own config file (`/etc/vigil/vigil.toml`) or HMAC key file (`/etc/vigil/hmac.key`). An attacker who modified either file would not trigger an alert.

**Remediation:** Default config now includes a `vigil_self` watch group at `Critical` severity covering both files. `validate_config_deep()` warns if no watch group covers the config file path. Real-time events on these files log at `tracing::error!` for immediate visibility.

---

### VIGIL-VULN-002 — Baseline silently replaceable without detection (Critical)

**Fixed in:** 0.21.0

The baseline database could be replaced or tampered with between daemon restarts without any verification.

**Remediation:** After every baseline initialization, a baseline HMAC is computed over all entries and stored in `config_state`. On daemon startup with `security.hmac_signing = true`, the stored HMAC is compared to a freshly computed one. Mismatch refuses to start and sends a Critical desktop notification. The baseline writer thread periodically recomputes the HMAC to keep it current.

---

### VIGIL-VULN-003 — Debounced paths silently dropped (Medium)

**Fixed in:** 0.21.0

When debounced pending paths were drained, they only had their LRU cache entries invalidated. If no further filesystem event arrived for that path, the change was silently missed until the next scheduled scan.

**Remediation:** Drained paths are now re-checked by processing them as synthetic `FsEvent` objects, ensuring changes are detected regardless of whether additional events arrive.

---

### VIGIL-VULN-004 — Audit chain HMAC did not include previous hash (High)

**Fixed in:** 0.21.0

Individual audit entry HMACs did not include the previous chain hash. An attacker with database access could delete entries from the middle of the chain without HMAC detection, since the BLAKE3 chain hash has no secret key.

**Remediation:** `build_audit_hmac_data()` now takes a `previous_chain_hash` parameter. Chained HMACs make mid-chain deletion detectable via HMAC verification. Added `verify_chain_with_hmac()` for verification.

---

### VIGIL-VULN-005 — Incremental scan default allowed mtime-reset evasion (High)

**Fixed in:** 0.21.0

The default scheduled scan mode was `Incremental`, which skips hashing for files whose mtime has not changed. An attacker who modified a file and reset its mtime to the original value would evade detection until a full scan was manually triggered.

**Remediation:** `scanner.scheduled_mode` now defaults to `Full`. Full mode rehashes every file regardless of mtime.

---

### VIGIL-VULN-006 — Control socket accepted unauthenticated commands (Critical)

**Fixed in:** 0.21.0

The daemon control socket accepted commands from any local process with socket file access. An attacker with local access could trigger reloads, scans, or other operations without authentication.

**Remediation:** New `security.control_socket_auth` config field (default: `true`). When enabled with `hmac_signing = true`, the server sends a 32-byte random hex nonce and the client must respond with `HMAC-SHA256(nonce, hmac_key)`. Falls back to unauthenticated mode with `tracing::warn!` when HMAC signing is disabled.

---

### VIGIL-VULN-007 — Control socket commands unlogged (Medium)

**Fixed in:** 0.21.0

Control socket commands were not logged and peer credentials were not captured. An attacker could issue commands without leaving an audit trail.

**Remediation:** `reload` and `scan` commands now log at `tracing::warn!`. Peer credentials (PID, UID, GID) are logged via `SO_PEERCRED` on every connection. A `control_commands` metric counter tracks total commands executed.

---

### VIGIL-VULN-008 — Sustained event drops were silent (Medium)

**Fixed in:** 0.21.0

When the event channel was full and filesystem events were being dropped, there was no alert or log entry. An attacker could flood the event channel to cause silent event loss.

**Remediation:** The coordinator thread now tracks `events_dropped` across housekeeping ticks and logs at `tracing::error!` with both the delta and total when the count increases.

---

### VIGIL-VULN-009 — Hardcoded event channel capacity (Low)

**Fixed in:** 0.21.0

The event channel capacity was hardcoded to 2048, which was not tunable for high-load environments where burst I/O could cause event drops.

**Remediation:** New config field `daemon.event_channel_capacity` (default: 4096). Higher values reduce event drops under sustained I/O load or flood conditions.

---

### VIGIL-VULN-010 — Blanket `/run/*` exclusion created blind spot (High)

**Fixed in:** 0.21.0

The `/run/*` system exclusion was a blanket pattern that excluded all of `/run/`. Attackers could persist via transient systemd units in `/run/systemd/transient/` without detection.

**Remediation:** Replaced with targeted exclusions: `/run/user/*`, `/run/lock/*`, `/run/utmp`. Vigil's own runtime directory (`/run/vigil/`) is excluded via the self-paths mechanism.

---

### VIGIL-VULN-011 — Empty baseline silently auto-reinitialized (Critical)

**Fixed in:** 0.21.0

If the baseline was previously initialized but later found empty (e.g., truncated by an attacker), the daemon would silently auto-reinitialize it. This allowed an attacker to clear the baseline and have it rebuilt from potentially compromised files.

**Remediation:** A `baseline_initialized` flag is set in `config_state` after the first successful initialization. If the baseline is later found empty but was previously initialized, Vigil refuses to auto-reinitialize and returns an error with a desktop notification.

---

### VIGIL-VULN-012 — Config file modifications undetected between restarts (High)

**Fixed in:** 0.21.0

Config file modifications between daemon restarts were not detected. An attacker could weaken monitoring configuration without triggering an alert.

**Remediation:** On daemon startup, the BLAKE3 hash of the config file is computed and stored. On SIGHUP reload, if `security.hmac_signing = true` and the stored config file HMAC does not match, the reload is rejected.

---

### VIGIL-VULN-013 — Capability escalation detection always returned false (Critical)

**Fixed in:** 0.22.0

`FileSnapshot::has_dangerous_capabilities()` searched for ASCII strings (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`) inside hex-encoded binary xattr data. Since the raw bytes never contain those ASCII strings, the function always returned false. Severity escalation to `Critical` for dangerous capability-bearing files never triggered.

**Remediation:** Capability detection now decodes `security.capability` bytes and checks dangerous bits directly in the permitted mask (`CAP_DAC_OVERRIDE` bit 1, `CAP_SETUID` bit 7, `CAP_SYS_ADMIN` bit 21).

---

### VIGIL-VULN-014 — Critical/High alerts suppressed during maintenance (High)

**Fixed in:** 0.22.0

During maintenance windows, package-owned changes were fully suppressed regardless of severity. This meant `Critical` and `High` severity alerts from genuinely dangerous changes were silently dropped.

**Remediation:** `Critical` and `High` severity alerts are never fully suppressed during maintenance; they are dispatched with `maintenance_window=true` context. `Low` and `Medium` package-owned changes remain suppressible.

---

### VIGIL-VULN-015 — Symlink detection followed symlinks via fstat (High)

**Fixed in:** 0.22.0

`from_fd()` used `file.metadata()` (`fstat`), which follows symlinks and cannot identify the path as a symlink. Symlink paths were misclassified as regular files.

**Remediation:** `from_fd()` now performs one path-level `symlink_metadata()` (`lstat`) check for symlink classification and reads `symlink_target` only when the path is a symlink.

---

### VIGIL-VULN-016 — Hash computation re-opened file by path (TOCTOU) (High)

**Fixed in:** 0.22.0

Hashing used `blake3::Hasher::update_mmap()` with `/proc/self/fd/N`, which re-opened the file by path and introduced a micro-TOCTOU window. An attacker could swap the file between the metadata read and the hash computation.

**Remediation:** Hashing now performs direct `libc::mmap` on the original fd with an RAII `munmap` guard and falls back to buffered I/O when mmap fails. Metadata and hash are now derived from the same file description.

---

### VIGIL-VULN-017 — Package manager invocation trusted PATH (High)

**Fixed in:** 0.22.0

Package backend detection and invocation trusted `PATH` resolution (`pacman`, `dpkg`, `rpm`). An attacker who controlled `PATH` ordering could hijack package manager commands.

**Remediation:** All package manager calls now use absolute paths (`/usr/bin/pacman`, `/usr/bin/dpkg`, `/usr/bin/rpm`). Added root-ownership guard for `/var/lib/dpkg/info` before parsing `*.list` files.

---

### VIGIL-VULN-018 — Clock-forward attack on audit rotation (High)

**Fixed in:** 0.22.0

Coordinator audit rotation operated directly from `Utc::now()` without anomaly checks. An attacker who jumped the system clock forward could trigger mass audit log deletion via the retention policy.

**Remediation:** Rotation now skips when the clock jumps forward by more than 1 hour between ticks and when one pass would delete more than 50% of all audit rows.

---

### VIGIL-VULN-019 — File size changes invisible to diff engine (Medium)

**Fixed in:** 0.22.0

The `diff()` function compared hashes but not sizes. No explicit size-change signal existed, so file size modifications were not reported as a distinct change type.

**Remediation:** Added `Change::SizeChanged { old, new }`, wired through display, primary change mapping, audit type mapping, and alert naming.

---

### VIGIL-VULN-020 — Device changes invisible to diff engine (Medium)

**Fixed in:** 0.22.0

The `diff()` function checked inode changes but omitted device (`st_dev`) changes. Cross-filesystem substitution or bind-mount swaps were not detected.

**Remediation:** Added `Change::DeviceChanged { old, new }`, wired through display, primary change mapping, audit type mapping, and alert naming.

---

### VIGIL-VULN-021 — Duplicate security.* xattrs in generic map (Low)

**Fixed in:** 0.22.0

`read_xattrs_fd()` filtered `system.*` xattrs from the generic map but not `security.*`. This left `security.*` xattrs duplicated in both dedicated fields and the generic xattr map, producing noisy duplicate change entries.

**Remediation:** Generic xattr collection now skips both `system.*` and `security.*` keys.

---

### VIGIL-VULN-022 — fanotify missed completed writes (Medium)

**Fixed in:** 0.22.0

Monitoring relied on `FAN_MODIFY` only, which can fire on partial writes. Post-write integrity checks could trigger on incomplete data, causing false positives, while completed writes without a separate modify event could be missed.

**Remediation:** Added `FAN_CLOSE_WRITE` to the fanotify mask and mapped it to `FsEventType::Modify` alongside `FAN_MODIFY`.

---

### VIGIL-VULN-023 — Stale baseline cache after commits (High)

**Fixed in:** 0.22.0

The worker LRU baseline cache could remain stale after the baseline writer committed new entries. Workers would continue comparing against outdated baseline data until the cache entry was naturally evicted.

**Remediation:** Added shared `Arc<AtomicU64>` generation counter. The baseline writer increments after successful commit; workers compare their local generation each loop tick and clear the cache on mismatch.

---

### VIGIL-VULN-024 — HMAC key material persisted in heap (Medium)

**Fixed in:** 0.22.0

Intermediate decoded key text in `load_hmac_key()` was not explicitly cleared from memory after use. Key material could persist in heap memory longer than necessary.

**Remediation:** Added `zeroize` dependency and applied explicit zeroization to intermediate decoded key text. `AlertDispatcher` now stores HMAC keys as `Option<Zeroizing<Vec<u8>>>`.
