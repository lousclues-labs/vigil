# Remediated Vulnerabilities

This document lists all security vulnerabilities identified and fixed in VigilBaseline, organized by tracking ID. Each entry includes the severity, the release that shipped the fix, and a description of the issue and remediation.

Use this as a reference when assessing VigilBaseline's security posture or auditing specific fixes.

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
| VIGIL-VULN-025 | Critical | 0.23.0 | Baseline DB opened by path after HMAC verification — TOCTOU window |
| VIGIL-VULN-026 | High | 0.23.0 | SQLite WAL/SHM sidecar files not permission-restricted |
| VIGIL-VULN-027 | High | 0.23.0 | Database directory ownership and permissions not verified |
| VIGIL-VULN-028 | Critical | 0.23.0 | VIGIL_CONFIG env var allows config path override in production |
| VIGIL-VULN-029 | Medium | 0.23.0 | VIGIL_SKIP_PACKAGE_OWNER env var accessible in production |
| VIGIL-VULN-030 | High | 0.23.0 | Bind mount over monitored directory evades fanotify detection |
| VIGIL-VULN-031 | High | 0.23.0 | fanotify kernel queue overflow (FAN_Q_OVERFLOW) silently ignored |
| VIGIL-VULN-032 | High | 0.23.0 | Baseline HMAC only covers 5 of 13 security-relevant fields |
| VIGIL-VULN-033 | Medium | 0.23.0 | VigilBaseline's own binary not in self-monitoring watch group |
| VIGIL-VULN-034 | Medium | 0.23.0 | sd_notify socket spoofable — systemd kept happy while VigilBaseline frozen |
| VIGIL-VULN-035 | Low | 0.23.0 | Process attribution via /proc/[pid]/exe raceable (PID recycling) |
| VIGIL-VULN-036 | Medium | 0.23.0 | Negative clock jump not detected — enables clock manipulation replay |
| VIGIL-VULN-037 | Medium | 0.23.0 | Scanner follows symlinks without recording resolution chain |
| VIGIL-VULN-038 | Critical | 0.24.0 | Audit DB has no TOCTOU protection — only baseline DB is identity-checked |
| VIGIL-VULN-039 | Critical | 0.24.0 | Scan scheduler opens baseline DB by path — bypasses TOCTOU check |
| VIGIL-VULN-040 | High | 0.24.0 | Coordinator WAL checkpoint opens baseline DB by path — same TOCTOU bypass |
| VIGIL-VULN-041 | Critical | 0.24.0 | HMAC key loaded from disk on every use — key file replacement undetected between loads |
| VIGIL-VULN-042 | High | 0.24.0 | Runtime dir files written without atomic rename — partial writes observable |
| VIGIL-VULN-043 | High | 0.24.0 | Bloom filter prefix insertion allows targeted false-negative evasion |
| VIGIL-VULN-044 | High | 0.24.0 | package_update field hardcoded false — auto-rebaseline is dead code |
| VIGIL-VULN-045 | Medium | 0.24.0 | Control socket nonce uses /dev/urandom with no fallback verification |
| VIGIL-VULN-046 | Medium | 0.24.0 | Alert dispatcher audit failures cause silent evidence loss |
| VIGIL-VULN-047 | Medium | 0.24.0 | Exclusion filter self-path check uses starts_with on strings — prefix collision |
| VIGIL-VULN-048 | Medium | 0.24.0 | Config reload HMAC verification opens fresh DB connection — TOCTOU |
| VIGIL-VULN-049 | Low | 0.24.0 | sd_notify called unconditionally — no NOTIFY_SOCKET safety verification |
| VIGIL-VULN-050 | Medium | 0.24.0 | Scheduled scan severity hardcoded Medium — critical changes downgraded |

---

## Detailed Descriptions

### VIGIL-VULN-001 — Config/HMAC key file changes unmonitored (Critical)

**Fixed in:** 0.21.0

VigilBaseline did not monitor its own config file (`/etc/vigil/vigil.toml`) or HMAC key file (`/etc/vigil/hmac.key`). An attacker who modified either file would not trigger an alert.

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

**Remediation:** Replaced with targeted exclusions: `/run/user/*`, `/run/lock/*`, `/run/utmp`. VigilBaseline's own runtime directory (`/run/vigil/`) is excluded via the self-paths mechanism.

---

### VIGIL-VULN-011 — Empty baseline silently auto-reinitialized (Critical)

**Fixed in:** 0.21.0

If the baseline was previously initialized but later found empty (e.g., truncated by an attacker), the daemon would silently auto-reinitialize it. This allowed an attacker to clear the baseline and have it rebuilt from potentially compromised files.

**Remediation:** A `baseline_initialized` flag is set in `config_state` after the first successful initialization. If the baseline is later found empty but was previously initialized, VigilBaseline refuses to auto-reinitialize and returns an error with a desktop notification.

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

---

### VIGIL-VULN-025 — Baseline DB TOCTOU after HMAC verification (Critical)

**Fixed in:** 0.23.0

After HMAC verification succeeded at startup, the baseline database was subsequently re-opened by path for scans and periodic HMAC recomputation. An attacker with root access could atomically replace the database file between HMAC verification and the next open, bypassing integrity checks entirely.

**Remediation:** On startup, after HMAC verification succeeds, the inode and device of the baseline DB file are recorded via `DbFileIdentity`. Before every coordinator housekeeping tick, the DB path is stat'd and compared against the recorded identity. If the inode or device differs, all operations are refused and a critical log is emitted: "baseline database file replaced — possible tampering."

---

### VIGIL-VULN-026 — WAL/SHM sidecar files not permission-restricted (High)

**Fixed in:** 0.23.0

SQLite WAL-mode databases create `-wal` and `-shm` sidecar files that inherited the default umask. On systems with permissive umasks, these files could be world-readable, leaking baseline content to unprivileged local users.

**Remediation:** After opening a database in WAL mode, permissions on `{db}-wal` and `{db}-shm` are explicitly set to 0600. The daemon process umask is set to 0077 in `harden_process()` before any file creation.

---

### VIGIL-VULN-027 — Database directory ownership not verified (High)

**Fixed in:** 0.23.0

The database directory was created via `create_dir_all` without verifying ownership or permissions. A non-root user who pre-created the directory could influence database file placement or access.

**Remediation:** After `create_dir_all`, the directory is verified to be owned by uid 0 with mode no wider than 0750. If the check fails, database opening returns an error: "database directory has unsafe ownership or permissions." The check is gated behind `#[cfg(not(any(test, debug_assertions)))]` so tests can use temp directories.

---

### VIGIL-VULN-028 — VIGIL_CONFIG env var allows config override in production (Critical)

**Fixed in:** 0.23.0

The `VIGIL_CONFIG` environment variable was unconditionally trusted for config path resolution. An attacker who could set environment variables (e.g., via systemd override, `/proc/pid/environ` manipulation, or PAM modules) could redirect VigilBaseline to a weakened configuration file.

**Remediation:** `VIGIL_CONFIG` is only unrestricted in test/debug builds (`#[cfg(any(test, debug_assertions))]`). In release builds, the target file must be owned by root (uid 0) with mode ≤ 0644. Applied consistently across `config_search_paths()`, `config_file_content()`, and `config_search_paths_for_hash()`.

---

### VIGIL-VULN-029 — VIGIL_SKIP_PACKAGE_OWNER accessible in production (Medium)

**Fixed in:** 0.23.0

The `VIGIL_SKIP_PACKAGE_OWNER` environment variable disabled package ownership lookups when set. An attacker could set this to suppress package-update context from alerts, degrading attribution quality.

**Remediation:** The env var check is gated behind `#[cfg(any(test, debug_assertions))]`. In production builds, package owner lookup is always performed.

---

### VIGIL-VULN-030 — Bind mount evades fanotify monitoring (High)

**Fixed in:** 0.23.0

fanotify with `FAN_MARK_MOUNT` monitors a specific mount. An attacker who bind-mounted a new filesystem over a watched directory would cause fanotify to continue monitoring the old (now hidden) mount point, while the visible directory contents are unmonitored.

**Remediation:** The coordinator records the mount set from `/proc/self/mountinfo` at startup. Every 60-second housekeeping tick, mountinfo is re-read and compared. New mounts that overlap with configured watch paths trigger error-level logging: "new mount detected over watched path — real-time monitoring may be compromised."

---

### VIGIL-VULN-031 — FAN_Q_OVERFLOW silently ignored (High)

**Fixed in:** 0.23.0

When the kernel's fanotify event queue overflowed, the `FAN_Q_OVERFLOW` flag was set on events but never checked. VigilBaseline silently missed an unknown number of filesystem events, creating a detection gap an attacker could exploit by generating high I/O to force overflow.

**Remediation:** Before the `event.fd >= 0` check, the event loop now checks for `FAN_Q_OVERFLOW` (mask `0x4000`). Overflow events are logged at error level, increment the new `kernel_queue_overflows` metric counter, and continue without attempting fd operations.

---

### VIGIL-VULN-032 — Baseline HMAC only covers 5 of 13 fields (High)

**Fixed in:** 0.23.0

`compute_baseline_hmac()` only included path, hash, mode, owner_uid, and owner_gid in the canonical HMAC data. An attacker who modified the remaining 8 fields (size, inode, device, file_type, symlink_target, capabilities, xattrs, security_context) would not trigger an HMAC mismatch.

**Remediation:** Canonical HMAC data now includes all 13 security-relevant fields: path, hash, size, mode, owner_uid, owner_gid, inode, device, file_type, symlink_target (or empty), capabilities (or empty), xattrs_json, and security_context. This is a breaking change for stored HMACs — on upgrade, the HMAC is automatically recomputed.

---

### VIGIL-VULN-033 — VigilBaseline binary not in self-monitoring watch group (Medium)

**Fixed in:** 0.23.0

The `vigil_self` watch group only covered config and HMAC key files. The VigilBaseline binaries themselves (`/usr/bin/vigil`, `/usr/bin/vigild`) were not monitored. An attacker who replaced the binary would not trigger an alert.

**Remediation:** `/usr/bin/vigil` and `/usr/bin/vigild` are added to the default `vigil_self` watch group. On startup, the BLAKE3 hash of `/proc/self/exe` is computed, logged at info level, and stored in `config_state` key `binary_hash`.

---

### VIGIL-VULN-034 — sd_notify socket spoofable (Medium)

**Fixed in:** 0.23.0

The systemd unit file did not set `NotifyAccess=main`. By default, systemd may accept `sd_notify` messages from any process in the service's cgroup. An attacker could send fake `READY=1` and `WATCHDOG=1` messages to keep systemd satisfied while the actual VigilBaseline process is frozen or killed.

**Remediation:** Added `NotifyAccess=main` to restrict sd_notify to the main process PID only. Changed `ProtectHome=read-only` to `ProtectHome=true` and removed `/var/log/vigil` from `ReadWritePaths`.

---

### VIGIL-VULN-035 — PID recycling race in process attribution (Low)

**Fixed in:** 0.23.0

Process attribution via `/proc/{pid}/exe` was performed inside the `if is_watched` block, after bloom filter checks and watch index lookups. The delay between fanotify delivering the event and the readlink increased the PID recycling window, allowing attribution to the wrong process.

**Remediation:** The `/proc/{pid}/exe` readlink is now performed immediately after reading the event metadata, before any channel send or bloom filter check, minimizing the recycling window. A comment documents that `FAN_REPORT_PIDFD` (Linux 6.2+) would eliminate this race entirely.

---

### VIGIL-VULN-036 — Negative clock jump not detected (Medium)

**Fixed in:** 0.23.0

Clock anomaly detection only checked for forward jumps exceeding 1 hour. A negative clock jump (setting the clock backward) was not detected. An attacker could set the clock back to make recent audit entries appear to be in the future, then forward again to trigger rotation of those entries — a clock manipulation replay attack.

**Remediation:** The coordinator now detects backward clock jumps exceeding 60 seconds and skips audit rotation. `last_rotation_timestamp` is not updated when any clock anomaly (forward or backward) is detected, preventing the attacker from resetting the reference point.

---

### VIGIL-VULN-037 — Symlink target not canonically resolved (Medium)

**Fixed in:** 0.23.0

When the scanner encountered a symlink pointing to a regular file, it followed the link and captured the snapshot, but recorded the immediate `read_link()` target rather than the fully resolved canonical path. If the symlink chain was modified (e.g., an intermediate link redirected) without changing the final target's name, the change would not be detected.

**Remediation:** `FileSnapshot::from_fd()` now resolves symlink targets via `canonicalize()`, falling back to `read_link()` if canonicalization fails. The scanner logs the canonical resolution at debug level. Changes in the resolved canonical target between scans emit `SymlinkTargetChanged` alerts at the watch group's severity level.

---

### VIGIL-VULN-038 — Audit DB identity not tracked (Critical)

**Fixed in:** 0.24.0

Only the baseline DB had inode/device identity checks. The coordinator opened `audit.db` by path on housekeeping ticks, while the alert dispatcher could continue writing to an older connection after replacement. An attacker could atomically replace `audit.db` and make operator-facing reads use the attacker-controlled file.

**Remediation:** VigilBaseline now records `audit.db` inode/device identity at startup and verifies it on coordinator ticks alongside baseline identity. If either DB identity changes, VigilBaseline enters degraded state and refuses housekeeping operations that rely on replaced storage.

---

### VIGIL-VULN-039 — Scan scheduler TOCTOU via path-open (Critical)

**Fixed in:** 0.24.0

Scheduled and on-demand scans opened baseline DB by path each run. This bypassed startup trust and let an attacker swap in a crafted baseline DB for scan execution, then swap it back before coordinator checks.

**Remediation:** The scan scheduler now receives and reuses a startup baseline connection, eliminating path-based re-open in the scan execution path.

---

### VIGIL-VULN-040 — WAL checkpoint TOCTOU via path-open (High)

**Fixed in:** 0.24.0

Periodic WAL checkpoints opened baseline/audit DB by path inside coordinator housekeeping. This created a window where checkpoint operations could run on attacker-replaced files.

**Remediation:** Coordinator WAL checkpoints now run on startup-opened baseline and audit connections, removing path-based trust refresh during runtime.

---

### VIGIL-VULN-041 — HMAC key trust-refresh from disk (Critical)

**Fixed in:** 0.24.0

Multiple components loaded `/etc/vigil/hmac.key` at different times. A root attacker replacing the key could poison future HMAC calculations and verification flows after startup.

**Remediation:** VigilBaseline now loads HMAC key material once at startup into zeroizing memory (`Zeroizing<Vec<u8>>`) and passes it to all runtime consumers (coordinator, baseline writer, alert dispatcher, control socket). Runtime code paths no longer re-read HMAC key from disk.

---

### VIGIL-VULN-042 — Runtime JSON snapshots not atomically written (High)

**Fixed in:** 0.24.0

Runtime files in `/run/vigil` were written with direct overwrite semantics, allowing partial/truncated reads during write windows and race opportunities around replacement timing.

**Remediation:** Runtime snapshots (`metrics.json`, `state.json`, `health.json`) are now written using same-directory temp file plus atomic `rename(2)`.

---

### VIGIL-VULN-043 — Bloom fast-reject semantic mismatch (High)

**Fixed in:** 0.24.0

The Bloom filter inserted watched path prefixes but checked full event paths directly. Correct behavior depended on accidental false positives rather than explicit prefix semantics.

**Remediation:** Bloom fast-reject now checks whether any prefix of the event path is present (`might_contain_prefix_of`), matching insertion semantics and preventing non-deterministic blind spots.

---

### VIGIL-VULN-044 — package_update hardcoded false (High)

**Fixed in:** 0.24.0

Worker change results always set `package_update = false`, so auto-rebaseline logic for package-owned files was effectively dead code.

**Remediation:** Worker now sets `package_update = true` when a baseline entry is package-owned and a content modification is detected, re-enabling intended auto-rebaseline behavior.

---

### VIGIL-VULN-045 — Nonce generation did not fail closed (Medium)

**Fixed in:** 0.24.0

Control socket nonce generation ignored `/dev/urandom` read failures and could produce predictable zero-filled output under error conditions.

**Remediation:** Nonce generation now returns `Result`, rejects failed entropy reads, rejects all-zero buffers, and closes authentication flow on nonce failure.

---

### VIGIL-VULN-046 — Audit write failures dropped evidence (Medium)

**Fixed in:** 0.24.0

On audit DB write failures, entries were logged as errors but not retried, causing silent evidence gaps during repeated DB failure windows.

**Remediation:** Alert dispatcher now buffers failed audit writes in a bounded retry queue and replays buffered entries after successful DB reopen. Permanent overflow loss is tracked via `audit_entries_lost` metric.

---

### VIGIL-VULN-047 — Self-path exclusion prefix collision (Medium)

**Fixed in:** 0.24.0

Self-path exclusion used plain string `starts_with`, so `/run/vigil` also matched attacker-controlled prefixes like `/run/vigil-backdoor`.

**Remediation:** Exclusion matching is now path-component aware by requiring exact self-path or self-path plus `/` prefix boundary.

---

### VIGIL-VULN-048 — Config reload HMAC check used fresh DB path-open (Medium)

**Fixed in:** 0.24.0

Config reload verification opened baseline DB by path for `config_file_hmac` lookups, reintroducing TOCTOU in reload-time trust checks.

**Remediation:** Coordinator reload path now uses startup baseline connection and startup-loaded HMAC key for config integrity verification.

---

### VIGIL-VULN-049 — sd_notify sent to unvalidated NOTIFY_SOCKET (Low)

**Fixed in:** 0.24.0

VigilBaseline sent lifecycle/watchdog notifications without validating `NOTIFY_SOCKET`, allowing information leakage to attacker-controlled sockets via environment injection.

**Remediation:** VigilBaseline now validates `NOTIFY_SOCKET` before `sd_notify`, accepting only `/run/systemd/` paths and abstract sockets.

---

### VIGIL-VULN-050 — Scheduled scan severity downgrade (Medium)

**Fixed in:** 0.24.0

Scheduled scanner emitted `Severity::Medium` for all change results, ignoring configured watch-group severities and potentially downgrading critical findings.

**Remediation:** Scanner now resolves severity from watch-group index per path, with fallback only when no watch-group mapping exists.
