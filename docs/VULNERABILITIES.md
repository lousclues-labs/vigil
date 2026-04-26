# Remediated Vulnerabilities

This document lists all security vulnerabilities identified and fixed in Vigil Baseline, organized by tracking ID. Each entry includes the severity, the release that shipped the fix, and a description of the issue and remediation.

Use this as a reference when assessing Vigil Baseline's security posture or auditing specific fixes.

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
| VIGIL-VULN-025 | Critical | 0.23.0 | Baseline DB opened by path after HMAC verification -- TOCTOU window |
| VIGIL-VULN-026 | High | 0.23.0 | SQLite WAL/SHM sidecar files not permission-restricted |
| VIGIL-VULN-027 | High | 0.23.0 | Database directory ownership and permissions not verified |
| VIGIL-VULN-028 | Critical | 0.23.0 | VIGIL_CONFIG env var allows config path override in production |
| VIGIL-VULN-029 | Medium | 0.23.0 | VIGIL_SKIP_PACKAGE_OWNER env var accessible in production |
| VIGIL-VULN-030 | High | 0.23.0 | Bind mount over monitored directory evades fanotify detection |
| VIGIL-VULN-031 | High | 0.23.0 | fanotify kernel queue overflow (FAN_Q_OVERFLOW) silently ignored |
| VIGIL-VULN-032 | High | 0.23.0 | Baseline HMAC only covers 5 of 13 security-relevant fields |
| VIGIL-VULN-033 | Medium | 0.23.0 | Vigil Baseline's own binary not in self-monitoring watch group |
| VIGIL-VULN-034 | Medium | 0.23.0 | sd_notify socket spoofable -- systemd kept happy while Vigil Baseline frozen |
| VIGIL-VULN-035 | Low | 0.23.0 | Process attribution via /proc/[pid]/exe raceable (PID recycling) |
| VIGIL-VULN-036 | Medium | 0.23.0 | Negative clock jump not detected -- enables clock manipulation replay |
| VIGIL-VULN-037 | Medium | 0.23.0 | Scanner follows symlinks without recording resolution chain |
| VIGIL-VULN-038 | Critical | 0.24.0 | Audit DB has no TOCTOU protection -- only baseline DB is identity-checked |
| VIGIL-VULN-039 | Critical | 0.24.0 | Scan scheduler opens baseline DB by path -- bypasses TOCTOU check |
| VIGIL-VULN-040 | High | 0.24.0 | Coordinator WAL checkpoint opens baseline DB by path -- same TOCTOU bypass |
| VIGIL-VULN-041 | Critical | 0.24.0 | HMAC key loaded from disk on every use -- key file replacement undetected between loads |
| VIGIL-VULN-042 | High | 0.24.0 | Runtime dir files written without atomic rename -- partial writes observable |
| VIGIL-VULN-043 | High | 0.24.0 | Bloom filter prefix insertion allows targeted false-negative evasion |
| VIGIL-VULN-044 | High | 0.24.0 | package_update field hardcoded false -- auto-rebaseline is dead code |
| VIGIL-VULN-045 | Medium | 0.24.0 | Control socket nonce uses /dev/urandom with no fallback verification |
| VIGIL-VULN-046 | Medium | 0.24.0 | Alert dispatcher audit failures cause silent evidence loss |
| VIGIL-VULN-047 | Medium | 0.24.0 | Exclusion filter self-path check uses starts_with on strings -- prefix collision |
| VIGIL-VULN-048 | Medium | 0.24.0 | Config reload HMAC verification opens fresh DB connection -- TOCTOU |
| VIGIL-VULN-049 | Low | 0.24.0 | sd_notify called unconditionally -- no NOTIFY_SOCKET safety verification |
| VIGIL-VULN-050 | Medium | 0.24.0 | Scheduled scan severity hardcoded Medium -- critical changes downgraded |
| VIGIL-VULN-051 | Critical | 0.33.0 | Baseline HMAC mismatch silently auto-recomputed -- tamper evidence nullified |
| VIGIL-VULN-052 | Critical | 0.33.0 | `baseline_refresh` re-read config from disk bypassing HMAC verification |
| VIGIL-VULN-053 | Critical | 0.33.0 | Control socket `read_line` unbounded -- local OOM denial of service |
| VIGIL-VULN-054 | High | 0.33.0 | HMAC key permission check warn-only -- world-readable key accepted |
| VIGIL-VULN-055 | High | 0.33.0 | `vigil update` under sudo builds from user-owned directory -- privilege escalation |
| VIGIL-VULN-056 | Medium | 0.33.0 | PID attribution did not detect exited processes -- stale attribution undetectable |
| VIGIL-VULN-057 | Critical | 0.34.0 | Control socket HMAC auth used non-constant-time string compare and was bypassable on empty response |
| VIGIL-VULN-058 | Critical | 0.34.0 | fanotify event loop did not validate `event_len` -- malformed event caused infinite loop |
| VIGIL-VULN-059 | High | 0.34.0 | Control socket accepted connections from any local UID -- peer credentials not enforced |
| VIGIL-VULN-060 | High | 0.34.0 | Control socket spawned unbounded threads per connection -- local thread-exhaustion DoS |
| VIGIL-VULN-061 | High | 0.34.0 | `vigil update` did not roll back when daemon failed to start -- only when started-but-unhealthy |
| VIGIL-VULN-062 | High | 0.34.0 | Package manager queries lacked `--` separator -- paths starting with `-` interpreted as flags |
| VIGIL-VULN-063 | High | 0.34.0 | Helper binaries invoked by bare name -- vulnerable to PATH hijacking |
| VIGIL-VULN-064 | Medium | 0.34.0 | fanotify queue overflow silently logged -- no Degraded state, no recovery scan |
| VIGIL-VULN-065 | Medium | 0.34.0 | fanotify mountinfo octal escapes not decoded -- mount points with whitespace not marked |
| VIGIL-VULN-066 | Medium | 0.34.0 | fanotify mark/read failures silently ignored -- daemon ran without real-time monitoring |
| VIGIL-VULN-067 | Critical | 0.35.0 | WAL HMAC verification bypass via zero-HMAC injection |
| VIGIL-VULN-068 | High | 0.35.0 | fanotify silently drops events for deleted files |
| VIGIL-VULN-069 | High | 0.35.0 | New-mount evasion: fanotify marks not applied to overlapping mounts |
| VIGIL-VULN-070 | Medium | 0.35.0 | Clock manipulation evades audit retention via slow drift |
| VIGIL-VULN-071 | Medium | 0.35.0 | Coordinator uses stale DB connections after Degraded transition |
| VIGIL-VULN-072 | Medium | 0.35.0 | User-space event loss not surfaced as Degraded state |
| VIGIL-VULN-073 | Medium | 0.35.0 | v0.34.0 follow-up bugs (composite) |
| VIGIL-VULN-074 | Medium | 0.35.0 | Key material in non-zeroizing buffers; fd leak across exec (composite) |
| VIGIL-VULN-075 | Medium | 1.7.3 | User-space event channel drops created silent blind spots without compensating scan |
| VIGIL-VULN-076 | High | 1.7.3 | Audit HMAC delimiter collision — pipe-separated input could be forged for paths containing the delimiter |
| VIGIL-VULN-077 | High | 1.7.3 | Directory-modification events silently dropped under FAN_MARK_MOUNT without FID-mode init |

---

## Detailed Descriptions

### VIGIL-VULN-001 -- Config/HMAC key file changes unmonitored (Critical)

**Fixed in:** 0.21.0

Vigil Baseline did not monitor its own config file (`/etc/vigil/vigil.toml`) or HMAC key file (`/etc/vigil/hmac.key`). An attacker who modified either file would not trigger an alert.

**Remediation:** Default config now includes a `vigil_self` watch group at `Critical` severity covering both files. `validate_config_deep()` warns if no watch group covers the config file path. Real-time events on these files log at `tracing::error!` for immediate visibility.

---

### VIGIL-VULN-002 -- Baseline silently replaceable without detection (Critical)

**Fixed in:** 0.21.0

The baseline database could be replaced or tampered with between daemon restarts without any verification.

**Remediation:** After every baseline initialization, a baseline HMAC is computed over all entries and stored in `config_state`. On daemon startup with `security.hmac_signing = true`, the stored HMAC is compared to a freshly computed one. Mismatch refuses to start and sends a Critical desktop notification. The baseline writer thread periodically recomputes the HMAC to keep it current.

---

### VIGIL-VULN-003 -- Debounced paths silently dropped (Medium)

**Fixed in:** 0.21.0

When debounced pending paths were drained, they only had their LRU cache entries invalidated. If no further filesystem event arrived for that path, the change was silently missed until the next scheduled scan.

**Remediation:** Drained paths are now re-checked by processing them as synthetic `FsEvent` objects, ensuring changes are detected regardless of whether additional events arrive.

---

### VIGIL-VULN-004 -- Audit chain HMAC did not include previous hash (High)

**Fixed in:** 0.21.0

Individual audit entry HMACs did not include the previous chain hash. An attacker with database access could delete entries from the middle of the chain without HMAC detection, since the BLAKE3 chain hash has no secret key.

**Remediation:** `build_audit_hmac_data()` now takes a `previous_chain_hash` parameter. Chained HMACs make mid-chain deletion detectable via HMAC verification. Added `verify_chain_with_hmac()` for verification.

---

### VIGIL-VULN-005 -- Incremental scan default allowed mtime-reset evasion (High)

**Fixed in:** 0.21.0

The default scheduled scan mode was `Incremental`, which skips hashing for files whose mtime has not changed. An attacker who modified a file and reset its mtime to the original value would evade detection until a full scan was manually triggered.

**Remediation:** `scanner.scheduled_mode` now defaults to `Full`. Full mode rehashes every file regardless of mtime.

---

### VIGIL-VULN-006 -- Control socket accepted unauthenticated commands (Critical)

**Fixed in:** 0.21.0

The daemon control socket accepted commands from any local process with socket file access. An attacker with local access could trigger reloads, scans, or other operations without authentication.

**Remediation:** New `security.control_socket_auth` config field (default: `true`). When enabled with `hmac_signing = true`, the server sends a 32-byte random hex nonce and the client must respond with `HMAC-SHA256(nonce, hmac_key)`. Falls back to unauthenticated mode with `tracing::warn!` when HMAC signing is disabled.

---

### VIGIL-VULN-007 -- Control socket commands unlogged (Medium)

**Fixed in:** 0.21.0

Control socket commands were not logged and peer credentials were not captured. An attacker could issue commands without leaving an audit trail.

**Remediation:** `reload` and `scan` commands now log at `tracing::warn!`. Peer credentials (PID, UID, GID) are logged via `SO_PEERCRED` on every connection. A `control_commands` metric counter tracks total commands executed.

---

### VIGIL-VULN-008 -- Sustained event drops were silent (Medium)

**Fixed in:** 0.21.0

When the event channel was full and filesystem events were being dropped, there was no alert or log entry. An attacker could flood the event channel to cause silent event loss.

**Remediation:** The coordinator thread now tracks `events_dropped` across housekeeping ticks and logs at `tracing::error!` with both the delta and total when the count increases.

---

### VIGIL-VULN-009 -- Hardcoded event channel capacity (Low)

**Fixed in:** 0.21.0

The event channel capacity was hardcoded to 2048, which was not tunable for high-load environments where burst I/O could cause event drops.

**Remediation:** New config field `daemon.event_channel_capacity` (default: 4096). Higher values reduce event drops under sustained I/O load or flood conditions.

---

### VIGIL-VULN-010 -- Blanket `/run/*` exclusion created blind spot (High)

**Fixed in:** 0.21.0

The `/run/*` system exclusion was a blanket pattern that excluded all of `/run/`. Attackers could persist via transient systemd units in `/run/systemd/transient/` without detection.

**Remediation:** Replaced with targeted exclusions: `/run/user/*`, `/run/lock/*`, `/run/utmp`. Vigil Baseline's own runtime directory (`/run/vigil/`) is excluded via the self-paths mechanism.

---

### VIGIL-VULN-011 -- Empty baseline silently auto-reinitialized (Critical)

**Fixed in:** 0.21.0

If the baseline was previously initialized but later found empty (e.g., truncated by an attacker), the daemon would silently auto-reinitialize it. This allowed an attacker to clear the baseline and have it rebuilt from potentially compromised files.

**Remediation:** A `baseline_initialized` flag is set in `config_state` after the first successful initialization. If the baseline is later found empty but was previously initialized, Vigil Baseline refuses to auto-reinitialize and returns an error with a desktop notification.

---

### VIGIL-VULN-012 -- Config file modifications undetected between restarts (High)

**Fixed in:** 0.21.0

Config file modifications between daemon restarts were not detected. An attacker could weaken monitoring configuration without triggering an alert.

**Remediation:** On daemon startup, the BLAKE3 hash of the config file is computed and stored. On SIGHUP reload, if `security.hmac_signing = true` and the stored config file HMAC does not match, the reload is rejected.

---

### VIGIL-VULN-013 -- Capability escalation detection always returned false (Critical)

**Fixed in:** 0.22.0

`FileSnapshot::has_dangerous_capabilities()` searched for ASCII strings (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`) inside hex-encoded binary xattr data. Since the raw bytes never contain those ASCII strings, the function always returned false. Severity escalation to `Critical` for dangerous capability-bearing files never triggered.

**Remediation:** Capability detection now decodes `security.capability` bytes and checks dangerous bits directly in the permitted mask (`CAP_DAC_OVERRIDE` bit 1, `CAP_SETUID` bit 7, `CAP_SYS_ADMIN` bit 21).

**Note (1.7.0):** The entire `has_dangerous_capabilities()` function and severity auto-escalation were removed in 1.7.0 per Principle III (no inference). The function only checked 3 of 40+ capability bits, producing partial coverage that appeared complete. Severity is now determined by the watch group alone. See CHANGELOG 1.7.0 "Removed."

---

### VIGIL-VULN-014 -- Critical/High alerts suppressed during maintenance (High)

**Fixed in:** 0.22.0

During maintenance windows, package-owned changes were fully suppressed regardless of severity. This meant `Critical` and `High` severity alerts from genuinely dangerous changes were silently dropped.

**Remediation:** `Critical` and `High` severity alerts are never fully suppressed during maintenance; they are dispatched with `maintenance_window=true` context. `Low` and `Medium` package-owned changes remain suppressible.

---

### VIGIL-VULN-015 -- Symlink detection followed symlinks via fstat (High)

**Fixed in:** 0.22.0

`from_fd()` used `file.metadata()` (`fstat`), which follows symlinks and cannot identify the path as a symlink. Symlink paths were misclassified as regular files.

**Remediation:** `from_fd()` now performs one path-level `symlink_metadata()` (`lstat`) check for symlink classification and reads `symlink_target` only when the path is a symlink.

---

### VIGIL-VULN-016 -- Hash computation re-opened file by path (TOCTOU) (High)

**Fixed in:** 0.22.0

Hashing used `blake3::Hasher::update_mmap()` with `/proc/self/fd/N`, which re-opened the file by path and introduced a micro-TOCTOU window. An attacker could swap the file between the metadata read and the hash computation.

**Remediation:** Hashing now performs direct `libc::mmap` on the original fd with an RAII `munmap` guard and falls back to buffered I/O when mmap fails. Metadata and hash are now derived from the same file description.

---

### VIGIL-VULN-017 -- Package manager invocation trusted PATH (High)

**Fixed in:** 0.22.0

Package backend detection and invocation trusted `PATH` resolution (`pacman`, `dpkg`, `rpm`). An attacker who controlled `PATH` ordering could hijack package manager commands.

**Remediation:** All package manager calls now use absolute paths (`/usr/bin/pacman`, `/usr/bin/dpkg`, `/usr/bin/rpm`). Added root-ownership guard for `/var/lib/dpkg/info` before parsing `*.list` files.

---

### VIGIL-VULN-018 -- Clock-forward attack on audit rotation (High)

**Fixed in:** 0.22.0

Coordinator audit rotation operated directly from `Utc::now()` without anomaly checks. An attacker who jumped the system clock forward could trigger mass audit log deletion via the retention policy.

**Remediation:** Rotation now skips when the clock jumps forward by more than 1 hour between ticks and when one pass would delete more than 50% of all audit rows.

---

### VIGIL-VULN-019 -- File size changes invisible to diff engine (Medium)

**Fixed in:** 0.22.0

The `diff()` function compared hashes but not sizes. No explicit size-change signal existed, so file size modifications were not reported as a distinct change type.

**Remediation:** Added `Change::SizeChanged { old, new }`, wired through display, primary change mapping, audit type mapping, and alert naming.

---

### VIGIL-VULN-020 -- Device changes invisible to diff engine (Medium)

**Fixed in:** 0.22.0

The `diff()` function checked inode changes but omitted device (`st_dev`) changes. Cross-filesystem substitution or bind-mount swaps were not detected.

**Remediation:** Added `Change::DeviceChanged { old, new }`, wired through display, primary change mapping, audit type mapping, and alert naming.

---

### VIGIL-VULN-021 -- Duplicate security.* xattrs in generic map (Low)

**Fixed in:** 0.22.0

`read_xattrs_fd()` filtered `system.*` xattrs from the generic map but not `security.*`. This left `security.*` xattrs duplicated in both dedicated fields and the generic xattr map, producing noisy duplicate change entries.

**Remediation:** Generic xattr collection now skips both `system.*` and `security.*` keys.

---

### VIGIL-VULN-022 -- fanotify missed completed writes (Medium)

**Fixed in:** 0.22.0

Monitoring relied on `FAN_MODIFY` only, which can fire on partial writes. Post-write integrity checks could trigger on incomplete data, causing false positives, while completed writes without a separate modify event could be missed.

**Remediation:** Added `FAN_CLOSE_WRITE` to the fanotify mask and mapped it to `FsEventType::Modify` alongside `FAN_MODIFY`.

---

### VIGIL-VULN-023 -- Stale baseline cache after commits (High)

**Fixed in:** 0.22.0

The worker LRU baseline cache could remain stale after the baseline writer committed new entries. Workers would continue comparing against outdated baseline data until the cache entry was naturally evicted.

**Remediation:** Added shared `Arc<AtomicU64>` generation counter. The baseline writer increments after successful commit; workers compare their local generation each loop tick and clear the cache on mismatch.

---

### VIGIL-VULN-024 -- HMAC key material persisted in heap (Medium)

**Fixed in:** 0.22.0

Intermediate decoded key text in `load_hmac_key()` was not explicitly cleared from memory after use. Key material could persist in heap memory longer than necessary.

**Remediation:** Added `zeroize` dependency and applied explicit zeroization to intermediate decoded key text. `AlertDispatcher` now stores HMAC keys as `Option<Zeroizing<Vec<u8>>>`.

---

### VIGIL-VULN-025 -- Baseline DB TOCTOU after HMAC verification (Critical)

**Fixed in:** 0.23.0

After HMAC verification succeeded at startup, the baseline database was subsequently re-opened by path for scans and periodic HMAC recomputation. An attacker with root access could atomically replace the database file between HMAC verification and the next open, bypassing integrity checks entirely.

**Remediation:** On startup, after HMAC verification succeeds, the inode and device of the baseline DB file are recorded via `DbFileIdentity`. Before every coordinator housekeeping tick, the DB path is stat'd and compared against the recorded identity. If the inode or device differs, all operations are refused and a critical log is emitted: "baseline database file replaced -- possible tampering."

---

### VIGIL-VULN-026 -- WAL/SHM sidecar files not permission-restricted (High)

**Fixed in:** 0.23.0

SQLite WAL-mode databases create `-wal` and `-shm` sidecar files that inherited the default umask. On systems with permissive umasks, these files could be world-readable, leaking baseline content to unprivileged local users.

**Remediation:** After opening a database in WAL mode, permissions on `{db}-wal` and `{db}-shm` are explicitly set to 0600. The daemon process umask is set to 0077 in `harden_process()` before any file creation.

---

### VIGIL-VULN-027 -- Database directory ownership not verified (High)

**Fixed in:** 0.23.0

The database directory was created via `create_dir_all` without verifying ownership or permissions. A non-root user who pre-created the directory could influence database file placement or access.

**Remediation:** After `create_dir_all`, the directory is verified to be owned by uid 0 with mode no wider than 0750. If the check fails, database opening returns an error: "database directory has unsafe ownership or permissions." The check is gated behind `#[cfg(not(any(test, debug_assertions)))]` so tests can use temp directories.

---

### VIGIL-VULN-028 -- VIGIL_CONFIG env var allows config override in production (Critical)

**Fixed in:** 0.23.0

The `VIGIL_CONFIG` environment variable was unconditionally trusted for config path resolution. An attacker who could set environment variables (e.g., via systemd override, `/proc/pid/environ` manipulation, or PAM modules) could redirect Vigil Baseline to a weakened configuration file.

**Remediation:** `VIGIL_CONFIG` is only unrestricted in test/debug builds (`#[cfg(any(test, debug_assertions))]`). In release builds, the target file must be owned by root (uid 0) with mode ≤ 0644. Applied consistently across `config_search_paths()`, `config_file_content()`, and `config_search_paths_for_hash()`.

---

### VIGIL-VULN-029 -- VIGIL_SKIP_PACKAGE_OWNER accessible in production (Medium)

**Fixed in:** 0.23.0

The `VIGIL_SKIP_PACKAGE_OWNER` environment variable disabled package ownership lookups when set. An attacker could set this to suppress package-update context from alerts, degrading attribution quality.

**Remediation:** The env var check is gated behind `#[cfg(any(test, debug_assertions))]`. In production builds, package owner lookup is always performed.

---

### VIGIL-VULN-030 -- Bind mount evades fanotify monitoring (High)

**Fixed in:** 0.23.0

fanotify with `FAN_MARK_MOUNT` monitors a specific mount. An attacker who bind-mounted a new filesystem over a watched directory would cause fanotify to continue monitoring the old (now hidden) mount point, while the visible directory contents are unmonitored.

**Remediation:** The coordinator records the mount set from `/proc/self/mountinfo` at startup. Every 60-second housekeeping tick, mountinfo is re-read and compared. New mounts that overlap with configured watch paths trigger error-level logging: "new mount detected over watched path -- real-time monitoring may be compromised."

---

### VIGIL-VULN-031 -- FAN_Q_OVERFLOW silently ignored (High)

**Fixed in:** 0.23.0

When the kernel's fanotify event queue overflowed, the `FAN_Q_OVERFLOW` flag was set on events but never checked. Vigil Baseline silently missed an unknown number of filesystem events, creating a detection gap an attacker could exploit by generating high I/O to force overflow.

**Remediation:** Before the `event.fd >= 0` check, the event loop now checks for `FAN_Q_OVERFLOW` (mask `0x4000`). Overflow events are logged at error level, increment the new `kernel_queue_overflows` metric counter, and continue without attempting fd operations.

---

### VIGIL-VULN-032 -- Baseline HMAC only covers 5 of 13 fields (High)

**Fixed in:** 0.23.0

`compute_baseline_hmac()` only included path, hash, mode, owner_uid, and owner_gid in the canonical HMAC data. An attacker who modified the remaining 8 fields (size, inode, device, file_type, symlink_target, capabilities, xattrs, security_context) would not trigger an HMAC mismatch.

**Remediation:** Canonical HMAC data now includes all 13 security-relevant fields: path, hash, size, mode, owner_uid, owner_gid, inode, device, file_type, symlink_target (or empty), capabilities (or empty), xattrs_json, and security_context. This is a breaking change for stored HMACs -- on upgrade, the HMAC is automatically recomputed.

---

### VIGIL-VULN-033 -- Vigil Baseline binary not in self-monitoring watch group (Medium)

**Fixed in:** 0.23.0

The `vigil_self` watch group only covered config and HMAC key files. The Vigil Baseline binaries themselves (`/usr/bin/vigil`, `/usr/bin/vigild`) were not monitored. An attacker who replaced the binary would not trigger an alert.

**Remediation:** `/usr/bin/vigil` and `/usr/bin/vigild` are added to the default `vigil_self` watch group. On startup, the BLAKE3 hash of `/proc/self/exe` is computed, logged at info level, and stored in `config_state` key `binary_hash`.

---

### VIGIL-VULN-034 -- sd_notify socket spoofable (Medium)

**Fixed in:** 0.23.0

The systemd unit file did not set `NotifyAccess=main`. By default, systemd may accept `sd_notify` messages from any process in the service's cgroup. An attacker could send fake `READY=1` and `WATCHDOG=1` messages to keep systemd satisfied while the actual Vigil Baseline process is frozen or killed.

**Remediation:** Added `NotifyAccess=main` to restrict sd_notify to the main process PID only. Changed `ProtectHome=read-only` to `ProtectHome=true` and removed `/var/log/vigil` from `ReadWritePaths`.

---

### VIGIL-VULN-035 -- PID recycling race in process attribution (Low)

**Fixed in:** 0.23.0

Process attribution via `/proc/{pid}/exe` was performed inside the `if is_watched` block, after bloom filter checks and watch index lookups. The delay between fanotify delivering the event and the readlink increased the PID recycling window, allowing attribution to the wrong process.

**Remediation:** The `/proc/{pid}/exe` readlink is now performed immediately after reading the event metadata, before any channel send or bloom filter check, minimizing the recycling window. A comment documents that `FAN_REPORT_PIDFD` (Linux 6.2+) would eliminate this race entirely.

---

### VIGIL-VULN-036 -- Negative clock jump not detected (Medium)

**Fixed in:** 0.23.0

Clock anomaly detection only checked for forward jumps exceeding 1 hour. A negative clock jump (setting the clock backward) was not detected. An attacker could set the clock back to make recent audit entries appear to be in the future, then forward again to trigger rotation of those entries -- a clock manipulation replay attack.

**Remediation:** The coordinator now detects backward clock jumps exceeding 60 seconds and skips audit rotation. `last_rotation_timestamp` is not updated when any clock anomaly (forward or backward) is detected, preventing the attacker from resetting the reference point.

---

### VIGIL-VULN-037 -- Symlink target not canonically resolved (Medium)

**Fixed in:** 0.23.0

When the scanner encountered a symlink pointing to a regular file, it followed the link and captured the snapshot, but recorded the immediate `read_link()` target rather than the fully resolved canonical path. If the symlink chain was modified (e.g., an intermediate link redirected) without changing the final target's name, the change would not be detected.

**Remediation:** `FileSnapshot::from_fd()` now resolves symlink targets via `canonicalize()`, falling back to `read_link()` if canonicalization fails. The scanner logs the canonical resolution at debug level. Changes in the resolved canonical target between scans emit `SymlinkTargetChanged` alerts at the watch group's severity level.

---

### VIGIL-VULN-038 -- Audit DB identity not tracked (Critical)

**Fixed in:** 0.24.0

Only the baseline DB had inode/device identity checks. The coordinator opened `audit.db` by path on housekeeping ticks, while the alert dispatcher could continue writing to an older connection after replacement. An attacker could atomically replace `audit.db` and make operator-facing reads use the attacker-controlled file.

**Remediation:** Vigil Baseline now records `audit.db` inode/device identity at startup and verifies it on coordinator ticks alongside baseline identity. If either DB identity changes, Vigil Baseline enters degraded state and refuses housekeeping operations that rely on replaced storage.

---

### VIGIL-VULN-039 -- Scan scheduler TOCTOU via path-open (Critical)

**Fixed in:** 0.24.0

Scheduled and on-demand scans opened baseline DB by path each run. This bypassed startup trust and let an attacker swap in a crafted baseline DB for scan execution, then swap it back before coordinator checks.

**Remediation:** The scan scheduler now receives and reuses a startup baseline connection, eliminating path-based re-open in the scan execution path.

---

### VIGIL-VULN-040 -- WAL checkpoint TOCTOU via path-open (High)

**Fixed in:** 0.24.0

Periodic WAL checkpoints opened baseline/audit DB by path inside coordinator housekeeping. This created a window where checkpoint operations could run on attacker-replaced files.

**Remediation:** Coordinator WAL checkpoints now run on startup-opened baseline and audit connections, removing path-based trust refresh during runtime.

---

### VIGIL-VULN-041 -- HMAC key trust-refresh from disk (Critical)

**Fixed in:** 0.24.0

Multiple components loaded `/etc/vigil/hmac.key` at different times. A root attacker replacing the key could poison future HMAC calculations and verification flows after startup.

**Remediation:** Vigil Baseline now loads HMAC key material once at startup into zeroizing memory (`Zeroizing<Vec<u8>>`) and passes it to all runtime consumers (coordinator, baseline writer, alert dispatcher, control socket). Runtime code paths no longer re-read HMAC key from disk.

---

### VIGIL-VULN-042 -- Runtime JSON snapshots not atomically written (High)

**Fixed in:** 0.24.0

Runtime files in `/run/vigil` were written with direct overwrite semantics, allowing partial/truncated reads during write windows and race opportunities around replacement timing.

**Remediation:** Runtime snapshots (`metrics.json`, `state.json`, `health.json`) are now written using same-directory temp file plus atomic `rename(2)`.

---

### VIGIL-VULN-043 -- Bloom fast-reject semantic mismatch (High)

**Fixed in:** 0.24.0

The Bloom filter inserted watched path prefixes but checked full event paths directly. Correct behavior depended on accidental false positives rather than explicit prefix semantics.

**Remediation:** Bloom fast-reject now checks whether any prefix of the event path is present (`might_contain_prefix_of`), matching insertion semantics and preventing non-deterministic blind spots.

---

### VIGIL-VULN-044 -- package_update hardcoded false (High)

**Fixed in:** 0.24.0

Worker change results always set `package_update = false`, so auto-rebaseline logic for package-owned files was effectively dead code.

**Remediation:** Worker now sets `package_update = true` when a baseline entry is package-owned and a content modification is detected, re-enabling intended auto-rebaseline behavior.

---

### VIGIL-VULN-045 -- Nonce generation did not fail closed (Medium)

**Fixed in:** 0.24.0

Control socket nonce generation ignored `/dev/urandom` read failures and could produce predictable zero-filled output under error conditions.

**Remediation:** Nonce generation now returns `Result`, rejects failed entropy reads, rejects all-zero buffers, and closes authentication flow on nonce failure.

---

### VIGIL-VULN-046 -- Audit write failures dropped evidence (Medium)

**Fixed in:** 0.24.0

On audit DB write failures, entries were logged as errors but not retried, causing silent evidence gaps during repeated DB failure windows.

**Remediation:** Alert dispatcher now buffers failed audit writes in a bounded retry queue and replays buffered entries after successful DB reopen. Permanent overflow loss is tracked via `audit_entries_lost` metric.

---

### VIGIL-VULN-047 -- Self-path exclusion prefix collision (Medium)

**Fixed in:** 0.24.0

Self-path exclusion used plain string `starts_with`, so `/run/vigil` also matched attacker-controlled prefixes like `/run/vigil-backdoor`.

**Remediation:** Exclusion matching is now path-component aware by requiring exact self-path or self-path plus `/` prefix boundary.

---

### VIGIL-VULN-048 -- Config reload HMAC check used fresh DB path-open (Medium)

**Fixed in:** 0.24.0

Config reload verification opened baseline DB by path for `config_file_hmac` lookups, reintroducing TOCTOU in reload-time trust checks.

**Remediation:** Coordinator reload path now uses startup baseline connection and startup-loaded HMAC key for config integrity verification.

---

### VIGIL-VULN-049 -- sd_notify sent to unvalidated NOTIFY_SOCKET (Low)

**Fixed in:** 0.24.0

Vigil Baseline sent lifecycle/watchdog notifications without validating `NOTIFY_SOCKET`, allowing information leakage to attacker-controlled sockets via environment injection.

**Remediation:** Vigil Baseline now validates `NOTIFY_SOCKET` before `sd_notify`, accepting only `/run/systemd/` paths and abstract sockets.

---

### VIGIL-VULN-050 -- Scheduled scan severity downgrade (Medium)

**Fixed in:** 0.24.0

Scheduled scanner emitted `Severity::Medium` for all change results, ignoring configured watch-group severities and potentially downgrading critical findings.

**Remediation:** Scanner now resolves severity from watch-group index per path, with fallback only when no watch-group mapping exists.

---

### VIGIL-VULN-051 -- Baseline HMAC mismatch silently auto-recomputed (Critical)

**Fixed in:** 0.33.0

In `ensure_baseline_health()`, when the baseline HMAC did not match the stored value, the daemon logged a warning ("likely caused by a version upgrade") and silently recomputed and stored the new HMAC. An attacker who modified the baseline database directly would have their tampered baseline accepted as truth on the next daemon restart, completely nullifying the HMAC tamper-evidence guarantee.

**Remediation:** On HMAC mismatch, the daemon now transitions to `Degraded` state with reason `baseline_hmac_mismatch`, logs at `error` level, and sends a `Critical` urgency desktop notification. The daemon continues running (Fail Open) but the operator must investigate. A new config option `security.trust_baseline_on_hmac_mismatch` (default `false`) provides an explicit escape hatch for genuine version upgrade scenarios -- when set to `true`, the old recompute behavior is restored with a warning to disable the setting after upgrade.

---

### VIGIL-VULN-052 -- `baseline_refresh` config bypass and degraded-state gate (Critical)

**Fixed in:** 0.33.0

`handle_baseline_refresh()` called `crate::config::load_config(None)` which re-read the config file from disk. The coordinator's `handle_reload()` verified config HMAC before accepting changes, but `baseline_refresh` bypassed that verification entirely. An attacker who modified the config file (e.g., removing watch paths for directories they had compromised) and sent `baseline_refresh` via the control socket would get the baseline rebuilt using tampered config without any HMAC check. Additionally, there was no guard against `baseline_refresh` execution while the daemon was in `Degraded` state -- after a security event (e.g., baseline DB replacement), an attacker could immediately rebuild the baseline from compromised filesystem state.

**Remediation:** `handle_baseline_refresh()` now uses the daemon's live config via a new `config: Arc<ArcSwap<Config>>` field on `ControlHandler`, threaded from `DaemonRuntime::start()`. This config is already HMAC-verified through the coordinator's reload path. Additionally, `baseline_refresh` now checks daemon state and refuses execution with a clear error when `Degraded`, preventing an attacker from cementing compromised state as the new baseline.

---

### VIGIL-VULN-053 -- Control socket unbounded read_line (Critical)

**Fixed in:** 0.33.0

Both `read_request()` and `authenticate_and_read()` used `BufReader::read_line()` which reads until `\n` with no size limit. A local process with socket access could send a multi-gigabyte line without a newline and OOM the daemon, causing a denial of service that kills integrity monitoring.

**Remediation:** A `read_bounded_line()` helper function bounds all control socket reads to 64KB (`MAX_REQUEST_LINE_BYTES = 65_536`) using `Read::take()` on the stream reference. Requests exceeding the limit are rejected with a `VigilError::Control` error. Legitimate requests are small JSON objects (typically < 1KB), so 64KB provides generous headroom.

---

### VIGIL-VULN-054 -- HMAC key permission check warn-only (High)

**Fixed in:** 0.33.0

`check_hmac_key_permissions()` logged a warning when the HMAC key file was world-readable (mode & 0o077 != 0) but continued to load and use the key. Any non-root user could read the key, compute valid HMACs, forge audit entries, or authenticate to the control socket, silently breaking the HMAC integrity guarantee.

**Remediation:** `check_hmac_key_permissions()` now returns `Result<()>` and is propagated by `load_hmac_key()`. In release builds (`#[cfg(not(any(test, debug_assertions)))]`), the function returns `Err(VigilError::HmacVerification(...))` when the key file has group or other permissions, refusing to load the key. In test/debug builds, a warning is logged instead to allow tests to run as unprivileged users in temporary directories.

---

### VIGIL-VULN-055 -- `vigil update` privilege escalation via user-owned directory (High)

**Fixed in:** 0.33.0

When `vigil update` was run with `sudo`, `$HOME` may point to the unprivileged user's home directory. `discover_vigil_repo()` searched user-writable paths like `/home/user/src/vigil/` and `validate_vigil_repo()` only checked the `Cargo.toml` package name. A non-root user who placed a malicious Rust project with `name = "vigil"` at `~/src/vigil/` could get arbitrary code execution as root via `cargo build --release`.

**Remediation:** When running as root, `discover_vigil_repo()` now skips `$HOME`-relative candidates entirely unless `$HOME` is `/root`. As defense-in-depth, `validate_vigil_repo()` checks directory and `Cargo.toml` ownership in release builds when running as root, rejecting non-root-owned source directories with a clear error message.

---

### VIGIL-VULN-056 -- PID attribution did not detect exited processes (Medium)

**Fixed in:** 0.33.0

While VIGIL-VULN-035 moved the `/proc/{pid}/exe` readlink earlier to minimize the PID recycling window, a successful readlink was not distinguished from a failed one -- the process field was always populated with the PID regardless. When the readlink failed (process already exited), the attribution was silently set to `exe: None` without any log entry, making stale or recycled PID attribution indistinguishable from valid attribution in audit records.

**Remediation:** Process attribution now explicitly detects when the `/proc/{pid}/exe` readlink fails and logs at `debug` level: "process exited before attribution -- PID may be stale". The `ProcessAttribution` is still recorded (with `exe: None`) to preserve the PID for forensic context, but the log entry provides operational visibility into potential attribution staleness.

---

### VIGIL-VULN-057 -- Control socket HMAC auth bypass via empty response and timing leak (Critical)

**Fixed in:** 0.34.0

The control socket's challenge-response authentication compared the client-supplied HMAC to the expected value with `client_response.unwrap_or_default() != expected_hmac`. Two distinct flaws: (1) string `!=` is not constant-time and leaked timing information about the expected MAC under repeated probing; (2) `unwrap_or_default()` produced an empty string on EOF or read error, which would never match a real HMAC but could be exploited if the expected MAC computation path was ever skipped or returned an empty string due to an upstream bug, since two empty strings compare equal.

**Remediation:** Authentication now calls `crate::hmac::verify_hmac(key, nonce.as_bytes(), client_response)` which uses `subtle::ConstantTimeEq` for the comparison and rejects malformed (non-hex, wrong-length, or empty) input before any compare happens. Regression test `verify_hmac_rejects_empty_response` exercises the empty-response bypass path.

---

### VIGIL-VULN-058 -- fanotify event loop infinite loop on malformed `event_len` (Critical)

**Fixed in:** 0.34.0

The fanotify reader advanced its parsing offset by `event.event_len as usize` on every iteration. The kernel guarantees `event_len >= sizeof(struct fanotify_event_metadata)` for well-formed events, but the daemon performed no validation. A buggy or malicious kernel module -- or a kernel bug producing `event_len == 0` -- would cause the parser to loop forever on the same offset, pinning a CPU core and starving the rest of the daemon. Even worse, `event_len` larger than the remaining buffer could read past the buffer boundary on the next iteration's metadata cast.

**Remediation:** The parser now validates `event.event_len >= FAN_EVENT_METADATA_LEN && offset + event.event_len as usize <= n_usize` before advancing. On violation, it increments the new `fanotify_read_errors` counter, logs at `error` with the observed lengths, and breaks the resync loop to drop the malformed batch cleanly.

---

### VIGIL-VULN-059 -- Control socket accepted connections from any local UID (High)

**Fixed in:** 0.34.0

The control socket called `getsockopt(SO_PEERCRED)` to log the peer's credentials but did not enforce them. Any local process (any UID) that could open `/run/vigil/control.sock` could send authenticated commands as long as it possessed the HMAC key -- and on systems where the socket file's mode was misconfigured (e.g., `0666` or `0660` with a permissive group), arbitrary local users could probe authentication.

**Remediation:** `peer_credentials()` (renamed from `log_peer_credentials()`) now returns `Option<ucred>` and `handle_connection()` rejects the connection unconditionally when (a) SO_PEERCRED is unavailable, (b) the peer UID is non-zero, or (c) the peer UID is non-zero and does not match the daemon's effective UID. Daemon EUID is resolved through a new `current_euid()` helper that wraps `libc::geteuid()` with `#[allow(unsafe_code)]` for the FFI call.

---

### VIGIL-VULN-060 -- Control socket thread-exhaustion DoS (High)

**Fixed in:** 0.34.0

The control socket accept loop spawned a fresh thread per incoming connection with no upper bound. A local attacker who could connect to the socket -- or who could trigger many legitimate clients -- could exhaust the process's thread budget and FD table.

**Remediation:** Introduced `MAX_CONCURRENT_CONNECTIONS = 8` and an `AtomicUsize` semaphore. Connections beyond the cap receive a JSON rejection (`{"ok":false,"error":"too many concurrent connections"}`) and are closed immediately. The semaphore is decremented in the worker thread's drop path so it is released even if the handler panics. To support sharing a single `rusqlite::Connection` across worker threads, `ControlHandler.baseline_conn` was rewrapped as `Arc<Mutex<Connection>>` (parking_lot Mutex).

---

### VIGIL-VULN-061 -- `vigil update` did not roll back when daemon failed to start (High)

**Fixed in:** 0.34.0

The post-install rollback in `vigil update` triggered only when the daemon started successfully but failed its health check. If `systemctl start vigild` itself failed (e.g., the new binary aborted during startup, the unit file became invalid, or systemd refused to start the unit), the new binaries remained installed even though the daemon was not running -- the operator now had to manually restore from `.vigil.backup` and `.vigild.backup`.

**Remediation:** Rollback condition changed from `started && !healthy` to `backups_exist && (!daemon_started || !healthy)`. Any failure to bring the daemon into a healthy state -- whether the start command failed or the health probe failed -- triggers automatic restoration of the backed-up binaries.

---

### VIGIL-VULN-062 -- Package manager queries vulnerable to path-as-flag injection (High)

**Fixed in:** 0.34.0

Package manager queries (`pacman -Qo <path>`, `dpkg -S <path>`, `rpm -qf <path>`) passed the file path positionally without a `--` argument-terminator. A path beginning with `-` (e.g., a deliberately-named file `/-rf` or any path under a maliciously-created directory `/--option`) could be interpreted by the package manager as a flag. While the practical exploitability was limited (Vigil only invokes these queries on paths it observes, and the exec is via `Command::arg()` not a shell), it represented an injection class that should be closed at the source.

**Remediation:** All four call sites -- `query_pacman()`, `query_dpkg()`, `query_rpm()`, and `batch_query_dpkg()` -- now insert `.arg("--")` immediately before the path argument(s).

---

### VIGIL-VULN-063 -- Helper binaries vulnerable to PATH hijacking (High)

**Fixed in:** 0.34.0

The daemon invoked `systemctl`, `journalctl`, `notify-send`, and (in the update path) `vigil` by bare command name, relying on PATH to resolve them. A unit file or environment that placed an attacker-controlled binary earlier in PATH could substitute a malicious helper. Most affected paths run as root.

**Remediation:** Added per-binary resolver helpers (`systemctl_binary()`, `journalctl_binary()`, `notify_send_binary()`, `installed_vigil_path()`) that prefer `/usr/bin/<name>`, then `/bin/<name>`, and only fall back to the bare name (PATH resolution) when no canonical absolute path exists. `notify_send_binary()` caches the result in a `OnceLock<Option<PathBuf>>` to avoid repeated stat calls.

---

### VIGIL-VULN-064 -- fanotify queue overflow silently logged with no recovery scan (Medium)

**Fixed in:** 0.34.0

When the kernel's fanotify event queue overflowed (`FAN_Q_OVERFLOW` event), the daemon logged a warning but did nothing else. Real-time events had been dropped, the baseline could now drift, and operators had no signal that detection had been bypassed during the overflow window.

**Remediation:** On `FAN_Q_OVERFLOW`, the monitor now (1) sets daemon state to `Degraded { reason: "fanotify_queue_overflow" }`, (2) sends a `Full` `ScanRequest` via the new scan-trigger channel using `try_send` to avoid blocking the read loop, and (3) increments the new `fanotify_overflow_scans_triggered` Prometheus counter. The Full scan re-establishes ground truth across the watch set.

---

### VIGIL-VULN-065 -- fanotify mountinfo octal escapes not decoded (Medium)

**Fixed in:** 0.34.0

`/proc/self/mountinfo` uses octal escapes (`\040` for space, `\011` for tab, `\134` for backslash, etc.) for special characters in mount point fields. The daemon's mountinfo parser took the raw field verbatim, so any mount point containing whitespace or backslashes was misparsed and would not receive a fanotify mark -- producing a silent monitoring gap on those mounts.

**Remediation:** New `unescape_mountinfo(s: &str) -> String` decodes the standard octal escape set used by the kernel. Applied to both the mount-point field used for fanotify marks and any subsequent path matching. Covered by 5 unit tests (passthrough, single space, single tab, backslash, and a realistic mixed-escape mount path).

---

### VIGIL-VULN-066 -- fanotify mark/read failures silently ignored (Medium)

**Fixed in:** 0.34.0

When `fanotify_mark()` failed during initial setup or mount reload, the failure was logged but the daemon continued running with no real-time monitoring on those mounts. Similarly, `read()` failures on the fanotify FD were classified only by the success/failure of the read syscall -- fatal errno values (EBADF, EFAULT, EINVAL) were not distinguished from transient ones (EAGAIN, EWOULDBLOCK, EINTR), so a fatal error would either spin in a tight error loop or terminate the monitor without surfacing the cause.

**Remediation:** Mark failures now increment the new `fanotify_mark_failures` counter and, when state is available (reload path), transition the daemon to `Degraded { reason: "fanotify_mark_failure" }`. Read failures are now classified: EAGAIN/EWOULDBLOCK/EINTR continue the loop benignly; any other errno increments `fanotify_read_errors`, degrades state, logs at `error`, and stops the monitor cleanly so the rest of the daemon can shut down or be restarted by systemd.

---

### VIGIL-VULN-067 -- WAL HMAC verification bypass via zero-HMAC injection (Critical)

**Fixed in:** 0.35.0

`compute_entry_hmac()` returns `[0u8; 32]` when HMAC is disabled. The WAL scanner only verified HMAC when `any_hmac` (any non-zero byte in the 32-byte field). An attacker with write access to the WAL file could append a forged entry with all-zero HMAC and a valid CRC32; the reader holding a valid HMAC key would accept it without cryptographic verification. Additionally, reopening an HMAC-protected WAL with `hmac_key = None` was silently allowed, downgrading security.

**Reproduction:** Create WAL with HMAC, manually craft a binary entry with `[0; 32]` HMAC field, valid CRC32, append to file, call `iter_unconsumed` -- entry accepted.

**Remediation:** (1) `scan_entries` reads the 16-byte key fingerprint from the WAL header; when non-zero (`hmac_required`), entries with all-zero HMAC are rejected with `error` log. (2) `open_with_sync` returns error when header fingerprint is non-zero but caller passes `hmac_key = None`. (3) Magic number `50` replaced with documented `MIN_ENTRY_SIZE` constant. New metric `wal_entries_rejected_hmac`. Code path: `src/wal/mod.rs`.

---

### VIGIL-VULN-068 -- fanotify silently drops events for deleted files (High)

**Fixed in:** 0.35.0

When a file is unlinked between fanotify event production and `read_link("/proc/self/fd/N")`, the kernel returns the path with literal suffix ` (deleted)`. The Bloom filter prefix walk fails on the suffixed string, silently dropping the event. Deletion is the most security-relevant event class.

**Reproduction:** Unlink a watched file while fanotify events are pending; observe that no deletion event reaches the worker pipeline.

**Remediation:** New `strip_deleted_suffix(path) -> (PathBuf, bool)` helper strips the suffix. When detected, `event_type` is forced to `FsEventType::Delete` regardless of the fanotify mask. Both raw and stripped paths are logged at `info`. Code path: `src/monitor/fanotify.rs`.

---

### VIGIL-VULN-069 -- new-mount evasion: fanotify marks not applied to overlapping mounts (High)

**Fixed in:** 0.35.0

`FAN_MARK_MOUNT` does not follow into newly-mounted submounts. An attacker mounting over a watched path (e.g. `mount -t tmpfs none /etc/cron.d`) could write malicious files undetected in real-time. The coordinator detected new mounts but only logged; no fanotify marks were applied.

**Remediation:** New `MountMarkRequest` channel from coordinator to fanotify thread. When `check_mount_evasion` detects a new mount overlapping a watched path, it sends `MountMarkOp::Add`; disappeared mounts get `MountMarkOp::Remove`. Inotify backend has no equivalent API and logs at `error`. Code path: `src/coordinator.rs`, `src/monitor/fanotify.rs`, `src/monitor/mod.rs`.

---

### VIGIL-VULN-070 -- clock manipulation evades audit retention via slow drift (Medium)

**Fixed in:** 0.35.0

`detect_clock_anomaly` only caught forward jumps > 3600s between 60s ticks. An attacker advancing the wall clock by < 3600s per tick would never trip the gate, gradually erasing audit history through the retention cutoff.

**Remediation:** Each tick compares wall-clock delta against monotonic (`Instant`) delta; skew > 5s triggers Degraded state and skips rotation. Rotation also refused when `MAX(timestamp)` in audit_log exceeds current time (clock rollback past existing entries). Code path: `src/coordinator.rs`.

**Note (1.7.0):** The hardcoded 5-second threshold was replaced with the configurable `security.clock_skew_threshold_seconds` field (default 60s). Daemon degradation now requires skew above 2× the threshold (default 120s), eliminating false positives from normal NTP corrections and laptop wake. Transient skew auto-clears after `clock_skew_recovery_window` seconds.

---

### VIGIL-VULN-071 -- coordinator uses stale DB connections after Degraded transition (Medium)

**Fixed in:** 0.35.0

When `is_replaced` returned true for baseline/audit DB, the coordinator entered Degraded but continued holding open the `rusqlite::Connection` against the orphaned inode. Writes appeared to succeed but were invisible to anything opening the path freshly.

**Remediation:** Coordinator holds connections as `Option<Connection>`. On Degraded due to `*_db_replaced`, connections are dropped immediately (`= None`). All methods using these connections early-return with warning when `None`. No auto-reopen; operator restart required. Code path: `src/coordinator.rs`.

---

### VIGIL-VULN-072 -- user-space event loss not surfaced as Degraded state (Medium)

**Fixed in:** 0.35.0

The `send_timeout(.., 1s)` drop path in fanotify.rs surfaced event loss only via `tracing::warn!` and the `events_dropped` counter. No Degraded transition, violating the principle that VIGIL-VULN-064 fixed for kernel-side drops.

**Remediation:** Coordinator tick samples `events_dropped` and `kernel_queue_overflows` deltas. When either exceeds `monitor.event_loss_alert_threshold` (default 10), daemon enters Degraded. Recovery after 5 consecutive zero-delta ticks. New `DetectionSource::HealthDegraded` variant. Code path: `src/coordinator.rs`, `src/config/mod.rs`, `src/wal/mod.rs`.

---

### VIGIL-VULN-073 -- v0.34.0 follow-up bugs (Medium, composite)

**Fixed in:** 0.35.0

Six bugs introduced or left open by the v0.34.0 sweep: (1) thread-spawn failure leaks in-flight slot, potentially wedging the control socket after ≤8 failures; (2) `current_euid()` called per connection instead of once; (3) backup archive timestamp collides on sub-second runs; (4) `sudo systemctl` in update.rs missing absolute path; (5) `prune_old_backup_archives` trusts lexical sort without filtering non-conforming directory names; (6) `start_monitor` accepts `None` for `state`/`scan_trigger` without warning, silently disabling VIGIL-VULN-064/066 protections.

**Remediation:** All six sub-issues fixed. See CHANGELOG.md v0.35.0 for details. Code paths: `src/control.rs`, `src/commands/update.rs`, `src/monitor/mod.rs`.

---

### VIGIL-VULN-074 -- key material in non-zeroizing buffers; fd leak across exec (Medium, composite)

**Fixed in:** 0.35.0

(1) `load_hmac_key` returned `Vec<u8>` -- key material lived in non-zeroizing buffers between read and consumer. (2) `dup_to_file` used `libc::dup` which does not set `FD_CLOEXEC`; if any future code path spawns children, the fd would leak across exec.

**Remediation:** (1) `load_hmac_key` returns `Zeroizing<Vec<u8>>`; intermediate content buffer explicitly zeroized. (2) `dup_to_file` uses `libc::fcntl(F_DUPFD_CLOEXEC)`. (3) WAL `random_nonce()` uses `libc::getrandom` syscall instead of per-call `/dev/urandom` open. Code paths: `src/hmac.rs`, `src/worker.rs`, `src/wal/mod.rs`.

---

### VIGIL-VULN-075 -- User-space event channel drops created silent blind spots without compensating scan (Medium)

**Fixed in:** 1.7.3

The `SendTimeoutError::Timeout` path in `fanotify.rs` dropped events when the user-space channel was full for >1 second. The drop was logged and metered (`events_dropped`), but unlike the `FAN_Q_OVERFLOW` path, no compensating full scan was triggered. A wedged worker pool created a silent blind spot — exactly the failure mode the kernel-overflow handler exists to defeat.

**Remediation:** Sliding-window drop-rate detector in `src/coordinator/mod.rs` tracks `events_dropped` increments over a configurable window (`monitor.userspace_drop_threshold = 100`, `monitor.userspace_drop_window_secs = 60`). On threshold breach, a compensating full scan is triggered via the existing `scan_trigger` channel, the daemon enters `Degraded { UserspaceEventDrops }`, and an error is logged with recovery prose. Recovery to Healthy occurs after `2 * window_secs` of clean operation. New metric: `userspace_drop_scans_triggered`. Code paths: `src/coordinator/mod.rs`, `src/config/mod.rs`, `src/types/config_types.rs`, `src/metrics.rs`.

---

### VIGIL-VULN-076 -- Audit HMAC delimiter collision — pipe-separated input could be forged for paths containing the delimiter (High)

**Fixed in:** 1.7.3

`build_audit_hmac_data` constructed the HMAC input as `format!("{}|{}|{}|{}|{}|{}|{}", ...)`. Linux paths may contain `|`, producing collisions: `("/etc/foo|bar", "modified", ...)` collides with `("/etc/foo", "bar|modified", ...)`. This breaks the audit-chain tamper-evidence guarantee for paths containing the delimiter.

**Reproduction:** Compute `build_audit_hmac_data` with path `"/etc/foo|bar"` and change `"modified"`; then with path `"/etc/foo"` and change `"bar|modified"`. Both produce identical bytes.

**Remediation:** (1) New `encoding_version` column added to `audit_log` schema (migration via `ALTER TABLE ADD COLUMN`). Existing rows tagged as v1 (default 1). (2) New `build_audit_hmac_data_v2` uses deterministic CBOR encoding (RFC 8949 §4.2) via `ciborium`. Path is CBOR byte string (preserves non-UTF-8), optional fields use CBOR `null`, keys are lexicographically sorted. (3) `verify_chain_detail` reads `encoding_version` per row and dispatches to v1 or v2 builder. Mixed v1+v2 chains verify correctly. (4) All new entries written with `encoding_version = 2`. The v1 format is kept forever for backward compatibility. Code paths: `src/hmac.rs`, `src/util/canonical_cbor.rs`, `src/db/schema.rs`, `src/db/audit_ops.rs`, `src/alert/mod.rs`, `src/wal/audit_writer.rs`, `src/db/audit_retention.rs`.

---

### VIGIL-VULN-077 -- Directory-modification events silently dropped under FAN_MARK_MOUNT without FID-mode init (High)

**Fixed in:** 1.7.3

`fanotify_init` was called with `FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK` without FID-mode flags. On Linux 5.1+ kernels, directory-modification events (`FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_FROM`, `FAN_MOVED_TO`) under `FAN_MARK_MOUNT` deliver `fanotify_event_info_fid` records with `event.fd == FAN_NOFD (-1)`. The code's `if event.fd >= 0` branch silently skipped these events, meaning the threat-model claim that closed-set directory watches detect persistence via unknown filenames was not honored for FID-capable kernels.

**Remediation:** (1) Capability probe `detect_fanotify_tier()` in `src/monitor/mod.rs` tries init flags in order: `FidDfidName` (Linux 5.9+), `Fid` (Linux 5.1+), `LegacyFd`, `Inotify`. Each probe fd is closed immediately. (2) Tier surfaced in `vigil status` JSON (`metrics.fanotify_tier` gauge), `vigil doctor` output, and logged at `info` at startup. (3) Config override `monitor.fanotify_tier` (default `"auto"`) allows operators to pin a tier. (4) New metrics: `fanotify_tier` (gauge), `fanotify_open_by_handle_at_failures` (counter). Code paths: `src/monitor/mod.rs`, `src/monitor/fanotify.rs`, `src/config/mod.rs`, `src/metrics.rs`.
