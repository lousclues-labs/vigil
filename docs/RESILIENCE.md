# Resilience

Failure modes happen. Vigil Baseline is designed to fail open, fail loud, and keep forensic truth.

---

## Resilience Model

Goals under failure:
1. keep monitoring if possible
2. keep writing audit truth
3. degrade loudly, not silently
4. preserve baseline state unless operator explicitly rebuilds

This is Principle X (Fail Open, Fail Loud) and Principle XIII (Audit Trail Never Lies).

---

## Failure Modes and Recovery

### fanotify Unavailable -> inotify Fallback

| Failure | Behavior | Recovery |
|---------|----------|----------|
| fanotify init/mark fails (capability or kernel constraints) | Vigil Baseline logs warning and starts inotify fallback | run with needed capability or accept degraded mode |

Known blind spots in fallback (logged by daemon):
- cannot watch some paths owned by other users
- constrained by `fs.inotify.max_user_watches`
- new subdirectories may require watch registration behavior considerations

Recovery actions:

```bash
vigil doctor
vigil status
# if needed, run daemon under service with required capabilities
```

---

### Database Corruption

| Failure | Behavior | Recovery |
|---------|----------|----------|
| SQLite integrity check fails on startup | daemon refuses normal operation and logs error | backup DB, reinitialize baseline on known-good host state |

Recovery flow:

```bash
sudo systemctl stop vigild.service
cp /var/lib/vigil/baseline.db /var/lib/vigil/baseline.db.bak
vigil doctor
vigil init
sudo systemctl start vigild.service
```

Tradeoff:
- rebuilding baseline restores function quickly
- but it trusts current disk state as new truth

---

### Signal Socket Dead

| Failure | Behavior | Recovery |
|---------|----------|----------|
| socket listener down/unreachable | signal channel drops events silently | restart consumer and verify socket permissions |

Important:
- alert channels continue: journald, JSON log, desktop notify
- audit logging remains unaffected

---

### File Deleted Between Event and Hash

| Failure | Behavior | Recovery |
|---------|----------|----------|
| transient race (event arrives, file gone by compare) | comparison returns transient error/deleted change path | monitor loop continues. Next events still process normally |

This is expected in real systems with high churn.

---

### Daemon Crash / Unexpected Exit

| Failure | Behavior | Recovery |
|---------|----------|----------|
| process exits unexpectedly | systemd `Restart=on-failure` restarts service (when managed by unit) | inspect journal, fix root cause |
| watchdog timeout during startup | daemon killed by SIGABRT before coordinator thread starts | eliminated since v0.27.1 -- heartbeats sent throughout pre-flight and startup |
| watchdog timeout during coordinator tick | slow `rotate_audit_log()` or `write_snapshots()` under I/O pressure starves watchdog | eliminated since v0.27.1 -- heartbeats interleaved between expensive tick sub-methods |
| crash with detections in WAL | AuditWriter `recover()` replays uncommitted entries on next startup | automatic since v0.28.0 -- deduplication prevents double-insertion |

Persistence safety:
- Detection WAL provides crash-safe buffering -- detections survive daemon crashes and are replayed on restart
- baseline DB remains on disk
- WAL checkpoint runs on clean shutdown path
- PID file is cleaned during graceful stop path

If stale PID file remains, restart unit and validate status.

---

### Detection WAL Failures (since v0.28.0)

| Failure | Behavior | Recovery |
|---------|----------|----------|
| WAL file full (`detection_wal_max_bytes` exceeded) | `append()` returns Err; worker falls back to `alert_tx` channel (pre-WAL path) | `detections_wal_full` metric increments; increase `detection_wal_max_bytes` or reduce WAL retention |
| WAL file corrupted (partial write, disk error) | `iter_unconsumed()` gap-scans byte-by-byte using CRC32 validation; corrupted entries are skipped, valid entries recovered. Gap scanning is bounded by `MAX_GAP_BYTES` (64KB) to prevent adversarial DoS -- if the scanner exceeds this limit without finding a valid entry, it stops and returns entries recovered so far | automatic -- no manual intervention needed |
| WAL entry HMAC verification failure | entry is skipped by AuditWriter/SinkRunner; `detections_wal_tampered` metric increments | investigate potential tampering; entry is logged at error level |
| Audit DB write failure during WAL consumption | AuditWriter increments `consecutive_failures`; reopens DB connection after 3 failures | automatic -- if DB path is permanently broken, entries accumulate in WAL until recovery |
| WAL instance nonce mismatch on recovery | AuditWriter `recover()` returns Err; prevents cross-instance replay | clear WAL file and restart daemon; indicates WAL file from a different daemon instance |
| WAL file replaced (inode/device changed) | coordinator `check_wal_identity()` detects TOCTOU; daemon transitions to Degraded state | investigate file replacement; restart daemon |
| WAL on tmpfs lost after reboot | non-persistent WAL (default) is on `/run/vigil` (tmpfs) and does not survive kernel panics or reboots | set `detection_wal_persistent = true` to store WAL alongside baseline DB on persistent storage |
| WAL sequence gap detected | AuditWriter logs gap at error level; `detections_wal_gaps` metric increments | indicates corrupted or missing entries; investigate WAL file integrity |

---

### Package Manager Hook Failure

| Failure | Behavior | Recovery |
|---------|----------|----------|
| pre/post hooks not installed or fail | package updates may create noisy alerts | re-accept drift or rebuild baseline |

Manual recovery:

```bash
# After package update with missing hooks:
vigil check --accept

# Or full baseline rebuild:
vigil init --force
```

Then install correct hooks from `hooks/`.

---

## Decision Tree

```
Did monitoring stop?
|- yes
|  Did DB integrity fail?
|  |- yes -> backup DB -> reinit baseline
|  `- no
|     fanotify unavailable?
|     |- yes -> run inotify now, restore fanotify capability later
|     `- no -> inspect systemd/journal and restart
`- no
   Is alert channel failing?
   |- yes
   |  Is WAL enabled?
   |  |- yes -> check detections_wal_audit_lag / detections_wal_sink_lag metrics
   |  |  WAL full?
   |  |  |- yes -> increase detection_wal_max_bytes or investigate consumption backlog
   |  |  `- no -> check audit DB health (reopen failures in journal)
   |  `- no -> check channel-specific config (socket/log/notify)
   `- no -> verify watch scope and exclusions
```

---

## Operational Hardening Checklist

- keep systemd unit hardening options enabled
- monitor `vigil doctor` output after upgrades
- keep package hooks installed and tested
- back up `/var/lib/vigil/baseline.db` regularly
- retain alert logs for incident windows
- set `detection_wal_persistent = true` on systems where detection loss across reboots is unacceptable
- monitor `detections_wal_audit_lag` and `detections_wal_sink_lag` gauges for consumption backlog
- monitor `detections_wal_full` counter for capacity issues
- run `CHAOS_TIER=B cargo test --test chaos` before deploying upgrades to verify resilience under compound stress

---

## Worker Self-Healing

Workers hold read-only baseline DB connections. If a connection becomes stale (e.g., baseline DB replaced during `vigil init --force`), the worker tracks consecutive `get_by_path()` failures. After 5 consecutive failures, the worker attempts to reopen the connection. On success, the LRU cache is cleared and the failure counter resets. On failure, the worker retries after 5 more failures.

| Failure | Behavior | Recovery |
|---------|----------|----------|
| stale read-only connection | `consecutive_db_errors` increments on each DB error | automatic -- reconnects after 5 consecutive failures |
| reconnect fails | error logged, counter left as-is | retries after 5 more failures |

Workers never panic on reconnect failure (Principle IV: Fail Open).

---

## Package Manager Circuit Breaker

During heavy package operations (e.g., system upgrades), the package manager database is locked. Every individual `query_package_owner()` call times out, starving workers. A circuit breaker suspends package queries after 3 consecutive timeouts for 60 seconds.

| Failure | Behavior | Recovery |
|---------|----------|----------|
| 3 consecutive package query timeouts | circuit breaker opens -- all queries return `None` for 60s | automatic -- circuit closes after 60s and resets timeout counter |
| successful query during/after open | timeout counter resets to 0 | immediate |

During circuit-open, package-managed file changes will generate alerts instead of being silently rebaselined. The circuit breaker only affects the 5-second `PKG_QUERY_TIMEOUT` path; `build_package_cache()` (used during baseline init) has its own 30-second timeout and is unaffected.

---

## Backpressure Recovery

When the event channel fills, the coordinator transitions to `Degraded` with reason `event_backpressure`. This degradation now auto-recovers when the backpressure flag clears (i.e., workers have drained the channel).

Security-related degradation (`baseline_db_replaced`, `audit_db_replaced`, `wal_file_replaced`, `baseline_hmac_mismatch`) requires daemon restart -- these are never auto-recovered because they indicate potential tampering.

---

## User-Space Event Drop Detection (VIGIL-VULN-075)

When the fanotify event channel saturates (worker pool wedged or slow), events are dropped and metered via `events_dropped`. The coordinator runs a sliding-window detector:

- **Window**: `monitor.userspace_drop_window_secs` (default 60s)
- **Threshold**: `monitor.userspace_drop_threshold` (default 100 drops)
- **On breach**: compensating full scan triggered, daemon enters `Degraded { UserspaceEventDrops }`, error logged with recovery prose
- **Recovery**: after `2 * window_secs` with no further drops above threshold, auto-recovers to Healthy

This mirrors the existing `FAN_Q_OVERFLOW` compensating scan pattern, closing the gap where user-space drops created silent blind spots.

---

## Baseline HMAC Mismatch Handling

When the daemon starts and detects a baseline HMAC mismatch:

| `trust_baseline_on_hmac_mismatch` | Behavior |
|----------------------------------|----------|
| `false` (default) | Daemon enters `Degraded` state with reason `baseline_hmac_mismatch`. Desktop notification at Critical urgency. Monitoring continues but operator must investigate. |
| `true` | HMAC is recomputed and stored. Warning logged. Use this after version upgrades that change baseline HMAC field coverage, then disable it. |

---

## Control Socket Size Limits

Control socket requests are bounded to 64KB per line. Requests exceeding this limit are rejected with an error. This prevents OOM attacks from local processes with socket access.

---

## Process Attribution Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| PID recycling between event generation and `/proc/PID/exe` readlink | Forensic attribution may be incorrect -- a malicious process's modification could be attributed to a legitimate process | Attribution is best-effort; audit entries with `exe: null` indicate the process exited before attribution |
| Kernel-level fix available | `FAN_REPORT_PIDFD` (Linux 6.2+) provides stable pidfd references that survive PID recycling | Future: migrate to pidfd-based attribution when minimum kernel version is raised |

Process attribution is informational, not authoritative. Vigil never makes security decisions based on process identity -- it always reports the file change regardless of attribution.

---

## Version Upgrade Recovery

Version upgrades may change the baseline schema or HMAC field coverage.

| Failure | Behavior | Recovery |
|---------|----------|----------|
| baseline table empty after schema migration | daemon detects non-trivial DB file size (>4096 bytes), logs warning, auto-reinitializes baseline | automatic since v0.25.0 |
| stored HMAC mismatches due to field set change | daemon enters Degraded state with reason `baseline_hmac_mismatch`; monitoring continues | set `security.trust_baseline_on_hmac_mismatch = true` in config, restart daemon, then disable (since v0.33.0) |
| older daemon version crash-loops on upgrade | `process::exit(1)` before sd_notify Ready | upgrade to v0.25.0+ or manually `vigil init --force` |
| update binary corrupted by mid-write crash | `vigil` or `vigild` binary is truncated or incomplete | eliminated since v0.26.0 -- `vigil update` uses atomic copy-then-rename |
| update build artifact corrupt | new binary crashes or exits non-zero on `--version` | eliminated since v0.32.3 -- `vigil update` smoke-tests build artifacts before touching installed binaries |
| update installed binary non-functional | new binary installed but fails `--version` smoke test | eliminated since v0.32.3 -- automatic rollback restores `.backup` copies of previous binaries |
| daemon not responding after update restart | `systemctl start` returns 0 but daemon crashes immediately | `vigil update` retries health check 3× with 2s intervals (since v0.32.3); rolls back to backup binaries if all checks fail (since v0.32.3); verifies health via control socket (since v0.26.0) |
| `sudo vigil update` cannot find repo | `HOME=/root` under sudo, user's source repo under `/home/<user>/` not searched | eliminated since v0.32.3 -- `discover_vigil_repo()` checks `SUDO_USER` to derive invoking user's home |
| watchdog kills daemon during startup baseline scan | `WatchdogSec=30` too aggressive for large file sets, no heartbeats during pre-flight | eliminated since v0.27.1 -- `WatchdogSec=120`, `TimeoutStartSec=300`, heartbeats throughout startup |
| watchdog kills daemon during coordinator tick | slow DB operations under I/O pressure exceed watchdog interval | eliminated since v0.27.1 -- heartbeats interleaved within `tick()` sub-methods |
| detection lost during daemon crash | detections written to alert channel lost if daemon exits before AlertDispatcher processes them | eliminated since v0.28.0 -- Detection WAL ensures crash-safe persistence; AuditWriter replays uncommitted entries on restart |
| audit DB blocked delays alert delivery | single-threaded AlertDispatcher blocks on audit DB write, delaying sink dispatch | eliminated since v0.28.0 -- WAL decouples audit persistence (AuditWriter) from alert dispatch (SinkRunner); they run as independent threads |
| compound environmental faults (fs races + DB flapping + clock jitter + config reload + concurrent load) | untested prior to v0.29.0 | validated since v0.29.0 -- chaos engineering suite exercises 8 compound-fault scenarios with 13 machine-checked invariants across all subsystems |

Startup diagnostics (baseline DB path, size, readability, HMAC status) are logged at `info` level before the health check runs. Use `RUST_LOG=debug` for maximum visibility.

---

## What Resilience Means Here

Vigil Baseline does not promise perfect detection under total system compromise.
Vigil Baseline promises explicit degradation signals and preserved audit truth under normal failure modes.

That is the point.

*Resilient systems are honest about blind spots.*

---

## Degraded Environments

For environments where a full daemon deployment is not possible (live USB,
containers, recovery shells, embedded systems), see
[Minimum Viable Trust](MINIMUM_VIABLE.md) for the smallest deployment that
still provides integrity checking.
