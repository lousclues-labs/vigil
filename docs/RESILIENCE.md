# Resilience

Failure modes happen. VigilBaseline is designed to fail open, fail loud, and keep forensic truth.

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
| fanotify init/mark fails (capability or kernel constraints) | VigilBaseline logs warning and starts inotify fallback | run with needed capability or accept degraded mode |

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
| watchdog timeout during startup | daemon killed by SIGABRT before coordinator thread starts | eliminated since v0.27.1 — heartbeats sent throughout pre-flight and startup |
| watchdog timeout during coordinator tick | slow `rotate_audit_log()` or `write_snapshots()` under I/O pressure starves watchdog | eliminated since v0.27.1 — heartbeats interleaved between expensive tick sub-methods |
| crash with detections in WAL | AuditWriter `recover()` replays uncommitted entries on next startup | automatic since v0.28.0 — deduplication prevents double-insertion |

Persistence safety:
- Detection WAL provides crash-safe buffering — detections survive daemon crashes and are replayed on restart
- baseline DB remains on disk
- WAL checkpoint runs on clean shutdown path
- PID file is cleaned during graceful stop path

If stale PID file remains, restart unit and validate status.

---

### Detection WAL Failures (since v0.28.0)

| Failure | Behavior | Recovery |
|---------|----------|----------|
| WAL file full (`detection_wal_max_bytes` exceeded) | `append()` returns Err; worker falls back to `alert_tx` channel (pre-WAL path) | `detections_wal_full` metric increments; increase `detection_wal_max_bytes` or reduce WAL retention |
| WAL file corrupted (partial write, disk error) | `iter_unconsumed()` gap-scans byte-by-byte using CRC32 validation; corrupted entries are skipped, valid entries recovered. Gap scanning is bounded by `MAX_GAP_BYTES` (64KB) to prevent adversarial DoS — if the scanner exceeds this limit without finding a valid entry, it stops and returns entries recovered so far | automatic — no manual intervention needed |
| WAL entry HMAC verification failure | entry is skipped by AuditWriter/SinkRunner; `detections_wal_tampered` metric increments | investigate potential tampering; entry is logged at error level |
| Audit DB write failure during WAL consumption | AuditWriter increments `consecutive_failures`; reopens DB connection after 3 failures | automatic — if DB path is permanently broken, entries accumulate in WAL until recovery |
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

## Version Upgrade Recovery

Version upgrades may change the baseline schema or HMAC field coverage.

| Failure | Behavior | Recovery |
|---------|----------|----------|
| baseline table empty after schema migration | daemon detects non-trivial DB file size (>4096 bytes), logs warning, auto-reinitializes baseline | automatic since v0.25.0 |
| stored HMAC mismatches due to field set change | daemon logs warning, recomputes and stores updated HMAC | automatic since v0.25.0 |
| older daemon version crash-loops on upgrade | `process::exit(1)` before sd_notify Ready | upgrade to v0.25.0+ or manually `vigil init --force` |
| update binary corrupted by mid-write crash | `vigil` or `vigild` binary is truncated or incomplete | eliminated since v0.26.0 — `vigil update` uses atomic copy-then-rename |
| daemon not responding after update restart | `systemctl start` returns 0 but daemon crashes immediately | `vigil update` now verifies health via control socket (since v0.26.0) |
| watchdog kills daemon during startup baseline scan | `WatchdogSec=30` too aggressive for large file sets, no heartbeats during pre-flight | eliminated since v0.27.1 — `WatchdogSec=120`, `TimeoutStartSec=300`, heartbeats throughout startup |
| watchdog kills daemon during coordinator tick | slow DB operations under I/O pressure exceed watchdog interval | eliminated since v0.27.1 — heartbeats interleaved within `tick()` sub-methods |
| detection lost during daemon crash | detections written to alert channel lost if daemon exits before AlertDispatcher processes them | eliminated since v0.28.0 — Detection WAL ensures crash-safe persistence; AuditWriter replays uncommitted entries on restart |
| audit DB blocked delays alert delivery | single-threaded AlertDispatcher blocks on audit DB write, delaying sink dispatch | eliminated since v0.28.0 — WAL decouples audit persistence (AuditWriter) from alert dispatch (SinkRunner); they run as independent threads |
| compound environmental faults (fs races + DB flapping + clock jitter + config reload + concurrent load) | untested prior to v0.29.0 | validated since v0.29.0 — chaos engineering suite exercises 8 compound-fault scenarios with 13 machine-checked invariants across all subsystems |

Startup diagnostics (baseline DB path, size, readability, HMAC status) are logged at `info` level before the health check runs. Use `RUST_LOG=debug` for maximum visibility.

---

## What Resilience Means Here

VigilBaseline does not promise perfect detection under total system compromise.
VigilBaseline promises explicit degradation signals and preserved audit truth under normal failure modes.

That is the point.

*Resilient systems are honest about blind spots.*
