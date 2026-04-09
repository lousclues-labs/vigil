# Resilience

Failure modes happen. Vigil is designed to fail open, fail loud, and keep forensic truth.

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
| fanotify init/mark fails (capability or kernel constraints) | Vigil logs warning and starts inotify fallback | run with needed capability or accept degraded mode |

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

Persistence safety:
- baseline DB remains on disk
- WAL checkpoint runs on clean shutdown path
- PID file is cleaned during graceful stop path

If stale PID file remains, restart unit and validate status.

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
   |- yes -> check channel-specific config (socket/log/notify)
   `- no -> verify watch scope and exclusions
```

---

## Operational Hardening Checklist

- keep systemd unit hardening options enabled
- monitor `vigil doctor` output after upgrades
- keep package hooks installed and tested
- back up `/var/lib/vigil/baseline.db` regularly
- retain alert logs for incident windows

---

## Version Upgrade Recovery

Version upgrades may change the baseline schema or HMAC field coverage.

| Failure | Behavior | Recovery |
|---------|----------|----------|
| baseline table empty after schema migration | daemon detects non-trivial DB file size (>4096 bytes), logs warning, auto-reinitializes baseline | automatic since v0.25.0 |
| stored HMAC mismatches due to field set change | daemon logs warning, recomputes and stores updated HMAC | automatic since v0.25.0 |
| older daemon version crash-loops on upgrade | `process::exit(1)` before sd_notify Ready | upgrade to v0.25.0+ or manually `vigil init --force` |

Startup diagnostics (baseline DB path, size, readability, HMAC status) are logged at `info` level before the health check runs. Use `RUST_LOG=debug` for maximum visibility.

---

## What Resilience Means Here

Vigil does not promise perfect detection under total system compromise.
Vigil promises explicit degradation signals and preserved audit truth under normal failure modes.

That is the point.

*Resilient systems are honest about blind spots.*
