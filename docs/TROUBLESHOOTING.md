# Troubleshooting

Use this page when Vigil Baseline behavior is unclear or degraded.

---

## Fast Triage

Run these first.

```bash
vigil doctor
vigil status
vigil audit stats
```

If daemon is systemd-managed:

```bash
systemctl status vigild.service --no-pager
journalctl -u vigild.service -n 100 --no-pager
```

---

## The Update Appears Stuck

### Symptoms

- `sudo vigil update` has been running for a long time with no visible output

### Cause

As of v0.36.0, `vigil update` shows a step counter `[N/11]` and elapsed time
for every phase. If you see a spinner without progress, the system is waiting
for a specific operation to complete. Common long-running steps:

- **Step 2 (Build release binaries)**: cargo compilation, can take 2–3 minutes on initial build
- **Step 4/8 (Stop/Start daemon)**: systemctl waiting for daemon to flush WAL or start fully
- **Step 9 (Verify daemon health)**: retry loop with countdown shown as `[attempt 2/3, next probe in 4s]`

### Fix

1. Run with `--verbose` to see extra detail: `sudo vigil update --verbose`
2. If the daemon is unresponsive, check its journal: `journalctl -u vigild.service -n 50`
3. Force plain output for CI/logging: `sudo vigil update --no-progress`
4. Machine-readable mode for automation: `sudo vigil --format=json update`

---

## fanotify Not Available

### Symptoms

- `vigil doctor` reports fanotify unavailable
- daemon logs mention fallback to inotify

### Cause

fanotify usually needs elevated capability.

### Fix

1. Run daemon with required service capabilities.
2. Confirm service override did not remove capabilities.
3. Verify backend in status output.

```bash
vigil doctor
vigil status
```

If capabilities cannot be granted, inotify fallback is expected.

---

## Too Many Alerts After Package Update

### Symptoms

- large burst of file modification alerts after package upgrades

### Cause

Package hooks were missing or failed.

### Recovery

```bash
# After a package update that triggered many alerts:
vigil check --accept

# Or refresh the baseline to match current state:
vigil baseline refresh

# Or if you want a full baseline rebuild:
vigil init --force
```

Then install the hook files from `hooks/apt/` or `hooks/pacman/`.

---

## Package Manager Hook Failure

If hooks fail and package operations already ran, use this recovery path.

```bash
# After package update with missing hooks:
vigil check --accept

# Or refresh the baseline:
vigil baseline refresh

# Or full baseline rebuild:
vigil init --force
```

Then install hooks from `hooks/` so this does not repeat.

You can verify the current maintenance window state with:

```bash
vigil maintenance status
```

---

## Database Locked or Corrupt

### Symptoms

- SQLite reports database locked
- integrity checks fail
- daemon refuses startup
- `vigil check` reports `database disk image is malformed`

### Recovery

```bash
sudo systemctl stop vigild.service
vigil doctor
sudo cp /var/lib/vigil/baseline.db /var/lib/vigil/baseline.db.bak
# Remove stale WAL/SHM sidecars left from a previous failed swap.
sudo rm -f /var/lib/vigil/baseline.db-wal /var/lib/vigil/baseline.db-shm
sudo vigil init --force
sudo systemctl start vigild.service
```

Rebuild only on known-good host state. As of v1.8.2 the baseline
refresh path checkpoints, closes, and removes the live WAL/SHM
sidecars before the atomic rename so this failure mode no longer
occurs after a successful refresh.

---

## Repeated Alerts for Expected Temporary Files

### Cause

A noisy path is in watch scope and not excluded.

### Fix

Add exclusions and validate.

```toml
[exclusions]
patterns = ["*.tmp", "*.cache", "*.log"]
```

Then run:

```bash
vigil config validate
vigil check --accept
```

---

## inotify Watch Limit Exhaustion

### Symptoms

- warnings about missing recursive watches
- degraded visibility with inotify fallback

### Fix

```bash
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl fs.inotify.max_user_instances=1024
```

Persist values in `/etc/sysctl.d/` for reboot durability.

---

## Signal Socket Not Receiving Events

### Cause

Socket channel is optional and best effort.

### Fix

1. Check `hooks.signal_socket` path.
2. Confirm listener process is running.
3. Check directory and socket permissions.
4. Use audit and JSON log as source of truth.

```bash
vigil config show
vigil audit show -n 20
```

---

## Daemon Crash Loop After Version Upgrade

### Symptoms

- `vigild.service` exits immediately after `systemctl start`
- journal shows `Failed with result 'exit-code'`
- no useful error message visible in `journalctl`

### Cause

A version upgrade may change the baseline schema or HMAC field coverage. If the baseline DB was previously initialized but tables are now empty after migration, or if the stored HMAC no longer matches, older versions treated this as tampering and called `process::exit(1)` before the error message was flushed to journald.

### Fix

1. Run the daemon manually with debug logging to see the actual error:

```bash
RUST_LOG=debug sudo /usr/local/bin/vigild
```

2. If the error mentions "baseline was previously initialized but is now empty", upgrade to v0.25.0+ which handles this automatically.

3. If you cannot upgrade, manually reinitialize:

```bash
sudo systemctl stop vigild.service
vigil init --force
sudo systemctl start vigild.service
```

4. If the error mentions HMAC verification failure, the HMAC field set changed between versions. Upgrade to v0.25.0+ (auto-recomputes) or delete the stored HMAC:

```bash
sqlite3 /var/lib/vigil/baseline.db "DELETE FROM config_state WHERE key = 'baseline_hmac';"
sudo systemctl restart vigild.service
```

---

## systemd Service Fails to Stay Up

Run this checklist.

```bash
systemctl cat vigild.service
systemctl status vigild.service --no-pager
journalctl -u vigild.service -n 200 --no-pager
vigil config validate
vigil doctor
```

Look for watchdog timeout messages:

```
vigild.service: Watchdog timeout (limit 30s)!
Main process exited, code=killed, status=6/ABRT
```

If you see watchdog timeouts, ensure you are running v0.27.1+ and using the updated systemd unit with `WatchdogSec=120` and `TimeoutStartSec=300`:

```bash
sudo cp systemd/vigild.service /etc/systemd/system/vigild.service
sudo systemctl daemon-reload
sudo systemctl restart vigild.service
```

Confirm these paths exist and have correct permissions:
- `/var/lib/vigil`
- `/var/log/vigil`
- `/run/vigil`

Apply updated units with:

```bash
sudo systemctl daemon-reload
sudo systemctl restart vigild.service
```

---

## Still Stuck

Include these artifacts in your issue:
- `vigil doctor` output
- `vigil status` output
- recent `journalctl -u vigild` lines
- sanitized config excerpt
- exact command sequence

---

## Quick Diagnostic Commands

| Question | Command |
|---|---|
| Is Vigil working? | `vigil why-silent` |
| What's the current state? | `vigil status` |
| Why is this path watched? | `vigil explain /path/to/file` |
| Can alerts reach me? | `vigil test alert` |
| Is the system healthy? | `vigil doctor` |
| What changed recently? | `vigil audit show -n 20` |

### After install, after reboot, after OS upgrade

```bash
vigil doctor
vigil test alert
vigil why-silent
```

### Understanding watch coverage

```bash
vigil explain /etc/sudoers
vigil explain /home/user/.ssh/authorized_keys
```

Shows which watch group covers a path, the matching rule, baseline entry,
and audit history. If the path is not watched, shows nearby watched paths.
