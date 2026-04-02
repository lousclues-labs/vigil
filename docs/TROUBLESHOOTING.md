# Troubleshooting

When Vigil is noisy or broken, use this page first.

---

## Fast Triage

Run these first:

```bash
vigil doctor
vigil status
vigil log stats
```

If daemon is systemd-managed:

```bash
systemctl status vigild.service --no-pager
journalctl -u vigild.service -n 100 --no-pager
```

---

## fanotify Not Available

### Symptoms

- `vigil doctor` reports fanotify unavailable
- logs mention fallback to inotify

### Cause

fanotify usually needs `CAP_SYS_ADMIN` (or root context).

### Fix

1. Run daemon with service capabilities (preferred via provided unit).
2. Verify service capabilities are not overridden.
3. Confirm backend in status output.

```bash
vigil doctor
vigil status
```

If you cannot grant capability, inotify fallback is expected.

---

## Too Many Alerts After Package Update

### Symptoms

- flood of modified-file alerts after `pacman -Syu` or `apt upgrade`

### Cause

Maintenance hooks missing or failed.

### Fix

1. Install package hooks.
2. Manually wrap update in maintenance window.
3. Refresh baseline after update.

```bash
vigil maintenance enter
# run package update
vigil baseline refresh
vigil maintenance exit
```

For pacman/apt automation, install files from `hooks/`.

---

## Database Locked or Corruption Errors

### Symptoms

- sqlite "database is locked"
- integrity check failures
- daemon start fails on DB checks

### Cause

- concurrent tooling against same DB
- abrupt shutdowns
- filesystem/storage issues

### Fix

1. Stop daemon.
2. Run doctor/integrity checks.
3. Backup DB.
4. Rebuild baseline if needed.

```bash
sudo systemctl stop vigild.service
vigil doctor
cp /var/lib/vigil/baseline.db /var/lib/vigil/baseline.db.bak
vigil init
sudo systemctl start vigild.service
```

Note: rebuild resets trusted baseline to current disk state. Do this only on known-good system state.

---

## Understanding `vigil doctor` Output

`vigil doctor` lines are grouped by checks.

| Marker | Meaning |
|--------|---------|
| `OK`/check mark | capability available and passed |
| warning marker | degraded mode, optional missing component |
| fail marker | broken prerequisite that needs action |

Typical warnings that are acceptable:
- not running as root in local CLI context
- notify-send unavailable on headless host
- signal socket unset (optional)

Typical failures that need action:
- config invalid
- DB integrity check failed
- HMAC key missing while signing enabled

---

## Alerts For Files You Expect To Change

### Symptoms

- recurring alerts for temp/cache/generated files

### Cause

Path is monitored but should be excluded.

### Fix

Add explicit exclusions:

```toml
[exclusions]
patterns = ["*.tmp", "*.cache", "*.log"]
```

Or scope watch groups tighter to high-value paths.

Then refresh baseline:

```bash
vigil config validate
vigil baseline refresh
```

---

## inotify Watch Limit Exhaustion

### Symptoms

- warnings about unable to watch directories
- partial monitoring under inotify fallback

### Cause

Kernel inotify watch limit too low for current tree size.

### Fix

Increase watch limits:

```bash
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl fs.inotify.max_user_instances=1024
```

Persist via `/etc/sysctl.d/` if needed.

Long-term fix: prefer fanotify mode where possible.

---

## Signal Socket Not Responding

### Symptoms

- downstream listener sees no events
- no hard errors in CLI/daemon

### Cause

Signal socket channel is best-effort and optional.
If listener is down or path permissions are wrong, Vigil drops this channel silently.

### Fix

1. Verify `hooks.signal_socket` value.
2. Confirm listener process is running.
3. Validate directory/socket permissions.
4. Use JSON log/journald as fallback truth source.

```bash
vigil config show
vigil log show --last 20
```

---

## systemd Service Failing

### Symptoms

- `vigild.service` repeatedly restarts or exits

### Cause

Common causes:
- binary path mismatch (`/usr/bin/vigild` missing)
- invalid config
- DB path permissions
- capability restrictions from overridden unit

### Fix Checklist

```bash
systemctl cat vigild.service
systemctl status vigild.service --no-pager
journalctl -u vigild.service -n 200 --no-pager
vigil config validate
vigil doctor
```

Verify these paths exist and are writable where required:
- `/var/lib/vigil`
- `/var/log/vigil`
- `/run/vigil`

If unit file changed:

```bash
sudo systemctl daemon-reload
sudo systemctl restart vigild.service
```

---

## Still Stuck?

Capture these and include in issue report:
- `vigil doctor` output
- `vigil status` output
- relevant `journalctl -u vigild` lines
- sanitized config excerpt
- exact command sequence to reproduce

---

*Troubleshooting should reduce uncertainty, not add guesswork.*
