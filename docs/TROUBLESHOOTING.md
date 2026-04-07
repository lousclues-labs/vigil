# Troubleshooting

Use this page when Vigil behavior is unclear or degraded.

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

# Or full baseline rebuild:
vigil init --force
```

Then install hooks from `hooks/` so this does not repeat.

---

## Database Locked or Corrupt

### Symptoms

- SQLite reports database locked
- integrity checks fail
- daemon refuses startup

### Recovery

```bash
sudo systemctl stop vigild.service
vigil doctor
cp /var/lib/vigil/baseline.db /var/lib/vigil/baseline.db.bak
vigil init --force
sudo systemctl start vigild.service
```

Rebuild only on known-good host state.

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

## systemd Service Fails to Stay Up

Run this checklist.

```bash
systemctl cat vigild.service
systemctl status vigild.service --no-pager
journalctl -u vigild.service -n 200 --no-pager
vigil config validate
vigil doctor
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
