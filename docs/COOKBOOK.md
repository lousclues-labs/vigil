# Vigil Baseline -- Cookbook

Answers to operator-shaped questions.

---

## I got an alert. What do I do?

1. Read the alert. It tells you the path, what changed, and the severity.

2. Investigate:

   ```bash
   vigil why /path/from/alert
   ```

   This shows the baseline entry, the current state, and the audit
   history for that path. Facts only.

3. If the change is expected (you edited the file, a package updated it):

   ```bash
   vigil check --accept --path '/path/from/alert'
   ```

4. If the change is unexpected: investigate outside vigil. Check
   `journalctl`, file timestamps, process logs. Vigil tells you
   *what* changed. Figuring out *who* and *why* is your job.

---

## Package updates

Before a package update, the pacman/apt hooks in `hooks/` automatically
handle baseline refresh. If hooks are installed, you don't need to do
anything.

If hooks are not installed, or you want to manually handle it:

```bash
# Before the update
sudo vigil maintenance enter

# Run your update
sudo pacman -Syu

# After the update
sudo vigil check --accept
sudo vigil maintenance exit
```

---

## vigil status says Degraded. How do I investigate?

```bash
vigil doctor --verbose
```

Doctor shows every diagnostic check with its status. Failed checks
include a recovery command you can run directly.

Common causes:

- **baseline_db_replaced**: The baseline file was replaced outside of
  vigil's control. If you did this intentionally, run `vigil recover`.
- **clock_skew_detected**: Your system clock jumped significantly.
  This usually self-clears after `clock_skew_recovery_window` seconds
  (default 5 minutes). If it persists, check NTP.
- **event_loss_detected**: The kernel dropped fanotify events (system
  was under heavy load). Vigil triggers a compensating full scan
  automatically.

---

## I want to monitor a custom directory

Edit `/etc/vigil/vigil.toml` and add a watch group:

```toml
[watch.my_app]
severity = "high"
paths = [
    "/opt/myapp/bin/",
    "/opt/myapp/config/",
]
```

Then reload:

```bash
sudo systemctl reload vigild
```

Or restart:

```bash
sudo vigil baseline refresh
```

---

## I want to silence one specific recurring alert

You don't. That's by design.

If a path keeps changing, that's the filesystem telling you something.
Fix the cause:

- If it's a log file, remove it from the watch paths.
- If it's a config that changes on boot, exclude it.
- If it's a package updating, install the hooks.

Vigil's silence is the signal. If it's noisy, the noise is real.
See [Principle II](PRINCIPLES.md).

---

## How do I rotate the HMAC key?

1. Generate a new key:

   ```bash
   sudo vigil setup hmac --force
   ```

2. Refresh the baseline (re-signs with new key):

   ```bash
   sudo vigil baseline refresh
   ```

3. Back up the new key file:

   ```bash
   sudo cp /etc/vigil/hmac.key /root/vigil-hmac-backup.key
   ```

4. Verify the chain:

   ```bash
   vigil audit verify
   ```

---

## How do I integrate vigil with my monitoring stack?

Use the alert socket or webhook:

```toml
[alerts]
webhook_url = "https://your-siem.example.com/api/events"
webhook_bearer_token = "your-token-here"
```

Or read from the JSON alert log:

```bash
tail -f /var/log/vigil/alerts.json | jq .
```

Or use `vigil status --format json` for structured polling.

---

## How do I forensically investigate a detection?

Use `vigil inspect` to compare files against a baseline on a different
machine. No daemon required:

```bash
vigil inspect /etc/shadow --baseline-db /mnt/evidence/baseline.db
```

Or create a portable attestation for offline verification:

```bash
vigil attest create --output /tmp/system-state.vatt
```

Transfer the `.vatt` file and verify it elsewhere:

```bash
vigil attest verify /tmp/system-state.vatt
```

See [Forensics](FORENSICS.md) for full workflows.
