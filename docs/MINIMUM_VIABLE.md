# Minimum Viable Trust

What the smallest Vigil deployment provides, what it does not, and how to step up.

---

## What "minimum viable" means

- Single `vigil` binary, no `vigild` daemon
- No systemd service or timer
- No HMAC key (audit chain unsigned)
- No package manager hooks
- Default configuration, no edits
- Operator runs commands by hand: `vigil init && vigil check`

This is Vigil at its lightest: a static comparator between what the filesystem
was and what it is now.

---

## What you get at the minimum

- **Initial baseline** of all default-watched paths (`/etc/passwd`, `/etc/shadow`,
  `/etc/sudoers`, `/boot/`, `/usr/bin/`, `/usr/sbin/`, cron directories, `~/.ssh/`,
  `~/.bashrc`, `/etc/hosts`, Vigil's own config and binaries)
- **On-demand integrity checking** via `vigil check` — compare current filesystem
  state against the baseline, report structural deviations
- **Closed-set directory protection** on `~/.ssh/` and cron directories — detect
  unknown filename additions or removals
- **Append-only audit log** — ordered and queryable, though unsigned without an HMAC key
- **Doctor diagnostics** on demand via `vigil doctor`
- **Forensic comparison** via `vigil inspect` against arbitrary paths and baselines
- **Status query** via `vigil status` — works without the daemon
- **Silence query** via `vigil why-silent` — understand why Vigil is quiet
- **Path explanation** via `vigil explain <path>` — understand watch coverage

---

## What you lose vs. full deployment

| Capability | Minimum | Full |
|---|---|---|
| Real-time monitoring | No (on-demand only) | Yes (fanotify/inotify) |
| Tamper-evident audit chain | No (unsigned) | Yes (HMAC-SHA256) |
| Automatic package-update acceptance | No (manual `--accept`) | Yes (hooks) |
| Daemon-driven self-checks | No | Yes (every 6h by default) |
| Continuous watch | No | Yes (`vigild` or `vigil watch`) |
| Alert delivery (D-Bus, journal, JSON log) | No | Yes |

---

## Threat model at minimum

**Defends against:**

- Opportunistic file modification discovered at the next manual `vigil check`
- Persistence files in default-watched directories
- Content and metadata drift on critical system files
- Unknown-filename additions to closed-set directories (`~/.ssh/`, cron dirs,
  `/etc/sudoers.d/`)

**Does not defend against:**

- Real-time evasion (attacker modifies and reverts between checks)
- Attacker who can rewrite the unsigned audit DB directly
- Attacker active in the window between manual checks
- Modifications to paths outside default coverage

---

## Step-up paths

Add these in order, each building on the previous:

1. **Generate HMAC key** → tamper-evident audit chain
   ```
   vigil setup hmac
   ```

2. **Install systemd units** → daemon with real-time monitoring
   ```
   sudo systemctl enable --now vigild.service
   sudo systemctl enable --now vigil-scan.timer
   ```

3. **Install package manager hooks** → silent acceptance of legitimate package updates
   ```
   sudo install -Dm644 hooks/pacman/vigil-pre.hook /etc/pacman.d/hooks/vigil-pre.hook
   sudo install -Dm644 hooks/pacman/vigil-post.hook /etc/pacman.d/hooks/vigil-post.hook
   ```

4. **Configure custom watch groups** → coverage matched to your threat model
   ```
   vigil config show    # review current config
   # Edit /etc/vigil/vigil.toml to add custom watch groups
   vigil config validate
   ```

5. **Enable daemon-driven doctor** → ambient self-health auditing (enabled by
   default at 6h intervals when the daemon is running)

---

## Verified examples

### Live USB forensics workstation

Mount a recovered disk, compare against a known-good baseline:

```
# Copy vigil binary and a baseline DB to the USB
# Mount the recovered disk at /mnt/recovered

vigil inspect /mnt/recovered/etc/sudoers \
  --baseline-db /media/usb/baselines/host-2026-04.db \
  --root /mnt/recovered

vigil inspect /mnt/recovered/etc/ \
  --baseline-db /media/usb/baselines/host-2026-04.db \
  --root /mnt/recovered \
  --recursive
```

No daemon, no config, no installation required. The `vigil` binary and a
baseline DB file are sufficient.

### Container with read-only root

```
# In a Dockerfile or at container startup:
vigil init
vigil check

# Periodically (via cron or health check):
vigil check --reason
vigil status --json
```

The read-only root means the baseline will not drift under normal operation.
Any deviation is a real event.

### Embedded device with no package manager

```
# After initial provisioning:
vigil init --force

# On a schedule (cron, watchdog timer, or manual):
vigil check --reason
vigil doctor
```

No package manager hooks needed. All changes are unexpected.

---

## Relationship to principles

- **VIII (stands alone):** minimum viable trust requires nothing outside the
  single binary and the filesystem it monitors.
- **IX (no configuration required):** default watch groups cover the critical
  paths. `vigil init && vigil check` works with zero configuration.
- **X (fail open, fail loud):** when the daemon is not running, `vigil status`
  and `vigil why-silent` report that fact clearly. Silence is never ambiguous.
