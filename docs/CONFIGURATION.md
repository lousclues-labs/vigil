# Configuration

Vigil config is TOML, layered, and explicit.
No hidden defaults beyond what is documented here.

---

## Config File Locations

Vigil loads from lowest priority to highest priority, then validates the result.

| Priority | Location | Notes |
|----------|----------|-------|
| 1 (lowest) | `/etc/vigil/vigil.toml` | system-wide base config |
| 2 | `~/.config/vigil/vigil.toml` | user override |
| 3 | `$VIGIL_CONFIG` | environment override |
| 4 (highest) | `--config <PATH>` | explicit CLI override |

Precedence rule: higher priority wins.

```
+-------------------------------+
| --config /path/custom.toml    |
+-------------------------------+
| $VIGIL_CONFIG                 |
+-------------------------------+
| ~/.config/vigil/vigil.toml    |
+-------------------------------+
| /etc/vigil/vigil.toml         |
+-------------------------------+
```

If no file is found, Vigil uses built-in defaults including built-in watch groups.

---

## Full Annotated Example

```toml
[daemon]
pid_file = "/run/vigil/vigild.pid"        # PID file path
db_path = "/var/lib/vigil/baseline.db"    # SQLite database path
log_level = "info"                         # runtime log level
monitor_backend = "fanotify"              # fanotify or inotify

[scanner]
schedule = "0 3 * * *"                     # cron-like schedule metadata
mode = "incremental"                       # incremental or full
hash_algorithm = "blake3"                  # hashing algorithm string
max_file_size = 2147483648                  # bytes (2 GiB)

[alerts]
desktop_notifications = true                # notify-send desktop alerts
syslog = true                               # journald/syslog logging
log_file = "/var/log/vigil/alerts.json"    # JSON alert file
webhook_url = ""                            # reserved; empty by default
rate_limit = 10                             # max alerts/minute
cooldown_seconds = 300                      # per-path cooldown

[alerts.severity_filter]
dbus_min_severity = "medium"               # low/medium/high/critical
log_min_severity = "low"                   # low/medium/high/critical

[exclusions]
patterns = [
  "*.swp", "*.swx", "*~", "*.tmp", "*.log", "*.cache",
  ".git/*", "__pycache__/*"
]

system_exclusions = [
  "/proc/*", "/sys/*", "/dev/*", "/run/*", "/tmp/*"
]

[package_manager]
auto_rebaseline = true                      # intended behavior flag
backend = "auto"                           # auto/dpkg/rpm/pacman

[hooks]
signal_socket = ""                         # optional Unix socket path

[security]
hmac_signing = false                        # baseline/audit signing gate
hmac_key_path = "/etc/vigil/hmac.key"      # key path when enabled
verify_config_integrity = true              # integrity-related guardrail

[database]
wal_mode = true                             # SQLite WAL mode
audit_rotation_size = 104857600             # bytes (100 MiB)
audit_retention_days = 90                   # retention metadata

[watch.system_critical]
severity = "critical"
paths = [
  "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
  "/etc/sudoers", "/etc/sudoers.d/", "/etc/pam.d/",
  "/etc/ssh/sshd_config", "/etc/ld.so.preload",
  "/etc/ld.so.conf", "/etc/ld.so.conf.d/", "/boot/",
  "/usr/bin/", "/usr/sbin/", "/usr/lib/systemd/system/", "/lib/modules/"
]

[watch.persistence]
severity = "high"
paths = [
  "/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
  "/var/spool/cron/", "/etc/systemd/system/", "/etc/xdg/autostart/",
  "/etc/init.d/", "/etc/rc.local", "/etc/profile", "/etc/profile.d/",
  "/etc/bash.bashrc", "/etc/environment"
]

[watch.user_space]
severity = "high"
paths = [
  "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc",
  "~/.ssh/", "~/.gnupg/", "~/.config/autostart/", "~/.local/share/applications/"
]

[watch.network]
severity = "medium"
paths = [
  "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
  "/etc/NetworkManager/", "/etc/iptables/", "/etc/nftables.conf"
]
```

---

## Option Reference

### `[daemon]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pid_file` | string(path) | `/run/vigil/vigild.pid` | daemon PID file location |
| `db_path` | string(path) | `/var/lib/vigil/baseline.db` | SQLite database path |
| `log_level` | string | `info` | runtime log level |
| `monitor_backend` | enum | `fanotify` | preferred backend (`fanotify` or `inotify`) |

### `[scanner]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `schedule` | string | `0 3 * * *` | scan schedule metadata |
| `mode` | enum | `incremental` | default scan mode |
| `hash_algorithm` | string | `blake3` | hash algorithm label |
| `max_file_size` | integer | `2147483648` | max file size in bytes |

### `[alerts]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `desktop_notifications` | bool | `true` | enable notify-send desktop notifications |
| `syslog` | bool | `true` | emit alert summaries to journald/syslog |
| `log_file` | string(path) | `/var/log/vigil/alerts.json` | JSON log target |
| `webhook_url` | string | empty | reserved webhook field |
| `rate_limit` | integer | `10` | max alerts per minute |
| `cooldown_seconds` | integer | `300` | per-path suppression cooldown |

### `[alerts.severity_filter]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dbus_min_severity` | enum | `medium` | minimum severity for desktop notify |
| `log_min_severity` | enum | `low` | minimum severity for JSON logging |

### `[exclusions]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `patterns` | string[] | editor/temp defaults | glob patterns ignored by event filter |
| `system_exclusions` | string[] | `/proc/*`, `/sys/*`, `/dev/*`, `/run/*`, `/tmp/*` | system path exclusions |

### `[package_manager]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `auto_rebaseline` | bool | `true` | package update workflow intent flag |
| `backend` | enum | `auto` | ownership backend: `auto|dpkg|rpm|pacman` |

### `[hooks]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `signal_socket` | string(path) | empty | optional Unix socket for alert events |

### `[security]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `hmac_signing` | bool | `false` | require HMAC signing workflow |
| `hmac_key_path` | string(path) | `/etc/vigil/hmac.key` | HMAC key file |
| `verify_config_integrity` | bool | `true` | integrity validation toggle |

### `[database]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `wal_mode` | bool | `true` | use SQLite WAL journal mode |
| `audit_rotation_size` | integer | `104857600` | audit rotation size metadata |
| `audit_retention_days` | integer | `90` | retention metadata |

### `[watch.<group>]`

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `severity` | enum | yes | group severity (`low|medium|high|critical`) |
| `paths` | string[] | yes | path list (file or directory) |

---

## Watch Groups

A watch group is a named path set with one severity.

Built-in defaults:
- `system_critical`
- `persistence`
- `user_space`
- `network`

Example custom group:

```toml
[watch.custom]
severity = "high"
paths = [
  "/opt/custom-app/bin/",
  "/etc/custom-app/config.toml"
]
```

Guidelines:
- Use one group per risk domain.
- Keep paths explicit.
- Prefer directories for whole surfaces, files for strict critical points.

---

## Exclusion Patterns

Vigil uses glob matching for exclusions.

| Pattern | Meaning |
|---------|---------|
| `*.swp` | editor swap files |
| `*~` | backup files |
| `.git/*` | git metadata subtree |
| `/proc/*` | pseudo filesystem |

Rules:
- Pattern globs are validated at startup.
- Invalid glob -> config validation failure.
- System exclusions are prefix-filtered in monitor filter stage.

---

## Alert Configuration

Three control points shape notification behavior:

| Control | Effect |
|---------|--------|
| `cooldown_seconds` | suppresses repeated alerts for same path within window |
| `rate_limit` | caps total notifications/minute |
| maintenance window | suppresses notifications for package-managed paths |

Audit truth rule:
- Suppression never drops audit rows.
- All detected changes are written to `audit_log`.

---

## HMAC Signing

When `security.hmac_signing = true`:
- Vigil expects `security.hmac_key_path` to exist.
- Config validation fails if key file is missing.
- `vigil doctor` reports key presence/absence, permissions, and ownership.
- At runtime, Vigil warns if the key file is more permissive than mode `0600`.

For detailed guidance on key generation, storage, rotation, and threat
model, see [SECURITY.md — HMAC Key Lifecycle](SECURITY.md#hmac-key-lifecycle).

Key management baseline:

```bash
sudo install -d -m 700 /etc/vigil
sudo sh -c 'head -c 32 /dev/urandom > /etc/vigil/hmac.key'
sudo chmod 600 /etc/vigil/hmac.key
```

Do:
- keep key root-owned
- mode `0600`
- rotate with controlled re-baseline process

Do not:
- commit key material
- reuse keys across unrelated hosts

---

## Live Reload (SIGHUP)

Sending `SIGHUP` to the daemon (`systemctl reload vigild` or `kill -HUP <pid>`)
triggers a config reload. Not all fields can be applied without a restart.

### Fields that take effect immediately on SIGHUP

| Field | Effect |
|-------|--------|
| `exclusions.patterns` | event filter rebuilt |
| `exclusions.system_exclusions` | event filter rebuilt |
| `alerts.rate_limit` | rate limiter reset with new limit |
| `alerts.cooldown_seconds` | per-path cooldown updated |
| `scanner.max_file_size` | used on next event comparison |
| `database.audit_retention_days` | used on next rotation cycle |

### Fields that require a full daemon restart

| Field | Why |
|-------|-----|
| `daemon.pid_file` | bound at startup |
| `daemon.db_path` | database opened at startup |
| `daemon.monitor_backend` | fanotify/inotify backend chosen at startup |
| `watch.*` paths | monitor marks set at startup |

Changes to restart-only fields are logged as warnings on SIGHUP.

---

## Validation Rules

Vigil rejects config when:

| Rule | Why |
|------|-----|
| no watch groups defined | no monitoring surface |
| exclusion glob invalid | ambiguous filtering behavior |
| `max_file_size == 0` | impossible scanner policy |
| `rate_limit == 0` | impossible alert policy |
| HMAC enabled but key missing | false integrity assurance |

Vigil warns (but does not reject) when:
- watch path does not currently exist
- log directory metadata checks suggest access issues

---

*Configuration should tune scope, not redefine purpose.*
