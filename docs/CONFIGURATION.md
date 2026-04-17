# Configuration

Vigil Baseline configuration is TOML. Fields map directly to `src/config/mod.rs`.

---

## Load Order

Vigil Baseline loads from lowest priority to highest priority.

| Priority | Source |
|----------|--------|
| 1 | `/etc/vigil/vigil.toml` |
| 2 | `~/.config/vigil/vigil.toml` |
| 3 | `$VIGIL_CONFIG` |
| 4 | `--config <PATH>` |

If no file exists, Vigil Baseline uses built-in defaults.

---

## Full Annotated Example

```toml
config_version = 2

[daemon]
pid_file = "/run/vigil/vigild.pid"
db_path = "/var/lib/vigil/baseline.db"
log_level = "info"              # error, warn, info, debug, trace
monitor_backend = "fanotify"    # fanotify, inotify
worker_threads = 2               # 1..16
log_format = "text"             # text, json
runtime_dir = "/run/vigil"
control_socket = "/run/vigil/control.sock"
debounce_ms = 100
event_channel_capacity = 4096    # event channel buffer size
detection_wal = true              # enable Detection WAL for crash-safe detection output
detection_wal_max_bytes = 67108864  # 64 MiB max WAL size (valid: 1 MiB - 1 GiB)
detection_wal_persistent = false  # false = tmpfs (/run/vigil), true = alongside baseline DB
detection_wal_sync = "every"      # every, batched, none — fdatasync after WAL append

[scanner]
schedule = "0 3 * * *"
mode = "incremental"            # incremental, full
hash_algorithm = "blake3"
max_file_size = 2147483648
mmap_threshold = 1048576
scheduled_mode = "full"          # incremental, full (full protects against mtime-reset attacks)
parallel = false
# drift_velocity_threshold = 50  # average changes per tick (60s) before high-drift warning

[alerts]
desktop_notifications = true
syslog = true
log_file = "/var/log/vigil/alerts.json"
webhook_url = ""
rate_limit = 10
cooldown_seconds = 300
notification_rate_limit = 5
notification_rate_window_secs = 10
max_alerts_per_minute = 10000

[alerts.severity_filter]
dbus_min_severity = "medium"    # low, medium, high, critical
log_min_severity = "low"

[alerts.remote_syslog]
enabled = false
server = ""
port = 514
protocol = "udp"                # tcp, udp
facility = "authpriv"           # auth, authpriv, daemon, local0..local7

[exclusions]
patterns = [
  "*.swp", "*.swx", "*~", "*.tmp", "*.log", "*.cache",
  ".git/*", "__pycache__/*"
]
system_exclusions = ["/proc/*", "/sys/*", "/dev/*", "/run/user/*", "/run/lock/*", "/run/utmp", "/tmp/*"]

[package_manager]
auto_rebaseline = true
backend = "auto"                # auto, dpkg, rpm, pacman

[hooks]
signal_socket = ""

[security]
hmac_signing = false
hmac_key_path = "/etc/vigil/hmac.key"
verify_config_integrity = true
control_socket_auth = true        # challenge-response auth on control socket
# trust_baseline_on_hmac_mismatch = false  # set true temporarily after version upgrades

[database]
wal_mode = true
audit_rotation_size = 104857600
audit_retention_days = 90
sync_mode = "normal"            # off, normal, full, extra
busy_timeout_ms = 5000

[watch.system_critical]
severity = "critical"
paths = [
  "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/boot/", "/usr/bin/", "/usr/sbin/"
]
```

---

## Option Reference

### Top-level

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `config_version` | integer | `2` | schema version for config migration logic |

### `[daemon]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `pid_file` | path | `/run/vigil/vigild.pid` | daemon pid file |
| `db_path` | path | `/var/lib/vigil/baseline.db` | baseline DB path |
| `log_level` | enum | `info` | `error`, `warn`, `info`, `debug`, `trace` |
| `monitor_backend` | enum | `fanotify` | preferred backend |
| `worker_threads` | integer | `2` | valid range is 1 to 16 |
| `log_format` | enum | `text` | `text` or `json` |
| `runtime_dir` | path | `/run/vigil` | runtime snapshots and daemon files |
| `control_socket` | path | `/run/vigil/control.sock` | daemon control socket |
| `debounce_ms` | integer | `100` | per-path debounce window |
| `event_channel_capacity` | integer | `4096` | event channel buffer size; higher values reduce event drops under I/O load |
| `detection_wal` | bool | `true` | enable Detection WAL for crash-safe detection output. When false, detections flow through the legacy alert channel. |
| `detection_wal_max_bytes` | integer | `67108864` | maximum WAL file size in bytes (64 MiB). Valid range: 1,048,576 (1 MiB) to 1,073,741,824 (1 GiB). |
| `detection_wal_persistent` | bool | `false` | when true, WAL is stored alongside baseline DB (survives reboots); when false, WAL is in `runtime_dir` (tmpfs). |
| `detection_wal_sync` | enum | `every` | `every` (fdatasync after each append), `batched`, `none`. Use `every` for maximum crash safety. |

### `[scanner]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `schedule` | string | `0 3 * * *` | cron expression |
| `mode` | enum | `incremental` | CLI default mode |
| `hash_algorithm` | enum | `blake3` | currently only `blake3` |
| `max_file_size` | integer | `2147483648` | bytes |
| `mmap_threshold` | integer | `1048576` | bytes |
| `scheduled_mode` | enum | `full` | mode used by scheduler. `full` rehashes every file regardless of mtime for protection against mtime-reset attacks |
| `parallel` | bool | `false` | enables optional parallel scanning paths |

### `[alerts]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `desktop_notifications` | bool | `true` | enables desktop notification sink (via `notify-send` with `--app-name=Vigil Baseline` and severity-based urgency) |
| `syslog` | bool | `true` | enables journald/syslog sink |
| `log_file` | path | `/var/log/vigil/alerts.json` | JSON alert sink path |
| `webhook_url` | string | empty | reserved field |
| `rate_limit` | integer | `10` | global alert rate gate |
| `cooldown_seconds` | integer | `300` | per-path cooldown |
| `notification_rate_limit` | integer | `5` | desktop sink limit |
| `notification_rate_window_secs` | integer | `10` | desktop sink window |
| `max_alerts_per_minute` | integer | `10000` | hard ceiling in alert dispatcher |

### `[alerts.severity_filter]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `dbus_min_severity` | enum | `medium` | desktop minimum severity. Alerts below this level are not shown. Severity maps to `notify-send` urgency: critical/high = `critical`, medium = `normal`, low = `low`. |
| `log_min_severity` | enum | `low` | JSON log minimum severity |

### `[alerts.remote_syslog]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `enabled` | bool | `false` | enable remote syslog sink |
| `server` | string | empty | hostname or IP |
| `port` | integer | `514` | remote syslog port |
| `protocol` | enum | `udp` | `udp` or `tcp` |
| `facility` | enum | `authpriv` | `auth`, `authpriv`, `daemon`, `local0..local7` |

### `[exclusions]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `patterns` | string[] | built-in list | globset pattern list |
| `system_exclusions` | string[] | `/proc/*`, `/sys/*`, `/dev/*`, `/run/user/*`, `/run/lock/*`, `/run/utmp`, `/tmp/*` | system path exclusions. `/run/*` is intentionally not blanket-excluded to prevent attacker persistence via `/run/systemd/transient/`. |

### `[package_manager]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `auto_rebaseline` | bool | `true` | update baseline after package updates |
| `backend` | enum | `auto` | `auto`, `dpkg`, `rpm`, `pacman` |

### `[hooks]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `signal_socket` | path string | empty | optional local alert socket path |

### `[security]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `hmac_signing` | bool | `false` | enables HMAC audit signing, baseline HMAC verification, and config HMAC verification |
| `hmac_key_path` | path | `/etc/vigil/hmac.key` | HMAC key file |
| `verify_config_integrity` | bool | `true` | integrity check toggle |
| `control_socket_auth` | bool | `true` | enables challenge-response authentication on the control socket (requires `hmac_signing = true`) |

### `[database]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `wal_mode` | bool | `true` | enables SQLite WAL |
| `audit_rotation_size` | integer | `104857600` | bytes |
| `audit_retention_days` | integer | `90` | rotation retention window |
| `sync_mode` | enum | `normal` | `off`, `normal`, `full`, `extra` |
| `busy_timeout_ms` | integer | `5000` | SQLite busy timeout |

### `[watch.<group>]`

| Option | Type | Required | Notes |
|--------|------|----------|-------|
| `severity` | enum | yes | `low`, `medium`, `high`, `critical` |
| `paths` | string[] | yes | watched file or directory paths |

---

## Validation Rules

Vigil Baseline rejects config when these rules fail.

- no watch groups are defined
- exclusion pattern is not a valid glob
- `scanner.max_file_size` is `0`
- `alerts.rate_limit` is `0`
- `daemon.worker_threads` is outside `1..16`
- `scanner.schedule` is not a valid cron expression
- `security.hmac_signing = true` and key file is missing

Deep validation warns when directories or watch paths do not exist yet.

---

## Reload Behavior (SIGHUP)

`SIGHUP` reload swaps `Config` in memory and logs field differences.
It does not restart all initialized components.

### Changes that currently apply without daemon restart

| Field | Why |
|-------|-----|
| `scanner.schedule` | scheduler reads config each loop |
| `scanner.scheduled_mode` | scheduler reads config each run |
| `scanner.max_file_size` | worker snapshot options read config per event |
| `scanner.mmap_threshold` | worker snapshot options read config per event |
| `database.audit_retention_days` | coordinator uses current value each housekeeping tick |

### Changes that require restart to be fully applied

| Field group | Why |
|-------------|-----|
| `daemon.control_socket` | socket bind happens at startup |
| `daemon.runtime_dir` | runtime paths are initialized at startup paths and tooling expects stable location |
| `daemon.monitor_backend` | backend thread starts at startup |
| `daemon.worker_threads` | worker pool size is fixed at startup |
| `daemon.debounce_ms` | worker event filter is built at startup |
| `alerts.*` including `notification_rate_limit`, `notification_rate_window_secs`, `max_alerts_per_minute` | alert dispatcher and sinks are built at startup |
| `exclusions.*` | worker exclusion filter is built at startup |
| `watch.*` path coverage | monitor watch registration happens at startup |
| `database.sync_mode`, `database.busy_timeout_ms`, `database.wal_mode` | DB connection pragmas are applied at open time |

---

Configuration should narrow scope and tune behavior. It should not hide runtime truth.
