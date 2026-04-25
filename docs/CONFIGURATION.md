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
detection_wal_sync = "every"      # every, batched, none -- fdatasync after WAL append

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
webhook_bearer_token = ""
storm_threshold = 50
storm_window_secs = 60
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
# auto_recover_inode_changes = false        # accept inode changes if content verification passes

[update]
backup_retention_count = 5                 # binary backup archives to keep

[monitor]
event_loss_alert_threshold = 10   # user-space or kernel event drops per tick before Degraded

[maintenance]
max_window_seconds = 1800         # safety timeout for maintenance windows (30 min)

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
| `drift_velocity_threshold` | integer (optional) | `50` | average baseline changes per coordinator tick (60s) before a high-drift-velocity warning. Set to `null` or omit to use the default. |

### `[alerts]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `desktop_notifications` | bool | `true` | enables desktop notification sink (via `notify-send` with `--app-name=Vigil Baseline` and severity-based urgency) |
| `syslog` | bool | `true` | enables journald/syslog sink |
| `log_file` | path | `/var/log/vigil/alerts.json` | JSON alert sink path |
| `webhook_url` | string | empty | HTTP POST endpoint for webhook alerts. Empty = disabled. |
| `webhook_bearer_token` | string (optional) | none | Bearer token for webhook authentication. |
| `storm_threshold` | integer | `50` | events within storm_window_secs before storm suppression activates. |
| `storm_window_secs` | integer | `60` | rolling window (seconds) for storm detection. |
| `rate_limit` | integer | `10` | global alert rate gate |
| `cooldown_seconds` | integer | `300` | per-path cooldown |
| `notification_rate_limit` | integer | `5` | desktop sink limit |
| `notification_rate_window_secs` | integer | `10` | desktop sink window |
| `max_alerts_per_minute` | integer | `10000` | hard ceiling in alert dispatcher |

For policy behavior (immediate/coalesced/digest delivery, storm transitions,
and critical escalation semantics), see `docs/NOTIFICATIONS.md`.

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
| `trust_baseline_on_hmac_mismatch` | bool | `false` | when true, HMAC mismatch on startup recomputes and stores rather than entering Degraded state. Use temporarily after version upgrades that change HMAC field coverage, then disable. |
| `auto_recover_inode_changes` | bool | `false` | when true, automatically accept inode changes if content verification passes (re-stat, verify schema sentinel or HMAC fingerprint). When false (default), inode changes always enter Degraded and require operator restart. |

### `[update]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `backup_retention_count` | integer | `5` | maximum number of binary backup archives kept under `/var/lib/vigil/binary-backups/`. `vigil update` prunes after a successful install. |

### `[notifications]`

Severity-aware delivery policies. Each severity level has its own sub-table.

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `storm_threshold` | integer | `50` | events within `storm_window_secs` before storm suppression activates for non-critical alerts. |
| `storm_window_secs` | integer | `60` | rolling window for storm detection. |

#### `[notifications.critical]`, `[notifications.high]`, `[notifications.medium]`, `[notifications.low]`

| Option | Type | Default (critical) | Notes |
|--------|------|---------------------|-------|
| `deliver` | enum | `immediate` | `immediate`, `coalesce`, or `digest`. Critical always uses `immediate`. |
| `coalesce_within_secs` | integer | `0` | window for grouping events by (group, parent, kind). 0 disables. |
| `digest_interval_secs` | integer | `0` | periodic digest interval. 0 disables. |
| `escalate_at_secs` | integer[] | `[300, 3600]` | escalation schedule for pending critical alerts. Empty disables. Distinct from `vigil ack`, which records doctor-event context. Critical: twice then stop. |
| `channels` | string[] | `["desktop", "journald", "socket"]` | delivery channels. No webhook or MQTT -- the signal socket is the extension point. |

### `[monitor]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `event_loss_alert_threshold` | integer (optional) | `10` | user-space `events_dropped` or kernel `kernel_queue_overflows` delta per coordinator tick that triggers Degraded state. Recovery after 5 consecutive zero-delta ticks. |

### `[maintenance]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `max_window_seconds` | integer | `1800` | maximum maintenance window duration in seconds (safety timeout). If the post-hook fails or the package manager crashes, the window closes automatically after this duration. |

### `[database]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `wal_mode` | bool | `true` | enables SQLite WAL |
| `audit_rotation_size` | integer | `104857600` | bytes |
| `audit_retention_days` | integer | `90` | rotation retention window |
| `sync_mode` | enum | `normal` | `off`, `normal`, `full`, `extra` |
| `busy_timeout_ms` | integer | `5000` | SQLite busy timeout |

### `[audit]`

Bounded audit retention. The daemon prunes old entries automatically,
replacing each pruned range with a cryptographic checkpoint that
preserves chain integrity. See `docs/RETENTION.md` for details.

| Option | Type | Default | Valid range | Notes |
|--------|------|---------|-------------|-------|
| `retention_days` | integer | `365` | >= 7 | Entries older than this are pruned on the next sweep |
| `retention_check_interval` | string | `"24h"` | 1h -- 7d | How often the prune sweep runs (e.g., `"12h"`, `"1d"`, `"7d"`) |
| `max_size_mb` | integer | `1024` | >= 64 | Hard cap on audit DB file size in MB. At 90%: doctor warns. At 100%: daemon enters Degraded. |
| `min_entries_to_keep` | integer | `1000` | any | Sweep refuses to prune below this threshold |

Example:

```toml
[audit]
retention_days = 730      # 2 years
max_size_mb = 2048        # 2 GB cap
retention_check_interval = "12h"
min_entries_to_keep = 500
```

### `[watch.<group>]`

| Option | Type | Required | Default | Notes |
|--------|------|----------|---------|-------|
| `severity` | enum | yes | -- | `low`, `medium`, `high`, `critical` |
| `paths` | string[] | yes | -- | watched file or directory paths |
| `mode` | enum | no | `per_file` | `per_file` or `closed_set` |
| `expect_present` | bool | no | `false` | when true, a warning is raised if any path in this group does not exist. Defaults to false for shipped default groups (so default installs produce zero missing-path warnings). Set to true for paths the operator explicitly added. |

#### Watch Modes

- `per_file` (default): track each file's content and metadata individually.
  This is the existing behavior for all watch groups.
- `closed_set`: additionally track the set of immediate directory entries.
  Any addition or removal of a file in the directory is a structural deviation.
  Per-file tracking still applies to each entry in the set.

Closed-set mode is recommended for directories where the set of filenames is
fixed and any new file is suspicious: `~/.ssh/`, `/etc/cron.d/`,
`/etc/sudoers.d/`.

Use `vigil explain <path>` to verify a config change matched what you intended.

### `[daemon]`

| Option | Type | Default | Notes |
|--------|------|---------|-------|
| `self_check_interval` | string | `"6h"` | interval for daemon-driven self-health checks. `"0"` disables. |

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

## CLI Editing

Configuration can be edited safely from the command line without
hand-editing TOML. All CLI edits atomically write the config (temp file,
fsync, rename), validate the result, and signal the daemon to reload.

```bash
# Add a path to a watch group
sudo vigil config watch add /etc/vigil
sudo vigil config watch add /opt/myapp --group custom_apps

# Remove a path
sudo vigil config watch remove /opt/myapp --group custom_apps

# Set a value (dotted-path syntax)
sudo vigil config set daemon.detection_wal_persistent true
sudo vigil config set alerts.rate_limit 50

# Preview a change without writing
sudo vigil config set daemon.log_level '"debug"' --dry-run

# Read a value
vigil config get daemon.detection_wal_persistent
```

Keys that require a daemon restart (not just reload):
`daemon.detection_wal_persistent`, `daemon.detection_wal`,
`daemon.monitor_backend`, `daemon.worker_threads`,
`daemon.event_channel_capacity`. The `set` command prints a restart
advisory for these keys.

Keys that require special handling (`security.hmac_key_path`,
`daemon.db_path`, `daemon.pid_file`) are refused with a message
directing the operator to `vigil setup` or manual editing.

See `docs/CLI.md` for full reference.

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
| `alerts.*` including `notification_rate_limit`, `notification_rate_window_secs`, `max_alerts_per_minute`, `storm_threshold`, `storm_window_secs`, `webhook_*` | alert dispatcher and sinks are built at startup |
| `exclusions.*` | worker exclusion filter is built at startup |
| `watch.*` path coverage | monitor watch registration happens at startup |
| `database.sync_mode`, `database.busy_timeout_ms`, `database.wal_mode` | DB connection pragmas are applied at open time |

---

Configuration should narrow scope and tune behavior. It should not hide runtime truth.
