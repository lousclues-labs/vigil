# CLI Reference

Every command that exists in `vigil`. Nothing fictional, nothing aspirational.
If it's here, it's in `src/cli.rs` and it works.

---

## Global Syntax

```bash
vigil [GLOBAL_OPTIONS] <COMMAND> [COMMAND_OPTIONS]
```

| Global Option | Type | Default | Description |
|---------------|------|---------|-------------|
| `-c`, `--config <PATH>` | path | layered search | explicit config file path override |
| `--format <human\|json>` | enum | `human` | output format selector |

---

## Top-Level Commands

| Command | Description |
|---------|-------------|
| `init` | initialize baseline database |
| `watch` | start real-time monitoring daemon in foreground |
| `check` | run one-shot integrity check |
| `diff` | compare a single file against its baseline |
| `status` | daemon and baseline health summary |
| `doctor` | system health diagnostics |
| `update` | build and install from local git repo |
| `audit` | audit log operations (show, stats, verify) |
| `config` | show or validate config |
| `setup` | HMAC key and socket configuration |
| `log` | show daemon log entries (errors, warnings, operational messages) |
| `version` | print version string |

---

## `init`

Create baseline entries for all configured watch groups.

```bash
vigil init [--force]
```

| Option | Description |
|--------|-------------|
| `--force` | skip confirmation when overwriting existing baseline |

Examples:

```bash
vigil init
vigil init --force
vigil --config /etc/vigil/vigil.toml init
```

---

## `watch`

Start VigilBaseline monitor in foreground mode.

```bash
vigil watch
```

This runs the daemon loop inline and blocks until interrupted.
For systemd-managed background operation, use `vigild` with the provided service unit.

---

## `check`

Run one-shot integrity check.

```bash
vigil check [--full] [--now] [--accept] [--path <GLOB>]
```

| Option | Description |
|--------|-------------|
| `--full` | full scan instead of incremental mtime-based scan |
| `--now` | trigger scan on running daemon via control socket |
| `--accept` | after showing changes, update baseline to accept current state |
| `--path <GLOB>` | only accept changes matching this glob pattern (requires `--accept`) |

Examples:

```bash
vigil check
vigil check --full
vigil check --now
vigil check --accept
vigil check --accept --path '/etc/*'
```

---

## `diff`

Compare a single file against its baseline entry.

```bash
vigil diff <PATH>
```

Example:

```bash
vigil diff /etc/passwd
vigil diff /usr/bin/sudo
```

---

## `status`

Show baseline counts, daemon state, backend, DB path, and daemon PID if available.

```bash
vigil status
```

Falls back to `/run/vigil/health.json` for baseline counts when the active user cannot read root-owned DB files directly. For automation, `vigil status --format json` includes a `health` object with the raw daemon health snapshot when present.

---

## `doctor`

Run environment and health diagnostics.

```bash
vigil doctor [--format <human|json>]
```

What it checks:
- fanotify availability
- privilege context
- config validity
- database access and integrity
- baseline entry count
- HMAC key presence (if enabled)
- notify-send availability
- package backend detection
- signal socket configuration
- control socket configuration

If VigilBaseline runs as a root-owned systemd service (default), running `vigil doctor` as an unprivileged user may show reduced-coverage checks. Run `sudo vigil doctor` for full database-level diagnostics.

---

## `update`

Build and install VigilBaseline from a local git repository. Performs atomic binary
replacement, step-by-step progress reporting, and post-update health verification.

```bash
vigil update [--repo <PATH>]
```

| Option | Description |
|--------|-------------|
| `--repo <PATH>` | path to the VigilBaseline git repository (skips auto-discovery) |

When `--repo` is not provided, VigilBaseline automatically searches for the source
repository in order: current directory, binary-relative parent directories,
`~/vigil`, `~/src/vigil`, `~/projects/vigil`, and `/opt/vigil`.

Binaries are installed atomically (copy → chmod → rename) so a crash mid-update
cannot leave a corrupted binary. After restarting the daemon, the command
verifies it is actually responding via the control socket before reporting
success.

Example:

```bash
vigil update
vigil update --repo /opt/vigil
```

Example output:

```
  Using repository: /home/user/src/vigil

Building update from /home/user/src/vigil
   Compiling vigil v0.26.0 (/home/user/src/vigil)
    Finished `release` profile [optimized] target(s) in 42.3s

Updating: v0.25.1 → v0.26.0

  Stopping vigild.service...
  ✓ Daemon stopped
  Installing vigil → /usr/local/bin...
  Installing vigild → /usr/local/bin...
  Updating symlinks...
  Checking systemd units...
  Checking hooks...
  Starting vigild.service...
  ✓ Daemon started

VigilBaseline — Update Complete
═══════════════════════

  ✓ v0.25.1 → v0.26.0
  Daemon:   restarted
  Units:    unchanged
  Hooks:    unchanged
  Baseline: preserved (14,832 entries)

  Running health check...
```

---

## `audit`

Audit log inspection and verification.

### `audit show`

Show recent audit entries.

```bash
vigil audit show [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n`, `--last <N>` | `50` | number of most recent entries to show |
| `--path <GLOB>` | none | filter by path glob (e.g. `/etc/*` or `/usr/bin/sudo`) |
| `--severity <LEVEL>` | none | filter by minimum severity: low, medium, high, critical |
| `--group <NAME>` | none | filter by watch group name |
| `--since <ISO8601>` | none | entries after this time (e.g. `2026-04-07` or `2026-04-07T14:00:00`) |
| `--until <ISO8601>` | none | entries before this time |
| `--maintenance` | false | show only changes during maintenance windows |
| `--suppressed` | false | show only suppressed changes |
| `-v`, `--verbose` | false | show full change details for each entry |

Examples:

```bash
vigil audit show
vigil audit show -n 100
vigil audit show --severity critical
vigil audit show --path '/etc/passwd'
vigil audit show --since 2026-04-01 --until 2026-04-07
vigil audit show --group system_critical -v
vigil audit show --maintenance
```

### `audit stats`

Show severity and suppression breakdown.

```bash
vigil audit stats [--period <PERIOD>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--period <PERIOD>` | `7d` | time period: today, 24h, 7d, 30d, all |

Examples:

```bash
vigil audit stats
vigil audit stats --period 30d
vigil audit stats --period all
```

### `audit verify`

Verify BLAKE3 hash chain integrity of the audit log. If HMAC signing is enabled, also verifies HMAC signatures.

```bash
vigil audit verify
```

---

## `config`

Configuration inspection and validation.

### `config show`

```bash
vigil config show
```

Prints the active configuration as TOML.

### `config validate`

```bash
vigil config validate
```

Valid config prints `Configuration is valid.` and exits 0.
Invalid config prints the error and exits 1.

---

## `setup`

Setup operations for HMAC signing and alert socket.

### `setup hmac`

Generate and configure HMAC signing key.

```bash
vigil setup hmac [--key-path <PATH>] [--force]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--key-path <PATH>` | `/etc/vigil/hmac.key` | path to write the HMAC key file |
| `--force` | false | overwrite existing key file without prompting |

Examples:

```bash
vigil setup hmac
vigil setup hmac --key-path /custom/path/hmac.key --force
```

### `setup socket`

Configure the alert socket path.

```bash
vigil setup socket [--path <PATH>] [--disable]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--path <PATH>` | `/run/vigil/alert.sock` | path for the Unix domain socket |
| `--disable` | false | disable the socket sink |

Examples:

```bash
vigil setup socket --path /run/vigil/alert.sock
vigil setup socket --disable
```

---

## `log`

Show daemon log entries from the systemd journal. Wraps `journalctl -u vigild.service` with ergonomic filters.

```bash
vigil log <SUBCOMMAND>
```

| Subcommand | Description |
|------------|-------------|
| `show` | show recent daemon log entries from the journal |
| `errors` | show only error and warning entries |

### `log show`

Show recent daemon log entries.

```bash
vigil log show [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-n`, `--lines <N>` | u32 | `100` | number of lines to show |
| `-l`, `--level <LEVEL>` | string | all | filter by minimum level: `error`, `warn`, `info`, `debug` |
| `-f`, `--follow` | flag | off | follow log output in real time |
| `--since <TIME>` | string | none | show entries after this time (e.g. `1h`, `30m`, `2026-04-07`) |
| `-g`, `--grep <PATTERN>` | string | none | grep pattern to filter log lines |

Examples:

```bash
vigil log show
vigil log show -n 200
vigil log show --level warn
vigil log show --since 1h
vigil log show -f
vigil log show --grep "database" --level error
sudo vigil log show --since "2026-04-07" -n 500
```

### `log errors`

Shortcut to show only error and warning entries. Equivalent to `vigil log show --level warn`.

```bash
vigil log errors [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-n`, `--lines <N>` | u32 | `50` | number of lines to show |
| `--since <TIME>` | string | none | show entries after this time |

Examples:

```bash
vigil log errors
vigil log errors -n 20
vigil log errors --since 1h
sudo vigil log errors --since "2026-04-06"
```

Notes:
- Both subcommands require access to the systemd journal. Use `sudo` if your user is not in the `systemd-journal` group.
- Output uses `journalctl -o short-iso` format.
- `--follow` streams output until interrupted with Ctrl+C.

---

## `version`

Print CLI version.

```bash
vigil version
```

Output:

```text
vigil 0.19.0
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | command completed successfully |
| `1` | command failed (runtime/config/DB/validation error) |
| `2` | `doctor` found one or more failed checks |

Details:
- `main` exits with `1` on any propagated error.
- `doctor` uses explicit health exit codes: `0` (all OK), `1` (warnings only), `2` (failures present).
- `config validate` exits with `1` on validation failure.

---

## Output Format Examples

VigilBaseline accepts `--format human|json` globally.

### Human

```bash
vigil --format human status
```

Example:

```text
VigilBaseline Status
  Baseline entries:    1234
  Last refresh:        1712039200
  Database:            /var/lib/vigil/baseline.db
  Monitor backend:     fanotify
```

### JSON

```bash
vigil --format json status
```

Example:

```json
{
  "baseline_entries": 1234,
  "last_refresh": 1712039200,
  "db_path": "/var/lib/vigil/baseline.db",
  "monitor_backend": "fanotify"
}
```

---

*Short commands. Deterministic output. No hidden behavior.*
