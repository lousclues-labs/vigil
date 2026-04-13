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
| `maintenance` | maintenance window operations (for package manager hooks) |
| `baseline` | baseline operations (refresh) |
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

Start Vigil Baseline monitor in foreground mode.

```bash
vigil watch
```

This runs the daemon loop inline and blocks until interrupted.
For systemd-managed background operation, use `vigild` with the provided service unit.

---

## `check`

Run one-shot integrity check.

```bash
vigil check [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--full` | full scan instead of incremental mtime-based scan |
| `--now` | trigger scan on running daemon via control socket |
| `--accept` | after showing changes, update baseline to accept current state |
| `--path <GLOB>` | only accept changes matching this glob pattern (requires `--accept`) |
| `--dry-run` | preview what would be accepted without mutating baseline (requires `--accept`) |
| `--accept-severity <LEVEL>` | accept only changes of this severity: low, medium, high, critical (requires `--accept`) |
| `--accept-group <NAME>` | accept only changes from this watch group (requires `--accept`) |
| `-v`, `--verbose` | show expanded detail for all changes |
| `--brief` | single-line summary output |
| `--no-pager` | disable automatic paging of long output |
| `--since <TIME>` | show only current changes with audit evidence since this time (`24h`, `7d`, `today`, `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS`, unix timestamp) |

The `--since` flag filters current scan results against the audit database. Only changes
with audit evidence in the specified time window are shown. Changes with no prior audit
history are kept visible to avoid hiding blind spots (Principle X: fail loud). The flag
cannot be used with `--now` because time-bound filtering requires local audit DB access.

Examples:

```bash
vigil check
vigil check --full
vigil check --now
vigil check --accept
vigil check --accept --path '/etc/*'
vigil check --accept --dry-run
vigil check --accept --accept-severity low --accept-group user_config
vigil check --since 24h
vigil check --since 7d --verbose
vigil check --brief
```

### Check Output Modes

**Human (default):** Layered, severity-triaged output with baseline identity,
scan summary, severity histogram, progressive disclosure (≤5 changes: full
detail; ≤20: expanded investigate/attention; >20: grouped benign), structural
"why" explanations, scan issues with guidance, and next-step commands.

**Brief (`--brief`):** Single-line summary: `● ok (N files, Xs)` or
`✗ N critical · M high (N files, Xs)`.

**JSON (`--format json`):** Backward-compatible with original `ScanResult` shape.

### Check Exit Codes

| Code | Meaning |
|------|---------|
| `0` | no changes detected |
| `1` | changes found (low or medium severity) |
| `2` | high-severity changes found |
| `3` | critical changes found |

The exit code line is self-documenting in TTY output when the code is non-zero.

### Accept Workflow

The `--accept` flag shows changes first, then updates the baseline. Filters
narrow which changes are accepted:

```bash
# Preview without mutating
vigil check --accept --dry-run

# Accept only low-severity changes from user_config group
vigil check --accept --accept-severity low --accept-group user_config

# Accept only changes matching a path glob
vigil check --accept --path '/usr/lib/modules/*'
```

The accept flow shows a condensed preview (up to 10 changes) with active
filters, then prints a baseline fingerprint receipt (old → new) after
acceptance. Pager is disabled during accept so the operator sees the
receipt directly.

---

## `diff`

Compare a single file against its baseline entry.

Output includes:
- Current vs baseline comparison (hash, permissions, ownership, inode, etc.)
- Structural change details with old → new values
- Package attribution when available
- **Recent audit history panel** — the last 8 audit entries for this path
  from `audit.db`, showing timestamp, severity, change type summary, and
  maintenance/suppression flags

The audit history panel opens `audit.db` automatically. If the audit database
cannot be opened, the panel is disabled with a warning and the baseline
comparison still works.

```bash
vigil diff <PATH>
```

Example:

```bash
vigil diff /etc/passwd
vigil diff /usr/bin/sudo
```

Example output (with audit history):

```
Vigil Baseline — Diff: /etc/passwd
══════════════════════════════════

  ⚠ 1 change detected:

    content: 9c7ae3f182bd04a6 → a1b2c3d4e5f6a7b8

    package: filesystem

  Recent audit history
  ────────────────────
    today 14:32:01 HIGH     content_modified
    yesterday 09:15:22 LOW  permissions_changed (maintenance)
    showing 2 most recent entries for this path.
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

If Vigil Baseline runs as a root-owned systemd service (default), running `vigil doctor` as an unprivileged user may show reduced-coverage checks. Run `sudo vigil doctor` for full database-level diagnostics.

---

## `update`

Build and install Vigil Baseline from a local git repository. Performs atomic binary
replacement, step-by-step progress reporting, and post-update health verification.

```bash
vigil update [--repo <PATH>]
```

| Option | Description |
|--------|-------------|
| `--repo <PATH>` | path to the Vigil Baseline git repository (skips auto-discovery) |

When `--repo` is not provided, Vigil Baseline automatically searches for the source
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

Vigil Baseline — Update Complete
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

## `maintenance`

Maintenance window operations. Used by package manager hooks to suppress
low-severity alerts during system upgrades.

```bash
vigil maintenance <SUBCOMMAND>
```

| Subcommand | Description |
|------------|-------------|
| `enter` | enter maintenance window (suppress low-severity package alerts) |
| `exit` | exit maintenance window |
| `status` | show current maintenance window status |

### `maintenance enter`

Enter maintenance window on the running daemon. During maintenance,
Low and Medium severity alerts for package-owned files are suppressed.
Critical and High alerts still pass through with `maintenance_window=true`.

```bash
vigil maintenance enter [--quiet]
```

| Option | Description |
|--------|-------------|
| `--quiet` | suppress all output; exit 0 even if the daemon is not running |

Examples:

```bash
vigil maintenance enter
vigil maintenance enter --quiet
```

### `maintenance exit`

Exit maintenance window on the running daemon.

```bash
vigil maintenance exit [--quiet]
```

| Option | Description |
|--------|-------------|
| `--quiet` | suppress all output; exit 0 even if the daemon is not running |

Examples:

```bash
vigil maintenance exit
vigil maintenance exit --quiet
```

### `maintenance status`

Show whether a maintenance window is currently active.

```bash
vigil maintenance status
```

Example output:

```
Maintenance window: active
Maintenance window: inactive
```

Notes:
- `--quiet` mode is designed for package manager hooks. Hooks must never
  block package operations — if the daemon is down, the command exits 0
  silently instead of producing an error.
- A safety timeout automatically exits maintenance after 30 minutes if
  the post-hook fails or the package manager crashes.
- The maintenance window state is visible in `vigil status` output under
  the `daemon.maintenance_window` field.

---

## `baseline`

Baseline operations.

```bash
vigil baseline <SUBCOMMAND>
```

| Subcommand | Description |
|------------|-------------|
| `refresh` | refresh baseline from configured watch paths |

### `baseline refresh`

Rebuild the baseline from all configured watch paths. If the daemon is
running, uses the control socket for a live refresh. If the daemon is not
running, falls back to direct database access.

```bash
vigil baseline refresh [--quiet]
```

| Option | Description |
|--------|-------------|
| `--quiet` | suppress all output; exit 0 even if both daemon and DB access fail |

Examples:

```bash
vigil baseline refresh
vigil baseline refresh --quiet
```

Notes:
- When invoked via control socket, the refresh uses the daemon's existing
  database connection (no TOCTOU risk from re-opening by path).
- When falling back to direct DB access, opens the baseline database,
  calls `build_initial_baseline()`, and recomputes the HMAC if signing
  is enabled.
- `--quiet` mode is designed for package manager hooks. On any failure,
  the command exits 0 silently.

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
| `0` | command completed successfully / no changes detected (`check`) |
| `1` | command failed, or changes found with low/medium severity (`check`) |
| `2` | `doctor` found failures, or high-severity changes found (`check`) |
| `3` | critical changes found (`check`) |

Details:
- `main` exits with `1` on any propagated error.
- `check` exit codes are severity-based: 0 (clean), 1 (low/medium), 2 (high), 3 (critical). The exit code is self-documented in TTY output.
- `doctor` uses explicit health exit codes: `0` (all OK), `1` (warnings only), `2` (failures present).
- `config validate` exits with `1` on validation failure.

---

## Output Format Examples

Vigil Baseline accepts `--format human|json` globally.

### Human

```bash
vigil --format human status
```

Example:

```text
Vigil Baseline Status
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
