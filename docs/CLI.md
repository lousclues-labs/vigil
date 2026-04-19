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
| `status` | one-shot query of current state with verdict |
| `explain` | query why a path is watched (or not) |
| `why-silent` | query why Vigil is currently quiet |
| `inspect` | offline forensic comparison against arbitrary paths/baselines |
| `test alert` | synthetic alert through full delivery pipeline |
| `doctor` | system health diagnostics |
| `update` | build and install from local git repo |
| `audit` | audit log operations (show, stats, verify) |
| `config` | show or validate config |
| `setup` | HMAC key and socket configuration |
| `log` | show daemon log entries (errors, warnings, operational messages) |
| `maintenance` | maintenance window operations (for package manager hooks) |
| `baseline` | baseline operations (refresh) |
| `attest` | create, verify, diff, show, and list attestation files |
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
| `--reason` | record a verification receipt in the audit chain |

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
- **Recent audit history panel** -- the last 8 audit entries for this path
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
Vigil Baseline -- Diff: /etc/passwd
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

One-shot query of Vigil's current state. Works whether vigild is running or not.

```bash
vigil status [--format json]
```

Default output (no flags) is a compact two-line summary for operators:

```
vigild healthy. uptime 4d 2h. baseline 59,122 entries.
last scan: 2026-04-19 03:01 (0 changes). 226 alerts in 24h (0 critical).
```

Use `--format json` for the full structured response (stable schema for scripts).

Reports a verdict (`ok`, `degraded`, or `down`) followed by: daemon liveness,
version, backend, paths watched, baseline state, last check, audit chain
status, suppressions, and WAL state.

Falls back to `/run/vigil/health.json` for baseline counts when the active user cannot read root-owned DB files directly. For automation, `vigil status --format json` includes a `health` object with the raw daemon health snapshot when present.

### `status` JSON Schema (stable contract)

```json
{
  "verdict": "ok | degraded | down",
  "reason": "string | null",
  "daemon_running": true,
  "daemon_pid": 8432,
  "daemon_uptime": "3d 14h",
  "version": "0.41.0",
  "backend": "fanotify",
  "backend_degraded": false,
  "watching_paths": 4217,
  "watching_groups": 6,
  "baseline_epoch": "1",
  "baseline_entries": 4217,
  "last_check": "2026-04-18 14:22:01 UTC",
  "last_check_result": "clean",
  "audit_chain_status": "intact",
  "audit_chain_last_verified": "2026-04-18 09:00:00 UTC",
  "suppressions": 0,
  "wal_state": "empty"
}
```

No fields are ever omitted; absent values are explicit `null`.

---

## `explain`

Query why a path is watched (or not).

```bash
vigil explain <path> [--verbose] [--format json]
```

Reports the matching watch group, severity, match rule, baseline entry,
last verification time, and audit history summary. If the path is not
watched, lists nearby watched paths.

`--verbose` adds: full hash, full xattr list, full audit entry list.

### `explain` JSON Schema (stable contract)

```json
{
  "path": "/etc/sudoers",
  "watch_group": {
    "name": "system_critical",
    "severity": "critical",
    "matched_by": "literal path in [watch.system_critical]",
    "mode": "per_file"
  },
  "baseline": {
    "hash": "a7f2...",
    "mode": 288,
    "owner_uid": 0,
    "owner_gid": 0,
    "inode": 1234567,
    "mtime": 1713456121,
    "size": 1024
  },
  "audit_history_count": 3
}
```

---

## `why-silent`

Query why Vigil is currently quiet.

```bash
vigil why-silent [--format json]
```

Reports watching status, backend, suppressions, last check, WAL state,
audit chain status, and daemon liveness. Ends with a single sentence:
`Reason for current silence: <X>`.

Works with daemon running or not.

### `why-silent` JSON Schema (stable contract)

```json
{
  "watching_paths": 4217,
  "watching_groups": 6,
  "backend": "fanotify",
  "backend_degraded": false,
  "daemon_running": true,
  "suppressions": 0,
  "wal_state": "empty",
  "audit_chain_status": "intact",
  "last_check": "2026-04-18 14:22:01 UTC",
  "last_check_result": "clean",
  "reason": "nothing has changed.",
  "issues": []
}
```

---

## `inspect`

Offline forensic comparison against arbitrary paths and baselines.

```bash
vigil inspect <path> [--baseline-db <path>] [--recursive] [--root <prefix>]
                     [--format json] [--brief]
```

| Option | Description |
|--------|-------------|
| `--baseline-db <path>` | path to a baseline DB file (defaults to local DB) |
| `--recursive` | walk directory and compare every entry |
| `--root <prefix>` | path prefix for baseline lookup translation |
| `--brief` | single-line summary |

No daemon required. Strictly read-only. See `docs/FORENSICS.md` for workflows.

### `inspect` JSON Schema (stable contract)

```json
{
  "target": "/mnt/recovered/etc/sudoers",
  "baseline_db": "/backups/2025-12.db",
  "root_prefix": "/mnt/recovered",
  "total_inspected": 1,
  "clean": 0,
  "deviations": 1,
  "errors": 0,
  "missing_in_baseline": 0,
  "details": [{"path": "...", "baseline_path": "...", "differences": ["..."]}]
}
```

---

## `test alert`

Send a synthetic alert through all configured delivery channels.

```bash
vigil test alert [--severity info|warning|critical] [--format json]
```

Default severity: `info`. Tests each backend and reports per-channel
delivery status. Records a `test_alert` entry in the audit chain.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | all configured channels delivered successfully |
| `1` | one or more configured channels failed |
| `2` | usage error |

### `test alert` JSON Schema (stable contract)

```json
{
  "test": true,
  "severity": "info",
  "channels": [
    {"channel": "desktop_notification", "status": "ok", "detail": "..."},
    {"channel": "journald", "status": "ok", "detail": "..."},
    {"channel": "json_log", "status": "ok", "detail": "..."},
    {"channel": "signal_socket", "status": "unconfigured", "detail": null}
  ],
  "configured": 3,
  "failed": 0
}
```

Per-channel status values: `ok`, `failed`, `no_listener`, `unconfigured`.

---

## `doctor`

Run environment and health diagnostics.

```bash
vigil doctor [--format <human|json>] [--now]
```

| Option | Description |
|--------|-------------|
| `--format` | output format (human or json) |
| `--now` | trigger a self-check on the running daemon via control socket |

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
replacement with backup and rollback, smoke-tests build artifacts before installation,
step-by-step progress reporting, and post-update health verification with retry.

```bash
vigil update [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--repo <PATH>` | path to the Vigil Baseline git repository (skips auto-discovery) |
| `-q`, `--quiet` | suppress all output except errors and final summary |
| `-v`, `--verbose` | include debug-level output and per-step timing table |
| `--no-progress` | force plain-text progress (no spinners) even on a TTY |

The global `--format=json` flag enables machine-readable NDJSON output on stdout (human-readable output continues on stderr).

**Environment variables:**

| Variable | Values | Description |
|----------|--------|-------------|
| `VIGIL_PROGRESS` | `auto`, `plain`, `fancy` | override progress rendering mode |
| `NO_COLOR` | any value | disable all ANSI color output |

When `--repo` is not provided, Vigil Baseline automatically searches for the source
repository in order: current directory, binary-relative parent directories,
`~/vigil`, `~/src/vigil`, `~/projects/vigil`, `/home/$SUDO_USER/{vigil,src/vigil,projects/vigil}`
(when running under `sudo`), and `/opt/vigil`. Candidates are deduplicated so the same
path is never checked twice. If no valid repository is found, the error message shows
*why* each candidate was rejected (e.g., "Cargo.toml not found", "wrong package name").

### Safety Features

- **Pre-install smoke test**: build artifacts are run with `--version` before any installed
  binary is touched. A corrupt build is caught immediately.
- **Binary backup**: existing `/usr/local/bin/vigil` and `vigild` are backed up to
  `.vigil.backup` and `.vigild.backup` before installation. After a successful install,
  backups are archived under `/var/lib/vigil/binary-backups/`. Retention is controlled
  by `[update] backup_retention_count` (default 5).
- **Atomic install**: each binary is installed via copy → chmod 755 → rename, so a crash
  mid-update cannot leave a corrupted binary.
- **Post-install smoke test**: installed binaries are verified with `--version` after
  installation. If either fails, backups are restored automatically.
- **Daemon health retry**: after restarting the daemon, health is checked up to 3 times
  with 2-second intervals (total max wait: 6 seconds).
- **Automatic rollback**: if the daemon fails all health checks and backups exist, the
  update command stops the daemon, restores the previous binaries, restarts the daemon,
  and returns an error.
- **Downgrade warning**: if the new version appears older than the current version, a
  warning is printed (the update is not blocked).

Example:

```bash
vigil update
vigil update --repo /opt/vigil
sudo vigil update    # discovers repo via SUDO_USER
```

Example output (TTY mode, ANSI stripped):

```
[ 1/11] Verify repository...
  ✓ Verify repository (12ms) -- /home/user/src/vigil
[ 2/11] Build release binaries...
╭─ cargo build --release ───────────────────────────
   Compiling vigil-baseline v0.36.0 (/home/user/src/vigil)
    Finished `release` profile [optimized] target(s) in 2m 27s
╰──────────────────────────────────────────────────
  ✓ Build release binaries (2m 29s)
[ 3/11] Verify artifacts...
  ✓ Verify artifacts (120ms) -- v0.35.0 → v0.36.0
[ 4/11] Stop daemon...
  ✓ Stop daemon (1.2s)
[ 5/11] Back up existing binaries...
  ✓ Back up existing binaries (85ms)
[ 6/11] Install new binaries (atomic)...
  ✓ Install new binaries (atomic) (210ms)
[ 7/11] Install systemd units & hooks...
  ✓ Install systemd units & hooks (45ms) -- unchanged
[ 8/11] Start daemon...
  ✓ Start daemon (1.1s)
[ 9/11] Verify daemon health...
  ✓ Verify daemon health (2.3s)
[10/11] Archive backups...
  ✓ Archive backups (52ms)
[11/11] Post-install health check...
  ✓ Post-install health check (310ms) -- v0.35.0 → v0.36.0 | daemon: restarted | baseline: preserved (14,832 entries)

  Update complete (2m 35s)
```

Example output (`--format=json`, one line per event on stdout):

```json
{"ts":"2026-04-17T15:30:00Z","step":1,"total":11,"label":"Verify repository","state":"begin","elapsed_ms":0}
{"ts":"2026-04-17T15:30:00Z","step":1,"total":11,"label":"Verify repository","state":"ok","elapsed_ms":12}
{"ts":"2026-04-17T15:30:00Z","step":2,"total":11,"label":"Build release binaries","state":"begin","elapsed_ms":0}
{"ts":"2026-04-17T15:32:29Z","step":2,"total":11,"label":"Build release binaries","state":"ok","elapsed_ms":149000}
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

### `setup attest`

Generate attestation signing key.

```bash
vigil setup attest [--key-path <PATH>] [--force]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--key-path <PATH>` | `/etc/vigil/attest.key` | path to write the attestation key file |
| `--force` | false | overwrite existing key file without prompting |

Examples:

```bash
vigil setup attest
vigil setup attest --key-path /secure/evidence/attest.key --force
```

---

## `attest`

Portable, signed attestations of baseline and audit state.

```bash
vigil attest <SUBCOMMAND>
```

| Subcommand | Description |
|------------|-------------|
| `create` | create a new `.vatt` attestation file |
| `verify` | verify an attestation file |
| `diff` | compare an attestation to current state or another attestation |
| `show` | display attestation metadata and contents |
| `list` | list attestation files in a directory |

### `attest create`

```bash
vigil attest create [--scope full\|baseline-only\|head-only] [--out <PATH>] [--key-path <PATH>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--scope <SCOPE>` | `full` | attestation scope: `full`, `baseline-only`, `head-only` |
| `--out <PATH>` | auto-generated `.vatt` name | output file path |
| `--key-path <PATH>` | key search paths | explicit attestation signing key path |

### `attest verify`

```bash
vigil attest verify <attestation-file> [--key-path <PATH>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<attestation-file>` | required | path to `.vatt` file |
| `--key-path <PATH>` | key search paths | explicit signing key path for signature verification |

Verification checks:

- magic bytes and format version
- recomputed content hash vs declared hash
- signature validity and key ID match
- embedded audit chain link integrity (when audit entries are present)

### `attest diff`

```bash
vigil attest diff <attestation-file> [--against current\|<other-attestation-file>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<attestation-file>` | required | left-hand attestation file |
| `--against` | `current` | compare against live baseline/audit state or another `.vatt` file |

### `attest show`

```bash
vigil attest show <attestation-file> [--verbose]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<attestation-file>` | required | path to `.vatt` file |
| `--verbose` | false | include embedded baseline/audit/watch-group details |

### `attest list`

```bash
vigil attest list [--dir <PATH>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--dir <PATH>` | `.` | directory to scan for `.vatt` files |

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
  block package operations -- if the daemon is down, the command exits 0
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
vigil 0.41.0
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
- `attest verify` uses: `0` (valid), `1` (invalid attestation), `2` (usage error), `3` (I/O error).

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

## `vigil ack`

Acknowledge a critical alert, canceling further escalation notifications.

```bash
vigil ack <event_id>           # acknowledge a specific critical alert
vigil ack --all-criticals      # acknowledge all pending critical alerts
```

Acknowledged alerts stop re-firing on the configured escalation schedule.
The acknowledgment is recorded in the audit log.

---

*Short commands. Deterministic output. No hidden behavior.*
