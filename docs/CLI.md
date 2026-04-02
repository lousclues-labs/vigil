# CLI Reference

This is the complete CLI surface for `vigil`.
Everything here comes from the current clap command tree.

---

## Global Syntax

```bash
vigil [GLOBAL_OPTIONS] <COMMAND> [COMMAND_OPTIONS]
```

| Global Option | Type | Default | Description |
|---------------|------|---------|-------------|
| `-c`, `--config <PATH>` | path | layered search | explicit config file path override |
| `--format <human|json|table>` | enum | `human` | output format selector |

Notes:
- `--format` is accepted globally and parsed for all commands.
- Current command handlers primarily emit human-readable output.

---

## Top-Level Commands

| Command | Description |
|---------|-------------|
| `init` | initialize baseline database (first run) |
| `baseline <ACTION>` | baseline lifecycle operations |
| `watch` | start real-time monitoring daemon in foreground |
| `check [--full]` | run one-shot integrity check |
| `maintenance <ACTION>` | maintenance window controls |
| `log <ACTION>` | alert history and statistics |
| `status` | daemon and baseline health summary |
| `config <ACTION>` | show or validate config |
| `doctor` | self-diagnostics |
| `version` | print version string |

---

## `init`

Create baseline entries for all configured watch groups.

```bash
vigil init
```

Examples:

```bash
vigil init
vigil --config /etc/vigil/vigil.toml init
```

---

## `baseline`

Manage baseline entries.

### `baseline init`

Alias for top-level `init`.

```bash
vigil baseline init
```

### `baseline refresh`

Re-scan configured paths and update baseline rows.

```bash
vigil baseline refresh [--paths <DIR>] [--quiet]
```

| Option | Description |
|--------|-------------|
| `--paths <DIR>` | refresh only paths dominated by this directory |
| `--quiet` | suppress non-error output |

Examples:

```bash
vigil baseline refresh
vigil baseline refresh --paths /etc
vigil baseline refresh --quiet
```

### `baseline diff`

Compare current filesystem state against baseline.

```bash
vigil baseline diff
```

### `baseline add`

Add one file to baseline.

```bash
vigil baseline add <PATH>
```

Example:

```bash
vigil baseline add /etc/ssh/sshd_config
```

### `baseline remove`

Remove one file from baseline.

```bash
vigil baseline remove <PATH>
```

Example:

```bash
vigil baseline remove /etc/ssh/sshd_config
```

### `baseline stats`

Show baseline entry counts and source breakdown.

```bash
vigil baseline stats
```

### `baseline export`

Export baseline entries as JSON.

```bash
vigil baseline export
```

---

## `watch`

Start Vigil monitor in foreground mode.

```bash
vigil watch
```

Notes:
- This runs the daemon loop inline and blocks until interrupted.
- For systemd-managed background operation, use `vigild` with the provided service unit.

---

## `check`

Run one-shot integrity check.

```bash
vigil check [--full]
```

| Option | Description |
|--------|-------------|
| `--full` | full scan instead of incremental mtime-based scan |

Examples:

```bash
vigil check
vigil check --full
```

---

## `maintenance`

Maintenance windows suppress notifications for package-managed paths.
Audit logging still records all events.

### `maintenance enter`

```bash
vigil maintenance enter [--quiet]
```

### `maintenance exit`

```bash
vigil maintenance exit [--quiet]
```

### `maintenance status`

```bash
vigil maintenance status
```

| Option | Commands | Description |
|--------|----------|-------------|
| `--quiet` | `enter`, `exit` | suppress non-error output |

Examples:

```bash
vigil maintenance enter
vigil maintenance enter --quiet
vigil maintenance status
vigil maintenance exit
```

---

## `log`

Audit log inspection.

### `log show`

Show recent events.

```bash
vigil log show [--severity <SEVERITY>] [--last <N>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--severity <SEVERITY>` | none | severity equality filter (string match) |
| `--last <N>` | `20` | number of most recent entries |

Examples:

```bash
vigil log show
vigil log show --severity critical
vigil log show --last 100
```

### `log search`

Search recent audit entries.

```bash
vigil log search [--path <SUBSTRING>] [--severity <SEVERITY>]
```

| Option | Description |
|--------|-------------|
| `--path <SUBSTRING>` | path substring filter |
| `--severity <SEVERITY>` | severity equality filter |

Examples:

```bash
vigil log search --path /etc/passwd
vigil log search --severity high
vigil log search --path /usr/bin --severity critical
```

### `log stats`

Show severity and suppression breakdown.

```bash
vigil log stats
```

### `log verify`

Verify HMAC integrity for audit log entries.

```bash
vigil log verify
```

Note:
- Current CLI prints a not-yet-implemented message unless HMAC workflow is fully wired.

---

## `status`

Show baseline counts, maintenance state, backend, DB path, and daemon PID if available.

```bash
vigil status
```

---

## `config`

Configuration inspection and validation.

### `config show`

```bash
vigil config show
```

### `config validate`

```bash
vigil config validate
```

- Valid config prints: `Configuration is valid.`
- Invalid config prints error and exits non-zero.

---

## `doctor`

Run environment and health diagnostics:
- fanotify availability
- privilege context
- config validity
- database access and integrity
- baseline entry count
- HMAC key presence (if enabled)
- notify-send availability
- package backend detection
- signal socket setting

```bash
vigil doctor
```

---

## `version`

Print CLI version.

```bash
vigil version
```

Output:

```text
vigil 0.2.1
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | command completed successfully |
| `1` | command failed (runtime/config/DB/validation error) |

Behavior details:
- `main` exits with `1` on any propagated error.
- `config validate` exits with `1` on validation failure.

---

## Output Format Examples

Vigil accepts `--format human|json|table` globally.

### Human

```bash
vigil --format human status
```

Example shape:

```text
Vigil Status
  Baseline entries:    1234
  Last refresh:        1712039200
  Maintenance window:  inactive
  Database:            /var/lib/vigil/baseline.db
  Monitor backend:     fanotify
```

### JSON

```bash
vigil --format json baseline export
```

Example shape:

```json
[
  {
    "path": "/etc/passwd",
    "hash": "...",
    "inode": 12345,
    "device": 2050
  }
]
```

### Table

```bash
vigil --format table baseline stats
```

Example shape:

```text
Baseline Statistics
  Total entries: 1234
  auto_scan: 1200
  manual: 20
  package_manager: 14
```

---

*Short commands. Deterministic output. No hidden behavior.*
