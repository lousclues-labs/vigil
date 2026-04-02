# Changelog

All notable changes to Vigil will be documented in this file.

## [0.1.0] - 2026-04-01

### Added

#### Core Infrastructure
- Project scaffolding with Cargo.toml and dependency manifest
- Core domain types (`Severity`, `ChangeType`, `BaselineEntry`, `FileMetadata`, `ChangeResult`, `Alert`, `FsEvent`, etc.) in `src/types.rs`
- Central error type with `thiserror` in `src/error.rs`
- `.gitignore` for build artifacts

#### Configuration (`src/config.rs`)
- TOML-based configuration with serde deserialization
- Layered config loading: `/etc/vigil/vigil.toml` → `~/.config/vigil/vigil.toml` → `$VIGIL_CONFIG` → CLI `--config`
- Config validation (watch groups, glob patterns, rate limits, HMAC key, paths)
- Home directory expansion via `/etc/passwd` enumeration (UID 1000–65533)
- Default config with four watch groups: `system_critical`, `persistence`, `user_space`, `network`
- Default configuration file at `config/vigil.toml`

#### Database Layer (`src/db/`)
- SQLite database with WAL mode, schema auto-creation
- `baseline` table with UNIQUE constraint on `(path, device, inode)` for inode-change detection
- `audit_log` table for tamper-evident change history
- `config_state` key-value table for daemon metadata
- Full CRUD operations: insert, upsert, update, query by path, query all, remove
- Audit log insertion with suppression/maintenance tracking
- Database integrity check (`PRAGMA integrity_check`) and WAL checkpoint

#### Baseline Engine (`src/baseline/`)
- BLAKE3 hashing via open file descriptors (TOCTOU-hardened)
- File metadata collection: permissions, ownership, mtime, inode, device, xattrs, SELinux/AppArmor context
- `vigil init` — full baseline generation across all watch groups
- `vigil baseline refresh` — re-scan with optional path filtering
- `vigil baseline add/remove` — single-file baseline management
- `vigil baseline diff` — compare current state vs. baseline without updating
- `vigil baseline stats` — entry counts by source, last refresh time
- `vigil baseline export` — JSON export of all baseline entries
- Recursive directory walking with configurable depth limit (max 20)
- Exclusion pattern matching (glob + system prefix)
- Automatic package manager ownership query during baseline generation

#### Comparison Engine (`src/compare.rs`)
- TOCTOU-hardened comparison: open file → fstat(fd) → hash(fd) → compare
- Inode + device verification to detect file replacement attacks
- Detection of: content modification, deletion, permission changes, ownership changes, inode replacement, xattr changes
- Separate `compare_entry` (for scheduled scans) and `compare_event` (for real-time monitor) functions

#### Real-Time Monitor (`src/monitor/`)
- **fanotify backend** (`src/monitor/fanotify.rs`): mount-wide monitoring via direct `libc::syscall`, epoll-based event loop, `/proc/self/fd` path resolution, automatic mount point detection from `/proc/self/mountinfo`
- **inotify backend** (`src/monitor/inotify.rs`): per-directory recursive watches, graceful degradation with explicit blind-spot warnings
- Automatic fallback from fanotify → inotify when `CAP_SYS_ADMIN` is unavailable
- **Event filter** (`src/monitor/filter.rs`): per-path 100ms debounce, glob exclusion patterns, system path exclusion, self-exclusion (Vigil's own DB/logs), periodic debounce map pruning

#### Alert Engine (`src/alert/`)
- Multi-channel alert dispatch: D-Bus, journald, JSON log, signal socket
- Per-path cooldown (default 300s) to suppress duplicate alerts
- Rate limiting (default 10 alerts/minute) with automatic window reset
- Maintenance window awareness: suppress package-managed path alerts, always fire HIGH/CRITICAL for non-package paths
- Audit log always written regardless of suppression
- **D-Bus notifications** (`src/alert/dbus.rs`): via `notify-send` with urgency mapping (critical/normal/low)
- **Journald logging** (`src/alert/journal.rs`): severity-mapped log levels (error/warn/info)
- **JSON log** (`src/alert/json_log.rs`): append-only structured log file with directory auto-creation
- **Signal socket** (`src/alert/socket.rs`): Unix domain socket for external tool integration, silent drop if no listener

#### Scheduled Scanner (`src/scanner.rs`)
- Incremental mode: only re-hash files with changed mtime
- Full mode: re-hash every baselined file
- I/O priority set to idle class via `ioprio_set` syscall
- CPU nice set to 19 via `setpriority` syscall

#### Package Manager Integration (`src/package.rs`)
- Auto-detection of pacman, dpkg, or rpm
- Package ownership queries (`pacman -Qo`, `dpkg -S`, `rpm -qf`)
- Maintenance window enter/exit commands for package manager hooks

#### CLI Interface (`src/cli.rs`, `src/main.rs`)
- Full command tree: `init`, `baseline {init,refresh,diff,add,remove,stats,export}`, `watch`, `check`, `maintenance {enter,exit,status}`, `log {show,search,stats,verify}`, `status`, `config {show,validate}`, `doctor`, `version`
- `--config` flag for explicit config path
- `--format` flag (`human`, `json`, `table`)
- `vigil doctor` — self-diagnostics (fanotify, root, config, DB, HMAC, D-Bus, package manager, signal socket)

#### Daemon (`src/daemon.rs`, `src/lib.rs`)
- Event loop: receive → filter → lookup baseline → compare → classify → dispatch
- PID file management with cleanup on shutdown
- Signal handling (SIGINT/SIGTERM) via `nix::sys::signal`
- WAL checkpoint every 1000 writes
- Periodic debounce map pruning (60s interval)
- Watch group lookup for severity classification

#### Systemd Integration (`systemd/`)
- `vigild.service`: hardened with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `MemoryMax=50M`, `CAP_SYS_ADMIN` + `CAP_DAC_READ_SEARCH`
- `vigil-scan.timer`: daily at 03:00 with 15-minute random delay, persistent
- `vigil-scan.service`: one-shot full integrity scan at idle I/O + nice 19

#### Package Manager Hooks (`hooks/`)
- pacman pre/post-transaction hooks (`hooks/pacman/vigil-pre.hook`, `hooks/pacman/vigil-post.hook`)
- apt pre/post-invoke config (`hooks/apt/99vigil`)
