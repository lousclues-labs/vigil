# Installation

Install Vigil Baseline from source on Linux.
No container, no network service, no cloud account.

> **Scope.** Vigil Baseline is a desktop Linux file integrity monitor.
> These instructions assume a workstation or laptop running a desktop
> distro (Arch, Debian, Ubuntu, Fedora, or similar) with one human
> operator. The daemon installs system-wide via systemd and sends
> notifications to the desktop session. Vigil is not designed for
> servers, headless hosts, container nodes, or fleets. See
> [docs/THREAT_MODEL.md](THREAT_MODEL.md) for the full scope statement.

---

## Requirements

Minimum:
- Linux
- Rust toolchain (edition 2021 target)
- standard build tools (`gcc`, `make`, `pkg-config`)

Optional but recommended:
- `notify-send` (desktop notifications)
- systemd (daemon + scheduled scans)
- `CAP_SYS_ADMIN` for fanotify backend

Without `CAP_SYS_ADMIN`, Vigil Baseline falls back to inotify automatically.

---

## Distro Dependencies

### Arch Linux

```bash
sudo pacman -S --needed rust base-devel pkgconf
```

Optional runtime tools:

```bash
sudo pacman -S --needed libnotify systemd
```

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y rustc cargo build-essential pkg-config
```

Optional runtime tools:

```bash
sudo apt install -y libnotify-bin systemd
```

### Fedora

```bash
sudo dnf install -y rust cargo gcc make pkgconf-pkg-config
```

Optional runtime tools:

```bash
sudo dnf install -y libnotify systemd
```

Notes:
- `rusqlite` is built with `bundled` SQLite. No system sqlite dev package required.

---

## Build From Source

```bash
git clone https://github.com/lousclues-labs/vigil.git
cd vigil
cargo build --release
```

Artifacts:
- `target/release/vigil`
- `target/release/vigild`

---

## Install Binaries

For manual installation, use the atomic copy-then-rename pattern to avoid
corrupted binaries if the process is interrupted:

```bash
sudo cp target/release/vigil /usr/local/bin/.vigil.new
sudo chmod 755 /usr/local/bin/.vigil.new
sudo mv /usr/local/bin/.vigil.new /usr/local/bin/vigil

sudo cp target/release/vigild /usr/local/bin/.vigild.new
sudo chmod 755 /usr/local/bin/.vigild.new
sudo mv /usr/local/bin/.vigild.new /usr/local/bin/vigild
```

Or use `vigil update` which handles this automatically (see [CLI Reference](CLI.md#update)).

Compatibility symlinks for the provided systemd units (`ExecStart=/usr/bin/vigild`):

```bash
sudo ln -sf /usr/local/bin/vigil /usr/bin/vigil
sudo ln -sf /usr/local/bin/vigild /usr/bin/vigild
```

Install default config:

```bash
sudo install -Dm644 config/vigil.toml /etc/vigil/vigil.toml
```

Create runtime directories:

```bash
sudo install -d -m 755 /var/lib/vigil /var/log/vigil /run/vigil
```

---

## systemd Setup

Install units:

```bash
sudo install -Dm644 systemd/vigild.service /etc/systemd/system/vigild.service
sudo install -Dm644 systemd/vigil-scan.service /etc/systemd/system/vigil-scan.service
sudo install -Dm644 systemd/vigil-scan.timer /etc/systemd/system/vigil-scan.timer
```

Reload and enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vigild.service
sudo systemctl enable --now vigil-scan.timer
```

Check status:

```bash
systemctl status vigild.service --no-pager
systemctl status vigil-scan.timer --no-pager
```

---

## Package Manager Hooks

Hooks reduce false positives during package upgrades by:
1. entering maintenance window before transaction
2. refreshing baseline after transaction
3. exiting maintenance window

**If you installed via the official `.deb` / `.rpm` packages (built
by [lousclues-pkg](PACKAGING.md)), these hooks are already in place;
skip this section.** The manual installation below is for source
builds.

### pacman hooks

Two self-contained hook files; each is a `pacman.hook(5)` entry
with embedded `Exec=`:

```bash
sudo install -Dm644 hooks/pacman/vigil-pre.hook  /etc/pacman.d/hooks/vigil-pre.hook
sudo install -Dm644 hooks/pacman/vigil-post.hook /etc/pacman.d/hooks/vigil-post.hook
```

### apt hook (three pieces — install as a set)

> **Important:** apt hooks ship as a config file *plus* two shell
> scripts. Installing only the config without the scripts makes the
> `test -x ... || true` guard always-false, so the hooks silently
> no-op — passing apt's syntax check but doing nothing. Always
> install all three together.

The split exists because `apt.conf(5)` has no escape for `"` inside
`"..."` string values, so multi-line shell with quoted log messages
cannot live inside the `DPkg::Pre-Invoke` / `DPkg::Post-Invoke`
directives directly.

```bash
# 1. apt.conf delegator (small, no embedded shell)
sudo install -Dm644 hooks/apt/99vigil     /etc/apt/apt.conf.d/99vigil

# 2. Pre-Invoke logic: enter maintenance window
sudo install -Dm755 hooks/apt/apt-pre.sh  /usr/lib/vigil/apt-pre.sh

# 3. Post-Invoke logic: refresh baseline, exit maintenance window
sudo install -Dm755 hooks/apt/apt-post.sh /usr/lib/vigil/apt-post.sh
```

Verify the hook config parses cleanly:

```bash
sudo apt-get check
```

### dnf hook (Fedora / EL — DNF4)

DNF4 plugin (Fedora ≤ 40, RHEL/Rocky/Alma 9):

```bash
sudo install -Dm644 hooks/dnf/vigil.conf /etc/dnf/plugins/vigil.conf
sudo install -Dm644 hooks/dnf/vigil.py   /usr/lib/python3/dist-packages/dnf-plugins/vigil.py
```

> **Note:** DNF5 (Fedora 41+) uses a different plugin ABI than DNF4;
> the DNF5 port is tracked separately. On Fedora 41+ the hook is
> not installed; transactions still succeed, they just don't enter
> a maintenance window.

---

## Permissions and Capabilities

### fanotify mode (preferred)

fanotify requires elevated capability (`CAP_SYS_ADMIN`).

Options:
- run daemon as root (typical with systemd unit)
- grant capabilities to executable (advanced deployment)

#### File capabilities (recommended for non-root deployment)

The official `.deb` / `.rpm` packages grant `CAP_SYS_ADMIN` and
`CAP_DAC_READ_SEARCH` to `/usr/bin/vigild` via file caps in the
`postinst` scriptlet — file caps are narrower than
`AmbientCapabilities=` (they do not propagate to children, and
fail loudly if `setcap` is missing).

For source builds, the equivalent step is:

```bash
sudo setcap cap_sys_admin,cap_dac_read_search+ep /usr/local/bin/vigild
getcap /usr/local/bin/vigild
# expected: /usr/local/bin/vigild cap_dac_read_search,cap_sys_admin=ep
```

If `setcap` is unavailable or the binary lives on a filesystem that
does not honour xattrs (some container overlays), fall back to
`AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH` in the
systemd unit. `systemd/vigild.service` ships this fallback already
so the daemon-launched path works even when file caps had to be
reverted. See [PACKAGING.md](PACKAGING.md) for the rationale
(post-spec CI iteration found that file caps activate `AT_SECURE=1`
and can break harmless invocations on minimal container images).

#### Kernel version and fanotify tier (VIGIL-VULN-077)

Vigil auto-detects the best fanotify mode at startup. Higher tiers
provide better coverage for closed-set directory watches (`~/.ssh/`,
`/etc/cron.d/`, etc.):

| Kernel | Tier | Coverage |
|--------|------|----------|
| 5.9+ | `fid_dfid_name` | Ideal: directory FID + filename in one event |
| 5.1+ | `fid` | Full: FID-mode events resolvable via `open_by_handle_at(2)` |
| <5.1 | `legacy_fd` | Partial: directory-creation events may be missed; scheduled scans compensate |
| no CAP_SYS_ADMIN | `inotify` | Partial: inotify fallback with limited scalability |

Check the resolved tier with `vigil status` or `vigil doctor`.
Override with `monitor.fanotify_tier` in the config (see
[Configuration](CONFIGURATION.md)).

### inotify fallback

If fanotify is unavailable, Vigil Baseline logs the reason and falls back to inotify.
This keeps monitoring available with reduced coverage.

Verify backend in use:

```bash
vigil status
vigil doctor
```

---

## First Run

Initialize baseline:

```bash
vigil init
```

Check health:

```bash
vigil status
vigil doctor
```

Run a one-shot check:

```bash
vigil check
```

Start foreground monitor (optional quick test):

```bash
vigil watch
```

For constrained environments (live USB, containers, embedded systems) where
a full daemon deployment is not possible, see
[Minimum Viable Trust](MINIMUM_VIABLE.md) for the smallest useful deployment.

---

## Uninstall (Manual)

```bash
sudo systemctl disable --now vigild.service vigil-scan.timer
sudo rm -f /etc/systemd/system/vigild.service
sudo rm -f /etc/systemd/system/vigil-scan.service
sudo rm -f /etc/systemd/system/vigil-scan.timer
sudo systemctl daemon-reload

sudo rm -f /usr/local/bin/vigil /usr/local/bin/vigild
sudo rm -f /etc/pacman.d/hooks/vigil-pre.hook /etc/pacman.d/hooks/vigil-post.hook
sudo rm -f /etc/apt/apt.conf.d/99vigil
sudo rm -f /usr/lib/vigil/apt-pre.sh /usr/lib/vigil/apt-post.sh
sudo rmdir /usr/lib/vigil 2>/dev/null || true
sudo rm -f /etc/dnf/plugins/vigil.conf
sudo rm -f /usr/lib/python3/dist-packages/dnf-plugins/vigil.py
```

Data directories are left intact by default:
- `/var/lib/vigil`
- `/var/log/vigil`

---

*Install it once. Let it watch quietly.*
