# Installation

Install Vigil from source on Linux.
No container, no network service, no cloud account.

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

Without `CAP_SYS_ADMIN`, Vigil falls back to inotify automatically.

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
git clone https://github.com/loujr/vigil.git
cd vigil
cargo build --release
```

Artifacts:
- `target/release/vigil`
- `target/release/vigild`

---

## Install Binaries

```bash
sudo install -Dm755 target/release/vigil /usr/local/bin/vigil
sudo install -Dm755 target/release/vigild /usr/local/bin/vigild
```

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

### pacman hooks

```bash
sudo install -Dm644 hooks/pacman/vigil-pre.hook  /etc/pacman.d/hooks/vigil-pre.hook
sudo install -Dm644 hooks/pacman/vigil-post.hook /etc/pacman.d/hooks/vigil-post.hook
```

### apt hook config

```bash
sudo install -Dm644 hooks/apt/99vigil /etc/apt/apt.conf.d/99vigil
```

---

## Permissions and Capabilities

### fanotify mode (preferred)

fanotify requires elevated capability (`CAP_SYS_ADMIN`).

Options:
- run daemon as root (typical with systemd unit)
- grant capabilities to executable (advanced deployment)

### inotify fallback

If fanotify is unavailable, Vigil logs the reason and falls back to inotify.
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
```

Data directories are left intact by default:
- `/var/lib/vigil`
- `/var/log/vigil`

---

*Install it once. Let it watch quietly.*
