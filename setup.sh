#!/usr/bin/env bash
set -euo pipefail

# ── Vigil Baseline setup script ─────────────────────────────────────────────
# One-command install, uninstall, and pre-flight check for Vigil Baseline.
#
# Usage:
#   ./setup.sh              # Full install
#   ./setup.sh --check      # Dry run: show what would happen
#   ./setup.sh --uninstall  # Remove Vigil Baseline (preserves data)
#   ./setup.sh --uninstall --purge  # Full removal including data

readonly VIGIL_BIN="/usr/local/bin/vigil"
readonly VIGILD_BIN="/usr/local/bin/vigild"
readonly VIGIL_SYMLINK="/usr/bin/vigil"
readonly VIGILD_SYMLINK="/usr/bin/vigild"
readonly CONFIG_DIR="/etc/vigil"
readonly CONFIG_FILE="${CONFIG_DIR}/vigil.toml"
readonly DATA_DIR="/var/lib/vigil"
readonly LOG_DIR="/var/log/vigil"
readonly RUN_DIR="/run/vigil"
readonly SYSTEMD_DIR="/etc/systemd/system"

MODE="install"
PURGE=false

# ── Argument parsing ───────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --check)      MODE="check" ;;
        --uninstall)  MODE="uninstall" ;;
        --purge)      PURGE=true ;;
        --help|-h)
            echo "Usage: $0 [--check | --uninstall [--purge]]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--check | --uninstall [--purge]]"
            exit 1
            ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────

info()  { printf '  %s\n' "$*"; }
ok()    { printf '  [OK]      %s\n' "$*"; }
miss()  { printf '  [MISSING] %s\n' "$*"; }
step()  { printf '\n── %s ──\n' "$*"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

confirm() {
    local prompt="$1"
    printf '%s [y/N] ' "$prompt"
    read -r answer
    case "$answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Distro detection ──────────────────────────────────────────────

detect_distro() {
    if command_exists pacman; then
        echo "arch"
    elif command_exists apt-get; then
        echo "debian"
    elif command_exists dnf; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

# ── Uninstall ─────────────────────────────────────────────────────

do_uninstall() {
    step "Stopping services"
    if command_exists systemctl; then
        sudo systemctl disable --now vigild.service 2>/dev/null || true
        sudo systemctl disable --now vigil-scan.timer 2>/dev/null || true
        sudo systemctl stop vigil-scan.service 2>/dev/null || true
    fi

    step "Removing systemd units"
    for unit in vigild.service vigil-scan.service vigil-scan.timer; do
        if [ -f "${SYSTEMD_DIR}/${unit}" ]; then
            sudo rm -f "${SYSTEMD_DIR}/${unit}"
            info "Removed ${SYSTEMD_DIR}/${unit}"
        fi
    done
    if command_exists systemctl; then
        sudo systemctl daemon-reload
    fi

    step "Removing binaries"
    for bin in "$VIGIL_BIN" "$VIGILD_BIN" "$VIGIL_SYMLINK" "$VIGILD_SYMLINK"; do
        if [ -f "$bin" ] || [ -L "$bin" ]; then
            sudo rm -f "$bin"
            info "Removed $bin"
        fi
    done

    step "Removing package manager hooks"
    for hook in /etc/pacman.d/hooks/vigil-pre.hook /etc/pacman.d/hooks/vigil-post.hook; do
        if [ -f "$hook" ]; then
            sudo rm -f "$hook"
            info "Removed $hook"
        fi
    done
    if [ -f /etc/apt/apt.conf.d/99vigil ]; then
        sudo rm -f /etc/apt/apt.conf.d/99vigil
        info "Removed /etc/apt/apt.conf.d/99vigil"
    fi

    if $PURGE; then
        step "Purging data directories"
        for dir in "$DATA_DIR" "$LOG_DIR" "$RUN_DIR" "$CONFIG_DIR"; do
            if [ -d "$dir" ]; then
                sudo rm -rf "$dir"
                info "Removed $dir"
            fi
        done
    else
        info "Data preserved at ${DATA_DIR} and ${LOG_DIR}. Use --purge to remove."
    fi

    echo ""
    echo "✓ Vigil Baseline uninstalled."
}

# ── Check mode helpers ────────────────────────────────────────────

check_binary() {
    local name="$1" path="$2"
    if [ -f "$path" ]; then
        ok "$name ($path)"
    else
        miss "$name ($path)"
    fi
}

# ── Step functions ────────────────────────────────────────────────

step_deps() {
    step "Checking build dependencies"
    local distro
    distro=$(detect_distro)
    local missing=()

    # Required tools
    for cmd in rustc cargo gcc pkg-config; do
        if command_exists "$cmd"; then
            ok "$cmd"
        else
            miss "$cmd"
            missing+=("$cmd")
        fi
    done

    # Optional: notify-send
    if command_exists notify-send; then
        ok "notify-send (optional)"
    else
        miss "notify-send (optional — desktop notifications disabled)"
    fi

    if [ "$MODE" = "check" ]; then
        return 0
    fi

    if [ ${#missing[@]} -eq 0 ]; then
        return 0
    fi

    info ""
    info "Missing build dependencies: ${missing[*]}"

    local install_cmd=""
    case "$distro" in
        arch)
            install_cmd="sudo pacman -S --needed base-devel pkgconf rust"
            ;;
        debian)
            install_cmd="sudo apt-get install -y build-essential pkg-config rustc cargo"
            ;;
        fedora)
            install_cmd="sudo dnf install -y gcc pkgconf rust cargo"
            ;;
        *)
            info "Unknown distro. Please install manually: ${missing[*]}"
            return 1
            ;;
    esac

    info "Install command: $install_cmd"
    if confirm "Install missing dependencies?"; then
        eval "$install_cmd"
    else
        echo "Cannot proceed without build dependencies."
        exit 1
    fi
}

step_build() {
    step "Building from source"
    if [ "$MODE" = "check" ]; then
        if [ -f target/release/vigil ] && [ -f target/release/vigild ]; then
            ok "target/release/vigil"
            ok "target/release/vigild"
        else
            miss "Release binaries not built yet"
        fi
        return 0
    fi

    cargo build --release

    if [ ! -f target/release/vigil ] || [ ! -f target/release/vigild ]; then
        echo "error: Build succeeded but binaries not found."
        exit 1
    fi
    ok "target/release/vigil"
    ok "target/release/vigild"
}

step_install_binaries() {
    step "Installing binaries"
    if [ "$MODE" = "check" ]; then
        check_binary "vigil"  "$VIGIL_BIN"
        check_binary "vigild" "$VIGILD_BIN"
        check_binary "vigil symlink"  "$VIGIL_SYMLINK"
        check_binary "vigild symlink" "$VIGILD_SYMLINK"
        return 0
    fi

    sudo install -Dm755 target/release/vigil  "$VIGIL_BIN"
    sudo install -Dm755 target/release/vigild "$VIGILD_BIN"
    sudo ln -sf "$VIGIL_BIN"  "$VIGIL_SYMLINK"
    sudo ln -sf "$VIGILD_BIN" "$VIGILD_SYMLINK"
    ok "Installed vigil and vigild"
}

step_config() {
    step "Installing configuration"
    if [ "$MODE" = "check" ]; then
        if [ -f "$CONFIG_FILE" ]; then
            ok "Config exists at $CONFIG_FILE"
        else
            miss "Config not installed ($CONFIG_FILE)"
        fi
        return 0
    fi

    if [ -f "$CONFIG_FILE" ]; then
        info "Config exists at $CONFIG_FILE — preserving."
    else
        sudo install -Dm644 config/vigil.toml "$CONFIG_FILE"
        ok "Installed $CONFIG_FILE"
    fi
}

step_dirs() {
    step "Creating runtime directories"
    if [ "$MODE" = "check" ]; then
        for dir in "$DATA_DIR" "$LOG_DIR" "$RUN_DIR"; do
            if [ -d "$dir" ]; then
                ok "$dir"
            else
                miss "$dir"
            fi
        done
        return 0
    fi

    sudo install -d -m 750 "$DATA_DIR" "$LOG_DIR" "$RUN_DIR"
    ok "Created $DATA_DIR $LOG_DIR $RUN_DIR"
}

step_systemd() {
    step "Installing systemd units"
    local units=(vigild.service vigil-scan.service vigil-scan.timer)

    if [ "$MODE" = "check" ]; then
        for unit in "${units[@]}"; do
            if [ -f "${SYSTEMD_DIR}/${unit}" ]; then
                ok "$unit"
            else
                miss "$unit"
            fi
        done
        return 0
    fi

    sudo install -Dm644 systemd/vigild.service       "${SYSTEMD_DIR}/vigild.service"
    sudo install -Dm644 systemd/vigil-scan.service    "${SYSTEMD_DIR}/vigil-scan.service"
    sudo install -Dm644 systemd/vigil-scan.timer      "${SYSTEMD_DIR}/vigil-scan.timer"
    ok "Installed systemd units"
}

step_hooks() {
    step "Installing package manager hooks"
    local distro
    distro=$(detect_distro)

    if [ "$MODE" = "check" ]; then
        case "$distro" in
            arch)
                for hook in /etc/pacman.d/hooks/vigil-pre.hook /etc/pacman.d/hooks/vigil-post.hook; do
                    if [ -f "$hook" ]; then ok "$hook"; else miss "$hook"; fi
                done
                ;;
            debian)
                if [ -f /etc/apt/apt.conf.d/99vigil ]; then
                    ok "/etc/apt/apt.conf.d/99vigil"
                else
                    miss "/etc/apt/apt.conf.d/99vigil"
                fi
                ;;
            *)
                info "No supported package manager hooks for this distro."
                ;;
        esac
        return 0
    fi

    case "$distro" in
        arch)
            sudo install -Dm644 hooks/pacman/vigil-pre.hook  /etc/pacman.d/hooks/vigil-pre.hook
            sudo install -Dm644 hooks/pacman/vigil-post.hook /etc/pacman.d/hooks/vigil-post.hook
            ok "Installed pacman hooks"
            ;;
        debian)
            sudo install -Dm644 hooks/apt/99vigil /etc/apt/apt.conf.d/99vigil
            ok "Installed apt hook"
            ;;
        *)
            info "No supported package manager detected — skipping hooks."
            ;;
    esac
}

step_enable_services() {
    step "Enabling services"
    if [ "$MODE" = "check" ]; then
        if command_exists systemctl; then
            for svc in vigild.service vigil-scan.timer; do
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    ok "$svc"
                else
                    miss "$svc"
                fi
            done
        else
            miss "systemctl not available"
        fi
        return 0
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable --now vigild.service
    sudo systemctl enable --now vigil-scan.timer
    ok "Enabled vigild.service and vigil-scan.timer"
}

step_init_baseline() {
    step "Initializing baseline"
    if [ "$MODE" = "check" ]; then
        if [ -f "${DATA_DIR}/baseline.db" ]; then
            ok "Baseline database exists"
        else
            miss "Baseline database not initialized"
        fi
        return 0
    fi

    if ! vigil init --force; then
        echo ""
        echo "error: Baseline initialization failed."
        echo "       Check configuration at $CONFIG_FILE and watch paths."
        exit 1
    fi
    ok "Baseline initialized"
}

step_doctor() {
    step "Running diagnostics"
    if [ "$MODE" = "check" ]; then
        info "Would run: vigil doctor"
        return 0
    fi

    vigil doctor || true
}

step_summary() {
    local baseline_count
    baseline_count=$(sqlite3 "${DATA_DIR}/baseline.db" "SELECT COUNT(*) FROM baseline" 2>/dev/null || echo "?")

    local timer_next=""
    if command_exists systemctl; then
        timer_next=$(systemctl show vigil-scan.timer --property=NextElapseUSecRealtime --value 2>/dev/null | head -1 || echo "")
    fi

    echo ""
    echo "✓ Vigil Baseline installed and watching."
    echo "  Daemon:    vigild.service (running)"
    if [ -n "$timer_next" ]; then
        echo "  Timer:     vigil-scan.timer (active, next: ${timer_next})"
    else
        echo "  Timer:     vigil-scan.timer (active)"
    fi
    echo "  Baseline:  ${baseline_count} entries"
    echo "  Config:    ${CONFIG_FILE}"
    echo ""
    echo "  Your filesystem has a witness now."
}

# ── Main ──────────────────────────────────────────────────────────

main() {
    echo "Vigil Baseline setup"
    echo "==========="

    case "$MODE" in
        uninstall)
            do_uninstall
            exit 0
            ;;
        check)
            echo "(dry run — no changes will be made)"
            ;;
    esac

    step_deps
    step_build
    step_install_binaries
    step_config
    step_dirs
    step_systemd
    step_hooks

    if [ "$MODE" = "check" ]; then
        step_enable_services
        step_init_baseline
        step_doctor
        echo ""
        echo "Dry run complete. Run without --check to install."
        exit 0
    fi

    step_enable_services
    step_init_baseline
    step_doctor
    step_summary
}

main
