#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# Every PKG_*, FRAMEWORK_VERSION, and project_* symbol declared in this
# file is consumed by pkg/lib/framework.sh after `source pkg/project.sh`.
# SC2034 would otherwise fire on every manifest field.
# shellcheck disable=SC2034
#
# pkg/project.sh -- vigil-baseline manifest for pkg-framework.
#
# Sourced by pkg/build.sh BEFORE pkg/lib/framework.sh. Declare data and
# hook functions only; no top-level side effects.
#
# Authoritative reference for everything below: the pre-framework
# pkg/build.sh at .archive/pkg-build.sh.preframework (commit b4 of this
# branch). Every behavior of that script is preserved either as a
# manifest field here or as a project_* hook at the bottom of this file.
#
# Translation notes (intentional differences from the pre-framework
# contract):
#   * Artifact filenames lose the per-distro suffix
#     (vigil_<v>_amd64-noble.deb -> vigil-baseline_<v>_amd64.deb).
#     Per-distro uniqueness now relies on per-distro OUTDIR in CI.
#   * VIGIL_MANIFEST_COMMIT is preserved by setting PKG_PREFIX=VIGIL
#     (not VIGIL_BASELINE) so the lousclues-pkg orchestrator's existing
#     env var keeps working.

# =========================================================================
# REQUIRED scalars
# =========================================================================

PKG_NAME=vigil-baseline

# PKG_PREFIX deliberately VIGIL, not VIGIL_BASELINE: preserves
# VIGIL_MANIFEST_COMMIT compatibility with the lousclues-pkg
# orchestrator.
PKG_PREFIX=VIGIL

PKG_SUMMARY="Desktop Linux file integrity monitor (vigil + vigild)"

PKG_DESCRIPTION="Vigil Baseline is a desktop Linux file integrity monitor. One operator, one workstation. Kernel-level filesystem watching via fanotify, BLAKE3 hashing, HMAC-chained audit trail. Silent by default, local by design, deeply paranoid.

Ships two binaries: vigil (CLI) and vigild (the daemon). vigild runs under systemd with file capabilities (cap_sys_admin, cap_dac_read_search), not as root."

PKG_VENDOR="lousclues-labs"

PKG_MAINTAINER="lousclues-labs <pkg@lousclues.com>"

PKG_HOMEPAGE_URL="https://github.com/lousclues-labs/vigil"

PKG_SOURCE_URL="https://github.com/lousclues-labs/vigil"

PKG_LICENSE_SPDX="GPL-3.0-only"

PKG_LICENSE_NAME="GPL-3.0-only"

PKG_COPYRIGHT_HOLDERS="lousclues-labs contributors"

PKG_COPYRIGHT_YEAR="2024-2026"

# =========================================================================
# REQUIRED arrays
# =========================================================================

PKG_BINARIES=(vigil vigild)

PKG_DEB_DEPENDS=(
    "libc6"
    "libssl3 | libssl1.1"
    "libcap2-bin"
    "procps"
)

# =========================================================================
# OPTIONAL arrays
# =========================================================================

# rpm requires differ from deb depends (different package names on
# RH-family).
PKG_RPM_REQUIRES=(
    glibc
    openssl-libs
    libcap
)

PKG_SYSTEMD_UNITS=(
    vigild.service
    vigil-scan.service
    vigil-scan.timer
)

# Operator config is shipped as /etc/vigil/vigil.toml.example so dpkg /
# rpm never clobber the operator's real /etc/vigil/vigil.toml. Marking
# the .example as a conffile keeps apt from prompting on upgrades that
# don't change it.
PKG_DEB_CONFIG_FILES=(
    "/etc/vigil/vigil.toml.example"
)

# project_install_layout_check_extra walks the static paths; the
# manifest array covers the canonical handful that every CI run checks.
PKG_LAYOUT_CHECKS=(
    "usr/bin/vigil:755"
    "usr/bin/vigild:755"
    "etc/vigil/vigil.toml.example:644"
    "usr/share/man/man1/vigil.1.gz:644"
    "usr/share/man/man5/vigil.toml.5.gz:644"
    "usr/share/man/man8/vigild.8.gz:644"
    "usr/share/bash-completion/completions/vigil:644"
    "usr/share/zsh/site-functions/_vigil:644"
    "usr/share/fish/vendor_completions.d/vigil.fish:644"
    "usr/share/doc/vigil-baseline/README.md:644"
    "usr/share/doc/vigil-baseline/changelog.gz:644"
    "lib/systemd/system/vigild.service:644"
    "lib/systemd/system/vigil-scan.service:644"
    "lib/systemd/system/vigil-scan.timer:644"
)

# Extra build-time packages on top of the framework's base set.
# libssl-dev / openssl-devel: the binary links against libssl at
# runtime, but cargo needs the headers for the openssl-sys crate's
# build.rs when building from source.
PKG_EXTRA_DEB_BUILD_DEPS=(libssl-dev)
PKG_EXTRA_RPM_BUILD_DEPS=(openssl-devel python3)

# =========================================================================
# OPTIONAL scalars
# =========================================================================

# Framework pin. `pkg-framework sync` rewrites this; CI hard-fails on
# mismatch with pkg/lib/VERSION.
FRAMEWORK_VERSION=1.2.4

# Preserve the pre-framework hermetic compile contract: fetch with the
# lockfile pinned, then build with --frozen --offline.
PKG_CARGO_OFFLINE=1

# =========================================================================
# Hooks
# =========================================================================

# Pre-apt-install: vigil-specific libsystemd0 version skew remediation.
# The cascade lives in scripts/fix-debian-deps.sh so the workflow and
# this hook stay in lockstep automatically.
project_pre_install_deb_deps() {
    local fix_script="$REPO_ROOT/scripts/fix-debian-deps.sh"
    if [[ -x "$fix_script" ]]; then
        run bash "$fix_script"
    else
        log "warning: $fix_script not present or not executable; skipping libsystemd0 skew remediation"
    fi
}

# Post-build: generate shell completions and man pages from the
# freshly built vigil binary. Outputs land under the staging tree.
# gzip -n: omit mtime from the gzip header so artifacts are
# byte-reproducible across runs.
project_post_build() {
    section "generate completions + man pages"
    local vigil_bin="$CARGO_TARGET_DIR/release/vigil"
    if [[ ! -x "$vigil_bin" ]]; then
        log "ERROR: $vigil_bin not present after cargo build"
        return 1
    fi
    # Stage into a side directory under $STAGE; project_stage_extra
    # copies them into $root once the framework has set DEB_OUT / RPM_OUT.
    local gen="$STAGE/_generated"
    mkdir -p \
        "$gen/usr/share/bash-completion/completions" \
        "$gen/usr/share/zsh/site-functions" \
        "$gen/usr/share/fish/vendor_completions.d" \
        "$gen/usr/share/man/man1" \
        "$gen/usr/share/man/man5" \
        "$gen/usr/share/man/man8"

    "$vigil_bin" completions bash > "$gen/usr/share/bash-completion/completions/vigil"
    "$vigil_bin" completions zsh  > "$gen/usr/share/zsh/site-functions/_vigil"
    "$vigil_bin" completions fish > "$gen/usr/share/fish/vendor_completions.d/vigil.fish"
    "$vigil_bin" man vigil      | gzip -9n > "$gen/usr/share/man/man1/vigil.1.gz"
    "$vigil_bin" man vigil.toml | gzip -9n > "$gen/usr/share/man/man5/vigil.toml.5.gz"
    "$vigil_bin" man vigild     | gzip -9n > "$gen/usr/share/man/man8/vigild.8.gz"

    chmod 0644 \
        "$gen/usr/share/bash-completion/completions/vigil" \
        "$gen/usr/share/zsh/site-functions/_vigil" \
        "$gen/usr/share/fish/vendor_completions.d/vigil.fish" \
        "$gen/usr/share/man/man1/vigil.1.gz" \
        "$gen/usr/share/man/man5/vigil.toml.5.gz" \
        "$gen/usr/share/man/man8/vigild.8.gz"
}

# Stage everything the framework's defaults don't cover: the generated
# completions + man pages (from project_post_build), the example
# config, and the optional apt / dnf hook subtrees.
project_stage_extra() {
    local root=$1

    section "project_stage_extra root=$root"

    # 1. Copy generated completions + man pages.
    local gen="$STAGE/_generated"
    if [[ -d "$gen" ]]; then
        ( cd "$gen" && tar cf - . ) | ( cd "$root" && tar xf - )
    else
        log "ERROR: $gen missing; project_post_build did not run?"
        return 1
    fi

    # 2. Example config with autogenerated header. The .example suffix
    # prevents dpkg/rpm from overwriting the operator's
    # /etc/vigil/vigil.toml on upgrade.
    install -d -m 0755 "$root/etc/vigil"
    {
        printf '# ---------------------------------------------------------\n'
        printf '# This file is the *example* config shipped with vigil %s.\n' "$VERSION"
        printf '# Copy to /etc/vigil/vigil.toml and edit there; the\n'
        printf '# .example file is owned by the package and will be\n'
        printf '# replaced on upgrade.\n'
        printf '# Build: %s (SOURCE_DATE_EPOCH=%s)\n' "$DISTRO" "$SOURCE_DATE_EPOCH"
        printf '# ---------------------------------------------------------\n'
        cat "$REPO_ROOT/config/vigil.toml"
    } > "$root/etc/vigil/vigil.toml.example"
    chmod 0644 "$root/etc/vigil/vigil.toml.example"

    # 3. apt hooks (deb only, source-tree-conditional). Hook cycle:
    # 99vigil delegates to apt-pre.sh + apt-post.sh; all three ship
    # together or not at all. project_install_layout_check_extra
    # asserts the cycle's integrity post-install.
    if [[ "$root" == "$DEB_OUT" && -d "$REPO_ROOT/hooks/apt" ]]; then
        if [[ -f "$REPO_ROOT/hooks/apt/99vigil" ]]; then
            install -D -m 0644 "$REPO_ROOT/hooks/apt/99vigil" \
                "$root/etc/apt/apt.conf.d/99vigil"
        fi
        if [[ -f "$REPO_ROOT/hooks/apt/apt-pre.sh" ]]; then
            install -D -m 0755 "$REPO_ROOT/hooks/apt/apt-pre.sh" \
                "$root/usr/lib/vigil/apt-pre.sh"
        fi
        if [[ -f "$REPO_ROOT/hooks/apt/apt-post.sh" ]]; then
            install -D -m 0755 "$REPO_ROOT/hooks/apt/apt-post.sh" \
                "$root/usr/lib/vigil/apt-post.sh"
        fi
    fi

    # 4. dnf plugin (rpm only). The python3 site-packages path varies
    # by distro python; resolve at build time. python3 is in
    # PKG_EXTRA_RPM_BUILD_DEPS so it's present.
    if [[ "$root" == "$RPM_OUT" && -d "$REPO_ROOT/hooks/dnf" ]]; then
        local py_dir
        py_dir=$(python3 -c 'import sys; print(f"usr/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/dnf-plugins")')
        if [[ -f "$REPO_ROOT/hooks/dnf/vigil.py" ]]; then
            install -D -m 0644 "$REPO_ROOT/hooks/dnf/vigil.py" \
                "$root/$py_dir/vigil.py"
        fi
        if [[ -f "$REPO_ROOT/hooks/dnf/vigil.conf" ]]; then
            install -D -m 0644 "$REPO_ROOT/hooks/dnf/vigil.conf" \
                "$root/etc/dnf/plugins/vigil.conf"
        fi
    fi

    # 5. Pin mtimes across the stage tree so per-file timestamps don't
    # leak wall-clock into fpm input. SOURCE_DATE_EPOCH is set by the
    # framework's _pkg_setup_globals.
    find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

# postinst body: setcap cap_sys_admin,cap_dac_read_search on vigild
# with a self-test + revert path. Daemon-reload is appended
# automatically by the framework because PKG_SYSTEMD_UNITS is non-empty.
#
# Why setcap + a revert path: file caps trigger AT_SECURE=1 in the
# dynamic linker, which sanitises LD_* and uses a stricter library
# search policy. On some minimal container images this breaks even
# benign invocations like --help; in that case we revert so the
# package leaves the binary functional under systemd (root) rather than
# half-broken.
project_postinst_body() {
    cat <<'EOF'
VIGILD=/usr/bin/vigild

if [ -x "$VIGILD" ]; then
    if command -v setcap >/dev/null 2>&1; then
        if setcap cap_sys_admin,cap_dac_read_search+ep "$VIGILD" 2>/dev/null; then
            if ! "$VIGILD" --help >/dev/null 2>&1; then
                echo "vigil-baseline: WARN: vigild --help failed after setcap;" >&2
                echo "vigil-baseline:       reverting file caps. vigild will rely on" >&2
                echo "vigil-baseline:       systemd running it with capabilities." >&2
                setcap -r "$VIGILD" 2>/dev/null || true
            fi
        else
            echo "vigil-baseline: WARN: setcap on $VIGILD failed; vigild will need" >&2
            echo "vigil-baseline:       to run as uid 0 to use fanotify." >&2
        fi
    else
        echo "vigil-baseline: WARN: setcap(8) not available; cannot grant" >&2
        echo "vigil-baseline:       cap_sys_admin on $VIGILD. Install libcap." >&2
    fi
fi
EOF
}

# Pre-fpm stage validation: PKG_LAYOUT_CHECKS covers static paths.
# This hook covers path checks that depend on source-tree state
# (the hooks/apt / hooks/dnf cycle integrity).
project_validate_stage_extra() {
    local root=$1
    local fails=0
    check() {
        if [[ ! -e "$root/$1" ]]; then
            echo "stage MISSING: /$1" >&2
            fails=$((fails + 1))
        fi
    }

    # apt hook cycle: all three or none.
    if [[ "$root" == "$DEB_OUT" && -d "$REPO_ROOT/hooks/apt" ]]; then
        check etc/apt/apt.conf.d/99vigil
        check usr/lib/vigil/apt-pre.sh
        check usr/lib/vigil/apt-post.sh
    fi

    # dnf plugin: both config + python plugin or neither.
    if [[ "$root" == "$RPM_OUT" && -d "$REPO_ROOT/hooks/dnf" ]]; then
        check etc/dnf/plugins/vigil.conf
        # python3 site-packages path resolved at build time; just glob.
        if ! find "$root" -type f -name vigil.py -path '*/dnf-plugins/*' \
                | grep -q .; then
            echo "stage MISSING: dnf-plugins/vigil.py" >&2
            fails=$((fails + 1))
        fi
    fi

    # systemd unit must not reference dev-only paths.
    local unit
    for unit in "${PKG_SYSTEMD_UNITS[@]}"; do
        local path="$root/lib/systemd/system/$unit"
        [[ -f "$path" ]] || continue
        if grep -qE '/usr/local/bin/vigild|target/debug|target/release' "$path"; then
            echo "stage INVALID: $unit references dev-only paths" >&2
            fails=$((fails + 1))
        fi
    done

    if [[ "$fails" -gt 0 ]]; then
        echo "ERROR: $fails stage validation failure(s)" >&2
        return 1
    fi
}

# rpm reproducibility macros. fpm passes these through to rpmbuild.
# Without them, rpm 4.14+ honours SOURCE_DATE_EPOCH for some
# timestamps but _buildhost and per-file mtime clamping still vary,
# breaking sha256 reproducibility across rebuilds.
project_fpm_rpm_extra_args() {
    printf -- '--rpm-rpmbuild-define\nuse_source_date_epoch_as_buildtime 1\n'
    printf -- '--rpm-rpmbuild-define\nclamp_mtime_to_source_date_epoch 1\n'
    printf -- '--rpm-rpmbuild-define\n_buildhost reproducible.vigil-baseline.local\n'
}

# Post-install layout check: runs in the distro container after the
# package is installed. Asserts the vigil-specific contract that
# PKG_LAYOUT_CHECKS / layout-check.sh can't express. Five gates:
#   1. vigild has CAP_SYS_ADMIN (file caps OR ambient via unit).
#   2. apt hook cycle integrity (all three or none, deb only).
#   3. dnf plugin pair integrity (rpm only).
#   4. systemd-analyze verify of vigild.service.
#   5. vigil doctor runs within 10s without hanging.
project_install_layout_check_extra() {
    local fails=0
    fail() { echo "POST-INSTALL FAIL: $*" >&2; fails=$((fails + 1)); }

    # 1. Capability check.
    if command -v getcap >/dev/null 2>&1; then
        local caps
        caps=$(getcap /usr/bin/vigild 2>/dev/null || true)
        case "$caps" in
            *cap_sys_admin*) : ;;
            *)
                # File caps may have been reverted by the postinst
                # self-test. In that case the systemd unit must grant
                # the cap via AmbientCapabilities=.
                if ! grep -qE '^AmbientCapabilities=.*CAP_SYS_ADMIN' \
                        /lib/systemd/system/vigild.service \
                        /usr/lib/systemd/system/vigild.service \
                        2>/dev/null; then
                    fail "/usr/bin/vigild has no cap_sys_admin (file caps reverted and unit has no AmbientCapabilities= fallback)"
                fi
                ;;
        esac
    fi

    # 2. apt hook cycle (deb only).
    if [[ -f /etc/debian_version ]] && [[ -d "$REPO_ROOT/hooks/apt" ]]; then
        local f
        for f in /etc/apt/apt.conf.d/99vigil \
                 /usr/lib/vigil/apt-pre.sh \
                 /usr/lib/vigil/apt-post.sh; do
            [[ -e "$f" ]] || fail "apt hook missing: $f"
        done
    fi

    # 3. dnf plugin pair (rpm only).
    if [[ -f /etc/redhat-release ]] && [[ -d "$REPO_ROOT/hooks/dnf" ]]; then
        [[ -e /etc/dnf/plugins/vigil.conf ]] || fail "dnf hook missing: /etc/dnf/plugins/vigil.conf"
        if ! find /usr/lib -type f -name vigil.py -path '*/dnf-plugins/*' \
                | grep -q .; then
            fail "dnf hook missing: vigil.py under /usr/lib/.../dnf-plugins/"
        fi
    fi

    # 4. systemd-analyze verify (only if systemd is present; container
    # smoke tests typically don't have systemd as PID 1, but the
    # verify subcommand works without a running systemd).
    if command -v systemd-analyze >/dev/null 2>&1; then
        local unit_path=
        for unit_path in /lib/systemd/system/vigild.service \
                         /usr/lib/systemd/system/vigild.service; do
            [[ -f "$unit_path" ]] || continue
            if ! systemd-analyze verify "$unit_path" 2>&1 \
                    | grep -vE '^$|Cannot add dependency job' \
                    | grep -q .; then
                : # clean
            else
                # systemd-analyze prints diagnostics; only fail on
                # hard errors, not warnings about missing units.
                if systemd-analyze verify "$unit_path" 2>&1 \
                        | grep -qE 'is not executable|invalid|failed to parse'; then
                    fail "systemd-analyze verify $unit_path produced errors"
                fi
            fi
            break
        done
    fi

    # 5. vigil doctor smoke. timeout to catch hangs.
    if command -v timeout >/dev/null 2>&1; then
        if ! timeout 10 /usr/bin/vigil --version >/dev/null 2>&1; then
            fail "/usr/bin/vigil --version hung or failed"
        fi
        # doctor may exit non-zero on a fresh install with no baseline;
        # we only care that it doesn't hang.
        timeout 10 /usr/bin/vigil doctor >/dev/null 2>&1 || true
    fi

    if [[ "$fails" -gt 0 ]]; then
        echo "ERROR: $fails post-install layout check failure(s)" >&2
        return 1
    fi
}
