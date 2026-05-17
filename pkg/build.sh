#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# pkg/build.sh -- source-project contract for lousclues-pkg.
#
# Reads DISTRO, VERSION, OUTDIR from the environment, emits exactly
# one .deb or .rpm into OUTDIR per invocation, and exits non-zero on
# any failure. The release-build workflow in lousclues-labs/lousclues-pkg
# invokes this script inside a container matching each target distro.
# The local merge-blocking gate is .github/workflows/pkg-build.yml.
#
# Supported DISTRO values:
#   noble    -- Ubuntu 24.04   -> .deb
#   jammy    -- Ubuntu 22.04   -> .deb
#   bookworm -- Debian 12      -> .deb
#   el9      -- Rocky 9        -> .rpm
#   fedora   -- Fedora latest  -> .rpm
#
# Exit codes (contract):
#   0 -- success, exactly one artifact in OUTDIR
#   1 -- required env var missing, or build step failed
#   2 -- invalid env-var value (leading 'v' in VERSION, relative
#        OUTDIR, mismatch with Cargo.toml, unknown DISTRO, ...)
#
# Optional knobs:
#   SOURCE_DATE_EPOCH      reproducible-build mtime + fpm timestamps
#   VIGIL_SKIP_DEPS=1      skip apt-get/dnf install of system build deps
#   VIGIL_SKIP_TOOLCHAIN=1 skip rustup + gem install fpm
#   VIGIL_CARGO_TARGET_DIR override CARGO_TARGET_DIR (default: target)
#
# Reference: lousclues-labs/lousclues-pkg/docs/operator-runbook-releases.md

set -euo pipefail

# ─── 1. Required env (contract pinned by .github/workflows/pkg-build.yml) ───
: "${DISTRO:?DISTRO must be set (one of: noble, jammy, bookworm, el9, fedora)}"
: "${VERSION:?VERSION must be set (semver, no leading v)}"
: "${OUTDIR:?OUTDIR must be set (absolute path; one .deb or .rpm emitted here)}"

# ─── 2. Input validation. Exit code 2 = invalid value. ───
# Reject leading 'v' in VERSION. The contract is semver only.
case "$VERSION" in
    v*)
        echo "ERROR: VERSION must not have a leading 'v' (got: '$VERSION')" >&2
        echo "       Pass the semver string directly, e.g. VERSION=1.11.4 not v1.11.4." >&2
        exit 2
        ;;
esac

# Reject relative OUTDIR. The release pipeline always passes an absolute
# path; refusing relative paths prevents accidental writes into the repo
# tree on local invocations.
case "$OUTDIR" in
    /*) ;;
    *)
        echo "ERROR: OUTDIR must be an absolute path (got: '$OUTDIR')" >&2
        exit 2
        ;;
esac

# VERSION must match Cargo.toml. Catches operator typos and prevents
# producing a package whose internal version disagrees with the source
# tree it was built from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"
if [ ! -f "$CARGO_TOML" ]; then
    echo "ERROR: Cargo.toml not found at $CARGO_TOML" >&2
    exit 2
fi
CARGO_VERSION=$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$CARGO_TOML")
if [ -z "$CARGO_VERSION" ]; then
    echo "ERROR: could not parse version from $CARGO_TOML" >&2
    exit 2
fi
if [ "$VERSION" != "$CARGO_VERSION" ]; then
    echo "ERROR: VERSION '$VERSION' does not match Cargo.toml version '$CARGO_VERSION'" >&2
    echo "       The packaging pipeline must build the version the source tree advertises." >&2
    exit 2
fi

mkdir -p "$OUTDIR"

# ─── 3. Global environment. Hermetic, reproducible, quiet. ───
umask 022
export LC_ALL=C
export TZ=UTC
export CARGO_NET_RETRY=10
export CARGO_INCREMENTAL=0
export CARGO_TERM_COLOR=always
export RUSTFLAGS="${RUSTFLAGS:-} -C debuginfo=0 -C strip=symbols"

if [ -n "${VIGIL_CARGO_TARGET_DIR:-}" ]; then
    export CARGO_TARGET_DIR="$VIGIL_CARGO_TARGET_DIR"
else
    export CARGO_TARGET_DIR="$REPO_ROOT/target"
fi

# SOURCE_DATE_EPOCH: prefer caller's value; else last git commit time;
# else a pinned constant (matches the workflow's shallow-clone fallback).
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if SDE=$(cd "$REPO_ROOT" && git log -1 --pretty=%ct 2>/dev/null) && [ -n "$SDE" ]; then
        export SOURCE_DATE_EPOCH="$SDE"
    else
        export SOURCE_DATE_EPOCH=1700000000
    fi
fi

# Staging area. Cleaned on exit; preserved on failure if VIGIL_KEEP_STAGE=1.
STAGE="$(mktemp -d -t vigil-stage.XXXXXX)"
trap '[ "${VIGIL_KEEP_STAGE:-0}" = "1" ] || rm -rf "$STAGE"' EXIT

# ─── 4. Helpers. ───
log()    { printf '[pkg/build.sh] %s\n' "$*" >&2; }
section(){ printf '\n[pkg/build.sh] ── %s ──\n' "$*" >&2; }
run()    { log "+ $*"; "$@"; }

# install_to <mode> <src> <dst-under-STAGE>
install_to() {
    local mode="$1" src="$2" dst="$STAGE/$3"
    install -Dm"$mode" "$src" "$dst"
}

# ─── 5. System build dependencies. ───
install_deb_deps() {
    [ "${VIGIL_SKIP_DEPS:-0}" = "1" ] && { log "VIGIL_SKIP_DEPS=1; skipping apt-get install"; return 0; }
    section "install_deb_deps"
    export DEBIAN_FRONTEND=noninteractive
    run apt-get update -qq
    # Defensive: some bookworm and jammy container images ship with a
    # partially-upgraded systemd dep chain (libsystemd0 was bumped but
    # libcryptsetup12 / libfdisk1 / libkmod2 / libsystemd-shared etc.
    # were not), and any subsequent apt-get install then trips on
    # 'unmet dependencies: systemd : Depends: libcryptsetup12 ...'
    # with exit 100.
    #
    # Two remediation passes before our real install:
    #   1. dist-upgrade pulls held-back libs forward to match the
    #      package they're depended on by (the standard apt term for
    #      'resolve everything to a consistent state').
    #   2. `install -f` (no packages) is a narrower fallback that
    #      asks apt to fix any remaining broken state.
    # Both are silenced + `|| true` so they never regress the common
    # case where state is already clean. If neither fixes the cascade,
    # the real install below fails the same way it would have without
    # these lines -- nothing lost.
    apt-get -y --no-install-recommends dist-upgrade >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends -f >/dev/null 2>&1 || true
    # strip-nondeterminism: post-processes .deb to scrub embedded
    # timestamps that fpm does not honour SOURCE_DATE_EPOCH for
    # (ar entry mtimes, gzip headers, tar entry mtimes/ordering).
    run apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential pkg-config libssl-dev \
        ruby ruby-dev rubygems file strip-nondeterminism
}

install_rpm_deps() {
    [ "${VIGIL_SKIP_DEPS:-0}" = "1" ] && { log "VIGIL_SKIP_DEPS=1; skipping dnf install"; return 0; }
    section "install_rpm_deps"
    # NOTE on strip-nondeterminism (deliberately NOT installed on RPM):
    #   The Debian `strip-nondeterminism` tool is Debian-native -- the
    #   underlying File::StripNondeterminism distribution has never been
    #   uploaded to CPAN (verified: metacpan download_url returns 404).
    #   The binary is also not packaged for Fedora or EPEL.
    #
    #   AND: even if installed, strip-nondeterminism has NO handler for
    #   the .rpm file format (its handlers/ tree covers ar/cpio/gzip/zip/
    #   jar/png/etc. only). Running it on an .rpm is a no-op.
    #
    #   RPM reproducibility therefore rides entirely on the rpmbuild
    #   macros passed via fpm in fpm_rpm():
    #     - use_source_date_epoch_as_buildtime 1  (rpm 4.14+)
    #     - clamp_mtime_to_source_date_epoch 1    (rpm 4.18+, fedora)
    #     - _buildhost reproducible.vigil-baseline.local  (all rpm)
    #   plus the SOURCE_DATE_EPOCH env var which rpm 4.14+ honours.
    #
    # --allowerasing handles curl-minimal -> curl on fedora.
    run dnf install -y --allowerasing --setopt=install_weak_deps=False \
        ca-certificates curl gcc gcc-c++ pkgconf-pkg-config openssl-devel \
        ruby ruby-devel rubygems rubygem-json rpm-build python3 file
}

# ─── 6. Rust toolchain + fpm. ───
ensure_toolchain() {
    [ "${VIGIL_SKIP_TOOLCHAIN:-0}" = "1" ] && { log "VIGIL_SKIP_TOOLCHAIN=1; assuming cargo+fpm on PATH"; return 0; }
    section "ensure_toolchain"
    if ! command -v cargo >/dev/null 2>&1; then
        run curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            -o /tmp/rustup-init.sh
        run sh /tmp/rustup-init.sh -y --default-toolchain stable --profile minimal
        # shellcheck source=/dev/null
        . "$HOME/.cargo/env"
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    if ! command -v fpm >/dev/null 2>&1; then
        run gem install --no-document fpm
        # Default rubygems bin dir varies; surface it for fpm calls.
        local gem_bin
        gem_bin=$(gem environment gemdir)/bin
        export PATH="$gem_bin:$PATH"
    fi
    run cargo --version
    run fpm --version
}

# ─── 7. Build the two binaries. ───
build_binaries() {
    section "build_binaries"
    # Two-step pattern to keep the compile step provably offline while
    # still tolerating a cold registry cache (the default state on a
    # fresh GitHub Actions runner where no prior cargo invocation has
    # populated ~/.cargo/registry/index).
    #
    #   1. cargo fetch --locked       network allowed, lockfile pinned
    #   2. cargo build --frozen --offline   network refused, lockfile pinned
    #
    # --locked alone (no --frozen) on step 1 means: do not regenerate
    # Cargo.lock; resolution must match the committed lock exactly.
    # --frozen on step 2 implies --locked AND --offline, which gives
    # us the audit-friendly "this compile touched no network" property.
    run cargo fetch --locked --manifest-path "$REPO_ROOT/Cargo.toml"
    run cargo build --release --frozen --offline \
        --bin vigil --bin vigild \
        --manifest-path "$REPO_ROOT/Cargo.toml"
}

# ─── 8. Stage the on-disk layout. ───
# Arg 1: unit_dir (deb: /lib/systemd/system, rpm: /usr/lib/systemd/system)
stage_assets() {
    section "stage_assets unit_dir=$1"
    local unit_dir="$1"
    local bin_dir=usr/bin
    local etc_dir=etc/vigil
    local man1=usr/share/man/man1
    local man5=usr/share/man/man5
    local man8=usr/share/man/man8
    local bash_dir=usr/share/bash-completion/completions
    local zsh_dir=usr/share/zsh/site-functions
    local fish_dir=usr/share/fish/vendor_completions.d
    local doc_dir=usr/share/doc/vigil

    # ── Binaries ──
    install_to 755 "$CARGO_TARGET_DIR/release/vigil"  "$bin_dir/vigil"
    install_to 755 "$CARGO_TARGET_DIR/release/vigild" "$bin_dir/vigild"

    # ── systemd units. Strip leading slash from unit_dir for STAGE join. ──
    local unit_rel="${unit_dir#/}"
    install_to 644 "$REPO_ROOT/systemd/vigild.service"      "$unit_rel/vigild.service"
    install_to 644 "$REPO_ROOT/systemd/vigil-scan.service"  "$unit_rel/vigil-scan.service"
    install_to 644 "$REPO_ROOT/systemd/vigil-scan.timer"    "$unit_rel/vigil-scan.timer"

    # ── Config example (marked as conffile in fpm calls). ──
    # Prepend an autogenerated header so operators know not to edit
    # the .example file in place. The .example suffix prevents
    # dpkg/rpm from overwriting an operator's /etc/vigil/vigil.toml
    # on upgrade.
    mkdir -p "$STAGE/$etc_dir"
    {
        printf '# ───────────────────────────────────────────────────────────\n'
        printf '# This file is the *example* config shipped with vigil %s.\n' "$VERSION"
        printf '# Copy to /etc/vigil/vigil.toml and edit there; the .example\n'
        printf '# file is owned by the package and will be replaced on upgrade.\n'
        printf '# Build: %s (SOURCE_DATE_EPOCH=%s)\n' "$DISTRO" "$SOURCE_DATE_EPOCH"
        printf '# ───────────────────────────────────────────────────────────\n'
        cat "$REPO_ROOT/config/vigil.toml"
    } > "$STAGE/$etc_dir/vigil.toml.example"
    chmod 0644 "$STAGE/$etc_dir/vigil.toml.example"

    # ── Shell completions (generated by the freshly built vigil). ──
    local vigil_bin="$CARGO_TARGET_DIR/release/vigil"
    mkdir -p "$STAGE/$bash_dir" "$STAGE/$zsh_dir" "$STAGE/$fish_dir"
    "$vigil_bin" completions bash > "$STAGE/$bash_dir/vigil"
    "$vigil_bin" completions zsh  > "$STAGE/$zsh_dir/_vigil"
    "$vigil_bin" completions fish > "$STAGE/$fish_dir/vigil.fish"
    chmod 0644 "$STAGE/$bash_dir/vigil" "$STAGE/$zsh_dir/_vigil" "$STAGE/$fish_dir/vigil.fish"

    # ── Man pages (generated by `vigil man`; gzipped with -n for
    # reproducibility -- gzip without -n embeds mtime in the header). ──
    mkdir -p "$STAGE/$man1" "$STAGE/$man5" "$STAGE/$man8"
    "$vigil_bin" man vigil      | gzip -9n > "$STAGE/$man1/vigil.1.gz"
    "$vigil_bin" man vigil.toml | gzip -9n > "$STAGE/$man5/vigil.toml.5.gz"
    "$vigil_bin" man vigild     | gzip -9n > "$STAGE/$man8/vigild.8.gz"
    chmod 0644 "$STAGE/$man1/vigil.1.gz" "$STAGE/$man5/vigil.toml.5.gz" "$STAGE/$man8/vigild.8.gz"

    # ── Package-manager hooks. Source-tree conditional: only install
    # when the hooks/ subtree is present in the repo. The workflow's
    # layout-check is symmetrically conditional.
    #
    # apt hook layout (split because apt.conf(5) has no \"-escape):
    #   /etc/apt/apt.conf.d/99vigil   -- two-line config delegating to
    #   /usr/lib/vigil/apt-pre.sh     -- pre-invoke maintenance enter
    #   /usr/lib/vigil/apt-post.sh    -- post-invoke baseline refresh
    if [ "${FPM_TARGET:-}" = "deb" ] && [ -d "$REPO_ROOT/hooks/apt" ]; then
        if [ -f "$REPO_ROOT/hooks/apt/99vigil" ]; then
            install_to 644 "$REPO_ROOT/hooks/apt/99vigil" \
                "etc/apt/apt.conf.d/99vigil"
        fi
        if [ -f "$REPO_ROOT/hooks/apt/apt-pre.sh" ]; then
            install_to 755 "$REPO_ROOT/hooks/apt/apt-pre.sh" \
                "usr/lib/vigil/apt-pre.sh"
        fi
        if [ -f "$REPO_ROOT/hooks/apt/apt-post.sh" ]; then
            install_to 755 "$REPO_ROOT/hooks/apt/apt-post.sh" \
                "usr/lib/vigil/apt-post.sh"
        fi
    fi
    if [ -d "$REPO_ROOT/hooks/dnf" ] && [ "${FPM_TARGET:-}" = "rpm" ]; then
        # DNF4 plugin layout: /usr/lib/python3.X/site-packages/dnf-plugins/
        # We resolve the path inside the build container at build time
        # because python3.X varies (el9: 3.9, fedora 40+: 3.12+).
        local py_dir
        py_dir=$(python3 -c 'import sys; print(f"usr/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/dnf-plugins")')
        install_to 644 "$REPO_ROOT/hooks/dnf/vigil.py"   "$py_dir/vigil.py"
        install_to 644 "$REPO_ROOT/hooks/dnf/vigil.conf" "etc/dnf/plugins/vigil.conf"
    fi

    # ── Documentation. ──
    install_to 644 "$REPO_ROOT/README.md" "$doc_dir/README.md"
    # changelog.gz: dpkg policy requires changelog.Debian.gz for native
    # changelogs; for upstream-only software, /usr/share/doc/<pkg>/changelog.gz
    # satisfies both the lintian rule and the rpm convention.
    gzip -9nc "$REPO_ROOT/CHANGELOG.md" > "$STAGE/$doc_dir/changelog.gz"
    chmod 0644 "$STAGE/$doc_dir/changelog.gz"
    if [ "${FPM_TARGET:-}" = "deb" ]; then
        emit_debian_copyright > "$STAGE/$doc_dir/copyright"
        chmod 0644 "$STAGE/$doc_dir/copyright"
    else
        install_to 644 "$REPO_ROOT/LICENSE" "$doc_dir/LICENSE"
    fi

    # ── Reproducibility: pin all mtimes to SOURCE_DATE_EPOCH. ──
    # find -exec touch is the GNU-coreutils-portable form.
    find "$STAGE" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

# ─── 9. Debian copyright file (machine-readable format 1.0). ───
emit_debian_copyright() {
    cat <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: vigil-baseline
Upstream-Contact: lousclues-labs/vigil <https://github.com/lousclues-labs/vigil>
Source: https://github.com/lousclues-labs/vigil

Files: *
Copyright: 2024-$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y) lousclues-labs contributors
License: GPL-3.0-only
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, version 3.
 .
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 General Public License for more details.
 .
 On Debian systems, the complete text of the GNU General Public
 License version 3 can be found in /usr/share/common-licenses/GPL-3.
EOF
}

# ─── 10. postinst scriptlet. ───
# Two responsibilities:
#   1. setcap cap_sys_admin,cap_dac_read_search+ep on /usr/bin/vigild
#      (replaces the AmbientCapabilities= line we deliberately removed
#      from the systemd unit -- file caps are narrower).
#   2. daemon-reload so systemd picks up the unit, but never enable
#      or start vigild on install: operators opt in explicitly.
emit_postinst() {
    cat <<'EOF'
#!/bin/sh
# vigil postinst -- file caps + daemon-reload (no enable/start).
set -eu

VIGILD=/usr/bin/vigild

if [ -x "$VIGILD" ]; then
    if command -v setcap >/dev/null 2>&1; then
        if ! setcap cap_sys_admin,cap_dac_read_search+ep "$VIGILD"; then
            echo "vigil-baseline: WARN: setcap on $VIGILD failed; vigild will need" >&2
            echo "vigil-baseline:       to run as uid 0 to use fanotify." >&2
        fi
    else
        echo "vigil-baseline: WARN: setcap(8) not available; cannot grant" >&2
        echo "vigil-baseline:       cap_sys_admin on $VIGILD. Install libcap." >&2
    fi
fi

# Pick up unit changes if systemd is the init.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF
}

# ─── 11. fpm invocations. ───
# Naming: must match the contract pinned by the lousclues-pkg
# release-build workflow and asserted by the local pkg-build gate.
fpm_deb() {
    section "fpm_deb"
    local out="$OUTDIR/vigil_${VERSION}_amd64-${DISTRO}.deb"
    local postinst
    postinst="$(mktemp -t vigil-postinst.XXXXXX)"
    emit_postinst > "$postinst"
    chmod 0755 "$postinst"
    # Pin the tempfile mtime: fpm captures it into control.tar.gz and
    # mktemp leaves it at wall-clock time, which breaks reproducibility.
    touch -h -d "@$SOURCE_DATE_EPOCH" "$postinst"

    rm -f "$out"
    run fpm \
        --input-type dir \
        --output-type deb \
        --name vigil-baseline \
        --version "$VERSION" \
        --iteration "1.${DISTRO}" \
        --architecture amd64 \
        --license 'GPL-3.0-only' \
        --maintainer 'lousclues-labs <pkg@lousclues.com>' \
        --vendor 'lousclues-labs' \
        --url 'https://github.com/lousclues-labs/vigil' \
        --description 'Vigil Baseline -- desktop Linux file integrity monitor (vigil + vigild).' \
        --depends 'libc6' \
        --depends 'libssl3 | libssl1.1' \
        --depends 'libcap2-bin' \
        --deb-recommends 'libnotify-bin' \
        --deb-suggests 'apt' \
        --deb-no-default-config-files \
        --config-files /etc/vigil/vigil.toml.example \
        --after-install "$postinst" \
        --package "$out" \
        --chdir "$STAGE" \
        .

    rm -f "$postinst"
    echo "$out"
}

fpm_rpm() {
    section "fpm_rpm"
    local out="$OUTDIR/vigil-${VERSION}-1.${DISTRO}.x86_64.rpm"
    local postinst
    postinst="$(mktemp -t vigil-postinst.XXXXXX)"
    emit_postinst > "$postinst"
    chmod 0755 "$postinst"
    # Same pin as fpm_deb -- rpmbuild captures the file's mtime into
    # the cpio archive and SOURCE_DATE_EPOCH alone doesn't cover it.
    touch -h -d "@$SOURCE_DATE_EPOCH" "$postinst"

    rm -f "$out"
    run fpm \
        --input-type dir \
        --output-type rpm \
        --name vigil-baseline \
        --version "$VERSION" \
        --iteration "1.${DISTRO}" \
        --architecture x86_64 \
        --license 'GPL-3.0-only' \
        --maintainer 'lousclues-labs <pkg@lousclues.com>' \
        --vendor 'lousclues-labs' \
        --url 'https://github.com/lousclues-labs/vigil' \
        --description 'Vigil Baseline -- desktop Linux file integrity monitor (vigil + vigild).' \
        --depends 'glibc' \
        --depends 'openssl-libs' \
        --depends 'libcap' \
        --rpm-dist "$DISTRO" \
        --rpm-os linux \
        --rpm-summary 'Desktop Linux file integrity monitor (vigil + vigild)' \
        --rpm-rpmbuild-define 'use_source_date_epoch_as_buildtime 1' \
        --rpm-rpmbuild-define 'clamp_mtime_to_source_date_epoch 1' \
        --rpm-rpmbuild-define '_buildhost reproducible.vigil-baseline.local' \
        --config-files /etc/vigil/vigil.toml.example \
        --after-install "$postinst" \
        --package "$out" \
        --chdir "$STAGE" \
        .

    rm -f "$postinst"
    echo "$out"
}

# ─── 12. Self-validation + manifest. ───
# The workflow runs an exhaustive layout check on the installed
# package; this self-check runs against the staged tree before fpm
# packs it, so failures surface inside this script (with stage paths
# preserved if VIGIL_KEEP_STAGE=1) rather than only in CI.
validate_stage() {
    section "validate_stage"
    local unit_dir="$1"
    local fails=0
    check() {
        if [ ! -e "$STAGE/$1" ]; then
            echo "stage MISSING: /$1" >&2
            fails=$((fails + 1))
        fi
    }
    check usr/bin/vigil
    check usr/bin/vigild
    check "${unit_dir#/}/vigild.service"
    check etc/vigil/vigil.toml.example
    check usr/share/man/man1/vigil.1.gz
    check usr/share/man/man5/vigil.toml.5.gz
    check usr/share/man/man8/vigild.8.gz
    check usr/share/bash-completion/completions/vigil
    check usr/share/zsh/site-functions/_vigil
    check usr/share/fish/vendor_completions.d/vigil.fish
    check usr/share/doc/vigil/README.md
    check usr/share/doc/vigil/changelog.gz
    if [ "${FPM_TARGET:-}" = "deb" ]; then
        check usr/share/doc/vigil/copyright
        # apt hook: config + both delegated scripts must ship together.
        # Shipping the config without the scripts (or vice-versa) would
        # leave apt unable to enter/exit the maintenance window cleanly.
        if [ -d "$REPO_ROOT/hooks/apt" ]; then
            check etc/apt/apt.conf.d/99vigil
            check usr/lib/vigil/apt-pre.sh
            check usr/lib/vigil/apt-post.sh
        fi
    else
        check usr/share/doc/vigil/LICENSE
    fi
    if [ "$fails" -gt 0 ]; then
        echo "ERROR: $fails missing file(s) in staged tree" >&2
        exit 1
    fi
    log "stage OK"
}

# Reproducibility post-processor.
#
# For .deb: fpm doesn't honour SOURCE_DATE_EPOCH in its internal
# tar/gzip/ar invocations -- ar entry mtimes, gzip header timestamps,
# and tar entry ordering all vary run-to-run. strip-nondeterminism is
# the standard tool for this (Debian reproducible-builds project) and
# ships in apt repos; install_deb_deps installs it.
#
# For .rpm: strip-nondeterminism has no .rpm handler -- running it on
# an .rpm is a no-op. RPM reproducibility is handled inside rpmbuild
# via the macros passed in fpm_rpm(). This step then logs + skips on
# RPM hosts where strip-nondeterminism is absent, which is expected.
make_reproducible() {
    local artifact="$1"
    section "make_reproducible"
    if command -v strip-nondeterminism >/dev/null 2>&1; then
        run strip-nondeterminism --timestamp="$SOURCE_DATE_EPOCH" "$artifact"
    else
        log "strip-nondeterminism not on PATH (expected on .rpm hosts); rpmbuild macros handle reproducibility"
    fi
}

# Sidecar JSON next to the artifact -- consumed by ATTEST.md generation
# in the lousclues-pkg pipeline. Format intentionally tiny + stable.
emit_manifest() {
    local artifact="$1"
    local sha256
    sha256=$(sha256sum "$artifact" | awk '{print $1}')
    local size
    size=$(stat -c '%s' "$artifact")
    local git_commit
    git_commit=$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo "unknown")
    cat > "${artifact}.manifest.json" <<EOF
{
  "artifact": "$(basename "$artifact")",
  "sha256": "$sha256",
  "size_bytes": $size,
  "version": "$VERSION",
  "distro": "$DISTRO",
  "source_date_epoch": $SOURCE_DATE_EPOCH,
  "git_commit": "$git_commit"
}
EOF
    log "manifest written: ${artifact}.manifest.json"
    log "sha256: $sha256"
}

# ─── 13. Per-distro dispatch. ───
case "$DISTRO" in
    noble|jammy|bookworm)
        export FPM_TARGET=deb
        install_deb_deps
        ensure_toolchain
        build_binaries
        stage_assets /lib/systemd/system
        validate_stage  /lib/systemd/system
        artifact=$(fpm_deb | tail -n1)
        ;;
    el9|fedora)
        export FPM_TARGET=rpm
        install_rpm_deps
        ensure_toolchain
        build_binaries
        stage_assets /usr/lib/systemd/system
        validate_stage  /usr/lib/systemd/system
        artifact=$(fpm_rpm | tail -n1)
        ;;
    *)
        echo "ERROR: unknown DISTRO '${DISTRO}'" >&2
        echo "       supported values: noble, jammy, bookworm, el9, fedora" >&2
        exit 2
        ;;
esac

# ─── 14. Verify exactly one artifact + emit manifest sidecar. ───
if [ ! -f "$artifact" ]; then
    echo "ERROR: fpm reported success but $artifact is missing" >&2
    exit 1
fi
make_reproducible "$artifact"
emit_manifest "$artifact"
log "done: $artifact"
