#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# scripts/fix-debian-deps.sh -- remediation chain for the
# libsystemd0-vs-deps version skew that the GH Actions debian:12 /
# ubuntu:22.04 / ubuntu:24.04 container images periodically ship in.
#
# Symptom: any apt-get install (including this repo's pkg/build.sh and
# the pkg-build.yml smoke-install step) fails with
#
#   E: Unable to correct problems, you have held broken packages.
#   Unmet dependencies:
#     systemd : Depends: libcryptsetup12 (>= 2:2.4) but it is not
#                going to be installed
#
# This is upstream's hand of fate, not a vigil regression. The five-step
# chain below makes apt's solver willing to pick a consistent version
# set even when the cached image has held / half-configured packages.
#
# Every step is intentionally `>/dev/null 2>&1 || true`:
#   * The clean case (most CI runs) gets zero output and zero failures.
#   * The skewed case gets repaired silently.
#   * If the chain still can't repair, the *real* install in the caller
#     fails the same way it would have without us -- nothing lost,
#     nothing hidden.
#
# Deliberately NOT `set -e`: every line is allowed to fail. Each step
# is independently idempotent; their combination is the contract.
#
# Used by:
#   * pkg/build.sh::install_deb_deps
#   * .github/workflows/pkg-build.yml -- "install layout-verify tooling
#     (deb)" step (re-run after smoke-install with --force-depends
#     leaves apt in a broken state)
#
# lesson: extracting drift remediation into a script means the script
# can be shellchecked + unit-tested + version-controlled separately
# from the YAML that calls it.

set -u

export DEBIAN_FRONTEND=noninteractive

# 1. dpkg --configure -a -- finish any half-configured packages.
#    A configured-but-not-finalised systemd trips apt's dep check on
#    every subsequent invocation; this step clears that state.
dpkg --configure -a >/dev/null 2>&1 || true

# 2. apt-mark unhold -- lift any package holds. Held libs can't be
#    upgraded by dist-upgrade, so the cascade persists.
apt-mark showhold 2>/dev/null | xargs -r apt-mark unhold >/dev/null 2>&1 || true

# 3. Explicit lib install -- ask apt directly for the libs that
#    systemd needs. If they're in the repo (just not chosen by the
#    solver in earlier steps), this forces them in. Names are
#    bookworm/jammy-specific; missing libs are tolerated.
apt-get install -y --no-install-recommends \
    libsystemd0 libcryptsetup12 libfdisk1 libkmod2 libsystemd-shared \
    libapparmor1 libip4tc2 >/dev/null 2>&1 || true

# 4. dist-upgrade -- consolidate everything. --allow-downgrades and
#    --allow-change-held-packages relax apt's safety checks so the
#    solver can pick a consistent version set even if it means
#    downgrading something.
apt-get -y --no-install-recommends \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    --allow-downgrades --allow-change-held-packages \
    dist-upgrade >/dev/null 2>&1 || true

# 5. install -f -- final dependency repair pass.
apt-get install -y --no-install-recommends -f >/dev/null 2>&1 || true

exit 0
