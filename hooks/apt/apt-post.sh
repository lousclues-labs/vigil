#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
#
# vigil apt post-invoke hook
# ──────────────────────────
# Runs immediately after apt finishes a transaction. Refreshes the
# baseline against the new on-disk state, then exits the maintenance
# window opened by apt-pre.sh.
#
# Invoked from /etc/apt/apt.conf.d/99vigil. Idempotent. Never blocks
# a transaction: every failure path exits 0.
set -u

VIGIL=/usr/bin/vigil

# Degraded case: vigil-baseline was removed (or partially removed) by
# this transaction. Tell the operator + log, but don't fail.
if [ ! -x "$VIGIL" ]; then
    if command -v systemctl >/dev/null 2>&1 \
       && systemctl is-active --quiet vigild 2>/dev/null; then
        logger -p daemon.err -t vigil-apt \
            "vigild is running but $VIGIL is missing; baseline NOT refreshed after this transaction. Vigil now reports inconsistent state. Reinstall vigil-baseline."
        if command -v notify-send >/dev/null 2>&1; then
            notify-send -u critical 'Vigil' \
                'vigild is running but the vigil binary is missing. Baseline NOT refreshed; reinstall vigil-baseline.' \
                2>/dev/null || true
        fi
    else
        logger -t vigil-apt \
            "vigil binary not found at $VIGIL and vigild not active; skipping refresh"
    fi
    exit 0
fi

# Common case: refresh the baseline. Capture stderr so we can attribute
# failures correctly in the system log.
if ! refresh_err=$("$VIGIL" baseline refresh --quiet 2>&1); then
    logger -p daemon.err -t vigil-apt "baseline refresh failed: $refresh_err"
    if command -v notify-send >/dev/null 2>&1; then
        notify-send -u critical 'Vigil' \
            'Baseline refresh failed after package transaction. Run vigil doctor to investigate.' \
            2>/dev/null || true
    fi
fi

# Always exit the maintenance window, even if refresh failed -- otherwise
# vigild stays muted until the next apt run.
"$VIGIL" maintenance exit --quiet 2>/dev/null || true

exit 0
