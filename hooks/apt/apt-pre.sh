#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
#
# vigil apt pre-invoke hook
# ─────────────────────────
# Runs immediately before apt unpacks/configures any package. Enters
# vigil's maintenance window so legitimate package writes don't fire
# alerts on the next baseline diff.
#
# Invoked from /etc/apt/apt.conf.d/99vigil. Idempotent. Never blocks
# a transaction: every failure path exits 0.
set -u

VIGIL=/usr/bin/vigil

# Common case: vigil installed, just enter the window.
if [ -x "$VIGIL" ]; then
    "$VIGIL" maintenance enter --quiet 2>/dev/null || true
    exit 0
fi

# Degraded case: vigild is still running but the CLI is gone. Operator
# must reinstall vigil-baseline -- without the CLI, the post-hook
# can't refresh the baseline either, and vigild will alert on every
# legitimate package write.
if command -v systemctl >/dev/null 2>&1 \
   && systemctl is-active --quiet vigild 2>/dev/null; then
    logger -p daemon.err -t vigil-apt \
        "vigild is running but $VIGIL is missing; maintenance window NOT entered. The post-hook will fail and Vigil will report inconsistent state. Reinstall vigil-baseline as soon as the transaction completes."
    command -v notify-send >/dev/null 2>&1 && notify-send -u critical 'Vigil' \
        'vigild is running but the vigil binary is missing. Reinstall vigil-baseline.' \
        2>/dev/null || true
fi

exit 0
