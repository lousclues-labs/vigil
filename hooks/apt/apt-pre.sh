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

# Common case: vigil installed. Seal the pre-transaction state, then enter
# the window. The seal is what makes "was my system already drifting before
# this update" answerable afterwards: a deviation found after a transaction
# looks the same whether it arrived with the transaction or was already there.
if [ -x "$VIGIL" ]; then
    seal_out=$("$VIGIL" maintenance enter --quiet --seal 2>&1) || true

    if [ -n "$seal_out" ]; then
        printf '%s\n' "$seal_out" | while IFS= read -r line; do
            [ -n "$line" ] && logger -t vigil-apt "$line"
        done
    fi

    if printf '%s\n' "$seal_out" | grep -q 'VIGIL PRE-UPDATE DEVIATIONS'; then
        summary=$(printf '%s\n' "$seal_out" \
            | sed -n 's/^VIGIL PRE-UPDATE DEVIATIONS: \([0-9]*\).*$/\1/p' | head -n 1)
        if command -v notify-send >/dev/null 2>&1; then
            notify-send -u critical 'Vigil' \
                "${summary:-Some} file(s) were already deviating BEFORE this update started. Run: vigil audit show --since 5m" \
                2>/dev/null || true
        fi
    fi
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
    if command -v notify-send >/dev/null 2>&1; then
        notify-send -u critical 'Vigil' \
            'vigild is running but the vigil binary is missing. Reinstall vigil-baseline.' \
            2>/dev/null || true
    fi
fi

exit 0
