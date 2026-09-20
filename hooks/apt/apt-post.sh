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

# Common case: refresh the baseline. Capture stderr for two reasons: to
# attribute failures correctly in the system log, and because the refresh
# reports the changes it could not prove benign on stderr even when quiet.
refresh_out=$("$VIGIL" baseline refresh --quiet 2>&1)
refresh_status=$?

if [ "$refresh_status" -ne 0 ]; then
    logger -p daemon.err -t vigil-apt "baseline refresh failed: $refresh_out"
    if command -v notify-send >/dev/null 2>&1; then
        notify-send -u critical 'Vigil' \
            'Baseline refresh failed after package transaction. Run vigil doctor to investigate.' \
            2>/dev/null || true
    fi
else
    # The whole point of the post-transaction refresh: apt just rewrote
    # hundreds of files, and vigil verified each one against the digest its
    # own package recorded. Files that matched are proven to be the package's
    # own bytes and are absorbed silently. Anything left over is the handful
    # the operator actually has to look at, so it gets exactly one
    # notification instead of being buried in the flood.
    unproven=$(printf '%s\n' "$refresh_out" | grep -c 'VIGIL UNPROVEN CHANGES' 2>/dev/null || true)
    if [ "${unproven:-0}" -gt 0 ]; then
        # Log every path; the system log is the durable copy.
        printf '%s\n' "$refresh_out" \
            | sed -n '/VIGIL UNPROVEN CHANGES/,$p' \
            | while IFS= read -r line; do
                  [ -n "$line" ] && logger -p daemon.warning -t vigil-apt "$line"
              done

        summary=$(printf '%s\n' "$refresh_out" \
            | sed -n 's/^VIGIL UNPROVEN CHANGES: \(.*\)$/\1/p' | head -n 1)
        if command -v notify-send >/dev/null 2>&1; then
            notify-send -u critical 'Vigil' \
                "This update left $summary that no package vouches for. Run: vigil audit show --since 5m" \
                2>/dev/null || true
        fi
    fi
fi

# Always exit the maintenance window, even if refresh failed -- otherwise
# vigild stays muted until the next apt run.
"$VIGIL" maintenance exit --quiet 2>/dev/null || true

exit 0
