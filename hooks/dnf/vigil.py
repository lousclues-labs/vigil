# SPDX-License-Identifier: Apache-2.0
"""DNF4 plugin: pause and refresh vigil around package transactions.

Mirrors the semantics of hooks/apt/99vigil:

  * Before any RPM transaction, enter a maintenance window so vigil(8)
    does not raise alerts for the legitimate file mutations performed
    by RPM.
  * After a successful transaction, refresh the baseline for the
    changed files, then exit the maintenance window.

The plugin is intentionally silent on the happy path. Failures are
logged through dnf's logger and forwarded to the system journal so an
operator sees them in `journalctl -u dnf-automatic` or in the terminal
output of an interactive `dnf install`.

A missing `vigil` binary while `vigild` is active is reported as a
critical condition: the maintenance window will not be entered, the
post-transaction refresh will not run, and vigil will accumulate
findings for every file the transaction touches until the operator
reinstalls vigil-baseline. The plugin still allows the transaction to
proceed; blocking dnf would be a denial-of-service against the
operator and is out of scope for a monitoring tool.

DNF5 (Fedora 41+) uses a different plugin ABI; that port is tracked
separately. Distros still on dnf4 (RHEL 9/10, Rocky 9, Alma 9,
openSUSE Leap, current Fedora ELN) load this file unchanged.
"""

from __future__ import absolute_import

import os
import subprocess

import dnf  # type: ignore[import-not-found]

VIGIL_BIN = "/usr/bin/vigil"
VIGILD_UNIT = "vigild.service"
LOG_TAG = "vigil-dnf"


def _vigil_present():
    return os.access(VIGIL_BIN, os.X_OK)


def _vigild_active():
    try:
        rc = subprocess.call(
            ["systemctl", "is-active", "--quiet", VIGILD_UNIT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return rc == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _journal(priority, message):
    """Best-effort syslog forwarding; never raises."""
    try:
        subprocess.call(
            ["logger", "-p", "daemon." + priority, "-t", LOG_TAG, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _vigil(args, capture=False):
    """Invoke vigil(1) with `args`. Returns (returncode, stderr_text)."""
    cmd = [VIGIL_BIN] + list(args)
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    err = ""
    if capture and proc.stderr:
        try:
            err = proc.stderr.decode("utf-8", "replace").strip()
        except UnicodeDecodeError:
            err = "<undecodable stderr>"
    return proc.returncode, err


class Vigil(dnf.Plugin):
    """DNF4 plugin entry point.

    DNF instantiates this once per `dnf` invocation and calls
    `pre_transaction` after dependency resolution but before any RPM
    work begins, then calls `transaction` after a successful commit.
    """

    name = "vigil"

    def __init__(self, base, cli):  # noqa: D401
        super(Vigil, self).__init__(base, cli)
        self.base = base
        self.cli = cli

    def pre_transaction(self):
        if not _vigil_present():
            if _vigild_active():
                _journal(
                    "err",
                    "vigild is running but " + VIGIL_BIN
                    + " is missing; maintenance window NOT entered. "
                    "The post-hook will not refresh the baseline and "
                    "vigil will report inconsistent state. Reinstall "
                    "vigil-baseline as soon as this transaction completes.",
                )
            return
        _vigil(["maintenance", "enter", "--quiet"])

    def transaction(self):
        if not _vigil_present():
            if _vigild_active():
                _journal(
                    "err",
                    "vigild is running but " + VIGIL_BIN
                    + " is missing; baseline NOT refreshed after this "
                    "transaction. Reinstall vigil-baseline.",
                )
            else:
                _journal(
                    "info",
                    "vigil binary not found and vigild not active; "
                    "skipping baseline refresh.",
                )
            return
        rc, err = _vigil(["baseline", "refresh", "--quiet"], capture=True)
        if rc != 0:
            _journal(
                "err",
                "baseline refresh failed (exit " + str(rc) + "): "
                + (err or "<no stderr>"),
            )
        _vigil(["maintenance", "exit", "--quiet"])
