# Principles

These aren't rules. They're promises.

Every design decision, every line of code, every contribution should align
with these values. If something contradicts a principle, either the thing
is wrong or the principle needs updating. We should talk about it.

---

## The Soul of Vigil Baseline

You download things. People send you files. You torrent. You install packages
from repositories you half-trust. You live in the real world of untrusted
content and shared systems.

Your fear was never "malware" in the abstract. Your fear was invisible
intrusion. Something slipping in, changing what shouldn't change, and you
never knowing it happened.

Vigil Baseline exists because of one truth:

> **No one tiptoes through your system without leaving footprints behind.**

Vigil Baseline is the gatekeeper that refuses to let anything cross the threshold
silently. Not a guard who fights. A witness who never looks away.

---

## I. Watch, Don't Act

Vigil Baseline is a watchman. It watches, compares, and reports.

It does not kill processes. It does not quarantine files. It does not modify
permissions. It does not block execution. It does not remediate threats.

When something changes that shouldn't have, Vigil Baseline tells you. Immediately,
clearly, and only once. What you do about it is your decision.

A tool that watches *and* acts will eventually act wrong. A tool that only
watches can never make the wrong move. It can only fail to see. That failure
mode is testable, fixable, and honest.

## II. Silence Is the Default

A healthy system produces zero alerts.

Vigil Baseline emits nothing during normal operation. No informational noise. No
advisory warnings. No "everything is fine" status messages. Quiet means
the boundaries are intact.

If you're receiving alerts during a normal day, either your system is
compromised or Vigil Baseline is poorly configured. Fix the configuration before
you investigate the system.

Coalescing and storm suppression honor this principle harder, not less.
When 50 package files change during `pacman -Syu`, the operator sees one
coalesced notification with a "Likely cause: package install" line -- not
50 individual desktop popups. When a filesystem storm produces hundreds
of events per second, the storm detector fires once and suppresses until
the rate drops. The audit log still records everything. Only the
operator's attention budget is protected.

**The test:** Run Vigil Baseline for seven days on a clean Arch install with normal
desktop use and package manager hooks installed. If it produces more than
one alert per day that does not correspond to a real filesystem change,
the tool has failed.

## III. Determinism Over Heuristics

Vigil Baseline does not guess. It does not infer. It does not predict. It does not
use heuristics, machine learning, behavioral analysis, or statistical models.

It compares. Hashes match or they don't. Permissions changed or they didn't.
The inode is the same or it isn't. The file exists or it's gone.

These are observable, repeatable, and verifiable facts. They do not depend
on training data, threat intelligence feeds, vendor cloud lookups, or
statistical distributions.

**The test:** Given the same file, the same path, the same permissions, and
the same baseline entry, does Vigil Baseline always produce the same result? If yes,
it belongs. If no, it doesn't.

## IV. Structure Over Behavior

Behavioral signals require judgment. Structural signals require only comparison.
Vigil Baseline compares. It does not judge.

- "The hash of `/usr/bin/sudo` does not match the baseline." Structural. Binary fact.
- "A new `.desktop` file appeared in `~/.config/autostart/`." Structural. Binary fact.
- "The file at this path has a different inode." Structural. Binary fact.
- "This process is accessing files suspiciously." Behavioral. Does not belong.

Every detection in Vigil Baseline can be expressed as a simple conditional statement
that a non-engineer could read and understand.

## V. Every Alert Must Be Rare, Clear, Actionable, Explainable, and Unambiguous

**Rare.** It should almost never fire during normal operation.

**Clear.** The reason is obvious from the alert text alone. No jargon,
no codes that require a lookup table.

**Actionable.** The user knows what to investigate. The alert shows the
path, the old hash, the new hash, what changed.

**Explainable.** Every alert maps to exactly one watch group with a
human-readable name. You can point to the config and say: "This path is
in the `system_critical` group. That's why it fired."

**Unambiguous.** The boundary was crossed or it wasn't. There is no "maybe."
No "potentially suspicious." No "anomalous." The hash matched or it didn't.

### V.a -- Recovery Actions Are Commands When Vigil Can Act

Every doctor row that identifies a fixable problem must offer a
real CLI command to fix it. Manual prose guidance is reserved
for actions vigil structurally cannot perform on the operator's
behalf.

The choice between `Recovery::Command` and `Recovery::Manual`
follows from this rule:

- **Use `Recovery::Command`** when vigil can perform the
  recovery autonomously: removing a configuration section,
  reinstalling hook scripts, refreshing the baseline, recovering
  the daemon from a degraded state, repairing key file
  permissions.

- **Use `Recovery::Manual`** when the recovery requires
  information vigil does not have: what listener program to
  attach to a socket, what paths to add to a watch group, what
  external archival schedule to set up.

- **Use multi-hint recovery (`Recovery::Multi`)** when a row has
  multiple explicit alternatives (for example, recover with a
  command, acknowledge as understood, or investigate manually).

A row that suggests manual prose for an action vigil could
perform is a bug. Reviewers reject doctor rows that violate this
rule. New CLI commands are added to satisfy the rule when
existing commands are insufficient.

### V.b -- Historical Events Are Acknowledgeable

Doctor rows that report historical events ("last X happened at T")
respect the operator's authority to add context to events.
Acknowledged events render with operator metadata (ack timestamp,
operator identity, optional note) alongside the event details.

Acknowledgment is operator context, never suppression. A fresh
occurrence of the same event kind warns afresh regardless of prior
acknowledgments. The mechanism is operator-controlled (`vigil ack`),
fully audited (chain-extending records with operator invocation
context), and reversible (`vigil ack revoke`).

A doctor row that surfaces a historical event without any
acknowledgment path is a design bug.

### V.c -- Doctor Shows Operational Truth Without Filtering

Doctor output reflects current operational state. Operators can act
on what doctor reports; they cannot configure doctor to omit
categories of operational data.

Acknowledgments add context to specific events. They do not hide
events. Rows that depend on prior operator preference to become
invisible violate this principle.

Operators who want to stop seeing a class of events must stop those
events at their source (disable integration, fix root cause), not at
the diagnostic layer.

## VI. The Filesystem Is the Source of Truth

No external threat intelligence feeds. No cloud-hosted signature databases.
No vendor-maintained blocklists. No reputation services.

The truth is on disk:
- The file exists or it doesn't.
- The hash matches or it doesn't.
- The permissions are what they should be or they aren't.
- The inode is the same or it was replaced.

Package managers are trusted because they are local: `pacman -Qo /usr/bin/sudo`
answers from `/var/lib/pacman/`, not from a cloud API.

**The test:** Disconnect the network cable. Does Vigil Baseline work? If yes, it passes.

## VII. Boundaries, Not Intelligence

Vigil Baseline enforces the state boundary: *has anything changed that shouldn't have?*

It does not try to be smart. It does not classify malware families. It does
not attribute attacks to threat actors. It does not compute risk scores that
fade into ambiguity.

A file's hash matches its baseline, or it doesn't. The boundary is crossed
or it is not. There is no gradient.

## VIII. Vigil Baseline Stands Alone

Vigil Baseline is independently useful. It works without any other tool installed.
It can be built, tested, and deployed in isolation.

No tool imports Vigil Baseline. Vigil Baseline imports no tool. No tool reads Vigil Baseline's database.
Vigil Baseline reads no tool's database. If every other security tool on the system
vanishes, Vigil Baseline still compiles, runs, and fulfills its core function.

A user who runs `vigil init && vigil watch` with zero other tools installed
is meaningfully more secure than they were before.

**The test:** Uninstall everything else. Does Vigil Baseline still work? If not,
there's a dependency that shouldn't exist.

## IX. No Configuration Required for Correct Operation

Vigil Baseline ships with sensible defaults that provide real security out of the box.
Configuration exists to tune, not to enable.

The default watched paths cover the attack surfaces that matter:
`/etc/passwd`, `/etc/shadow`, `/usr/bin/`, `/boot/`, `~/.ssh/`,
`~/.bashrc`, cron directories, systemd units, autostart entries.

A user who runs `vigil init` with zero config changes is protected against
the filesystem modifications that matter most.

**The test:** Delete the config file. Run `vigil init && vigil watch`
with zero arguments. Is the user protected? If not, the defaults are wrong.

## X. Fail Open, Fail Loud

When Vigil Baseline encounters an error, two things happen:

**Fail open:** The system does not freeze, hang, or prevent the user from
working. A missed detection is recoverable. A frozen desktop is not.

**Fail loud:** The failure is visible. If fanotify is unavailable and Vigil Baseline
falls back to inotify, it lists every path it cannot watch. If a file
disappears between event and hash, it logs the transient error. Silent
degradation is a security vulnerability.

The user must know their blind spots.

**The test:** Remove `CAP_SYS_ADMIN`. Start Vigil Baseline. Does it clearly communicate
that it fell back to inotify and which paths have reduced coverage?

## XI. Complexity Is a Vulnerability

Every line of code is a potential bug. Every dependency is a potential supply
chain attack. Every configuration option is a potential misconfiguration.

Vigil Baseline is small. It hashes files, compares metadata, and writes alerts.
That's it. When deciding whether to add a feature, ask:

- Does this make Vigil Baseline better at watching the filesystem?
- Or does this make Vigil Baseline do a second job?

If it's a second job, it's a second tool. Or it doesn't exist.

**The test:** Can you explain Vigil Baseline's entire architecture in a single ASCII
diagram that fits on one terminal screen? If not, simplify.

## XII. The Baseline Is Sacred

The baseline is the source of truth for what "correct" looks like.

Every monitored file has a known-good snapshot: hash, permissions, ownership,
timestamps, inode, device, extended attributes, security context. Every change
is compared against this snapshot. Every alert explains exactly what differs.

The baseline is never silently modified. Package manager hooks update it
explicitly. Manual additions are logged. The audit trail records every
change, even suppressed ones. If HMAC signing is enabled, the baseline
is tamper-evident.

The user trusts the baseline because the baseline is transparent.

## XIII. The Audit Trail Never Lies

The audit log records every detected change, including changes that were
suppressed by maintenance windows, cooldowns, or rate limiting.

Suppression affects notifications. It never affects the audit trail.

An attacker who modifies `/etc/shadow` during a `pacman -Syu` will not
trigger a desktop notification (the maintenance window suppresses it for
package-managed paths). But the audit log will contain the entry. The
truth is always written down.

## XIV. No Network I/O

Vigil Baseline operates entirely locally. No telemetry. No update checks. No cloud
lookups. No license validation. No DNS queries. No outbound connections.

The webhook feature is optional, off by default, and outbound-only. It
exists for users who choose to send alerts somewhere. It never activates
without explicit configuration.

**The test:** Disconnect the network cable. Does Vigil Baseline work identically?

## XV. The User Is the Operator

Vigil Baseline is designed for someone who understands their system, reads alerts
and acts on them, and trusts their own judgment.

No confirmation prompts. No "are you sure?" dialogs. No safety rails
except the ones that prevent unrecoverable damage (like `vigil init`
warning before overwriting an existing baseline).

Vigil Baseline provides information, not opinions. The operator decides.

---

## The Compass Question

When in doubt about any design decision (a new feature, a new detection,
a new output format) ask:

> **"Does this make Vigil Baseline quieter or noisier?"**

If it makes Vigil Baseline quieter by removing false positives, eliminating ambiguity,
or suppressing redundant information, it belongs.

If it makes Vigil Baseline noisier by adding uncertain signals, soft thresholds,
or informational messages, it doesn't belong.

---

## Vigil Baseline's Promise

**Vigil Baseline promises: *You know when something changes that shouldn't have.***

When Vigil Baseline is silent, your boundaries are intact. You tested the
conditions under which it alerts, and none of those conditions are present.

When Vigil Baseline speaks, something real has happened. Every detection is
deterministic, every rule is structural, and every source of noise has been
eliminated.

The difference between feeling safe and being informed is the difference
between trusting a vendor's dashboard and trusting your own code.

You trust your own code.

---

*These principles are promises. To the user, to the system, and to ourselves.
Break them only after serious discussion. Update them only when the world changes.*
