# Correlation

Vigil detects filesystem changes. Correlation explains them.

These are two different jobs, deliberately kept apart. This document describes
what correlation does, what it refuses to do, and how to read its output.

---

## The problem

Vigil's sensitivity is intentional, but a routine system update trips it many
times over:

- A `snap refresh` of two snaps removes two obsolete revisions. snapd deletes
  their generated systemd mount units and the `*.target.wants` symlinks that
  pointed at them. **Six HIGH deletions, one transaction.**
- An `apt upgrade` of 22 packages replaces 39 package-owned files and three
  systemd unit files that `/etc/systemd` symlinks resolve to. **42 alerts, one
  authorized update.**

Every one of those detections is a correct raw observation. Presented as 42
independent incidents, they are also useless: the signal is buried in its own
volume, and an operator who learns to dismiss the batch will dismiss the one
that matters.

Correlation addresses the presentation, never the observation.

---

## Raw detection versus correlated explanation

These are separate dimensions and are always reported separately.

| | Raw detection | Correlated explanation |
|---|---|---|
| Question | What changed on disk? | Is there local evidence attributing it to a package transaction? |
| Source | Filesystem comparison against the signed baseline | APT/dpkg logs, package database, snapd state |
| Severity | From the watch group. Never rewritten. | Not a severity. A separate confidence dimension. |
| Storage | Permanent, HMAC-chained audit record | Derived, recomputed on demand, never persisted into the baseline |
| Effect on baseline | None until explicit acceptance | None, ever |

A CRITICAL change explained by a verified APT transaction is still a CRITICAL
change. The report says so:

```
Raw impact (unchanged by correlation)
  CRITICAL  39
  HIGH       3

Disposition
  Explanation: verified package transaction
  Baseline:    not accepted — correlation never updates the baseline
```

The exit code is computed from raw severity alone. An explained transaction does
not make `vigil check` exit 0.

---

## Why a verified transaction is not a trusted one

"Verified package transaction" is the strongest verdict Vigil issues. It means:

> Several independent local records agree that these specific files changed as
> part of this specific package operation.

It does **not** mean the change is safe. It says nothing about whether the
package itself is benign, whether the repository was compromised, or whether the
maintainer shipped something hostile. Provenance is not safety.

This is why the output never uses green, never says "clean", and never says
"safe". Those words are reserved for claims Vigil can actually support.

Package ownership alone proves even less. An attacker who can write to
`/usr/bin/` can write to a path a package happens to own. Ownership is one
signal; a high-confidence verdict requires several that agree.

---

## Confidence levels

| Level | Meaning |
|---|---|
| `verified package transaction` | Independent sources agree, and content verification passed for every file the package manager holds a digest for. |
| `strongly correlated` | Timing, ownership, and versions line up, but content verification was unavailable or only partially covered. |
| `partially explained` | A transaction explains some of the changes. Others are not accounted for. |
| `unverified` | A transaction is suspected, but the evidence supporting it is missing. |
| `conflicting evidence` | Sources contradict each other, or a verification actively failed. |

Events needing attention sort first. `conflicting evidence` outranks everything.

There is no level meaning "safe", by design.

### What earns a downgrade

Any of these prevents a verified verdict, and several force `conflicting
evidence`:

- Package content verification mismatch
- A file changed after its package was installed
- A path owned by a package the transaction did not touch
- A failed or interrupted transaction
- Unexpected owner, group, mode, capabilities, or file type
- A package-owned executable changed with no matching transaction
- Timestamps outside a reasonable transaction window
- Installed version disagreeing with the transaction record
- Logs unavailable, truncated, or internally inconsistent

### Dimensions a content digest cannot vouch for

`dpkg --verify` compares recorded md5sums. It does not examine mode, owner,
capabilities, xattrs, or file type. A file whose *bytes* are exactly what the
package shipped therefore verifies clean even if its permissions were changed
afterwards — and `chmod` moves ctime rather than mtime, so the file still looks
like it was written during the transaction.

That combination is a ready-made disguise, so correlation treats those
dimensions separately from content:

| Changed dimension | Outcome |
|---|---|
| Content only, matching package digest | may reach `verified package transaction` |
| Mode, owner, capabilities, xattr, security context, file type, device | at most `partially explained` |
| A privilege boundary moved: setuid/setgid gained, world-writable gained, capabilities altered, ownership involving root, file type changed | `conflicting evidence` |

So `chmod u+s /usr/bin/gs` after a ghostscript upgrade is reported as
conflicting evidence naming the path, not folded into the upgrade. An ordinary
content-only package change is unaffected and still reads as one verified
event.

---

## How evidence is collected

Everything is local. See [Privacy](#privacy-and-offline-behaviour).

### APT and dpkg

| Source | Used for |
|---|---|
| `/var/log/apt/history.log` (+ `.1`) | Transaction windows, command line, `Requested-By`, package version transitions |
| `/var/log/dpkg.log` (+ `.1`) | Per-package completion (`status installed`) |
| `/var/lib/dpkg/status` | Current installed state and version, conffile digests |
| `dpkg -S` (batched) | File-to-package ownership |
| `dpkg --verify` | Per-package content verification |

A high-confidence APT event requires all of:

1. The changes fall within the transaction window.
2. Each explained path is owned by a package the transaction upgraded, or is a
   known alias to such a path.
3. The package reached a complete installed state.
4. The transaction completed successfully.
5. Files match installed package metadata where verification is supported.
6. Version transitions match the transaction record.
7. No unexplained changes in the same window.

### Snap

| Source | Used for |
|---|---|
| `snap changes --abs-time` | Change id, status, spawn/ready times, summary |
| `snap tasks --abs-time <id>` | Per-revision remove / mount / link / security-profile tasks |
| `/snap/<name>/current` | Which revision is active |
| `/snap/<name>/` | Which revisions remain on disk |
| Mount unit names | Snap name and revision, decoded from systemd escaping |

A systemd unit named `snap-desktop\x2dsecurity\x2dcenter-150.mount` decodes to
the mount point `/snap/desktop-security-center/150`, which identifies both the
snap and the revision that was removed.

`--abs-time` is not optional. Without it snapd prints relative times
("yesterday at 13:24 EDT"), which is four whitespace-separated tokens where the
parser expects one, shifting every later column. A row in that shape is
rejected and reported as a parse error rather than accepted as a transaction
dated to the epoch.

A snap artifact's name proves *which* revision it belongs to, not *when* it
changed. Where a timestamp survives it is checked against the transaction
window; a deleted mount unit has no timestamp left to check, so the window
check is reported as unavailable rather than passed.

Strong confidence requires a completed change, matching names and revisions,
explicit removal tasks for the deleted revisions, the replacement revision
present and current, and no failed tasks.

---

## Incomplete evidence

Missing evidence lowers confidence. It never raises it, and it is never
converted into a pass.

A check that could not run is rendered `?`, not `+`:

```
Verification
  + transaction completed — apt recorded a successful end
  + files match installed package metadata — 39 of 42 verified
  ? content verification coverage — 3 of 42 have no digest to check against
```

Typical honest outcomes:

- *"APT transaction suspected; package verification unavailable."*
- *"Snap revisions match, but snapd transaction history is unavailable."*
- *"35 of 42 changes explained; 7 require investigation."*
- *"Transaction completed, but 1 package-owned executable fails verification."*

Systems without APT, dpkg, snapd, or readable logs degrade to reporting raw
detections exactly as before, plus a visible note saying why nothing was
explained.

---

## Symlink object versus symlink target

Vigil follows symlinks when hashing, so a symlink's content and inode fields
describe its **target**. Before this was tracked explicitly, replacing a target
made every symlink pointing at it look independently replaced — the three
`/etc/systemd` alerts in the APT example above.

Four things are now tracked separately:

| Field | Meaning |
|---|---|
| `link_text` | Raw `readlink(2)` output, unresolved |
| `link_inode` / `link_device` | `lstat(2)` identity of the symlink object itself |
| `symlink_target` | Fully resolved canonical target; `None` when it does not resolve |
| `inode` / `device` / content hash | The target the link resolves to |

The rules:

- **Link object unchanged, target replaced** → reported as
  `symlink_target_replaced`: an alias of the target's change, listed beneath it.
  The underlying content, size, and inode observations are still recorded.
- **Link text changed** → reported as `link_text_changed`, attributed to the
  link. This is detected even when the canonical target is identical
  (`/lib/x` rewritten to `../lib/x`), which was previously invisible.
- **Link object replaced** (new inode, same text) → not an alias. Reported on
  its own terms.
- **Broken link or link loop** → the link still exists, so it is captured from
  its own `lstat` identity rather than reported as a deletion. `symlink_target`
  becomes `None`, which makes the transition visible.

Alias attribution requires positive evidence on every point. A baseline entry
written before these fields existed carries no link data, and absence of
evidence is never treated as sameness — such entries are reported with the older
semantics rather than explained away.

---

## Explicit acceptance and stale-scan protection

Correlation never touches the baseline. Only `vigil check --accept` does, and it
is unchanged in that respect.

What is new is a revalidation step. `check --accept` involves two separate
observations of the same path: the scan that produced the report, and the read
that writes the baseline. Anything can happen in between.

Before each write, Vigil re-reads the path and re-runs the same comparison the
scan ran, against the same baseline entry. The resulting change list must equal
the one the operator reviewed. Comparing only the dimensions the detection
happened to report would leave the rest unchecked — a detection of a changed
xattr would let an attacker swap the file's *contents* in the meantime, and the
fresh snapshot is what gets written. Re-diffing closes the whole class.

A path with no baseline entry cannot be re-diffed against anything, so it is
refused rather than accepted. If they differ, the write is refused:

```
  REFUSED /usr/bin/gs: changed since you reviewed it
          content hash 9f2a1c4e8b31 -> 04ff1a9e7c22

  ● 38 accepted, 1 refused as stale, 0 failed

  Refused entries were NOT written to the baseline.
  Re-run `vigil check` to review their current state before accepting.
```

The snapshot that passed revalidation is the one written, so no third read can
slip in between the check and the commit.

A verified explanation does not relax this. Explanation and acceptance are
independent: `vigil check --accept` still requires the operator, and the
revalidation still applies.

`--dry-run` remains available and mutates nothing.

### Acceptance receipts

Each acceptance records an audit entry (`vigil:baseline_acceptance`) naming:

- every raw detection accepted, with its path, severity, group, and change kinds
- the count refused as stale
- the correlated event ids that were on screen, with their confidence, packages,
  evidence sources, and collector-error counts
- the baseline fingerprint before and after

Correlation appears in the receipt as *evidence the operator saw*, never as the
authority for the write.

---

## Privacy and offline behaviour

Correlation is local-first and works with no network:

- Sources are local log files, the local package database, local snapd state,
  and the local filesystem.
- No path, hash, package name, version, or any other datum leaves the machine.
- No reputation service, no telemetry, no remote lookup of any kind.
- No privilege escalation. Files are read as the invoking user; a file that
  cannot be read is reported as a permission problem, not silently skipped.

---

## Performance

Correlation runs only in `vigil check`, only when that scan found changes, and
never in the daemon, the filesystem watcher, or the incremental scanner. A
running `vigild` is unaffected.

Costs are bounded by design:

- **No per-file subprocess.** Ownership for all changed paths is resolved in one
  batched query.
- **Short-circuit.** If no changed path is package-owned and none is
  snap-related, no logs are read and no package manager is consulted.
- **Verification is scoped.** Only packages a candidate transaction actually
  names are verified, because verification corroborates a transaction claim and
  cannot change attribution for a package with no transaction. `dpkg --verify`
  walks every file in a package, so this matters: an unscoped run over 42 paths
  from 40 packages measured 1.8 s, versus 182 ms scoped.
- **snapd is queried only when a snap artifact changed**, and follow-up task
  queries are capped.
- **Log reads are size-capped at 4 MiB and read from the tail**, so a large
  `dpkg.log` yields recent transactions rather than ancient ones. Truncation is
  reported, never silent.
- Subprocesses run with argument arrays and timeouts. No shell is involved.

Reference numbers (`cargo bench`, engine only, excluding evidence collection):

| Benchmark | Time |
|---|---|
| `correlate_apt_22pkg_42detections` | ~21 µs |
| `correlate_apt_500pkg_2000detections` | ~1.5 ms |
| `symlink_alias_diff` | ~141 ns |

To disable correlation entirely:

```sh
vigil check --no-correlate
```

---

## Worked example: APT upgrade

```
  VERIFIED APT/DPKG TRANSACTION
    22 packages · 42 filesystem detections
    2025-09-20 00:07:14 UTC – 2025-09-20 00:07:16 UTC
    requested by operator (1000) (as recorded by the package manager)

    Verification
      + transaction completed — apt recorded a successful end
      + files match installed package metadata — 39 of 42 verified
      + symlink aliases resolve to transaction files — 3 unchanged symlink(s)
        resolve to replaced targets
      + packages reached a complete state — 22 package(s) fully installed
      + installed versions match the transaction — 22 package version(s) agree
      + no unexplained files — every change in this window is attributed

    Raw impact (unchanged by correlation)
      CRITICAL  39
      HIGH       3

    Packages
      ghostscript      9.55.0-1 -> 9.55.0-2   27 detections
      libglib2.0-bin   2.72.4-0 -> 2.72.4-1    7 detections
      libxml2-utils    2.9.13-1 -> 2.9.13-2    2 detections
      rsyslog          8.2112-1 -> 8.2312-1    3 files + 3 aliases

    Disposition
      Explanation: verified package transaction
      Baseline:    not accepted — correlation never updates the baseline
```

The three rsyslog aliases are the `/etc/systemd` symlinks. Their own objects
never changed; `--verbose` shows each one with the target it resolves to.

## Worked example: Snap refresh

```
  CORRELATED SNAP REFRESH
    2 packages · 6 filesystem detections
    2025-09-20 00:07:14 UTC – 2025-09-20 00:07:26 UTC
    transaction 40

    Verification
      + transaction completed — snap recorded a successful end
      + replacement revision active — 2 snap(s) running the new revision
      + no unexplained files — every change in this window is attributed

    Raw impact (unchanged by correlation)
      HIGH  6

    Packages
      desktop-security-center  150 -> 188   3 detections
      prompting-client         204 -> 228   3 detections
```

All six mount-unit and `*.target.wants` deletions are retained as raw evidence
beneath the event and listed individually under `--verbose`.

---

## Troubleshooting collector failures

Failures are always shown, never swallowed.

```
  Evidence unavailable
  Correlation ran with incomplete evidence. Absent evidence is not a
  clean result; the changes below were simply not explainable.
    ? snapd change history [permission denied]: snap changes: requires
      administrator privileges
      (this check needs privileges this process does not have)
```

| Symptom | Cause | Remedy |
|---|---|---|
| `apt history log [unavailable]` | Not an APT system, or logs removed | Expected on non-Debian systems; detections report raw |
| `apt history log [truncated]` | Log exceeded the 4 MiB cap, or compressed rotations hold the window | Correlate sooner after an update |
| `snapd change history [permission denied]` | `snap changes` needs more privilege | Re-run with sufficient privilege, or accept reduced confidence |
| `snapd change history [timeout]` | snapd unresponsive | Check `systemctl status snapd` |
| `dpkg status database [permission denied]` | `/var/lib/dpkg/status` unreadable | Check permissions |
| `... [parse error]` | Log line did not match the expected shape | Report it; the parser is strict on purpose |
| Everything `uncorrelated` | No transaction matched | This is a real answer: the changes have no package explanation |

Compressed rotations (`history.log.*.gz`) are not read. When the correlation
window reaches back past the retained uncompressed logs, that gap is reported as
truncation rather than being allowed to look like "no transaction".

---

## Compatibility

Baseline schema **v3** adds three nullable columns: `link_text`, `link_inode`,
`link_device`. The migration is additive — existing rows keep every byte and
receive `NULL` — and runs automatically on open.

**The baseline HMAC field set is unchanged.** The new columns sit outside it, so
a baseline signed before v3 still verifies afterwards and nothing is silently
resigned. This is a deliberate boundary:

- A symlink's *canonical target* is signed, and any semantic retarget moves it.
- The v3 columns add attribution granularity on top of that signed field.

Known limitation: symlink ownership (`uid`/`gid` of the link object itself) is
still not captured. A `chown` of a symlink that changes neither its text nor its
target is not detected.

Entries carried over from an older baseline have no link data until their next
scan, and are compared with pre-v3 semantics until then.

---

## See also

- [ARCHITECTURE.md](./ARCHITECTURE.md) — where the correlate module sits
- [THREAT_MODEL.md](./THREAT_MODEL.md) — what Vigil defends against
- [PRINCIPLES.md](./PRINCIPLES.md) — why detection and judgment stay apart
