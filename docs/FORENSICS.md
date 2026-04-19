# Forensic Workflows

Using `vigil inspect` for offline filesystem comparison.

---

## What `vigil inspect` Does

`vigil inspect` compares files on disk against entries in a baseline database.
It opens the baseline DB read-only, hashes the target files, and reports
structural deviations (content, permissions, ownership, inode, xattrs).

It does not require a running daemon. It does not require a config file
(when `--baseline-db` is specified). It never writes to the inspected
filesystem or modifies any database.

Permissions the runtime user cannot read are reported as errors without
failing the entire inspection.

---

## Offline Mode

`vigil inspect` runs entirely offline. The only inputs are:

1. A trusted `vigil` binary (from known-good media).
2. A baseline DB file (from before the incident).
3. The filesystem to inspect (mounted read-only).

No daemon, no network, no config file, no audit DB, no HMAC key.
This makes it safe to use from a live USB or recovery environment.

---

## Command Reference

```bash
vigil inspect <path> [--baseline-db <path>] [--recursive] [--root <prefix>]
                     [--format json] [--brief]
```

| Option | Description |
|--------|-------------|
| `--baseline-db <path>` | path to a baseline DB file (defaults to local DB from config) |
| `--recursive` | walk directory and compare every entry |
| `--root <prefix>` | path prefix translation for baseline lookup |
| `--brief` | single-line summary output |
| `--format json` | machine-readable JSON output |

The `--root` flag translates paths for baseline lookup. If you mount a
recovered disk at `/mnt/recovered`, baseline entries are stored as `/etc/passwd`
(not `/mnt/recovered/etc/passwd`). The `--root /mnt/recovered` flag strips
the prefix before looking up each path in the baseline.

---

## Workflow: Incident Response

When investigating a compromised system:

1. **Do not run Vigil on the compromised system.** The binary may be tampered with.
2. Boot from trusted media (live USB, recovery environment).
3. Mount the compromised filesystem read-only.
4. Use a trusted `vigil` binary and the pre-incident baseline DB.

```bash
# Mount the compromised disk read-only
sudo mount -o ro /dev/sda2 /mnt/compromised

# Compare /etc against the pre-incident baseline
vigil inspect /mnt/compromised/etc/ \
  --baseline-db /media/usb/baselines/pre-incident.db \
  --root /mnt/compromised \
  --recursive
```

The output lists every file that differs from baseline, every file present
on disk but absent from baseline, and every baseline entry not found on disk.

---

## Workflow: Recovered Disk Analysis

Extract a baseline from a known-good backup and compare against a recovered disk.

```bash
# Mount recovered disk
sudo mount -o ro /dev/sdb1 /mnt/recovered

# Compare against saved baseline
vigil inspect /mnt/recovered/ \
  --baseline-db /backups/host-baseline-2026-03.db \
  --root /mnt/recovered \
  --recursive \
  --format json > /tmp/inspection-report.json
```

The JSON output includes deviation details for each file (path, baseline path,
list of differences). Pipe it to `jq` or load it in your analysis tooling.

---

## Workflow: Comparing Two Systems

Export a baseline from one system, inspect the other:

```bash
# On system A: copy baseline.db to portable media
cp /var/lib/vigil/baseline.db /media/usb/system-a.db

# On system B: compare against system A's baseline
vigil inspect /etc/ --baseline-db /media/usb/system-a.db --recursive
```

---

## Workflow: Air-Gapped Analyst Workstation

For environments where the analyst workstation has no access to the
incident host:

```bash
# On the incident host (or from its backup):
# 1. Copy the baseline DB
cp /var/lib/vigil/baseline.db /media/usb/incident-baseline.db

# 2. Create a filesystem image or tar of the paths of interest
sudo tar cf /media/usb/incident-etc.tar /etc/

# On the analyst workstation:
# 3. Extract the tar to a working directory
mkdir /tmp/analysis && cd /tmp/analysis
tar xf /media/usb/incident-etc.tar

# 4. Run inspect with root prefix translation
vigil inspect /tmp/analysis/etc/ \
  --baseline-db /media/usb/incident-baseline.db \
  --root /tmp/analysis \
  --recursive \
  --format json > incident-report.json

# 5. Review deviations
cat incident-report.json | jq '.details[] | select(.differences | length > 0)'
```

---

## Combining with Attestations

For stronger evidentiary workflows, combine `vigil inspect` with
`vigil attest`:

1. Before an incident: `vigil attest create --scope full` stores a
   signed snapshot of baseline and audit state.
2. After an incident: `vigil inspect` compares the recovered disk against
   the pre-incident baseline.
3. The `.vatt` file proves what the baseline looked like before the incident.
   The inspect report shows what changed. Together they form a complete
   forensic evidence package.

See [Attestation](ATTEST.md) for the attestation workflow.

---

## Constraints

- `vigil inspect` is strictly read-only. It never writes to the inspected
  filesystem or modifies any database.
- No daemon required. No config file required if `--baseline-db` is specified.
- Paths the runtime user cannot read are reported as "permission denied"
  without failing the entire inspection.
- No audit chain interaction. Inspect is forensic, not operational.
- The `--root` flag does simple prefix stripping. It does not resolve
  symlinks or handle bind mounts.
