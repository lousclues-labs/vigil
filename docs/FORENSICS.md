# Forensic Workflows

Using `vigil inspect` for offline filesystem comparison.

---

## Incident response

When investigating a compromised system:

1. **Do not run Vigil on the compromised system.** The binary may be tampered with.
2. Boot from trusted media (live USB, recovery environment).
3. Mount the compromised filesystem read-only.
4. Use a trusted `vigil` binary and the pre-incident baseline DB.

```
vigil inspect /mnt/compromised/etc/ \
  --baseline-db /media/usb/baselines/pre-incident.db \
  --root /mnt/compromised \
  --recursive
```

## Comparing recovered disk to baseline

```
# Mount recovered disk
sudo mount -o ro /dev/sdb1 /mnt/recovered

# Compare against saved baseline
vigil inspect /mnt/recovered/ \
  --baseline-db /backups/host-baseline-2026-03.db \
  --root /mnt/recovered \
  --recursive \
  --json > /tmp/inspection-report.json
```

## Comparing two systems

Export a baseline from one system, inspect the other:

```
# On system A: copy baseline.db to portable media
cp /var/lib/vigil/baseline.db /media/usb/system-a.db

# On system B: compare against system A's baseline
vigil inspect /etc/ --baseline-db /media/usb/system-a.db --recursive
```

## Constraints

- `vigil inspect` is strictly read-only. It never writes to the inspected
  filesystem or modifies any database.
- No daemon required. No config file required if `--baseline-db` is specified.
- Paths the runtime user cannot read are reported as "permission denied"
  without failing the entire inspection.
- No audit chain interaction. Inspect is forensic, not operational.
