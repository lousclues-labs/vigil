# Threat Model

Vigil is a filesystem integrity witness.
It detects structural changes. It does not interpret intent.

---

## What Vigil Detects

| Detection | Example |
|-----------|---------|
| content modification | `/usr/bin/sudo` hash no longer matches baseline |
| deletion | `/etc/shadow` missing |
| permission drift | `/etc/sudoers` mode changed unexpectedly |
| owner/group changes | critical file ownership changed |
| inode replacement | file replaced in-place with same path |
| xattr changes | security labels/attributes changed |

How it does this:
- open file descriptor first
- fstat on descriptor
- hash same descriptor
- compare against baseline row

---

## What Vigil Does NOT Detect

| Not Detected | Why |
|--------------|-----|
| kernel rootkits that forge syscall output | user-space monitor depends on kernel truth |
| memory-only process tampering | Vigil is file integrity, not process introspection |
| runtime behavior anomalies | no heuristics, no ML, no behavior scoring |
| attacks outside watch scope | Vigil only sees configured paths |
| physical tampering while host offline | outside runtime software boundary |

---

## Adversary Assumptions

Assumed adversary capabilities:
- can modify files on disk
- may attempt to replace files atomically
- may try to hide changes during package updates

Not assumed as defendable by Vigil alone:
- kernel-level compromise
- full root control of host with binary/key replacement

---

## Trust Boundaries

```
+-----------------------------+
|         Trusted-ish         |
|-----------------------------|
| kernel file metadata APIs   |
| local package DB ownership  |
| SQLite transactional rules  |
+--------------+--------------+
               |
               | compare boundary
               v
+-----------------------------+
|        Untrusted            |
|-----------------------------|
| file contents before hash   |
| paths outside watch groups  |
| unvalidated config input    |
| optional external consumers |
+-----------------------------+
```

Key boundaries:
- filesystem state
- package manager metadata
- kernel syscall responses

---

## Attack Surface

| Surface | Risk |
|---------|------|
| config files (`/etc/vigil/vigil.toml`, user override) | scope manipulation or suppression settings |
| SQLite DB (`/var/lib/vigil/baseline.db`) | baseline/audit tampering |
| JSON alert log (`/var/log/vigil/alerts.json`) | forensic record tampering |
| signal socket path (`hooks.signal_socket`) | local IPC misuse if path permissions weak |
| monitor backend interfaces (fanotify/inotify) | dropped events or reduced coverage under fallback |

---

## Evasion Considerations

Possible bypass/evasion routes:
- in-memory-only malware that avoids disk writes
- kernel-level attacker spoofing file metadata/events
- modifications in paths never added to watch groups
- alert flooding to trigger suppression windows (still audited)
- direct tampering with logs/db by privileged attacker

Mitigations in design:
- deterministic structural comparison
- inode/device checks for replacement attacks
- audit entries written even when notifications suppressed
- explicit fallback warnings when fanotify is unavailable

---

## Operational Reality

Vigil is strongest when:
- watch groups are scoped to high-value paths
- baseline is initialized on known-good system state
- package hooks are installed
- alert channels are monitored and audit log is retained

Vigil is not a silver bullet.
It is a high-signal boundary witness.

*No heuristics. No guessing. Changed or unchanged.*
