# Trust Boundaries

What vigil trusts, what it doesn't, where HMAC sits, where
the audit chain sits, and what an attacker with various
access levels can and cannot do. This diagram maps directly
to the threat model document but in visual form.

```
╭───────────────────────────────────────────────────────╮
│                                                       │
│                  UNTRUSTED ZONE                       │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ Filesystem content                     │            │
│  │   Files change. That's the whole point.│            │
│  │   Vigil hashes and compares; it never  │            │
│  │   trusts content to be unchanged.      │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ Process attribution                    │            │
│  │   /proc/N/exe can be spoofed; PIDs     │            │
│  │   can be reused; exited processes       │            │
│  │   leave no trace. Attribution is        │            │
│  │   best-effort metadata, never used     │            │
│  │   for security decisions.              │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ Network (if webhook configured)        │            │
│  │   Outbound-only. Never trusted for     │            │
│  │   input. Off by default.               │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
╰───────────────────────────────────────────────────────╯

╭───────────────────────────────────────────────────────╮
│                                                       │
│              TRUSTED-BUT-VERIFIED ZONE                │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ Package managers (pacman, apt, etc.)   │            │
│  │   Queried locally via /var/lib/pacman  │            │
│  │   and dpkg. Trusted for file ownership │            │
│  │   attribution. Circuit-breaker on      │            │
│  │   timeout. Never network queries.      │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ System clock                           │            │
│  │   Used for timestamps. Monotonic time  │            │
│  │   preferred for durations. Wall clock  │            │
│  │   skew detected and triggers Degraded  │            │
│  │   state if beyond threshold.           │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
╰───────────────────────────────────────────────────────╯

╭───────────────────────────────────────────────────────╮
│                                                       │
│                   TRUSTED ZONE                        │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ Kernel (fanotify / inotify)            │            │
│  │   Event delivery trusted. Queue        │            │
│  │   overflows detected and handled       │            │
│  │   (compensating scan). A compromised   │            │
│  │   kernel is outside the threat model.  │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ HMAC key file (/etc/vigil/hmac.key)    │            │
│  │   Permissions enforced (0600 root).    │            │
│  │   Loaded once at startup, held in      │            │
│  │   Zeroizing memory, never re-read.     │            │
│  │   Compromise = full audit bypass.       │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
│  ╭────────────────────────────────────────╮            │
│  │ vigil.toml configuration              │            │
│  │   Config HMAC detects tampering.       │            │
│  │   Reloaded on SIGHUP via coordinator.  │            │
│  │   Invalid config rejected, old config  │            │
│  │   retained.                            │            │
│  ╰────────────────────────────────────────╯            │
│                                                       │
╰───────────────────────────────────────────────────────╯


╭──── HMAC Protection Model ────────────────────────────╮
│                                                       │
│                  ╭───────────╮                         │
│                  │ HMAC Key  │                         │
│                  │(0600 root)│                         │
│                  ╰─────┬─────╯                        │
│                        │ signs                        │
│          ┌─────────────┼─────────────┐                │
│          ▼             ▼             ▼                │
│  ╭──────────────╮╭───────────╮╭──────────────╮        │
│  │ Baseline     ││ Audit     ││ WAL Entry    │        │
│  │ HMAC         ││ Entry     ││ HMAC         │        │
│  │(13 fields per││ HMAC      ││(nonce+seq+   │        │
│  │ entry, stored││(7 fields, ││ payload,     │        │
│  │ in config    ││ per-entry)││ per-entry)   │        │
│  │ _state)      ││           ││              │        │
│  ╰──────────────╯╰───────────╯╰──────────────╯        │
│          │             │             │                │
│          ▼             ▼             ▼                │
│  detects:       detects:       detects:              │
│  baseline       audit record   WAL entry             │
│  tampering      tampering      tampering/replay      │
│                                                       │
│  ╭─────────────────────────────────────────╮          │
│  │ Config HMAC    (config_state key)       │          │
│  │   detects: config file modification     │          │
│  ╰─────────────────────────────────────────╯          │
│                                                       │
│  ╭─────────────────────────────────────────╮          │
│  │ Control socket challenge-response       │          │
│  │   /dev/urandom nonce + HMAC response    │          │
│  │   detects: unauthorized CLI commands    │          │
│  ╰─────────────────────────────────────────╯          │
│                                                       │
╰───────────────────────────────────────────────────────╯


╭──── Attacker Capability Matrix ───────────────────────╮
│                                                       │
│  Access Level          Can Do / Cannot Do             │
│  ────────────────────  ─────────────────────────────  │
│                                                       │
│  Unprivileged user     ✗ Cannot read baseline.db      │
│                        ✗ Cannot read audit.db         │
│                        ✗ Cannot read HMAC key         │
│                        ✗ Cannot connect to control    │
│                        ✗ Cannot modify watched files  │
│                          (if properly owned)          │
│                                                       │
│  Root (no HMAC key)    ✓ Can modify files             │
│                        ✓ Can read/replace databases   │
│                        ✗ Cannot forge audit entries    │
│                        ✗ Cannot forge WAL entries      │
│                        ✗ Cannot suppress detection    │
│                          (chain hash breaks)          │
│                                                       │
│  Root + HMAC key       ✓ Can forge audit entries      │
│                        ✓ Can modify baseline           │
│                        ✓ Full audit bypass              │
│                        → HMAC key is the crown jewel  │
│                                                       │
│  Compromised kernel    ✓ Can suppress fanotify events │
│                        ✓ Can modify memory             │
│                        → Outside threat model          │
│                                                       │
╰───────────────────────────────────────────────────────╯
```

## Walkthrough

**Three trust zones.** Vigil classifies its inputs into
three zones. The untrusted zone includes everything vigil
is designed to monitor: filesystem content, process
attribution, and network endpoints. The
trusted-but-verified zone includes system services that
vigil relies on but validates: package managers (circuit
breaker on timeout) and the system clock (skew detection).
The trusted zone includes the kernel event interface and
the HMAC key.

**HMAC as crown jewel.** The HMAC key protects four
surfaces: baseline integrity, audit entry authenticity, WAL
entry authenticity, and control socket authentication. All
four are signed with the same key, loaded once at startup,
held in `Zeroizing` memory (cleared on drop), and never
re-read from disk. The key file permissions are enforced
(0600, root-owned) and hard-fail in release builds.

**Chain hash vs HMAC.** The audit chain hash proves
ordering and integrity (an attacker cannot reorder or
modify entries without detection). The HMAC proves
authenticity (an entry was written by a process holding the
key). These are complementary: the chain hash catches
tampering even without an HMAC key; the HMAC prevents an
attacker from forging a valid chain.

**DB identity tracking.** Vigil records the inode and
device number of each database file at startup. The
guardian thread checks these every second. If the
inode/device changes (indicating the file was replaced on
disk), the daemon enters Degraded state unless an
authorized replacement window is active (baseline refresh
TOCTOU coordination).

**Attacker capability matrix.** The matrix maps access
levels to capabilities. An unprivileged user can do nothing
meaningful. Root without the HMAC key can modify files (and
vigil will detect it) but cannot forge audit entries (the
chain hash will break). Root with the HMAC key has full
bypass capability — which is why the key file is the single
most important protection target.

This diagram shows the trust model. It does NOT show the
specific HMAC computation (see [audit-chain.md](
audit-chain.md)), the control socket authentication
protocol (see [control-socket.md](control-socket.md)), or
the DB identity check implementation (see code comments in
`src/coordinator/mod.rs`).

## Related diagrams

- [audit-chain.md](audit-chain.md) — chain hash and HMAC
  field composition
- [control-socket.md](control-socket.md) — authentication
  protocol
- [daemon-state-machine.md](daemon-state-machine.md) —
  Degraded states from identity checks
