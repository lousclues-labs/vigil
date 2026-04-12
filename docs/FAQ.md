# FAQ

Short answers to common questions.

---

## What is the difference between `vigil watch` and `vigil check`?

- `vigil watch` starts real-time monitoring and waits for filesystem events.
- `vigil check` is a one-shot scan run and then exits.

Use `watch` for continuous protection.
Use `check` for scheduled or manual verification.

---

## Does Vigil Baseline need root?

Not always.

- fanotify backend usually needs elevated capability (`CAP_SYS_ADMIN`), so daemon deployments commonly run as root/systemd service.
- if fanotify is unavailable, Vigil Baseline falls back to inotify with reduced coverage.

So root improves coverage, but Vigil Baseline can still run without it.

---

## Does Vigil Baseline phone home?

No.

Vigil Baseline performs no built-in telemetry, update checks, DNS lookups, or outbound network reporting.
All core behavior is local.

---

## What happens during `pacman -Syu`?

With hooks installed:
1. pre-transaction hook enters maintenance window
2. package updates apply
3. post-transaction hook refreshes baseline
4. maintenance window exits

Result: lower false-positive noise for package-managed file changes.
Audit records still retain detected changes.

---

## Can Vigil Baseline detect rootkits?

It can detect filesystem-level artifacts that rootkits leave on disk.
It cannot reliably detect a kernel-level rootkit that controls syscall truth.

Vigil Baseline is a user-space integrity observer, not kernel attestation.

---

## Why BLAKE3 instead of SHA-256?

Performance and determinism.

Vigil Baseline hashes a lot of files, repeatedly. BLAKE3 is faster for this workload while preserving strong integrity properties.
Faster hashing means less monitoring overhead and tighter scan windows.

---

## How is the audit trail tamper-evident?

Audit rows are always written, even when notifications are suppressed.

Use `vigil audit verify` to validate the audit chain.
It checks that each entry `chain_hash` links to the previous entry.

If HMAC signing is enabled, signatures add another integrity layer.

---

## Can I use Vigil Baseline on a server with no desktop?

Yes.

Desktop notifications are optional. They use `--app-name=Vigil Baseline` and map alert severity to `notify-send` urgency levels (critical, normal, low). On headless hosts, rely on:
- journald/syslog
- JSON alert file
- optional signal socket integration

Systemd units are included for daemon and scheduled scans.

---

## What is the performance impact of fanotify monitoring?

Typical impact is low for normal desktop/server activity because:
- event filtering removes excluded/self-generated noise
- per-path debounce suppresses repeated bursts
- scheduled scans run at low priority (`ioprio` idle, `nice` 19)

Actual cost depends on watch scope size and file churn.
If noise/perf is high, tighten watch groups and exclusions.

---

## Does Vigil Baseline block attacks automatically?

No.

Principle I is explicit: Watch, Don't Act.
Vigil Baseline reports boundary violations. Operator decides response.

---

## Is this an EDR or antivirus replacement?

No.

Vigil Baseline focuses on deterministic file integrity monitoring.
It does not do behavioral analysis, malware classification, quarantine, or remediation.

---

*Vigil Baseline answers one question very well: did this file boundary change?*
