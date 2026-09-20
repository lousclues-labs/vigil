# Notification Pipeline

Vigil Baseline's notification pipeline routes filesystem change detections
through severity-aware delivery policies, coalescing, storm suppression,
and channel fan-out.

## Pipeline Shape

```
WAL -> sink_runner -> NotificationRouter
                         |
                         +- per-severity policy lookup
                         +- coalesce buffer (per severity/group/parent)
                         +- storm detector (global rolling window)
                         +- channel fan-out
                         |
                         +-> desktop (notify-send)
                         +-> journald
                         +-> socket (Unix domain, NDJSON)
                         +-> webhook (HTTP POST, JSON)
                         +-> remote syslog (RFC 5424)
```

## Severity Policies

Each severity level has its own delivery policy:

| Severity | Delivery | Coalesce Window | Channels |
|----------|----------|-----------------|----------|
| Critical | immediate | -- | desktop, journald, socket, webhook |
| High | immediate | 30s | desktop, journald, socket |
| Medium | coalesce | 300s | journald, socket |
| Low | digest | 3600s | journald |

### Delivery Modes

- **immediate**: fire the notification as soon as the event arrives.
- **coalesce**: group events sharing the same coalescing key and fire
  when the window expires or when an immediate-severity event flushes.
- **digest**: accumulate into a periodic digest notification.

## Coalescing

Events coalesce when they share `(monitored_group, parent_directory, severity)`.
A coalesced notification reads:

```
3 files modified in /usr/bin (system_critical) in last window:
  - /usr/bin/curl  (content+mtime, package: curl)
  - /usr/bin/git   (content+mtime, package: git)
  - /usr/bin/ssh   (content+mtime, package: openssh)
Likely cause: package install
```

The "Likely cause" line is computed: if `package` is present for all events,
says "package install."

## Storm Suppression

When more than `alerts.storm_threshold` events (default 50) are eligible
for delivery within `alerts.storm_window_secs` (default 60), individual
notifications are suppressed and one storm notification fires:

```
ALERT STORM: 412 events in last 60s. Channel suppressed.
Run `vigil audit show --since 1m` for details.
Storm will end when event rate drops below threshold for 30s.
```

The audit log still records every event. Only the notification channel
is suppressed. The storm notification itself is Critical-priority and
never coalesces.

## Escalation (Critical Alerts)

Critical alerts include `event_id` in the notification text.

Escalation cadence is configured via
`[notifications.critical].escalate_at_secs` (default: `[300, 3600]`).
Each elapsed interval re-fires the critical alert with escalation context.

## Acknowledgment

Operator acknowledgment in 1.4.0 is for historical doctor events, not
notification `event_id` values.

Use:

- `vigil ack <kind> [--sequence <N>] [--note "<text>"]`
- `vigil ack list`
- `vigil ack revoke <kind> [--sequence <N>]`
- `vigil ack show <sequence>`

Acknowledgment adds operator context to doctor historical events.
It does not suppress doctor categories or silence future alerts.

For details, see [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) and
[CLI.md](CLI.md).

## Maintenance Window

When a maintenance window is active, every notification includes a
`[maintenance]` prefix. Operators stop being startled by package-install
bursts.

Inside a window, changes to files a package owns are **deferred**, at every
severity, rather than notified one by one. A single `apt upgrade` rewrites
hundreds of files under `/usr/bin/`, `/usr/sbin/` and `/boot/`, all of which
sit in the Critical watch group; alerting per file produced a notification
storm that buried the handful of changes that actually mattered.

Deferral is safe because it is not the end of the story. When the transaction
finishes, the post-transaction baseline refresh asks the package manager
whether each changed file's content matches the digest that package recorded:

| Verdict | Meaning | Operator sees |
|---------|---------|---------------|
| verified | Content matches the package's own recorded digest | nothing; proven benign |
| conffile | The package marks it operator-editable | nothing; you are meant to edit these |
| mismatch | A package owns it and the content is **not** what the package shipped | Critical alert |
| unverifiable | The package manager could not answer | reported, never assumed clean |

So the flood becomes one line naming only the files no package will vouch for.
A change to a path **no** package owns is never deferred: it alerts
immediately, even mid-transaction, because an attacker writing to
`/usr/local/bin` during your update is exactly the moment you need to know.

Every deferred change is still written to the audit log with its `suppressed`
flag set. Suppression decides what reaches your attention; it never decides
what is recorded (Principle XIII).

### The pre-transaction seal

Deferral answers "what did this update change". It does not answer "was
anything already wrong before it started", and after the fact nothing can: a
deviation found afterwards looks identical whether the update brought it or it
had been sitting there for a week.

So the pre-hooks take a seal first. Before the window opens and before the
package manager writes anything, vigil scans the watched set and records what
it finds, with a timestamp that necessarily precedes the transaction:

```
Vigil: sealed clean before this transaction (7,624 files checked)
```

or, when it is not clean:

```
VIGIL PRE-UPDATE DEVIATIONS: 2 (checked 7,624)
  /usr/local/bin/helper    already deviating before this transaction
  /etc/rc.local            already deviating before this transaction
```

Those go to the journal, and a non-clean seal raises one critical
notification. Afterwards, anything reported by the post-transaction verdict
that was not in the seal arrived with the update.

Seal records are written through the daemon's detection WAL and carry no
package attribution, so the maintenance window they precede can never silence
them. If an attestation key is configured at `/etc/vigil/attest.key`, the seal
also writes a signed, offline-verifiable receipt to
`<runtime_dir>/pre-transaction.vatt` binding the audit chain head at that
instant.

A seal whose scan fails says so and never reports a clean system.

## Webhook Channel

HTTP POST to a configured URL with the same JSON envelope as other channels.
Bearer-token auth optional. Retry with exponential backoff on 5xx responses.
Maximum 3 retries.

Configure in `vigil.toml`:

```toml
[alerts]
webhook_url = "http://alertmanager.local:9093/webhook"
webhook_bearer_token = "secret-token"
```

## Configuration Reference

```toml
[alerts]
storm_threshold = 50         # events before storm suppression activates
storm_window_secs = 60       # rolling window for storm detection
webhook_url = ""             # HTTP POST endpoint (empty = disabled)
webhook_bearer_token = ""    # optional Bearer token
```

See also: [CONFIGURATION.md](CONFIGURATION.md) for the full reference.
