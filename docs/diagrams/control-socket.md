# Control Socket

Daemon-to-CLI architecture: request/response framing,
every request type listed by name, and the dispatch shape.
Specific request implementations change; the protocol
shape is the architectural commitment.

The control socket handler lives in
`src/control.rs::ControlHandler`.

```
╭──── CLI (vigil status / vigil scan / ...) ────────╮
│                                                    │
│  Connect to /run/vigil/control.sock (Unix socket)  │
│                                                    │
╰───────────────────────┬────────────────────────────╯
                        │
                   Unix stream
                        │
╭──── vigild control thread ────────────────────────╮
│                                                    │
│  ╭──── Connection Handling ──────────────────────╮ │
│  │                                               │ │
│  │  1. Accept connection (non-blocking poll)     │ │
│  │  2. Concurrency guard (max 8 in-flight)       │ │
│  │  3. Set read/write timeouts (5s each)         │ │
│  │  4. Read peer credentials (SO_PEERCRED)       │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
│  ╭──── Authentication (if HMAC enabled) ────────╮ │
│  │                                               │ │
│  │  Daemon                         CLI           │ │
│  │    │                             │            │ │
│  │    │  ◄── connect ──────────────►│            │ │
│  │    │                             │            │ │
│  │    │  ── challenge ──────────────►│            │ │
│  │    │     { nonce: <32B random> }  │            │ │
│  │    │                             │            │ │
│  │    │  ◄── response ──────────────│            │ │
│  │    │     { hmac: HMAC(key,nonce)} │            │ │
│  │    │                             │            │ │
│  │    │  verify HMAC                │            │ │
│  │    │  ── ok / reject ───────────►│            │ │
│  │                                               │ │
│  │  Nonce: /dev/urandom, single-use              │ │
│  │  HMAC: SHA-256 with same key as audit chain   │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
│  ╭──── Request/Response Framing ────────────────╮ │
│  │                                               │ │
│  │  Request:  single JSON line (max 64KB)        │ │
│  │    { "method": "<name>", ...params }          │ │
│  │                                               │ │
│  │  Response: single JSON line                   │ │
│  │    { "ok": true/false, ...data }              │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
│  ╭──── Dispatch ────────────────────────────────╮  │
│  │                                               │ │
│  │  method              action                   │ │
│  │  ──────────────────  ──────────────────────── │ │
│  │  status              daemon state + metrics   │ │
│  │  baseline_count      row count from baseline  │ │
│  │  reload              trigger config reload    │ │
│  │  scan                trigger on-demand scan   │ │
│  │  metrics_prometheus  Prometheus-format export  │ │
│  │  maintenance_enter   start maintenance window │ │
│  │  maintenance_exit    end maintenance window   │ │
│  │  baseline_refresh    swap baseline atomically │ │
│  │  expect_file_change  register file expectation│ │
│  │                                               │ │
│  │  Unknown method → {"ok":false, "error":...}   │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
╰────────────────────────────────────────────────────╯


╭──── Security Properties ──────────────────────────╮
│                                                    │
│  Socket permissions    0600 (root only)            │
│  Peer credentials      SO_PEERCRED UID check       │
│  Read bound            64KB max per request        │
│  Concurrency bound     8 max in-flight             │
│  Timeouts              5s read, 5s write           │
│  Auth (if enabled)     challenge-response HMAC     │
│  Stale socket          removed on startup          │
│                                                    │
╰────────────────────────────────────────────────────╯
```

## Walkthrough

**Protocol shape.** The control socket uses a simple
request/response protocol over a Unix domain stream
socket. Each request is a single JSON line with a `method`
field and optional parameters. Each response is a single
JSON line with an `ok` boolean and method-specific data.
The protocol is synchronous: one request, one response,
then the connection closes.

**Authentication.** When HMAC is enabled, the daemon sends
a challenge containing a random nonce (32 bytes from
`/dev/urandom`). The CLI computes `HMAC-SHA256(key, nonce)`
and sends it back. The daemon verifies using constant-time
comparison. This prevents unauthorized CLI commands even if
an attacker gains access to the socket file.

**Concurrency control.** At most 8 connections can be
in-flight simultaneously. This prevents a slow or
malicious peer from starving legitimate health-check
traffic (e.g., from `vigil update`'s post-install health
check). Excess connections receive a JSON refusal and close
immediately.

**Request types.** The dispatch table lists every request
the daemon handles. Adding a new request type is an
architectural change (it extends the protocol surface).
Modifying an existing request's internal implementation is
not (the protocol shape stays the same).

**Bounded reads.** Every request is read with a 64KB bound
(`MAX_REQUEST_LINE_BYTES`). This prevents OOM attacks from
a malicious socket client sending unbounded data.

This diagram shows the control socket architecture. It
does NOT show the specific JSON schema for each request
type (see code comments on each `handle_*` method in
`src/control.rs`), the `baseline_refresh` TOCTOU
coordination (see [coordinator-split.md](
coordinator-split.md)), or the `expect_file_change`
expectation registry mechanics (see code comments in
`src/coordinator/expectation.rs`).

## Related diagrams

- [trust-boundaries.md](trust-boundaries.md) — where
  the control socket sits in the trust model
- [system-overview.md](system-overview.md) — the control
  thread in the full system
