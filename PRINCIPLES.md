# Principles

This is the values layer of Promise Driven Development (PDD) for Vigil
Baseline.

A principle here is not a slogan. It is a value that a real frustration forced
us to name, and it earns its place only by forbidding something the tool would
otherwise be tempted to do. Every principle below must spawn at least one
promise in [PROMISES.md](PROMISES.md). A principle that guards nothing has been
cut or sharpened until it does.

The longer-form philosophy that these operationalize lives in
[docs/PRINCIPLES.md](docs/PRINCIPLES.md). This file is the part we can prove.

The spine: **Principles -> Promises -> Canaries -> Ledger.** A claim Vigil
Baseline makes about itself must be something the tool can prove, and the proof
must fail loudly when the claim stops being true.

---

## P1. A witness watches. It never acts.

**The frustration.** Security tools that act are tools that eventually act
wrong. A quarantine that eats a file you needed, a kill that takes out the
session, an execution block that fires on the wrong binary. The damage lands on
the operator, and it lands at the worst possible moment, because tools act at
exactly the moments the operator is least able to absorb a surprise.

**What we value.** Vigil observes and reports. The operator decides. A tool
that only watches can never make the wrong move; it can only fail to see, and
that failure mode is testable, fixable, and honest. This is also why the
fanotify backend is opened in notification class: the kernel interface that
would let Vigil block a syscall is one we refuse to hold.

**This principle forbids:**
- Requesting fanotify permission events or answering them with an allow or
  deny verdict.
- Deleting, quarantining, truncating, renaming, or re-permissioning a watched
  file from any detection path.
- Signalling, stopping, or killing another process. A liveness probe
  (`kill(pid, 0)`, which sends nothing) is the only permitted use of `kill`.

Spawns promises: PR1, PR2.

---

## P2. The verdict is a comparison, never a judgment.

**The frustration.** "Suspicious." "Anomalous." "Risk score 72." Every one of
those words moves the burden of proof onto the operator while telling them
nothing they can check. A tool that guesses is a tool whose output you cannot
reason about, and a tool whose output you cannot reason about gets ignored.

**What we value.** Hashes match or they do not. The inode is the same or it was
replaced. Every detection is a pure comparison of a captured snapshot against a
recorded baseline, and the same inputs always produce the same output. Nothing
in the verdict depends on training data, a vendor feed, or a threshold someone
tuned once.

**This principle forbids:**
- Risk scores, confidence values, probabilities, or severity computed from
  anything other than the operator's own configuration.
- Machine learning, behavioral analysis, reputation lookups, or threat
  intelligence feeds anywhere in the detection surface.
- Letting a probabilistic structure decide anything. The Bloom prefilter may
  say "maybe," and a "maybe" is always resolved by exact comparison.

Spawns promises: PR3, PR4, PR5.

---

## P3. Silence means intact, never ignored.

**The frustration.** A quiet dashboard is worthless if quiet is also what a
dropped event looks like. The moment silence becomes ambiguous, the tool has
trained its operator to stop trusting it, and every alert after that costs
more attention than it is worth.

**What we value.** Vigil is silent during normal operation because nothing
crossed a boundary, not because something got swallowed. An unchanged file
produces no change, and a watched path is never discarded by an optimization
on the way to the comparison.

**This principle forbids:**
- A diff that reports a change for a file that did not change.
- Any prefilter, cache, or fast path that can drop an event for a watched path
  before the comparison runs.

Spawns promises: PR5, PR6.

---

## P4. The audit trail never lies.

**The frustration.** Notification suppression is necessary (fifty popups during
a package upgrade is a failure), but a tool that suppresses the *record* along
with the popup has quietly deleted the evidence. An attacker who moves during a
maintenance window would then be invisible forever, not just tonight.

**What we value.** Suppression is a decision about the operator's attention. It
is never a decision about the truth. Everything detected is written down, the
suppressed ones flagged as suppressed, in a chain where an edit or a deletion
is detectable after the fact.

**This principle forbids:**
- Skipping the audit write for an event because it was suppressed, coalesced,
  rate limited, or inside a maintenance window.
- An audit log whose rows can be altered or removed without the tampering
  being detectable.
- Treating the fact that a package owns a path as proof that the package wrote
  the bytes now in it, or reading a verification that did not run as one that
  passed.
- Leaving the operator unable to tell drift that predates a change window from
  drift the window brought with it.

Spawns promises: PR7, PR8, PR18, PR20.

---

## P5. Degradation is announced, never silent.

**The frustration.** A monitor running with half its coverage and a green
status line is worse than no monitor, because the operator budgets their
attention against a lie. Silent degradation is the specific failure that turns
a security tool into a liability.

**What we value.** When the kernel, the capability set, or the queue cannot
give Vigil what it needs, the operator hears about it. Blind spots are counted
and reported. A fallback is a warning, never an "OK."

**This principle forbids:**
- Reporting a healthy or "OK" status for a degraded backend or a reduced
  event mask.
- Dropping events without counting them and without triggering the
  compensating scan.
- Leaving a maintenance window open indefinitely, or letting a closure that
  only happened in memory be undone by a restart.

Spawns promises: PR9, PR10, PR19.

---

## P6. Local by design.

**The frustration.** "No telemetry" in a README is a sentence, and sentences
drift. One dependency with a built-in update check, one crash reporter added
for convenience, and the tool that was supposed to watch your filesystem is
talking to someone else's server about it.

**What we value.** Vigil works with the network cable unplugged, because there
is nothing in it that wants the network. The two outbound integrations that
exist (a webhook and remote syslog) are the operator's own choice, aimed at the
operator's own infrastructure, and off until they say otherwise.

**This principle forbids:**
- Linking an HTTP client, telemetry SDK, crash reporter, cloud SDK, or
  update-check crate.
- Network code anywhere outside the two opt-in alert sinks.
- Any outbound integration that is on by default.

Spawns promises: PR11, PR12.

---

## P7. Stands alone, and stays small.

**The frustration.** Tools that grow tendrils into each other cannot be
reasoned about, audited, or removed. Complexity is the vulnerability that
enables all the others, and every unsafe block is a place where the compiler
stops helping.

**What we value.** Vigil compiles, runs, and does its whole job with no other
tool present. It reads no sibling project's database and no sibling project
reads its own. Unsafe code exists only where a Linux syscall must be made, in a
small enumerated set of modules, and nowhere else.

**This principle forbids:**
- Depending on, importing, or reading the state of another lousclues tool.
- Introducing `unsafe` outside the enumerated syscall-boundary modules, or
  removing the crate-level `#![deny(unsafe_code)]`.

Spawns promises: PR13, PR14.

---

## P8. A self-claim ships with a proof that fails loud, or it does not ship.

**The frustration.** Claims rot silently. A README line that was true at commit
time drifts out of truth three refactors later, and nothing notices until an
operator gets burned. Some invariants (no network client anywhere in the tree,
no actuation in any detection path) are cross-cutting, so no single unit test
ever sees them.

**What we value.** Each promise is matched to a canary that lives where the
promise lives, and the loud failure of that canary is the alarm. Drift is
caught by a required, merge-blocking gate and recorded in the ledger so the
same regression cannot return unguarded. What we hand a user is verifiable by
that user, not just by us.

**This principle forbids:**
- Adding or keeping a self-claim that has no canary.
- Merging past a red canary.
- Shipping a release the operator cannot independently verify.
- Closing a ledger finding without naming the canary that prevents recurrence.

Spawns promises: PR15, PR16, PR17.

---

*These principles are the values layer. The commitments that discharge them,
and the canaries that prove them, are in [PROMISES.md](PROMISES.md). Drift is
tracked in [AUDIT_FINDINGS.md](AUDIT_FINDINGS.md).*
