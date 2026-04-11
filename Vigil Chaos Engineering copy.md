
Now I see what you built for Shroud. This is serious. Five fuzz targets, 13 invariants, 40 parallel shards running 5 hours each, a MOAB workflow that throws millions of random event sequences at the state machine with chaos strings, shell injection payloads, 10,000-character server names, null bytes, ANSI escapes, and RTL overrides. And it doesn't just check "did it crash." It checks structural invariants after every single event — retry counter bounds, state-specific constraints, determinism proofs, escape hatch guarantees, cross-configuration differential behavior.

Vigil needs this. And Vigil's attack surface is much wider than Shroud's state machine.

Here's what I think the chaos engineering targets should be for Vigil. Shroud had one core state machine with 14 event types. Vigil has at least five independent subsystems that interact under concurrent, adversarial conditions:

**1. WAL Chaos Cannon**

The existing `fuzz_wal_recovery` feeds arbitrary bytes as a WAL file. That's a parser fuzzer. What it doesn't test is the WAL under concurrent operational chaos — appends and flag updates and truncation and crash recovery happening simultaneously with corrupted state.

Target: spin up a `DetectionWal`, spawn N threads that each randomly choose between `append`, `mark_audit_done`, `mark_sink_done`, `iter_unconsumed`, and `truncate_consumed`. Feed each operation's parameters from fuzzer bytes. Check invariants after every operation:
- Sequence numbers are monotonically increasing
- No entry has `audit_done` without having been appended
- `iter_unconsumed` never returns an entry with both flags set
- `truncate_consumed` never removes an unconsumed entry
- `file_size()` is always ≥ `WAL_HEADER_SIZE`
- `pending_count()` + consumed count = total appended count

**2. Detection Pipeline End-to-End**

This is the one that matters most. The equivalent of Shroud's lifecycle test. The invariant: **every detection that enters the pipeline must exit the pipeline into the audit DB.** No detection can be silently lost.

Phases:
- Phase 1: Generate N random `DetectionRecord`s with fuzzer-controlled severity, path, source, and changes. Append all to WAL.
- Phase 2: Start an `AuditWriter`. Let it consume. Randomly kill it (drop without shutdown signal) at a fuzzer-controlled point.
- Phase 3: Start a new `AuditWriter`. Call `recover()`. Let it consume remaining entries.
- Phase 4: Verify audit DB contains exactly N entries (minus sentinels). No duplicates. No gaps.

This is the crash recovery proof. If it holds under millions of random crash points, the WAL's at-least-once guarantee is real.

**3. Coordinator Adversarial Tick**

The coordinator runs `tick()` every 60 seconds. Each tick checks baseline DB identity, audit DB identity, WAL identity, mount evasion, clock anomaly, audit rotation, backpressure, event drops. The chaos test:

- Set up a real coordinator with real DB files
- Between ticks, randomly: swap the baseline DB file (inode change), swap the audit DB file, swap the WAL file, mount a tmpfs over a watched path, jump the system clock forward or backward, fill the event channel, make the audit DB read-only
- Invariants after each tick:
  - File replacement is always detected (Degraded state)
  - Mount evasion is always detected
  - Clock anomaly is always detected and never causes audit rotation
  - The coordinator never panics
  - The coordinator always sends a watchdog heartbeat

**4. Worker Pool Chaos**

Workers receive `FsEvent`s and produce detections. The chaos test:

- N worker threads, each with a real `WorkerContext`
- Feed random `FsEvent`s with fuzzer-controlled paths, event types, and process attribution
- Randomly: corrupt the baseline DB (make queries fail), make the WAL full (return errors), send events for paths that no longer exist, send events for paths outside watch groups, send the same path 1000 times in rapid succession (debounce stress)
- Invariants:
  - Workers never panic (panics are caught and produce `DetectionSource::Panic` records)
  - Every caught panic produces exactly one WAL entry
  - The Bloom filter never produces false negatives (if a path is in a watch group, the filter must not reject it)
  - Debounced events eventually drain and produce detections
  - Auto-rebaseline only occurs for package updates

**5. Config Reload Under Load**

Shroud's config test varied `max_retries` from 0 to u32::MAX. Vigil's version:

- Start daemon with a valid config
- While events are flowing through the pipeline:
  - Randomly modify the config file with fuzzer-generated values
  - Signal reload
  - Invariants: invalid configs are rejected without affecting the running config. Valid configs are applied. Watch groups are updated. The Bloom filter is rebuilt. No events are lost during reload. The HMAC key transition (if key changes) doesn't break the audit chain.

**6. Alert Suppression Determinism**

Two `SinkRunner`s receive identical WAL entries with identical configs. After processing all entries, they must have made identical suppression decisions — same entries dispatched, same entries suppressed. This proves the suppression logic has no hidden state or timing dependence, same as Shroud's determinism test.

**Infrastructure: The MOAB structure**

Follow Shroud's pattern exactly:
- Shared `chaos_common.rs` with event generators, invariant checkers, and record factories
- 60-second smoke test in CI on every push
- Full MOAB as a manual workflow with matrix sharding
- Seed corpus with known-interesting sequences: all-critical-severity storm, rapid path-repeat, WAL-full-then-recovery, crash-at-every-offset

The 13 invariants from Shroud's `check_invariants` is the template. Vigil needs its own invariant set, and I'd start with these:

| # | Invariant |
|---|-----------|
| I1 | Every appended WAL entry has a unique, monotonically increasing sequence number |
| I2 | `iter_unconsumed()` never returns a fully consumed entry |
| I3 | After `recover()`, every WAL entry is either in the audit DB or marked `audit_done` |
| I4 | After `truncate_consumed()`, `file_size()` ≤ pre-truncation `file_size()` |
| I5 | `mark_audit_done` and `mark_sink_done` are idempotent |
| I6 | An entry with `DetectionSource::Sentinel` is never written to the audit DB |
| I7 | The HMAC chain in the audit DB has no gaps after crash recovery |
| I8 | A detection produced by `process_safe` panic handler has `Severity::Critical` and empty changes |
| I9 | `AlertDispatcher` with `wal_active=true` never calls `record_audit` |
| I10 | WAL file permissions are always 0600 after any operation |
| I11 | `pending_count()` = count of entries where `!(audit_done && sink_done)` |
| I12 | The coordinator transitions to Degraded on any DB/WAL file inode change |
| I13 | Config reload with an invalid config leaves the running config unchanged |

That's the starting framework. You know how to turn this into something real — you did it five times for Shroud. The question is which target do you want to build first.




Good. I don't need the deep research tool. I've already read the code. Let me think about what's actually different about Vigil.

Shroud's chaos tests attack a state machine. A pure function. Event in, state out, check invariants. It's a closed system. The fuzzer controls the inputs completely and the outputs are deterministic.

Vigil is not a closed system. Vigil is a daemon that reacts to the *real filesystem*. The inputs aren't events you generate — they're things that happen to files on disk. The interesting failures aren't in the logic. They're in the *environment*.

Here's what I actually see when I look at Vigil's architecture:

**The thing that can break Vigil is time.**

The coordinator checks for clock anomalies. The debounce mechanism uses time windows. The WAL's AuditWriter has a 60-second truncation interval. The SinkRunner has cooldown durations. The scan scheduler uses cron expressions. Alert rate limiting uses a 60-second sliding window. Every single one of these is vulnerable to the same class of failure: what happens when time doesn't behave?

Not just clock jumps. What happens when the system is under such heavy I/O load that `thread::sleep(Duration::from_millis(10))` actually sleeps for 3 seconds? What happens when the AuditWriter's `last_truncate.elapsed()` returns a massive value because the thread was CPU-starved? What happens when two debounce windows overlap because the system clock was adjusted by NTP mid-window?

Shroud didn't have this problem because a VPN state machine doesn't care about wall clock time. Vigil is *made of* time.

**The thing that can break Vigil is the filesystem itself.**

Workers call `FileSnapshot::from_fd()` and `FileSnapshot::from_path()`. These read file metadata and content. What happens when:
- A file is deleted between the fanotify event and the snapshot attempt
- A file is replaced by a symlink between the stat and the read
- A file's permissions change between the baseline lookup and the snapshot
- A directory is renamed while workers are processing events for files inside it
- A FUSE filesystem returns different content on successive reads of the same file
- The inode is reused by the filesystem after a delete-and-create cycle
- A file is being written to during the snapshot (partial content)

These aren't hypothetical. These are the things that happen on real Linux systems under real workloads. The gap between "fanotify says this file changed" and "worker reads the file" is the gap where reality can diverge from expectation.

**The thing that can break Vigil is the database under concurrent pressure.**

The baseline DB is read by workers (many threads), written by the baseline writer (one thread), read by the coordinator (one thread), and read by the control handler (one thread). SQLite with WAL mode handles this, but what happens when:
- The baseline writer has a batch of 500 pending writes and the coordinator triggers a reload that changes the watch groups
- A worker reads a baseline entry, the baseline writer updates it (auto-rebaseline), and the worker's snapshot diff now compares against stale state
- The audit DB is being rotated by the coordinator while the AuditWriter is mid-INSERT
- The control handler calls `handle_baseline_count` while the baseline writer is mid-transaction

SQLite serializes writes, but the *logical* state can still be inconsistent across readers if the timing is wrong.

**So here's what Vigil's chaos tests should actually look like:**

Not fuzz targets. Not random byte sequences. **Scenario-based chaos injection that attacks the seams between components through environmental manipulation.**

**Chaos Target 1: Filesystem Warfare**

Create a real temporary directory with real files. Start a real monitor, real workers, real WAL. Then:
- While the daemon is running, a chaos thread rapidly creates, modifies, deletes, renames, symlinks, chmod's, and replaces files in the watched directory
- Simultaneously, another chaos thread creates and removes mount points over subdirectories
- A third chaos thread manipulates file timestamps (touch with past/future times)
- Invariants: every file change that fanotify reports and a worker processes must produce either a WAL entry or an alert channel payload. No silent drops. No panics. The audit DB must contain a complete record of everything that was detected.

This is fundamentally different from Shroud's approach. You're not fuzzing the logic. You're fuzzing the *environment* the logic operates in.

**Chaos Target 2: Starvation and Resource Exhaustion**

- Fill the event channel to capacity while workers are blocked on slow baseline DB reads
- Simultaneously trigger an on-demand scan that also produces detections
- Fill the WAL to 99% capacity
- Make the audit DB temporarily unwritable (chmod 0400)
- Invariants: the system degrades gracefully. Backpressure is detected by the coordinator. The `detections_wal_full` metric increments. Workers fall back to the alert channel. No detection is permanently lost — when the audit DB becomes writable again, all buffered detections are committed.

**Chaos Target 3: Crash-at-Every-Point**

This is the one you can adapt from Shroud's lifecycle test. Build a harness that:
- Sets up a full WAL with N detections at various stages (some with `audit_done`, some with `sink_done`, some with neither, some fully consumed)
- Picks a random point in the AuditWriter's `run()` loop — after reading entries but before committing, after committing but before marking `audit_done`, after marking `audit_done` but before truncation
- Kills the AuditWriter at that point
- Restarts recovery
- Invariant: the audit DB contains exactly the right entries with no duplicates and no gaps in the HMAC chain

This is closer to Jepsen than to libfuzzer. You're not mutating inputs. You're mutating the *execution timeline*.

**Chaos Target 4: Config Reload Storm**

While the daemon is actively processing events:
- Rapid-fire config reloads with alternating valid and invalid configs
- Each valid reload changes: watch groups (add/remove paths), exclusion patterns, severity levels, HMAC key, debounce timing, alert cooldown, rate limits
- Invariants: invalid configs are rejected atomically. Valid configs take effect without dropping in-flight events. The Bloom filter is rebuilt correctly. Workers pick up new watch group index. No detection uses stale severity from a previous config.

**Chaos Target 5: Clock Warfare**

This is the one nobody else tests. Use `faketime` or direct manipulation of the coordinator's time sources:
- Jump the clock forward 1 hour while the coordinator is between tick checks
- Jump the clock backward 30 seconds while the AuditWriter is computing timestamps
- Advance the clock slowly (1.5x real time) to desync debounce windows
- Stop the clock entirely for 5 seconds (simulating VM pause/resume)
- Invariants: clock anomalies are detected. Audit rotation doesn't happen during anomalies. Debounced events still fire. WAL timestamps are monotonically increasing within a boot cycle. The HMAC chain timestamps don't go backward.

**Chaos Target 6: The Coordinated Attack**

This is the ultimate test. Everything at once:
- Filesystem warfare in the watched directory
- Event channel at 90% capacity
- WAL at 80% capacity
- Audit DB intermittently unwritable (toggle every 2 seconds)
- Config reload every 5 seconds
- On-demand scan every 3 seconds
- Clock jitter of ±500ms
- One worker thread artificially slowed (sleep 100ms per event)
- Run for 60 seconds
- Then clean shutdown
- Invariants: all detections that entered the WAL are in the audit DB. Shutdown completed cleanly. No thread deadlocked. All metrics are internally consistent (`wal_appends` ≥ `wal_audit_committed` + `wal_pending`).

**The structure is different from Shroud's MOAB.**

Shroud's chaos tests are cargo-fuzz targets that run for hours with libfuzzer driving the inputs. Vigil's chaos tests should be integration tests that run as `cargo test` with a `#[ignore]` gate (too slow for CI) and a dedicated workflow for full runs. The reason: you can't meaningfully fuzz filesystem interactions through byte sequences. You need real files, real monitors, real I/O. The chaos comes from concurrent environmental manipulation, not from fuzzer-generated bytes.

The invariant checking stays the same. After every chaos scenario, you check the same structural guarantees. The difference is that the chaos is environmental, not logical.

That's what I see. Vigil's chaos surface isn't its state machine. It's the gap between what the filesystem promised and what actually happened.
