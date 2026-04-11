// tests/chaos/harness.rs — Chaos harness: seeded RNG, clock abstraction, fault injectors,
// invariant engine, and artifact writer.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Seeded RNG
// ---------------------------------------------------------------------------

/// Simple xoshiro256** PRNG — deterministic, seedable, no external dep.
#[derive(Clone)]
pub struct ChaosRng {
    s: [u64; 4],
}

impl ChaosRng {
    pub fn new(seed: u64) -> Self {
        // SplitMix64 seeding
        let mut z = seed;
        let mut s = [0u64; 4];
        for slot in &mut s {
            z = z.wrapping_add(0x9e3779b97f4a7c15);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            *slot = z ^ (z >> 31);
        }
        Self { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = (self.s[1].wrapping_mul(5))
            .rotate_left(7)
            .wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Random u64 in [0, bound).
    pub fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    /// Random usize in [0, bound).
    pub fn next_usize(&mut self, bound: usize) -> usize {
        self.next_bounded(bound as u64) as usize
    }

    /// Random bool with given probability (0.0 = never, 1.0 = always).
    pub fn chance(&mut self, p: f64) -> bool {
        (self.next_u64() as f64 / u64::MAX as f64) < p
    }

    /// Pick a random element from a slice.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.next_usize(items.len())]
    }

    /// Shuffle a slice in-place (Fisher-Yates).
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.next_usize(i + 1);
            items.swap(i, j);
        }
    }

    /// Derive a child RNG for parallel use.
    pub fn fork(&mut self) -> Self {
        Self::new(self.next_u64())
    }
}

// ---------------------------------------------------------------------------
// Schedule Generation
// ---------------------------------------------------------------------------

/// A chaos schedule is a sequence of fault actions to perform at specific steps.
#[derive(Debug, Clone)]
pub struct ChaosSchedule {
    pub seed: u64,
    pub total_steps: usize,
    pub actions: Vec<ScheduledAction>,
}

#[derive(Debug, Clone)]
pub struct ScheduledAction {
    pub step: usize,
    pub action: FaultAction,
}

#[derive(Debug, Clone)]
pub enum FaultAction {
    /// Create/modify/delete/rename a file.
    FsMutate { path: PathBuf, mutation: FsMutation },
    /// Toggle DB file permissions (writable ↔ read-only).
    DbPermissionToggle { path: PathBuf },
    /// Fill an event channel to a percentage of its capacity.
    ChannelSaturate { fill_pct: u8 },
    /// Inject a time anomaly.
    ClockAnomaly(ClockFault),
    /// Force a WAL recovery cycle.
    ForceRecovery,
    /// Simulate a crash at a specific failpoint.
    CrashAt { failpoint: CrashFailpoint, iteration: u32 },
    /// Inject slow-path processing.
    SlowPath { delay_ms: u64 },
    /// Trigger config reload.
    ConfigReload,
    /// Trigger an on-demand scan.
    OnDemandScan,
}

#[derive(Debug, Clone)]
pub enum FsMutation {
    Create { content: Vec<u8> },
    Modify { content: Vec<u8> },
    Delete,
    Rename { new_name: String },
    Chmod { mode: u32 },
    SymlinkReplace { target: PathBuf },
    InodeReuse,
    PartialWrite { content: Vec<u8>, write_bytes: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum CrashFailpoint {
    AfterReadBeforeCommit,
    AfterCommitBeforeMarkAuditDone,
    AfterMarkAuditDoneBeforeTruncate,
}

impl fmt::Display for CrashFailpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AfterReadBeforeCommit => write!(f, "after_read_before_commit"),
            Self::AfterCommitBeforeMarkAuditDone => {
                write!(f, "after_commit_before_mark_audit_done")
            }
            Self::AfterMarkAuditDoneBeforeTruncate => {
                write!(f, "after_mark_audit_done_before_truncate")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Clock Abstraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockFault {
    /// Jump forward by given seconds.
    ForwardJump(i64),
    /// Jump backward by given seconds.
    BackwardJump(i64),
    /// Freeze clock for given duration.
    Freeze(u64),
    /// Random jitter in [-ms, +ms].
    Jitter(i64),
}

/// An injectable clock for deterministic time testing.
#[derive(Clone)]
pub struct InjectedClock {
    /// Offset from real time in seconds.
    offset_secs: Arc<AtomicI64>,
    /// Whether the clock is frozen.
    frozen: Arc<AtomicBool>,
    /// Frozen timestamp value.
    frozen_at: Arc<AtomicI64>,
}

impl InjectedClock {
    pub fn new() -> Self {
        Self {
            offset_secs: Arc::new(AtomicI64::new(0)),
            frozen: Arc::new(AtomicBool::new(false)),
            frozen_at: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn now_timestamp(&self) -> i64 {
        if self.frozen.load(Ordering::Acquire) {
            return self.frozen_at.load(Ordering::Acquire);
        }
        chrono::Utc::now().timestamp() + self.offset_secs.load(Ordering::Acquire)
    }

    pub fn inject_fault(&self, fault: &ClockFault) {
        match fault {
            ClockFault::ForwardJump(secs) => {
                self.offset_secs.fetch_add(*secs, Ordering::AcqRel);
            }
            ClockFault::BackwardJump(secs) => {
                self.offset_secs.fetch_sub(*secs, Ordering::AcqRel);
            }
            ClockFault::Freeze(_) => {
                let t = self.now_timestamp();
                self.frozen_at.store(t, Ordering::Release);
                self.frozen.store(true, Ordering::Release);
            }
            ClockFault::Jitter(ms) => {
                let secs = *ms / 1000;
                self.offset_secs.fetch_add(secs, Ordering::AcqRel);
            }
        }
    }

    pub fn unfreeze(&self) {
        self.frozen.store(false, Ordering::Release);
    }

    pub fn reset(&self) {
        self.offset_secs.store(0, Ordering::Release);
        self.frozen.store(false, Ordering::Release);
    }
}

impl Default for InjectedClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Fault Injectors
// ---------------------------------------------------------------------------

/// Filesystem mutator — applies controlled mutations to a target directory.
pub struct FsMutator {
    pub root: PathBuf,
}

impl FsMutator {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    pub fn apply(&self, mutation: &FsMutation, target: &Path) {
        let full = if target.is_absolute() {
            target.to_path_buf()
        } else {
            self.root.join(target)
        };
        match mutation {
            FsMutation::Create { content } => {
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent).ok();
                }
                fs::write(&full, content).ok();
            }
            FsMutation::Modify { content } => {
                fs::write(&full, content).ok();
            }
            FsMutation::Delete => {
                fs::remove_file(&full).ok();
            }
            FsMutation::Rename { new_name } => {
                if let Some(parent) = full.parent() {
                    let dest = parent.join(new_name);
                    fs::rename(&full, &dest).ok();
                }
            }
            FsMutation::Chmod { mode } => {
                if let Ok(meta) = fs::metadata(&full) {
                    let mut perms = meta.permissions();
                    perms.set_mode(*mode);
                    fs::set_permissions(&full, perms).ok();
                }
            }
            FsMutation::SymlinkReplace { target: tgt } => {
                fs::remove_file(&full).ok();
                std::os::unix::fs::symlink(tgt, &full).ok();
            }
            FsMutation::InodeReuse => {
                // Delete and recreate — new inode, same path.
                let content = fs::read(&full).unwrap_or_default();
                fs::remove_file(&full).ok();
                fs::write(&full, &content).ok();
            }
            FsMutation::PartialWrite {
                content,
                write_bytes,
            } => {
                let n = (*write_bytes).min(content.len());
                fs::write(&full, &content[..n]).ok();
            }
        }
    }

    /// Create N random files in root.
    pub fn seed_files(&self, rng: &mut ChaosRng, count: usize) -> Vec<PathBuf> {
        let mut paths = Vec::with_capacity(count);
        for i in 0..count {
            let name = format!("chaos_file_{:04}", i);
            let p = self.root.join(&name);
            let size = 64 + rng.next_bounded(4096) as usize;
            let content: Vec<u8> = (0..size).map(|_| rng.next_u64() as u8).collect();
            fs::write(&p, &content).ok();
            paths.push(p);
        }
        paths
    }
}

/// DB permission toggler.
pub struct DbPermissionToggler {
    path: PathBuf,
    read_only: AtomicBool,
}

impl DbPermissionToggler {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            read_only: AtomicBool::new(false),
        }
    }

    pub fn toggle(&self) {
        let currently_ro = self.read_only.load(Ordering::Acquire);
        let mode = if currently_ro { 0o600 } else { 0o400 };
        if let Ok(meta) = fs::metadata(&self.path) {
            let mut perms = meta.permissions();
            perms.set_mode(mode);
            fs::set_permissions(&self.path, perms).ok();
        }
        self.read_only.store(!currently_ro, Ordering::Release);
    }

    pub fn ensure_writable(&self) {
        if let Ok(meta) = fs::metadata(&self.path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.path, perms).ok();
        }
        self.read_only.store(false, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Invariant Engine
// ---------------------------------------------------------------------------

/// Identifies which global invariant is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvariantId {
    I1UniqueMonotonicSeq,
    I2IterUnconsumedNoFullyConsumed,
    I3NoPermanentLoss,
    I4TruncateNeverIncreasesSize,
    I5MarkIdempotent,
    I6SentinelExcludedFromDurability,
    I7AuditHmacChainNoGaps,
    I8PanicSeverityCritical,
    I9WalMediatedPath,
    I10WalPermissions0600,
    I11PendingCountCorrect,
    I12CoordinatorDegradedOnInodeChange,
    I13InvalidConfigRejected,
}

impl fmt::Display for InvariantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A structured invariant failure report.
#[derive(Debug, Clone)]
pub struct InvariantFailure {
    pub id: InvariantId,
    pub step: usize,
    pub message: String,
    pub context: BTreeMap<String, String>,
}

impl fmt::Display for InvariantFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] step={}: {}", self.id, self.step, self.message)?;
        for (k, v) in &self.context {
            write!(f, "\n  {}: {}", k, v)?;
        }
        Ok(())
    }
}

/// Accumulates invariant checks and failures.
pub struct InvariantEngine {
    failures: Vec<InvariantFailure>,
    current_step: usize,
}

impl InvariantEngine {
    pub fn new() -> Self {
        Self {
            failures: Vec::new(),
            current_step: 0,
        }
    }

    pub fn set_step(&mut self, step: usize) {
        self.current_step = step;
    }

    /// Record a check — if condition is false, record failure.
    pub fn check(
        &mut self,
        id: InvariantId,
        condition: bool,
        message: impl Into<String>,
    ) {
        if !condition {
            self.failures.push(InvariantFailure {
                id,
                step: self.current_step,
                message: message.into(),
                context: BTreeMap::new(),
            });
        }
    }

    /// Record a check with additional context.
    pub fn check_ctx(
        &mut self,
        id: InvariantId,
        condition: bool,
        message: impl Into<String>,
        ctx: Vec<(&str, String)>,
    ) {
        if !condition {
            let context = ctx
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();
            self.failures.push(InvariantFailure {
                id,
                step: self.current_step,
                message: message.into(),
                context,
            });
        }
    }

    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    pub fn failures(&self) -> &[InvariantFailure] {
        &self.failures
    }

    /// Produce a summary report string.
    pub fn report(&self) -> String {
        if self.failures.is_empty() {
            return "All invariants passed.".to_string();
        }
        let mut s = format!("{} invariant failure(s):\n", self.failures.len());
        for f in &self.failures {
            s.push_str(&format!("  {}\n", f));
        }
        s
    }

    /// Assert no failures, panicking with full report if any.
    pub fn assert_ok(&self) {
        if self.has_failures() {
            panic!("Invariant failures:\n{}", self.report());
        }
    }
}

impl Default for InvariantEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Artifact Writer
// ---------------------------------------------------------------------------

/// Collects and serializes chaos run artifacts for forensic replay.
pub struct ArtifactWriter {
    pub seed: u64,
    pub scenario: String,
    pub timeline: Vec<TimelineEntry>,
    pub start_time: Instant,
    wal_summary: Option<WalSummary>,
    audit_summary: Option<AuditSummary>,
}

#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub elapsed_ms: u64,
    pub step: usize,
    pub event: String,
}

#[derive(Debug, Clone, Default)]
pub struct WalSummary {
    pub file_size: u64,
    pub pending_count: u64,
    pub total_appended: u64,
}

#[derive(Debug, Clone, Default)]
pub struct AuditSummary {
    pub entry_count: i64,
    pub chain_valid: bool,
    pub chain_breaks: usize,
}

impl ArtifactWriter {
    pub fn new(seed: u64, scenario: &str) -> Self {
        Self {
            seed,
            scenario: scenario.to_string(),
            timeline: Vec::new(),
            start_time: Instant::now(),
            wal_summary: None,
            audit_summary: None,
        }
    }

    pub fn record(&mut self, step: usize, event: impl Into<String>) {
        self.timeline.push(TimelineEntry {
            elapsed_ms: self.start_time.elapsed().as_millis() as u64,
            step,
            event: event.into(),
        });
    }

    pub fn set_wal_summary(&mut self, size: u64, pending: u64, appended: u64) {
        self.wal_summary = Some(WalSummary {
            file_size: size,
            pending_count: pending,
            total_appended: appended,
        });
    }

    pub fn set_audit_summary(&mut self, count: i64, valid: bool, breaks: usize) {
        self.audit_summary = Some(AuditSummary {
            entry_count: count,
            chain_valid: valid,
            chain_breaks: breaks,
        });
    }

    /// Serialize the full artifact bundle to a string.
    pub fn to_report(&self, invariant_engine: &InvariantEngine) -> String {
        let mut s = String::new();
        s.push_str("=== Chaos Artifact Report ===\n");
        s.push_str(&format!("Scenario: {}\n", self.scenario));
        s.push_str(&format!("Seed: {}\n", self.seed));
        s.push_str(&format!(
            "Duration: {}ms\n",
            self.start_time.elapsed().as_millis()
        ));
        s.push_str(&format!("Timeline events: {}\n\n", self.timeline.len()));

        if let Some(ref ws) = self.wal_summary {
            s.push_str("--- WAL Summary ---\n");
            s.push_str(&format!("  file_size: {}\n", ws.file_size));
            s.push_str(&format!("  pending_count: {}\n", ws.pending_count));
            s.push_str(&format!("  total_appended: {}\n\n", ws.total_appended));
        }

        if let Some(ref audit) = self.audit_summary {
            s.push_str("--- Audit DB Summary ---\n");
            s.push_str(&format!("  entry_count: {}\n", audit.entry_count));
            s.push_str(&format!("  chain_valid: {}\n", audit.chain_valid));
            s.push_str(&format!("  chain_breaks: {}\n\n", audit.chain_breaks));
        }

        s.push_str("--- Invariants ---\n");
        s.push_str(&invariant_engine.report());
        s.push('\n');

        if !self.timeline.is_empty() {
            s.push_str("--- Timeline (last 50) ---\n");
            let start = if self.timeline.len() > 50 {
                self.timeline.len() - 50
            } else {
                0
            };
            for entry in &self.timeline[start..] {
                s.push_str(&format!(
                    "  [{:>6}ms] step={:<4} {}\n",
                    entry.elapsed_ms, entry.step, entry.event
                ));
            }
        }

        s
    }

    /// Write artifact to a file if there are failures.
    pub fn write_on_failure(
        &self,
        dir: &Path,
        invariant_engine: &InvariantEngine,
    ) {
        if !invariant_engine.has_failures() {
            return;
        }
        let report = self.to_report(invariant_engine);
        let fname = format!(
            "chaos_{}_{}.txt",
            self.scenario,
            self.seed
        );
        let path = dir.join(fname);
        fs::write(&path, &report).ok();
        eprintln!("Artifact written to: {}", path.display());
    }
}

// ---------------------------------------------------------------------------
// Scenario Runner
// ---------------------------------------------------------------------------

/// Chaos tier for CI integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosTier {
    /// Default CI (<=60s total).
    A,
    /// Nightly (10-20 min).
    B,
    /// Manual full chaos run.
    C,
}

impl ChaosTier {
    /// Get the current tier from environment, defaulting to A.
    pub fn current() -> Self {
        match std::env::var("CHAOS_TIER").as_deref() {
            Ok("B") | Ok("b") => ChaosTier::B,
            Ok("C") | Ok("c") => ChaosTier::C,
            _ => ChaosTier::A,
        }
    }
}

/// Scale parameters based on tier.
pub struct ScaleParams {
    pub threads: usize,
    pub iterations: usize,
    pub records: usize,
    pub duration_secs: u64,
}

impl ScaleParams {
    pub fn for_tier(tier: ChaosTier) -> Self {
        match tier {
            ChaosTier::A => ScaleParams {
                threads: 4,
                iterations: 100,
                records: 50,
                duration_secs: 5,
            },
            ChaosTier::B => ScaleParams {
                threads: 8,
                iterations: 1000,
                records: 500,
                duration_secs: 30,
            },
            ChaosTier::C => ScaleParams {
                threads: 16,
                iterations: 10000,
                records: 5000,
                duration_secs: 120,
            },
        }
    }
}

/// Get default seed, overridable via CHAOS_SEED env var.
pub fn default_seed() -> u64 {
    std::env::var("CHAOS_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42)
}

/// Get seed list for sweeps.
pub fn seed_list() -> Vec<u64> {
    let tier = ChaosTier::current();
    match tier {
        ChaosTier::A => vec![default_seed()],
        ChaosTier::B => (0..10).map(|i| default_seed().wrapping_add(i)).collect(),
        ChaosTier::C => (0..100).map(|i| default_seed().wrapping_add(i)).collect(),
    }
}

/// Check if a privileged test should be skipped. Returns Some(reason) if skip.
pub fn check_privilege_skip(reason: &str) -> Option<String> {
    // Check if we're running as root
    if nix::unistd::getuid().is_root() {
        return None;
    }
    Some(format!("skipped_due_to_privilege: {}", reason))
}
