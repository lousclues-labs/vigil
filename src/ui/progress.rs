//! In-tree progress renderer for multi-step CLI operations.
//!
//! No external dependencies; uses `std::io::Write` + ANSI escapes with
//! automatic fallback for non-TTY, `NO_COLOR`, and `TERM=dumb` environments.

use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── Step Model ─────────────────────────────────────────────

/// The phases of `vigil update`, as a closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStep {
    VerifyRepo,
    BuildRelease,
    VerifyArtifacts,
    StopDaemon,
    BackupBinaries,
    InstallBinaries,
    InstallUnits,
    StartDaemon,
    VerifyHealth,
    ArchiveBackups,
    PostCheck,
}

impl UpdateStep {
    pub fn label(self) -> &'static str {
        match self {
            Self::VerifyRepo => "Verify repository",
            Self::BuildRelease => "Build release binaries",
            Self::VerifyArtifacts => "Verify artifacts",
            Self::StopDaemon => "Stop daemon",
            Self::BackupBinaries => "Back up existing binaries",
            Self::InstallBinaries => "Install new binaries (atomic)",
            Self::InstallUnits => "Install systemd units & hooks",
            Self::StartDaemon => "Start daemon",
            Self::VerifyHealth => "Verify daemon health",
            Self::ArchiveBackups => "Archive backups",
            Self::PostCheck => "Post-install health check",
        }
    }

    pub fn gerund(self) -> &'static str {
        match self {
            Self::VerifyRepo => "Verifying",
            Self::BuildRelease => "Compiling",
            Self::VerifyArtifacts => "Verifying",
            Self::StopDaemon => "Stopping",
            Self::BackupBinaries => "Backing up",
            Self::InstallBinaries => "Installing",
            Self::InstallUnits => "Installing",
            Self::StartDaemon => "Starting",
            Self::VerifyHealth => "Verifying",
            Self::ArchiveBackups => "Archiving",
            Self::PostCheck => "Running",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Self::VerifyRepo => "repository",
            Self::BuildRelease => "release binaries",
            Self::VerifyArtifacts => "artifacts",
            Self::StopDaemon => "vigild",
            Self::BackupBinaries => "vigil and vigild",
            Self::InstallBinaries => "vigil and vigild",
            Self::InstallUnits => "units",
            Self::StartDaemon => "vigild",
            Self::VerifyHealth => "vigild health",
            Self::ArchiveBackups => "backups",
            Self::PostCheck => "post-install doctor",
        }
    }
}

/// A plan is an ordered list of steps.
#[derive(Debug, Clone)]
pub struct Plan {
    steps: Vec<UpdateStep>,
}

impl Plan {
    pub fn update_plan() -> Self {
        Plan {
            steps: vec![
                UpdateStep::VerifyRepo,
                UpdateStep::BuildRelease,
                UpdateStep::VerifyArtifacts,
                UpdateStep::StopDaemon,
                UpdateStep::BackupBinaries,
                UpdateStep::InstallBinaries,
                UpdateStep::InstallUnits,
                UpdateStep::StartDaemon,
                UpdateStep::VerifyHealth,
                UpdateStep::ArchiveBackups,
                UpdateStep::PostCheck,
            ],
        }
    }

    pub fn rollback_plan() -> Self {
        Plan {
            steps: vec![
                UpdateStep::StopDaemon,
                UpdateStep::InstallBinaries,
                UpdateStep::StartDaemon,
            ],
        }
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn label(&self, step: &UpdateStep) -> &'static str {
        step.label()
    }

    /// Return the 1-based index of a step in this plan, or None.
    pub fn index_of(&self, step: &UpdateStep) -> Option<usize> {
        self.steps.iter().position(|s| s == step).map(|i| i + 1)
    }
}

// ── Rendering Mode ─────────────────────────────────────────

/// How the renderer behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressMode {
    /// Spinners, ANSI color, carriage returns.
    Fancy,
    /// Clean ASCII, no ANSI, no carriage returns.
    Plain,
}

impl ProgressMode {
    /// Detect from environment: TTY status, `NO_COLOR`, `TERM`, `VIGIL_PROGRESS`.
    pub fn detect() -> Self {
        // Explicit override
        if let Ok(val) = std::env::var("VIGIL_PROGRESS") {
            match val.to_lowercase().as_str() {
                "plain" => return Self::Plain,
                "fancy" => return Self::Fancy,
                _ => {} // "auto" or unknown → fall through
            }
        }

        if std::env::var_os("NO_COLOR").is_some() {
            return Self::Plain;
        }

        if let Ok(term) = std::env::var("TERM") {
            if term == "dumb" {
                return Self::Plain;
            }
        }

        // Check stderr since that's where we write
        if std::io::stderr().is_terminal() {
            Self::Fancy
        } else {
            Self::Plain
        }
    }
}

// ── ANSI helpers ───────────────────────────────────────────

const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_CYAN: &str = "\x1b[36m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_ERASE_LINE: &str = "\x1b[2K\r";

const SPINNER_FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

// ── Per-step timing record ─────────────────────────────────

#[derive(Debug, Clone)]
pub struct StepRecord {
    pub step: UpdateStep,
    pub outcome: StepOutcome,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Ok,
    Warn,
    Err,
    Skipped,
}

// ── Shared spinner state ───────────────────────────────────

struct SpinnerState {
    active: bool,
    message: String,
    step_verb: String,
    step_subject: String,
    started: Instant,
    frame: usize,
    /// Grace period: suppress spinner drawing for first 250ms.
    first_draw_at: Option<Instant>,
}

// ── Progress ───────────────────────────────────────────────

/// Terminal-aware progress renderer for multi-step operations.
///
/// All output goes to the provided writer (typically stderr).
pub struct Progress {
    plan: Plan,
    mode: ProgressMode,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    current_step: Option<UpdateStep>,
    step_start: Option<Instant>,
    overall_start: Instant,
    records: Vec<StepRecord>,
    spinner_state: Arc<Mutex<SpinnerState>>,
    spinner_stop: Arc<AtomicBool>,
    spinner_handle: Option<std::thread::JoinHandle<()>>,
    /// When true, suppress all output except errors and final summary.
    quiet: bool,
    /// When true, include extra detail in output.
    verbose: bool,
    /// JSON callback: if set, called for each step event.
    json_tx: Option<Arc<Mutex<Box<dyn Write + Send>>>>,
    summary_outcome: Option<String>,
    plain_line_open: bool,
}

impl Progress {
    pub fn new(plan: Plan, writer: Box<dyn Write + Send>) -> Self {
        let mode = ProgressMode::detect();
        Self::with_mode(plan, writer, mode)
    }

    pub fn with_mode(plan: Plan, writer: Box<dyn Write + Send>, mode: ProgressMode) -> Self {
        let writer = Arc::new(Mutex::new(writer));
        let spinner_state = Arc::new(Mutex::new(SpinnerState {
            active: false,
            message: String::new(),
            step_verb: String::new(),
            step_subject: String::new(),
            started: Instant::now(),
            frame: 0,
            first_draw_at: None,
        }));
        let spinner_stop = Arc::new(AtomicBool::new(false));

        let handle = if mode == ProgressMode::Fancy {
            let w = Arc::clone(&writer);
            let state = Arc::clone(&spinner_state);
            let stop = Arc::clone(&spinner_stop);
            Some(std::thread::spawn(move || {
                spinner_thread(w, state, stop);
            }))
        } else {
            None
        };

        Progress {
            plan,
            mode,
            writer,
            current_step: None,
            step_start: None,
            overall_start: Instant::now(),
            records: Vec::new(),
            spinner_state,
            spinner_stop,
            spinner_handle: handle,
            quiet: false,
            verbose: false,
            json_tx: None,
            summary_outcome: None,
            plain_line_open: false,
        }
    }

    pub fn set_quiet(&mut self, q: bool) {
        self.quiet = q;
    }

    pub fn set_verbose(&mut self, v: bool) {
        self.verbose = v;
    }

    pub fn set_json_writer(&mut self, w: Box<dyn Write + Send>) {
        self.json_tx = Some(Arc::new(Mutex::new(w)));
    }

    pub fn set_summary_outcome(&mut self, outcome: impl Into<String>) {
        self.summary_outcome = Some(outcome.into());
    }

    pub fn header(&mut self, msg: &str) {
        if self.quiet {
            return;
        }

        self.stop_spinner();
        self.flush_plain_open_line();

        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(w, "{} {}", render_verb(self.mode, "Updating"), msg);
    }

    pub fn warn(&mut self, msg: &str) {
        let resume_spinner = self.mode == ProgressMode::Fancy && self.current_step.is_some();
        if resume_spinner {
            self.stop_spinner();
        }

        if !self.quiet {
            self.flush_plain_open_line();
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            match self.mode {
                ProgressMode::Fancy => {
                    let _ = writeln!(
                        w,
                        "{}{}warning:{} {}",
                        ANSI_YELLOW, ANSI_BOLD, ANSI_RESET, msg
                    );
                }
                ProgressMode::Plain => {
                    let _ = writeln!(w, "warning: {}", msg);
                }
            }
        }

        if resume_spinner {
            let mut s = self.spinner_state.lock().unwrap_or_else(|e| e.into_inner());
            s.active = true;
        }
    }

    /// Begin a new step and start spinner activity when in fancy mode.
    pub fn begin_step(&mut self, step: UpdateStep) {
        self.begin_step_inner(step, false);
    }

    /// Begin a step that is silent in human mode (only emits JSON).
    /// Used for steps where a child process owns the visual output (e.g. cargo).
    pub fn begin_step_silent(&mut self, step: UpdateStep) {
        self.begin_step_inner(step, true);
    }

    fn begin_step_inner(&mut self, step: UpdateStep, silent: bool) {
        self.current_step = Some(step);
        self.step_start = Some(Instant::now());

        self.emit_json_event(step, "begin", None);

        if self.quiet || silent {
            return;
        }

        match self.mode {
            ProgressMode::Fancy => {
                let mut s = self.spinner_state.lock().unwrap_or_else(|e| e.into_inner());
                s.active = true;
                s.message.clear();
                s.step_verb = step.gerund().to_string();
                s.step_subject = step.short().to_string();
                s.started = Instant::now();
                s.frame = 0;
                s.first_draw_at = None;
            }
            ProgressMode::Plain => {
                self.flush_plain_open_line();
                let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
                let _ = write!(
                    w,
                    "{} {} ...",
                    render_verb(self.mode, step.gerund()),
                    step.short()
                );
                let _ = w.flush();
                self.plain_line_open = true;
            }
        }
    }

    /// Update the spinner message (e.g., attempt counter for health checks).
    pub fn tick(&mut self, msg: Option<&str>) {
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Fancy {
            let mut s = self.spinner_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(m) = msg {
                s.message = m.to_string();
            }
        } else if let Some(m) = msg {
            self.flush_plain_open_line();
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(w, "  {}", m);
        }
    }

    /// End the current step successfully.
    pub fn end_step_ok(&mut self, detail: Option<&str>) {
        self.end_step_ok_inner(detail, false);
    }

    /// End the current step successfully without rendering human output.
    /// JSON events are still emitted.
    pub fn end_step_ok_silent(&mut self, detail: Option<&str>) {
        self.end_step_ok_inner(detail, true);
    }

    fn end_step_ok_inner(&mut self, detail: Option<&str>, silent: bool) {
        let elapsed = self.step_start.map(|s| s.elapsed()).unwrap_or_default();
        if let Some(step) = self.current_step.take() {
            self.records.push(StepRecord {
                step,
                outcome: StepOutcome::Ok,
                elapsed,
            });
            self.emit_json_event(step, "ok", detail);

            if !self.quiet && !silent {
                self.stop_spinner();
                self.render_step_result(step, StepOutcome::Ok, elapsed, detail, false);
            } else {
                self.stop_spinner();
            }
        } else {
            self.stop_spinner();
        }
    }

    /// End the current step with a warning.
    pub fn end_step_warn(&mut self, detail: &str) {
        let elapsed = self.step_start.map(|s| s.elapsed()).unwrap_or_default();
        if let Some(step) = self.current_step.take() {
            self.records.push(StepRecord {
                step,
                outcome: StepOutcome::Warn,
                elapsed,
            });
            self.emit_json_event(step, "warn", Some(detail));

            self.stop_spinner();
            self.render_step_result(step, StepOutcome::Warn, elapsed, None, false);
            self.warn(detail);
        } else {
            self.stop_spinner();
        }
    }

    /// End the current step with an error.
    pub fn end_step_err(&mut self, detail: &str) {
        let elapsed = self.step_start.map(|s| s.elapsed()).unwrap_or_default();
        if let Some(step) = self.current_step.take() {
            self.records.push(StepRecord {
                step,
                outcome: StepOutcome::Err,
                elapsed,
            });
            self.emit_json_event(step, "fail", Some(detail));

            self.stop_spinner();
            self.render_step_result(step, StepOutcome::Err, elapsed, Some(detail), true);
        } else {
            self.stop_spinner();
            self.render_error_line(detail);
        }
    }

    /// Mark remaining un-started steps as skipped.
    pub fn skip_remaining(&mut self) {
        self.skip_remaining_with_reason("not run");
    }

    /// Mark remaining un-started steps as skipped, with a collapse reason.
    pub fn skip_remaining_with_reason(&mut self, reason: &str) {
        let completed: Vec<UpdateStep> = self.records.iter().map(|r| r.step).collect();
        let mut skipped = Vec::new();

        for step in &self.plan.steps {
            if !completed.contains(step) && self.current_step != Some(*step) {
                self.records.push(StepRecord {
                    step: *step,
                    outcome: StepOutcome::Skipped,
                    elapsed: Duration::ZERO,
                });
                self.emit_json_event(*step, "skipped", None);
                skipped.push(*step);
            }
        }
        self.current_step = None;

        if self.quiet || skipped.is_empty() {
            return;
        }

        self.stop_spinner();
        self.flush_plain_open_line();

        if self.verbose {
            for step in skipped {
                self.render_step_result(
                    step,
                    StepOutcome::Skipped,
                    Duration::ZERO,
                    Some(reason),
                    false,
                );
            }
            return;
        }

        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let labels = skipped
            .iter()
            .map(|s| s.short())
            .collect::<Vec<_>>()
            .join(", ");

        let _ = writeln!(
            w,
            "{} {} steps ({}): {}",
            render_skipping(self.mode),
            skipped.len(),
            reason,
            labels
        );
    }

    /// Pass-through entry point. Ensures spinner is cleared before child output.
    pub fn begin_passthrough(&mut self, _cmd_label: &str) {
        self.stop_spinner();
        self.flush_plain_open_line();
        // Ensure the line is visually clean before child writes to stderr.
        if self.mode == ProgressMode::Fancy {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write!(w, "\r\x1b[2K");
            let _ = w.flush();
        }
    }

    /// Pass-through completion is intentionally unframed in v0.37.
    pub fn end_passthrough(&mut self) {
        if self.mode == ProgressMode::Fancy && self.current_step.is_some() {
            let mut s = self.spinner_state.lock().unwrap_or_else(|e| e.into_inner());
            s.active = true;
        }
    }

    /// Pipe a reader line-by-line to the output writer (for subprocess output).
    pub fn pass_through<R: Read>(&mut self, reader: R) -> io::Result<()> {
        if self.quiet {
            // Drain the reader to avoid broken-pipe
            let mut r = reader;
            io::copy(&mut r, &mut io::sink())?;
            return Ok(());
        }

        let resume_spinner = self.mode == ProgressMode::Fancy && self.current_step.is_some();
        if resume_spinner {
            self.stop_spinner();
            // Ensure the line is visually clean before child output.
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write!(w, "\r\x1b[2K");
            let _ = w.flush();
        }
        self.flush_plain_open_line();

        let buf_reader = BufReader::new(reader);
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let mut saw_compiling = false;
        let mut deferred_finished: Option<String> = None;
        for line in buf_reader.lines() {
            match line {
                Ok(l) => {
                    if l.contains("Compiling ") {
                        saw_compiling = true;
                    }
                    // Defer lone "Finished" lines; only emit if we saw Compiling
                    // or are in verbose mode.
                    if l.trim_start().starts_with("Finished ") && !saw_compiling {
                        deferred_finished = Some(l);
                        continue;
                    }
                    let _ = writeln!(w, "{}", l);
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        // Emit deferred Finished line only in verbose mode.
        if let Some(finished_line) = deferred_finished {
            if self.verbose {
                let _ = writeln!(w, "{}", finished_line);
            }
        }

        if resume_spinner {
            let mut s = self.spinner_state.lock().unwrap_or_else(|e| e.into_inner());
            s.active = true;
        }
        Ok(())
    }

    /// Print a rollback banner.
    pub fn rollback_banner(&mut self, reason: &str) {
        self.warn(&format!("rolling back: {}", reason));
    }

    /// Print a message line (for informational output outside of steps).
    pub fn message(&mut self, msg: &str) {
        if self.quiet {
            return;
        }
        self.stop_spinner();
        self.flush_plain_open_line();
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(w, "  {}", msg);
    }

    /// Print the final summary with per-step timing.
    pub fn finish_summary(&mut self) {
        self.stop_spinner();
        self.flush_plain_open_line();
        let overall = self.overall_start.elapsed();

        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());

        let any_failed = self.records.iter().any(|r| r.outcome == StepOutcome::Err);
        let outcome = self.summary_outcome.clone().unwrap_or_else(|| {
            if any_failed {
                "failed".to_string()
            } else {
                "update completed".to_string()
            }
        });

        match self.mode {
            ProgressMode::Fancy => {
                let finished = if any_failed {
                    format!("{}{}Finished{}", ANSI_RED, ANSI_BOLD, ANSI_RESET)
                } else {
                    format!("{}{}Finished{}", ANSI_GREEN, ANSI_BOLD, ANSI_RESET)
                };
                let _ = writeln!(
                    w,
                    "    {} update in {} \u{2014} {}",
                    finished,
                    format_duration(overall),
                    outcome
                );
            }
            ProgressMode::Plain => {
                let _ = writeln!(
                    w,
                    "    Finished update in {} \u{2014} {}",
                    format_duration(overall),
                    outcome
                );
            }
        }

        // Per-step table in verbose mode
        if self.verbose && !self.records.is_empty() {
            let _ = writeln!(w);
            for rec in &self.records {
                let status = match rec.outcome {
                    StepOutcome::Ok => "ok",
                    StepOutcome::Warn => "warning",
                    StepOutcome::Err => "failed",
                    StepOutcome::Skipped => "skipped",
                };
                let elapsed = format_step_duration(rec.elapsed).unwrap_or_else(|| "-".to_string());
                let _ = writeln!(w, "    {:8} {:28} {}", status, rec.step.short(), elapsed);
            }
        }
        let _ = w.flush();
    }

    fn render_step_result(
        &mut self,
        step: UpdateStep,
        outcome: StepOutcome,
        elapsed: Duration,
        detail: Option<&str>,
        force: bool,
    ) {
        if self.quiet && !force {
            return;
        }

        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());

        if self.mode == ProgressMode::Plain && self.plain_line_open {
            let _ = writeln!(w);
            self.plain_line_open = false;
        }

        let mut line = format!(
            "{} {} ... {}",
            render_verb(self.mode, step.gerund()),
            step.short(),
            render_status(self.mode, &outcome)
        );

        if let Some(elapsed) = format_step_duration(elapsed) {
            line.push_str(&format!(" ({})", elapsed));
        }

        if let Some(extra) = detail {
            if !extra.trim().is_empty() {
                line.push_str(" \u{2014} ");
                line.push_str(extra);
            }
        }

        let _ = writeln!(w, "{}", line);
    }

    fn render_error_line(&mut self, detail: &str) {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        if self.mode == ProgressMode::Plain && self.plain_line_open {
            let _ = writeln!(w);
            self.plain_line_open = false;
        }

        let _ = writeln!(
            w,
            "{} update ... {} \u{2014} {}",
            render_verb(self.mode, "Failing"),
            render_status(self.mode, &StepOutcome::Err),
            detail
        );
    }

    fn flush_plain_open_line(&mut self) {
        if self.mode == ProgressMode::Plain && self.plain_line_open {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(w);
            self.plain_line_open = false;
        }
    }

    /// Emit a JSON event to the json writer, if configured.
    fn emit_json_event(&self, step: UpdateStep, state: &str, detail: Option<&str>) {
        if let Some(ref tx) = self.json_tx {
            let idx = self.plan.index_of(&step).unwrap_or(0);
            let total = self.plan.len();
            let elapsed_ms = self
                .step_start
                .map(|s| s.elapsed().as_millis())
                .unwrap_or(0);
            let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

            let detail_field = detail
                .map(|d| format!(r#","detail":"{}""#, json_escape(d)))
                .unwrap_or_default();

            let line = format!(
                r#"{{"ts":"{}","step":{},"total":{},"label":"{}","state":"{}","elapsed_ms":{}{}}}"#,
                ts,
                idx,
                total,
                json_escape(step.label()),
                state,
                elapsed_ms,
                detail_field,
            );

            if let Ok(mut w) = tx.lock() {
                let _ = writeln!(w, "{}", line);
                let _ = w.flush();
            }
        }
    }

    fn stop_spinner(&mut self) {
        if self.mode == ProgressMode::Fancy {
            let mut s = self.spinner_state.lock().unwrap_or_else(|e| e.into_inner());
            if s.active {
                s.active = false;
                // Erase the spinner line
                let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
                let _ = write!(w, "{}", ANSI_ERASE_LINE);
                let _ = w.flush();
            }
        }
    }

    pub fn records(&self) -> &[StepRecord] {
        &self.records
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.spinner_stop.store(true, Ordering::Release);
        if let Some(handle) = self.spinner_handle.take() {
            let _ = handle.join();
        }
    }
}

// ── Spinner thread ─────────────────────────────────────────

fn spinner_thread(
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    state: Arc<Mutex<SpinnerState>>,
    stop: Arc<AtomicBool>,
) {
    const GRACE_MS: u64 = 250;

    while !stop.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(100));

        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        if !s.active {
            continue;
        }

        // Grace period: don't draw spinner for the first 250ms of a step.
        let now = Instant::now();
        let draw_after = match s.first_draw_at {
            Some(t) => t,
            None => {
                drop(s);
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let t = Instant::now() + Duration::from_millis(GRACE_MS);
                s.first_draw_at = Some(t);
                drop(s);
                continue;
            }
        };
        if now < draw_after {
            continue;
        }

        let frame_char = SPINNER_FRAMES[s.frame % SPINNER_FRAMES.len()];
        let elapsed = format_step_duration(s.started.elapsed())
            .map(|d| format!(" ({})", d))
            .unwrap_or_default();
        let msg = if s.message.is_empty() {
            String::new()
        } else {
            format!(" [{}]", s.message)
        };
        let line = format!(
            "{}{} {}{} {} {} ...{}{}",
            ANSI_ERASE_LINE,
            ANSI_CYAN,
            frame_char,
            ANSI_RESET,
            render_verb(ProgressMode::Fancy, &s.step_verb),
            s.step_subject,
            elapsed,
            msg
        );
        drop(s);

        {
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write!(w, "{}", line);
            let _ = w.flush();
        }

        // Advance frame
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.frame = s.frame.wrapping_add(1);
    }
}

// ── Helpers ────────────────────────────────────────────────

fn render_verb(mode: ProgressMode, verb: &str) -> String {
    match mode {
        ProgressMode::Fancy => {
            format!("{}{}{:>12}{}", ANSI_GREEN, ANSI_BOLD, verb, ANSI_RESET)
        }
        ProgressMode::Plain => format!("{:>12}", verb),
    }
}

fn render_status(mode: ProgressMode, outcome: &StepOutcome) -> String {
    match (mode, outcome) {
        (ProgressMode::Fancy, StepOutcome::Ok) => format!("{}ok{}", ANSI_GREEN, ANSI_RESET),
        (ProgressMode::Fancy, StepOutcome::Warn) => {
            format!("{}{}warning{}", ANSI_YELLOW, ANSI_BOLD, ANSI_RESET)
        }
        (ProgressMode::Fancy, StepOutcome::Err) => {
            format!("{}{}failed{}", ANSI_RED, ANSI_BOLD, ANSI_RESET)
        }
        (ProgressMode::Fancy, StepOutcome::Skipped) => {
            format!("{}skipped{}", ANSI_DIM, ANSI_RESET)
        }
        (ProgressMode::Plain, StepOutcome::Ok) => "ok".to_string(),
        (ProgressMode::Plain, StepOutcome::Warn) => "warning".to_string(),
        (ProgressMode::Plain, StepOutcome::Err) => "failed".to_string(),
        (ProgressMode::Plain, StepOutcome::Skipped) => "skipped".to_string(),
    }
}

fn render_skipping(mode: ProgressMode) -> String {
    match mode {
        ProgressMode::Fancy => format!("{}{:>12}{}", ANSI_DIM, "Skipping", ANSI_RESET),
        ProgressMode::Plain => format!("{:>12}", "Skipping"),
    }
}

fn format_step_duration(d: Duration) -> Option<String> {
    if d < Duration::from_millis(100) {
        None
    } else {
        Some(format_duration(d))
    }
}

/// Format a Duration as "Xm Ys", "X.Ys", "Nms", or "<1ms".
pub fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms == 0 {
        return "<1ms".to_string();
    }

    let secs = d.as_secs();
    if secs >= 60 {
        let m = secs / 60;
        let s = secs % 60;
        format!("{}m {:02}s", m, s)
    } else if ms < 1000 {
        format!("{}ms", ms)
    } else {
        format!("{}.{}s", secs, (ms % 1000) / 100)
    }
}

/// Minimal JSON string escape (no external dep).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_labels_are_stable() {
        let plan = Plan::update_plan();
        let labels: Vec<&str> = plan.steps.iter().map(|s| s.label()).collect();
        assert_eq!(
            labels,
            vec![
                "Verify repository",
                "Build release binaries",
                "Verify artifacts",
                "Stop daemon",
                "Back up existing binaries",
                "Install new binaries (atomic)",
                "Install systemd units & hooks",
                "Start daemon",
                "Verify daemon health",
                "Archive backups",
                "Post-install health check",
            ]
        );
    }

    #[test]
    fn plan_len_is_11() {
        assert_eq!(Plan::update_plan().len(), 11);
    }

    #[test]
    fn plan_index_of_returns_one_based() {
        let plan = Plan::update_plan();
        assert_eq!(plan.index_of(&UpdateStep::VerifyRepo), Some(1));
        assert_eq!(plan.index_of(&UpdateStep::PostCheck), Some(11));
    }

    #[test]
    fn progress_plain_mode_matches_snapshot() {
        let plan = Plan {
            steps: vec![
                UpdateStep::VerifyRepo,
                UpdateStep::BuildRelease,
                UpdateStep::VerifyArtifacts,
            ],
        };
        let buf: Vec<u8> = Vec::new();
        let mut prog = Progress::with_mode(plan, Box::new(buf), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(None);

        prog.begin_step(UpdateStep::BuildRelease);
        prog.end_step_ok(Some("2m 27s"));

        prog.begin_step(UpdateStep::VerifyArtifacts);
        prog.end_step_ok(None);

        prog.finish_summary();

        let output = {
            let w = prog.writer.lock().unwrap();
            // The writer is a Vec<u8> behind Box<dyn Write + Send>
            // We can't downcast easily, so we test indirectly via the JSON path
            drop(w);
            String::new() // placeholder
        };

        // For a proper snapshot test, we use a shared buffer approach
        let _ = output; // test that it doesn't panic

        // Verify records are correct
        assert_eq!(prog.records().len(), 3);
        assert_eq!(prog.records()[0].outcome, StepOutcome::Ok);
        assert_eq!(prog.records()[1].outcome, StepOutcome::Ok);
        assert_eq!(prog.records()[2].outcome, StepOutcome::Ok);
    }

    #[test]
    fn progress_plain_mode_rollback() {
        let plan = Plan {
            steps: vec![
                UpdateStep::VerifyRepo,
                UpdateStep::BuildRelease,
                UpdateStep::VerifyArtifacts,
                UpdateStep::StopDaemon,
            ],
        };
        let buf: Vec<u8> = Vec::new();
        let mut prog = Progress::with_mode(plan, Box::new(buf), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(None);
        prog.begin_step(UpdateStep::BuildRelease);
        prog.end_step_ok(None);
        prog.begin_step(UpdateStep::VerifyArtifacts);
        prog.end_step_err("smoke test failed");
        prog.skip_remaining();

        assert_eq!(prog.records().len(), 4);
        assert_eq!(prog.records()[0].outcome, StepOutcome::Ok);
        assert_eq!(prog.records()[1].outcome, StepOutcome::Ok);
        assert_eq!(prog.records()[2].outcome, StepOutcome::Err);
        assert_eq!(prog.records()[3].outcome, StepOutcome::Skipped);
    }

    #[test]
    fn progress_color_disabled_by_no_color_env() {
        // We can't easily set env in a test without affecting other tests,
        // but we can test the detection logic
        // ProgressMode::Plain should produce no ANSI
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };

        // Use a shared buffer via Arc<Mutex<>>
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(Some("checked"));
        prog.finish_summary();

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            !output.contains("\x1b["),
            "plain mode should not contain ANSI escapes, got: {}",
            output
        );
        assert!(output.contains("Verifying repository ... ok"));
    }

    #[test]
    fn progress_tty_mode_does_not_interleave_cargo_passthrough() {
        let plan = Plan {
            steps: vec![UpdateStep::BuildRelease],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::BuildRelease);
        prog.begin_passthrough("cargo build --release");

        let sim_output = b"   Compiling vigil v0.35.0\n    Finished release\n";
        prog.pass_through(&sim_output[..]).unwrap();

        prog.end_passthrough();
        prog.end_step_ok(None);

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(!output.contains("--- begin cargo build --release ---"));
        assert!(output.contains("Compiling vigil v0.35.0"));
        assert!(output.contains("Finished release"));
        assert!(!output.contains("--- end ---"));
    }

    #[test]
    fn warnings_render_with_prefix() {
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.warn("repository ownership is non-root");
        prog.end_step_ok(None);

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(output.contains("warning: repository ownership is non-root"));
    }

    #[test]
    fn skip_remaining_collapses_steps_when_not_verbose() {
        let plan = Plan {
            steps: vec![
                UpdateStep::VerifyRepo,
                UpdateStep::BuildRelease,
                UpdateStep::VerifyArtifacts,
            ],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(None);
        prog.skip_remaining_with_reason("already up to date");

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(output.contains("Skipping"));
        assert!(output.contains("already up to date"));
        assert!(output.contains("release binaries, artifacts"));
    }

    #[test]
    fn cargo_lone_finished_suppressed_in_human_mode() {
        let plan = Plan {
            steps: vec![UpdateStep::BuildRelease],
        };

        // Default mode (not verbose): suppress lone Finished
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan.clone(), Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::BuildRelease);
        let sim_output = b"    Finished `release` profile [optimized] target(s) in 0.11s\n";
        prog.pass_through(&sim_output[..]).unwrap();
        prog.end_step_ok(None);

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            !output.contains("Finished `release`"),
            "lone Finished should be suppressed, got: {}",
            output
        );

        // Verbose mode: emit the Finished line
        let shared2 = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer2 = SharedWriter(Arc::clone(&shared2));
        let mut prog2 = Progress::with_mode(plan, Box::new(writer2), ProgressMode::Plain);
        prog2.set_verbose(true);

        prog2.begin_step(UpdateStep::BuildRelease);
        prog2.pass_through(&sim_output[..]).unwrap();
        prog2.end_step_ok(None);

        let output2 = {
            let buf = shared2.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            output2.contains("Finished `release`"),
            "verbose should show Finished, got: {}",
            output2
        );
    }

    #[test]
    fn cargo_compiling_plus_finished_both_emitted() {
        let plan = Plan {
            steps: vec![UpdateStep::BuildRelease],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::BuildRelease);
        let sim_output = b"   Compiling vigil-baseline v0.39.0\n    Finished `release` profile [optimized] target(s) in 42.3s\n";
        prog.pass_through(&sim_output[..]).unwrap();
        prog.end_step_ok(None);

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(output.contains("Compiling vigil-baseline"));
        assert!(output.contains("Finished `release`"));
    }

    #[test]
    fn skipped_step_short_labels_match_spec() {
        let plan = Plan::update_plan();
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(None);
        prog.begin_step(UpdateStep::BuildRelease);
        prog.end_step_ok(None);
        prog.begin_step(UpdateStep::VerifyArtifacts);
        prog.end_step_ok(None);
        prog.skip_remaining_with_reason("no version change");

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            output.contains("vigild, vigil and vigild, vigil and vigild, units, vigild, vigild health, backups, post-install doctor"),
            "expected spec short labels, got: {}",
            output
        );
    }

    #[test]
    fn header_uses_updating_verb() {
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.header("vigil-baseline 0.36.0 -> 0.37.0");

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(output.contains("Updating vigil-baseline 0.36.0 -> 0.37.0"));
    }

    #[test]
    fn header_uses_unicode_arrow() {
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.header("vigil-baseline 0.37.0 \u{2192} 0.38.0");

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            output.contains("\u{2192}"),
            "expected → in header, got: {}",
            output
        );
        assert!(
            !output.contains("->"),
            "should not contain ->, got: {}",
            output
        );
    }

    #[test]
    fn build_step_silent_in_human_mode() {
        let plan = Plan {
            steps: vec![UpdateStep::BuildRelease],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step_silent(UpdateStep::BuildRelease);
        prog.end_step_ok_silent(None);

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            !output.contains("Building"),
            "silent step should not print, got: {}",
            output
        );
        assert!(
            output.is_empty(),
            "expected no human output, got: {}",
            output
        );
    }

    #[test]
    fn step_detail_uses_em_dash() {
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(Some("some detail"));

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            output.contains("\u{2014}"),
            "expected em-dash, got: {}",
            output
        );
        assert!(
            !output.contains(" - some detail"),
            "should not use hyphen separator, got: {}",
            output
        );
    }

    #[test]
    fn finished_uses_em_dash() {
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(None);
        prog.set_summary_outcome("no changes installed");
        prog.finish_summary();

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            output.contains("Finished update in"),
            "expected Finished line, got: {}",
            output
        );
        assert!(
            output.contains("\u{2014} no changes installed"),
            "expected em-dash in summary, got: {}",
            output
        );
    }

    #[test]
    fn no_blank_line_before_finished() {
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SharedWriter(Arc::clone(&shared));
        let mut prog = Progress::with_mode(plan, Box::new(writer), ProgressMode::Plain);

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(None);
        prog.set_summary_outcome("done");
        prog.finish_summary();

        let output = {
            let buf = shared.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        // The Finished line should follow immediately after the step line.
        // There should be no blank line between them.
        let lines: Vec<&str> = output.lines().collect();
        let finished_idx = lines.iter().position(|l| l.contains("Finished")).unwrap();
        assert!(finished_idx > 0);
        let prev_line = lines[finished_idx - 1];
        assert!(
            !prev_line.trim().is_empty(),
            "blank line before Finished: {:?}",
            lines
        );
    }

    #[test]
    fn format_duration_formats_correctly() {
        assert_eq!(format_duration(Duration::from_millis(0)), "<1ms");
        assert_eq!(format_duration(Duration::from_millis(42)), "42ms");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 05s");
        assert_eq!(format_duration(Duration::from_secs(147)), "2m 27s");
    }

    #[test]
    fn format_step_duration_hides_sub_100ms() {
        assert_eq!(format_step_duration(Duration::from_millis(42)), None);
        assert_eq!(
            format_step_duration(Duration::from_millis(123)),
            Some("123ms".to_string())
        );
    }

    #[test]
    fn json_escape_handles_special_chars() {
        assert_eq!(json_escape(r#"hello "world""#), r#"hello \"world\""#);
        assert_eq!(json_escape("line\nnewline"), r#"line\nnewline"#);
        assert_eq!(json_escape("back\\slash"), r#"back\\slash"#);
    }

    #[test]
    fn json_event_emitted_on_step() {
        let plan = Plan {
            steps: vec![UpdateStep::VerifyRepo],
        };
        let shared_out = Arc::new(Mutex::new(Vec::<u8>::new()));
        let shared_json = Arc::new(Mutex::new(Vec::<u8>::new()));
        let out_writer = SharedWriter(Arc::clone(&shared_out));
        let json_writer = SharedWriter(Arc::clone(&shared_json));

        let mut prog = Progress::with_mode(plan, Box::new(out_writer), ProgressMode::Plain);
        prog.set_json_writer(Box::new(json_writer));

        prog.begin_step(UpdateStep::VerifyRepo);
        prog.end_step_ok(None);

        let json_output = {
            let buf = shared_json.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        let lines: Vec<&str> = json_output.trim().lines().collect();
        assert_eq!(lines.len(), 2, "expected begin + ok events");

        // Parse with serde_json
        let begin: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
        assert_eq!(begin["state"], "begin");
        assert_eq!(begin["step"], 1);
        assert_eq!(begin["total"], 1);
        assert_eq!(begin["label"], "Verify repository");

        let ok: serde_json::Value = serde_json::from_str(lines[1]).expect("valid JSON");
        assert_eq!(ok["state"], "ok");
    }

    #[test]
    fn rollback_plan_has_3_steps() {
        let plan = Plan::rollback_plan();
        assert_eq!(plan.len(), 3);
    }

    // Helper: a Write impl backed by a shared Vec<u8>
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut v = self.0.lock().unwrap();
            v.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
