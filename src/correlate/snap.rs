//! Snap transaction evidence.
//!
//! snapd records refreshes as *changes* made of *tasks*. A refresh that
//! replaces revision 150 with 188 produces, among others, a task that sets up
//! the new revision's security profiles and a task that removes the old
//! revision -- and removing a revision deletes its generated systemd mount unit
//! and the `*.target.wants` symlinks pointing at it.
//!
//! Those deletions are exactly what Vigil observes. This module turns snapd's
//! own account of the refresh into a [`TransactionRecord`] so the engine can
//! attribute them.
//!
//! Parsers here are pure functions over text. The collector runs `snap` with an
//! argument array and a timeout, never a shell.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::error::{CollectorError, CollectorErrorKind, EvidenceSource};
use super::transaction::{
    PackageAction, PackageTransition, TransactionRecord, TransactionSource, TransactionStatus,
};

/// Absolute path to the snap client; prevents PATH injection.
const SNAP_PATH: &str = "/usr/bin/snap";

/// Where snapd keeps per-snap revision directories.
const SNAP_MOUNT_ROOT: &str = "/snap";

/// Time budget for a `snap` invocation.
const SNAP_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on `snap changes` rows parsed.
const MAX_CHANGES: usize = 256;

/// Cap on how many changes get a follow-up `snap tasks` invocation.
///
/// Each one is a subprocess. A busy machine can list dozens of changes in the
/// lookback window, and spawning a process for every one of them on every
/// `vigil check` is exactly the kind of cost a modest box cannot absorb.
/// Candidates are filtered to snaps that actually changed on disk before this
/// cap is applied, so in practice it is rarely approached.
const MAX_TASK_QUERIES: usize = 16;

/// Cap on bytes accepted from a `snap` subprocess.
const MAX_SNAP_OUTPUT: usize = 4 * 1024 * 1024;

/// A snapd change: one transaction, made of tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapChange {
    pub id: String,
    pub status: String,
    pub spawn: Option<i64>,
    pub ready: Option<i64>,
    pub summary: String,
    pub tasks: Vec<SnapTask>,
}

impl SnapChange {
    /// snapd reports `Done` only when every task succeeded.
    pub fn is_done(&self) -> bool {
        self.status.eq_ignore_ascii_case("Done")
    }

    pub fn has_failed_task(&self) -> bool {
        self.tasks.iter().any(|t| t.is_failure())
    }

    /// Snap names mentioned anywhere in the change, sorted.
    pub fn snap_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .tasks
            .iter()
            .filter_map(|t| t.snap.clone())
            .chain(quoted_names(&self.summary))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }
}

/// One task inside a snapd change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapTask {
    pub status: String,
    pub summary: String,
    /// Snap name parsed out of the task summary, when present.
    pub snap: Option<String>,
    /// Revision parsed out of the task summary, when present.
    pub revision: Option<String>,
    pub kind: SnapTaskKind,
}

impl SnapTask {
    pub fn is_done(&self) -> bool {
        self.status.eq_ignore_ascii_case("Done")
    }

    pub fn is_failure(&self) -> bool {
        matches!(
            self.status.to_ascii_lowercase().as_str(),
            "error" | "undone" | "hold"
        )
    }
}

/// The task kinds that matter for explaining filesystem changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnapTaskKind {
    /// Removing an obsolete revision: deletes its mount unit and symlinks.
    RemoveRevision,
    /// Mounting or unlinking a revision.
    MountRevision,
    /// Making a revision current.
    LinkRevision,
    UnlinkRevision,
    /// Security profile setup for a revision.
    SecurityProfile,
    /// Copying or discarding a revision's data.
    RevisionData,
    /// Stopping or starting the snap's services.
    ServiceControl,
    Download,
    Other,
}

impl SnapTaskKind {
    /// Classify from a task summary. snapd's summaries are stable English
    /// sentences; unknown shapes fall through to `Other` rather than guessing.
    fn classify(summary: &str) -> Self {
        let s = summary.to_ascii_lowercase();
        if s.starts_with("remove snap") || s.contains("remove snap file") {
            Self::RemoveRevision
        } else if s.contains("security profiles") || s.contains("security profile") {
            Self::SecurityProfile
        } else if s.starts_with("mount snap") || s.contains("unmount") {
            Self::MountRevision
        // "unavailable" contains "available", so the negative case must be
        // tested first or an unlink is recorded as a link -- which would file
        // the *old* revision as the new one and break attribution of the
        // artifacts that revision left behind.
        } else if s.contains("unavailable") {
            Self::UnlinkRevision
        } else if s.starts_with("make snap") && s.contains("available") {
            Self::LinkRevision
        } else if s.contains("snap data") || s.contains("snap \"") && s.contains("data") {
            Self::RevisionData
        } else if s.contains("services of snap") || s.contains("service") {
            Self::ServiceControl
        } else if s.starts_with("download snap") || s.starts_with("fetch") {
            Self::Download
        } else {
            Self::Other
        }
    }
}

/// Extract names appearing in double quotes: `snap "foo" (188)` -> `foo`.
fn quoted_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        let name = &after[..close];
        // Snap names are lowercase alphanumerics with dashes. Anything else is
        // some other quoted token (a channel, a message) and is skipped.
        if !name.is_empty()
            && name.len() <= 128
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            out.push(name.to_string());
        }
        rest = &after[close + 1..];
    }
    out
}

/// Extract the first parenthesised revision: `(188)` -> `188`.
fn parenthesised_revision(text: &str) -> Option<String> {
    let open = text.find('(')?;
    let after = &text[open + 1..];
    let close = after.find(')')?;
    let rev = after[..close].trim();
    (!rev.is_empty()
        && rev.len() <= 32
        && rev
            .chars()
            .all(|c| c.is_ascii_digit() || c == 'x' || c == '-'))
    .then(|| rev.to_string())
}

/// Parse an RFC3339-ish timestamp as snapd prints it.
fn parse_snap_timestamp(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp())
        .or_else(|| {
            // `snap changes` in a non-UTC locale prints local time without a
            // zone offset. Interpret it locally rather than assuming UTC.
            let naive = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S").ok()?;
            use chrono::TimeZone;
            match chrono::Local.from_local_datetime(&naive) {
                chrono::LocalResult::Single(dt) => Some(dt.timestamp()),
                chrono::LocalResult::Ambiguous(a, _) => Some(a.timestamp()),
                chrono::LocalResult::None => None,
            }
        })
}

/// Parse `snap changes` tabular output.
///
/// ```text
/// ID   Status  Spawn                 Ready                 Summary
/// 123  Done    2025-09-20T00:07:14Z  2025-09-20T00:07:20Z  Auto-refresh snaps "a", "b"
/// ```
pub fn parse_snap_changes(text: &str) -> (Vec<SnapChange>, Vec<CollectorError>) {
    let mut changes = Vec::new();
    let mut errors = Vec::new();
    let mut malformed = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("ID ") || trimmed.starts_with("ID\t") {
            continue;
        }
        if trimmed.starts_with("no changes") || trimmed.starts_with("No changes") {
            continue;
        }

        let fields: Vec<&str> = trimmed.splitn(5, char::is_whitespace).collect();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let _ = fields;
        if parts.len() < 4 {
            malformed += 1;
            continue;
        }

        let id = parts[0];
        if !id.chars().all(|c| c.is_ascii_digit()) {
            malformed += 1;
            continue;
        }

        let status = parts[1].to_string();
        // `snap changes` prints relative times ("yesterday at 13:24 EDT")
        // unless --abs-time is passed. That is four tokens per column, which
        // shifts every later field. Refusing to parse such a row is the only
        // honest response: a shifted row would yield an epoch-dated
        // transaction and a summary full of time fragments, and would be
        // indistinguishable from real evidence downstream.
        let (Some(spawn), Some(ready)) = (
            parse_snap_timestamp(parts[2]),
            parse_snap_timestamp(parts[3]),
        ) else {
            malformed += 1;
            continue;
        };
        let (spawn, ready) = (Some(spawn), Some(ready));
        // Everything after the fourth column is the summary; rebuild it from
        // the original line so internal spacing is preserved.
        let summary = parts[4..].join(" ");

        changes.push(SnapChange {
            id: id.to_string(),
            status,
            spawn,
            ready,
            summary,
            tasks: Vec::new(),
        });

        if changes.len() >= MAX_CHANGES {
            errors.push(CollectorError::truncated(
                EvidenceSource::SnapdChanges,
                format!("stopped after {MAX_CHANGES} changes"),
            ));
            break;
        }
    }

    if malformed > 0 {
        errors.push(CollectorError::parse(
            EvidenceSource::SnapdChanges,
            format!("{malformed} unparseable row(s) in snap changes output"),
        ));
    }

    (changes, errors)
}

/// Parse `snap tasks <id>` output into tasks.
pub fn parse_snap_tasks(text: &str) -> (Vec<SnapTask>, Vec<CollectorError>) {
    let mut tasks = Vec::new();
    let mut errors = Vec::new();
    let mut malformed = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Status ") || trimmed.starts_with("Status\t") {
            continue;
        }
        // snapd prints a dotted separator after the task table, followed by its
        // own log lines ("... INFO No re-refreshes found."). Those are not task
        // rows; counting them as malformed would report parse errors on every
        // healthy refresh, and an error that always fires is one an operator
        // learns to ignore.
        if trimmed.len() > 3 && trimmed.chars().all(|c| c == '.') {
            break;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            malformed += 1;
            continue;
        }

        let status = parts[0].to_string();
        // Status Spawn Ready Summary... Both time columns must parse as single
        // tokens, for the same reason as the change rows above.
        if parse_snap_timestamp(parts[1]).is_none() || parse_snap_timestamp(parts[2]).is_none() {
            malformed += 1;
            continue;
        }
        let summary = parts[3..].join(" ");
        if summary.is_empty() {
            malformed += 1;
            continue;
        }

        let snap = quoted_names(&summary).into_iter().next();
        let revision = parenthesised_revision(&summary);

        tasks.push(SnapTask {
            status,
            kind: SnapTaskKind::classify(&summary),
            snap,
            revision,
            summary,
        });
    }

    if malformed > 0 {
        errors.push(CollectorError::parse(
            EvidenceSource::SnapdChanges,
            format!("{malformed} unparseable task row(s)"),
        ));
    }

    (tasks, errors)
}

/// Undo systemd's path escaping for a unit name.
///
/// systemd escapes `/` as `-` and a literal `-` as `\x2d`, so
/// `snap-desktop\x2dsecurity\x2dcenter-150.mount` describes the mount point
/// `/snap/desktop-security-center/150`.
pub fn unescape_systemd_unit(name: &str) -> String {
    // Resolve \xNN escapes first so a decoded byte is never re-interpreted as
    // a path separator.
    //
    // Indexing is done on the byte slice, never on the &str. A unit name is an
    // attacker-controllable filename and may hold multi-byte UTF-8; slicing the
    // &str at `i + 2 .. i + 4` would panic whenever those offsets land inside a
    // character rather than on a boundary.
    let mut decoded = Vec::new();
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            let hi = (bytes[i + 2] as char).to_digit(16);
            let lo = (bytes[i + 3] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                // Mark decoded bytes so the '-' to '/' pass skips them.
                decoded.push(Escaped::Literal((hi * 16 + lo) as u8));
                i += 4;
                continue;
            }
        }
        decoded.push(Escaped::Raw(bytes[i]));
        i += 1;
    }

    let mut out = Vec::with_capacity(decoded.len());
    for item in decoded {
        match item {
            Escaped::Raw(b'-') => out.push(b'/'),
            Escaped::Raw(b) | Escaped::Literal(b) => out.push(b),
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

enum Escaped {
    Raw(u8),
    Literal(u8),
}

/// Identify the snap and revision a systemd mount-unit path refers to.
///
/// Accepts both the unit file itself and a `*.target.wants` symlink to it.
/// Returns `None` for anything that is not a snap mount unit.
pub fn snap_mount_unit_identity(path: &Path) -> Option<(String, String)> {
    let file_name = path.file_name()?.to_str()?;
    let stem = file_name.strip_suffix(".mount")?;
    if !stem.starts_with("snap-") {
        return None;
    }

    let decoded = unescape_systemd_unit(stem);
    // Expect "snap/<name>/<revision>".
    let mut parts = decoded.split('/');
    if parts.next()? != "snap" {
        return None;
    }
    let name = parts.next()?.to_string();
    let revision = parts.next()?.to_string();
    if parts.next().is_some() || name.is_empty() || revision.is_empty() {
        return None;
    }
    Some((name, revision))
}

/// Whether a path lives under a systemd `*.target.wants` directory, which makes
/// it an enablement symlink rather than the unit itself.
pub fn is_target_wants_path(path: &Path) -> bool {
    path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".target.wants"))
}

/// On-disk revision state for a snap, read without privilege.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapRevisionState {
    /// Revision that `/snap/<name>/current` points at.
    pub current: Option<String>,
    /// Revision directories still present under `/snap/<name>`.
    pub present: Vec<String>,
}

impl SnapRevisionState {
    pub fn has_revision(&self, revision: &str) -> bool {
        self.present.iter().any(|r| r == revision)
    }
}

/// Read `/snap/<name>` to see which revisions exist and which is current.
///
/// `/snap` is world-readable, so this needs no privilege. A name that is not a
/// plain snap name is refused rather than joined into a path.
pub fn read_revision_state(snap_name: &str) -> Result<SnapRevisionState, CollectorError> {
    if !is_safe_snap_name(snap_name) {
        return Err(CollectorError::new(
            EvidenceSource::SnapdRevisionState,
            CollectorErrorKind::Parse,
            format!("refusing to inspect implausible snap name: {snap_name:?}"),
        ));
    }

    let dir = Path::new(SNAP_MOUNT_ROOT).join(snap_name);
    let mut state = SnapRevisionState::default();

    // `current` is a symlink to a revision directory. Read the link text
    // rather than canonicalizing, so a swapped-out target cannot redirect the
    // read elsewhere.
    if let Ok(target) = std::fs::read_link(dir.join("current")) {
        state.current = target
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string);
    }

    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name == "current" {
                    continue;
                }
                if name.chars().all(|c| c.is_ascii_digit() || c == 'x') {
                    state.present.push(name.to_string());
                }
            }
            state.present.sort();
        }
        Err(e) => {
            return Err(CollectorError::from_io(
                EvidenceSource::SnapdRevisionState,
                &dir,
                &e,
            ))
        }
    }

    Ok(state)
}

/// Snap names are lowercase alphanumerics and dashes. Used to refuse path
/// traversal before any filesystem join.
fn is_safe_snap_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        && !name.starts_with('-')
}

/// Turn a completed snapd change into a normalized transaction record.
///
/// Revisions are read from the change's own tasks: the revision a `Remove snap`
/// task names is the old one, and the revision a security-profile or link task
/// names is the new one.
pub fn change_to_transaction(change: &SnapChange) -> TransactionRecord {
    let mut tx = TransactionRecord::new(
        TransactionSource::Snap,
        change.spawn.or(change.ready).unwrap_or(0),
    );
    tx.id = Some(change.id.clone());
    tx.end = change.ready;
    tx.command = Some(change.summary.clone());
    tx.status = if change.has_failed_task() {
        TransactionStatus::Failed
    } else if change.is_done() {
        TransactionStatus::Completed
    } else if change.status.eq_ignore_ascii_case("Error") {
        TransactionStatus::Failed
    } else if change.status.eq_ignore_ascii_case("Doing")
        || change.status.eq_ignore_ascii_case("Do")
    {
        TransactionStatus::Interrupted
    } else {
        TransactionStatus::Unknown
    };

    for task in &change.tasks {
        if task.is_failure() {
            tx.errors.push(task.summary.clone());
        }
    }

    // Collect per-snap old/new revisions from task evidence.
    let mut removed: BTreeMap<String, String> = BTreeMap::new();
    let mut added: BTreeMap<String, String> = BTreeMap::new();

    for task in &change.tasks {
        let (Some(snap), Some(rev)) = (&task.snap, &task.revision) else {
            continue;
        };
        match task.kind {
            SnapTaskKind::RemoveRevision | SnapTaskKind::UnlinkRevision => {
                removed.insert(snap.clone(), rev.clone());
            }
            SnapTaskKind::SecurityProfile
            | SnapTaskKind::LinkRevision
            | SnapTaskKind::MountRevision
            | SnapTaskKind::Download => {
                added.insert(snap.clone(), rev.clone());
            }
            _ => {}
        }
    }

    let mut names: Vec<String> = removed
        .keys()
        .chain(added.keys())
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if names.is_empty() {
        names = change.snap_names();
    }
    names.sort();

    for name in names {
        let mut transition = PackageTransition::new(&name, PackageAction::Refresh);
        transition.old_version = removed.get(&name).cloned();
        transition.new_version = added.get(&name).cloned();
        tx.packages.push(transition);
    }

    tx.normalize();
    tx
}

/// Everything the snap collector could gather.
#[derive(Debug, Default)]
pub struct SnapEvidence {
    pub transactions: Vec<TransactionRecord>,
    pub changes: Vec<SnapChange>,
    pub errors: Vec<CollectorError>,
    pub sources: Vec<EvidenceSource>,
}

/// Run a `snap` subcommand with a timeout and a bounded output buffer.
///
/// Arguments are passed as an array; no shell is involved, so nothing in a
/// snap name or change id can be interpreted as a command.
fn run_snap(args: &[&str]) -> Result<String, CollectorError> {
    let mut child = Command::new(SNAP_PATH)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            CollectorError::from_io(EvidenceSource::SnapdChanges, Path::new(SNAP_PATH), &e)
        })?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = child.wait_with_output().map_err(|e| {
                    CollectorError::new(
                        EvidenceSource::SnapdChanges,
                        CollectorErrorKind::Parse,
                        format!("reading snap output: {e}"),
                    )
                })?;
                if !status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let detail = stderr.lines().next().unwrap_or("no detail").trim();
                    let kind = if detail.contains("permission")
                        || detail.contains("access denied")
                        || detail.contains("administrator")
                    {
                        CollectorErrorKind::PermissionDenied
                    } else {
                        CollectorErrorKind::Unavailable
                    };
                    return Err(CollectorError::new(
                        EvidenceSource::SnapdChanges,
                        kind,
                        format!("snap {}: {}", args.join(" "), detail),
                    ));
                }
                let mut stdout = out.stdout;
                if stdout.len() > MAX_SNAP_OUTPUT {
                    stdout.truncate(MAX_SNAP_OUTPUT);
                }
                return Ok(String::from_utf8_lossy(&stdout).into_owned());
            }
            Ok(None) => {
                if start.elapsed() > SNAP_QUERY_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CollectorError::new(
                        EvidenceSource::SnapdChanges,
                        CollectorErrorKind::Timeout,
                        format!("snap {} exceeded {:?}", args.join(" "), SNAP_QUERY_TIMEOUT),
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                return Err(CollectorError::new(
                    EvidenceSource::SnapdChanges,
                    CollectorErrorKind::Parse,
                    format!("waiting on snap: {e}"),
                ))
            }
        }
    }
}

/// Whether this system has snapd at all.
pub fn is_available() -> bool {
    Path::new(SNAP_PATH).is_file() && Path::new(SNAP_MOUNT_ROOT).is_dir()
}

/// Gather snap evidence for changes that ended at or after `window_start`.
///
/// `relevant_snaps` names the snaps that actually have filesystem changes to
/// explain. When it is empty this returns immediately without spawning
/// anything: if nothing snap-related changed, snapd has nothing to tell us and
/// there is no reason to pay for the query.
pub fn collect_local(window_start: i64, relevant_snaps: &HashSet<String>) -> SnapEvidence {
    let mut evidence = SnapEvidence::default();

    if relevant_snaps.is_empty() || !is_available() {
        // Not an error on a system without snapd, or with no snap-related
        // detections; the engine simply has no snap transactions to offer.
        return evidence;
    }
    evidence.sources.push(EvidenceSource::SnapdChanges);

    let text = match run_snap(&["changes", "--abs-time"]) {
        Ok(t) => t,
        Err(e) => {
            evidence.errors.push(e);
            return evidence;
        }
    };

    let (mut changes, errs) = parse_snap_changes(&text);
    evidence.errors.extend(errs);

    // Keep only changes inside the window that mention a snap we care about.
    // Filtering before the per-change subprocess is what keeps this bounded.
    changes.retain(|c| {
        let in_window = c.ready.or(c.spawn).is_none_or(|t| t >= window_start);
        let relevant = c.snap_names().iter().any(|n| relevant_snaps.contains(n));
        in_window && relevant
    });

    // Newest first, so if the cap bites it drops the least relevant history.
    changes.sort_by_key(|c| std::cmp::Reverse(c.ready.or(c.spawn).unwrap_or(0)));
    if changes.len() > MAX_TASK_QUERIES {
        let dropped = changes.len() - MAX_TASK_QUERIES;
        changes.truncate(MAX_TASK_QUERIES);
        evidence.errors.push(CollectorError::truncated(
            EvidenceSource::SnapdChanges,
            format!(
                "{dropped} older snapd change(s) were not examined (query cap {MAX_TASK_QUERIES})"
            ),
        ));
    }

    for change in &mut changes {
        match run_snap(&["tasks", "--abs-time", &change.id]) {
            Ok(task_text) => {
                let (tasks, errs) = parse_snap_tasks(&task_text);
                evidence.errors.extend(errs);
                change.tasks = tasks;
            }
            Err(e) => evidence.errors.push(e),
        }
    }

    evidence.transactions = changes.iter().map(change_to_transaction).collect();
    evidence.transactions.sort_by_key(|t| t.start);
    changes.sort_by_key(|c| c.ready.or(c.spawn).unwrap_or(0));
    evidence.changes = changes;
    evidence
}

/// Snap names implicated by a set of changed paths.
///
/// Pure string work over the detections, so the decision to query snapd at all
/// costs nothing.
pub fn snap_names_for_paths<'a>(paths: impl Iterator<Item = &'a Path>) -> HashSet<String> {
    let mut names = HashSet::new();
    for path in paths {
        if let Some((name, _revision)) = snap_mount_unit_identity(path) {
            names.insert(name);
            continue;
        }
        let Some(text) = path.to_str() else { continue };
        for prefix in ["/snap/", "/var/snap/"] {
            if let Some(rest) = text.strip_prefix(prefix) {
                if let Some(name) = rest.split('/').next() {
                    if is_safe_snap_name(name) {
                        names.insert(name.to_string());
                    }
                }
                break;
            }
        }
    }
    names
}

/// Revision state for each snap named in a transaction, keyed by snap name.
pub fn revision_states(
    tx: &TransactionRecord,
) -> (BTreeMap<String, SnapRevisionState>, Vec<CollectorError>) {
    let mut states = BTreeMap::new();
    let mut errors = Vec::new();
    for pkg in &tx.packages {
        match read_revision_state(&pkg.name) {
            Ok(state) => {
                states.insert(pkg.name.clone(), state);
            }
            Err(e) => errors.push(e),
        }
    }
    (states, errors)
}

/// Paths under `/snap` and the snap mount unit directories, for quick tests of
/// whether a changed path is snap-related at all.
pub fn is_snap_related_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    text.starts_with("/snap/")
        || text.starts_with("/var/snap/")
        || snap_mount_unit_identity(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANGES: &str = "\
ID   Status  Spawn                 Ready                 Summary
40   Done    2025-09-20T00:07:14Z  2025-09-20T00:07:26Z  Auto-refresh snaps \"desktop-security-center\", \"prompting-client\"
39   Done    2025-09-19T00:00:01Z  2025-09-19T00:00:09Z  Auto-refresh snap \"firefox\"
";

    const TASKS: &str = "\
Status  Spawn                 Ready                 Summary
Done    2025-09-20T00:07:14Z  2025-09-20T00:07:16Z  Download snap \"desktop-security-center\" (188) from channel \"latest/stable\"
Done    2025-09-20T00:07:16Z  2025-09-20T00:07:18Z  Mount snap \"desktop-security-center\" (188)
Done    2025-09-20T00:07:18Z  2025-09-20T00:07:19Z  Setup snap \"desktop-security-center\" (188) security profiles
Done    2025-09-20T00:07:20Z  2025-09-20T00:07:22Z  Remove snap \"desktop-security-center\" (150)
";

    /// snapd prints relative times unless `--abs-time` is passed. A row in
    /// that shape has four tokens per time column, shifting every later field.
    /// It must be rejected, not accepted as an epoch-dated transaction.
    #[test]
    fn relative_time_rows_are_rejected_not_silently_accepted() {
        let relative = "\
ID   Status  Spawn                   Ready                   Summary
61   Done    yesterday at 13:24 EDT  yesterday at 13:24 EDT  Auto-refresh snaps \"firefox\"
";
        let (changes, errs) = parse_snap_changes(relative);
        assert!(
            changes.is_empty(),
            "a relative-time row must not become a transaction: {changes:?}"
        );
        assert!(
            errs.iter().any(|e| e.kind == CollectorErrorKind::Parse),
            "the unparseable row must be reported: {errs:?}"
        );
    }

    #[test]
    fn relative_time_task_rows_are_rejected() {
        let relative = "\
Status  Spawn                   Ready                   Summary
Done    yesterday at 13:24 EDT  yesterday at 13:24 EDT  Remove snap \"firefox\" (100)
";
        let (tasks, errs) = parse_snap_tasks(relative);
        assert!(tasks.is_empty(), "{tasks:?}");
        assert!(errs.iter().any(|e| e.kind == CollectorErrorKind::Parse));
    }

    /// "unavailable" contains "available". Tested against the real task
    /// vocabulary snapd emits, including the unlink form that appears when a
    /// revision is retired.
    #[test]
    fn unavailable_is_not_classified_as_available() {
        assert_eq!(
            SnapTaskKind::classify("Make snap \"foo\" (150) unavailable to the system"),
            SnapTaskKind::UnlinkRevision,
            "an unlink must not be filed as a link, or the old revision becomes the new one"
        );
        assert_eq!(
            SnapTaskKind::classify("Make snap \"foo\" (188) available to the system"),
            SnapTaskKind::LinkRevision
        );
        assert_eq!(
            SnapTaskKind::classify("Make current revision for snap \"foo\" unavailable"),
            SnapTaskKind::UnlinkRevision
        );
    }

    /// Every task summary observed on a live system during a two-snap
    /// auto-refresh, captured verbatim from `snap tasks --abs-time`.
    /// Classification must not regress against the real vocabulary.
    #[test]
    fn real_snapd_task_summaries_classify_as_expected() {
        let cases: &[(&str, SnapTaskKind)] = &[
            (
                "Download snap \"desktop-security-center\" (188) from channel \"1/stable/ubuntu-26.04\"",
                SnapTaskKind::Download,
            ),
            (
                "Mount snap \"desktop-security-center\" (188)",
                SnapTaskKind::MountRevision,
            ),
            (
                "Setup snap \"desktop-security-center\" (188) security profiles",
                SnapTaskKind::SecurityProfile,
            ),
            (
                "Make snap \"desktop-security-center\" (188) available to the system",
                SnapTaskKind::LinkRevision,
            ),
            (
                "Make current revision for snap \"desktop-security-center\" unavailable",
                SnapTaskKind::UnlinkRevision,
            ),
            (
                "Remove snap \"desktop-security-center\" (150) from the system",
                SnapTaskKind::RemoveRevision,
            ),
        ];
        for (summary, expected) in cases {
            assert_eq!(
                SnapTaskKind::classify(summary),
                *expected,
                "classification drifted for: {summary}"
            );
        }
    }

    /// The whole point of the collector: a real refresh must yield both
    /// revisions, because attribution of a deleted `...-150.mount` unit
    /// depends on 150 being recorded as the old revision.
    #[test]
    fn a_real_refresh_transcript_yields_both_revisions() {
        let changes_text = "\
ID   Status  Spawn                      Ready                      Summary
61   Done    2026-09-21T13:24:14-04:00  2026-09-21T13:24:20-04:00  Auto-refresh snaps \"desktop-security-center\", \"prompting-client\"
";
        let tasks_text = "\
Status  Spawn                      Ready                      Summary
Done    2026-09-21T13:24:14-04:00  2026-09-21T13:24:15-04:00  Download snap \"desktop-security-center\" (188) from channel \"1/stable/ubuntu-26.04\"
Done    2026-09-21T13:24:15-04:00  2026-09-21T13:24:16-04:00  Mount snap \"desktop-security-center\" (188)
Done    2026-09-21T13:24:16-04:00  2026-09-21T13:24:17-04:00  Make current revision for snap \"desktop-security-center\" unavailable
Done    2026-09-21T13:24:17-04:00  2026-09-21T13:24:18-04:00  Setup snap \"desktop-security-center\" (188) security profiles
Done    2026-09-21T13:24:18-04:00  2026-09-21T13:24:19-04:00  Make snap \"desktop-security-center\" (188) available to the system
Done    2026-09-21T13:24:19-04:00  2026-09-21T13:24:20-04:00  Remove snap \"desktop-security-center\" (150) from the system
";
        let (mut changes, errs) = parse_snap_changes(changes_text);
        assert!(errs.is_empty(), "{errs:?}");
        let (tasks, errs) = parse_snap_tasks(tasks_text);
        assert!(errs.is_empty(), "{errs:?}");
        changes[0].tasks = tasks;

        let tx = change_to_transaction(&changes[0]);
        let p = tx
            .package("desktop-security-center")
            .expect("snap present in the transaction");
        assert_eq!(
            p.old_version.as_deref(),
            Some("150"),
            "the removed revision must be recorded as the old one"
        );
        assert_eq!(p.new_version.as_deref(), Some("188"));
        assert_eq!(tx.status, TransactionStatus::Completed);
    }

    #[test]
    fn parses_change_rows() {
        let (changes, errs) = parse_snap_changes(CHANGES);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].id, "40");
        assert!(changes[0].is_done());
        assert!(changes[0].summary.contains("desktop-security-center"));
        assert!(changes[0].spawn.is_some());
        assert!(changes[0].ready.is_some());
    }

    #[test]
    fn parses_tasks_with_snap_and_revision() {
        let (tasks, errs) = parse_snap_tasks(TASKS);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(tasks.len(), 4);

        let remove = tasks
            .iter()
            .find(|t| t.kind == SnapTaskKind::RemoveRevision)
            .expect("remove task");
        assert_eq!(remove.snap.as_deref(), Some("desktop-security-center"));
        assert_eq!(remove.revision.as_deref(), Some("150"));

        let profile = tasks
            .iter()
            .find(|t| t.kind == SnapTaskKind::SecurityProfile)
            .expect("security profile task");
        assert_eq!(profile.revision.as_deref(), Some("188"));
    }

    #[test]
    fn change_becomes_a_refresh_transaction_with_both_revisions() {
        let (mut changes, _) = parse_snap_changes(CHANGES);
        let (tasks, _) = parse_snap_tasks(TASKS);
        changes[0].tasks = tasks;

        let tx = change_to_transaction(&changes[0]);
        assert_eq!(tx.status, TransactionStatus::Completed);
        assert_eq!(tx.id.as_deref(), Some("40"));

        let p = tx.package("desktop-security-center").expect("snap present");
        assert_eq!(p.action, PackageAction::Refresh);
        assert_eq!(p.old_version.as_deref(), Some("150"));
        assert_eq!(p.new_version.as_deref(), Some("188"));
        assert_eq!(p.version_summary(), "150 -> 188");
    }

    #[test]
    fn a_failed_task_makes_the_whole_change_failed() {
        let (mut changes, _) = parse_snap_changes(CHANGES);
        let (mut tasks, _) = parse_snap_tasks(TASKS);
        tasks[3].status = "Error".into();
        changes[0].tasks = tasks;

        let tx = change_to_transaction(&changes[0]);
        assert_eq!(tx.status, TransactionStatus::Failed);
        assert!(!tx.status.is_success());
        assert_eq!(tx.errors.len(), 1);
    }

    #[test]
    fn an_in_progress_change_is_not_completed() {
        let text = "\
ID   Status  Spawn                 Ready                 Summary
41   Doing   2025-09-20T00:07:14Z  2025-09-20T00:07:26Z  Auto-refresh snap \"x\"
";
        let (changes, _) = parse_snap_changes(text);
        let tx = change_to_transaction(&changes[0]);
        assert_eq!(tx.status, TransactionStatus::Interrupted);
    }

    #[test]
    fn systemd_escaping_round_trips_for_dashed_snap_names() {
        assert_eq!(
            unescape_systemd_unit("snap-desktop\\x2dsecurity\\x2dcenter-150"),
            "snap/desktop-security-center/150"
        );
        assert_eq!(
            unescape_systemd_unit("snap-firefox-1234"),
            "snap/firefox/1234"
        );
    }

    #[test]
    fn mount_unit_paths_yield_snap_and_revision() {
        let unit = Path::new("/etc/systemd/system/snap-desktop\\x2dsecurity\\x2dcenter-150.mount");
        assert_eq!(
            snap_mount_unit_identity(unit),
            Some(("desktop-security-center".into(), "150".into()))
        );

        let wants = Path::new(
            "/etc/systemd/system/multi-user.target.wants/snap-prompting\\x2dclient-204.mount",
        );
        assert_eq!(
            snap_mount_unit_identity(wants),
            Some(("prompting-client".into(), "204".into()))
        );
        assert!(is_target_wants_path(wants));
        assert!(!is_target_wants_path(unit));
    }

    /// A unit filename is attacker-controllable. Decoding must never panic,
    /// whatever bytes it holds.
    ///
    /// The escape decoder previously sliced the &str at `i+2..i+4`, which
    /// panics when those offsets land inside a multi-byte character rather
    /// than on a boundary. A file named `snap-\x<3-byte char>.mount` in a
    /// watched systemd directory was enough to abort `vigil check`.
    #[test]
    fn malformed_escapes_in_unit_names_never_panic() {
        let hostile = [
            "snap-\\x\u{20ac}foo",       // \x followed by a 3-byte character
            "snap-\\x\u{e9}",            // \x followed by a 2-byte character
            "snap-\\x",                  // truncated escape at end of input
            "snap-\\x2",                 // half an escape
            "snap-\\xZZ",                // non-hex digits
            "snap-\\\\x2d",              // escaped backslash
            "\u{1f600}-\\x2d-\u{1f600}", // multi-byte either side
            "",
        ];
        for name in hostile {
            let decoded = unescape_systemd_unit(name);
            // The only contract is that it returns rather than panicking.
            assert!(decoded.len() <= name.len() + 8);
        }
    }

    /// The same bytes must not crash the identity parser either.
    #[test]
    fn malformed_unit_paths_are_rejected_without_panicking() {
        for name in [
            "snap-\\x\u{20ac}foo.mount",
            "snap-\\xZZ-1.mount",
            "snap-.mount",
            "snap-\u{20ac}.mount",
        ] {
            let path = std::path::PathBuf::from("/etc/systemd/system").join(name);
            let _ = snap_mount_unit_identity(&path);
        }
    }

    #[test]
    fn non_snap_units_are_not_claimed() {
        assert_eq!(
            snap_mount_unit_identity(Path::new("/etc/systemd/system/rsyslog.service")),
            None
        );
        assert_eq!(
            snap_mount_unit_identity(Path::new("/etc/systemd/system/home.mount")),
            None
        );
        assert_eq!(
            snap_mount_unit_identity(Path::new("/etc/systemd/system/snap-a-b-c-1.mount")),
            None,
            "a unit decoding to more than snap/<name>/<rev> is not a revision mount"
        );
    }

    #[test]
    fn snap_names_with_traversal_are_refused() {
        assert!(!is_safe_snap_name("../../etc"));
        assert!(!is_safe_snap_name("/etc/passwd"));
        assert!(!is_safe_snap_name(""));
        assert!(!is_safe_snap_name("-leading-dash"));
        assert!(is_safe_snap_name("desktop-security-center"));

        let err = read_revision_state("../../etc").unwrap_err();
        assert_eq!(err.kind, CollectorErrorKind::Parse);
    }

    #[test]
    fn quoted_name_extraction_ignores_non_snap_tokens() {
        let names = quoted_names("Download snap \"foo-bar\" (188) from channel \"latest/stable\"");
        assert_eq!(names, vec!["foo-bar"]);
    }

    #[test]
    fn malformed_change_rows_are_reported() {
        let (_, errs) = parse_snap_changes("ID Status Spawn Ready Summary\nnot-a-row\n");
        assert!(errs.iter().any(|e| e.kind == CollectorErrorKind::Parse));
    }

    #[test]
    fn multiple_snaps_in_one_change_each_get_a_transition() {
        let tasks_text = "\
Status  Spawn                 Ready                 Summary
Done    2025-09-20T00:07:18Z  2025-09-20T00:07:19Z  Setup snap \"desktop-security-center\" (188) security profiles
Done    2025-09-20T00:07:20Z  2025-09-20T00:07:22Z  Remove snap \"desktop-security-center\" (150)
Done    2025-09-20T00:07:22Z  2025-09-20T00:07:23Z  Setup snap \"prompting-client\" (228) security profiles
Done    2025-09-20T00:07:24Z  2025-09-20T00:07:25Z  Remove snap \"prompting-client\" (204)
";
        let (mut changes, _) = parse_snap_changes(CHANGES);
        let (tasks, _) = parse_snap_tasks(tasks_text);
        changes[0].tasks = tasks;

        let tx = change_to_transaction(&changes[0]);
        assert_eq!(tx.packages.len(), 2);
        assert_eq!(
            tx.package("prompting-client").unwrap().version_summary(),
            "204 -> 228"
        );
        assert_eq!(
            tx.package("desktop-security-center")
                .unwrap()
                .version_summary(),
            "150 -> 188"
        );
    }

    #[test]
    fn snap_related_path_detection() {
        assert!(is_snap_related_path(Path::new("/snap/firefox/100/bin/x")));
        assert!(is_snap_related_path(Path::new("/var/snap/firefox/common")));
        assert!(is_snap_related_path(Path::new(
            "/etc/systemd/system/snap-firefox-100.mount"
        )));
        assert!(!is_snap_related_path(Path::new("/usr/bin/gs")));
    }

    /// Deciding whether to query snapd at all must be pure string work, and
    /// must name only the snaps that actually changed.
    #[test]
    fn candidate_snap_names_come_only_from_changed_paths() {
        let paths = [
            Path::new("/etc/systemd/system/snap-desktop\\x2dsecurity\\x2dcenter-150.mount"),
            Path::new("/snap/firefox/1234/bin/firefox"),
            Path::new("/var/snap/lxd/common/x"),
            Path::new("/usr/bin/gs"),
        ];
        let names = snap_names_for_paths(paths.iter().copied());

        assert!(names.contains("desktop-security-center"));
        assert!(names.contains("firefox"));
        assert!(names.contains("lxd"));
        assert_eq!(
            names.len(),
            3,
            "non-snap paths contribute nothing: {names:?}"
        );
    }

    /// The common case on any machine: nothing snap-related changed. snapd must
    /// not be queried at all, so a box without snaps pays nothing.
    #[test]
    fn no_snap_paths_means_no_snap_subprocess() {
        let names = snap_names_for_paths(
            [Path::new("/usr/bin/gs"), Path::new("/etc/ssh/sshd_config")]
                .iter()
                .copied(),
        );
        assert!(names.is_empty());

        // An empty candidate set short-circuits before any subprocess spawn.
        let evidence = collect_local(0, &names);
        assert!(evidence.transactions.is_empty());
        assert!(evidence.errors.is_empty());
        assert!(
            evidence.sources.is_empty(),
            "no evidence source is claimed when nothing was consulted"
        );
    }

    #[test]
    fn traversal_attempts_never_become_snap_candidates() {
        let paths = [
            Path::new("/snap/../../etc/passwd"),
            Path::new("/var/snap//x"),
        ];
        let names = snap_names_for_paths(paths.iter().copied());
        assert!(
            !names.iter().any(|n| n.contains("..")),
            "traversal must not survive into a filesystem join: {names:?}"
        );
    }
}
