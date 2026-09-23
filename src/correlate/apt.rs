//! APT and dpkg transaction evidence.
//!
//! Parsing is pure: [`parse_apt_history`] and [`parse_dpkg_log`] take text and
//! return records, so the correlation engine can be exercised from fixtures
//! without a package manager, a privileged process, or a modified host.
//!
//! Every value read here -- package names, versions, command lines, paths --
//! is untrusted input from a file any root process can write. It is parsed,
//! bounded, and never interpolated into a shell.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::error::{CollectorError, CollectorErrorKind, EvidenceSource};
use super::transaction::{
    PackageAction, PackageTransition, TransactionRecord, TransactionSource, TransactionStatus,
};

/// APT's transaction journal.
const APT_HISTORY_LOG: &str = "/var/log/apt/history.log";
/// The most recent rotation, kept uncompressed by logrotate's `delaycompress`.
const APT_HISTORY_LOG_ROTATED: &str = "/var/log/apt/history.log.1";
/// dpkg's per-action journal.
const DPKG_LOG: &str = "/var/log/dpkg.log";
const DPKG_LOG_ROTATED: &str = "/var/log/dpkg.log.1";
/// dpkg's status database, used for installed-state confirmation.
const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// Hard ceiling on how much log text is parsed, per file.
///
/// A log is attacker-influenceable: any root-equivalent process can append to
/// it, and a rotation policy can leave a very large file behind. Parsing is
/// bounded so a hostile or merely unlucky log cannot exhaust memory on a small
/// machine. Exceeding the cap is reported as truncation, never silently
/// ignored.
///
/// 4 MiB is far above what a correlation window needs in practice (an apt
/// history log is typically tens of KiB, a dpkg log a few hundred), while
/// staying small enough to be harmless on a low-memory box.
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

/// Ceiling on retained transactions per log, newest first.
const MAX_TRANSACTIONS: usize = 512;

/// Ceiling on packages recorded per transaction.
const MAX_PACKAGES_PER_TRANSACTION: usize = 4096;

/// Everything the APT/dpkg collector could gather.
#[derive(Debug, Default)]
pub struct AptEvidence {
    pub transactions: Vec<TransactionRecord>,
    /// Packages dpkg reports as fully installed, with their versions.
    pub installed: HashMap<String, String>,
    pub errors: Vec<CollectorError>,
    pub sources: Vec<EvidenceSource>,
}

/// Read a log file with a size cap, keeping the *most recent* entries.
///
/// Returns the text plus a flag indicating the file was longer than the cap.
///
/// When a log exceeds the cap the tail is read, not the head. Recent
/// transactions are the only ones that can explain a current scan, so reading
/// from the start of a large log would parse ancient history and miss the
/// update that actually happened. After seeking, the first (probably partial)
/// line is discarded so a half-record cannot be parsed as a whole one.
fn read_capped(path: &Path, source: EvidenceSource) -> Result<(String, bool), CollectorError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file =
        std::fs::File::open(path).map_err(|e| CollectorError::from_io(source, path, &e))?;
    let len = file
        .metadata()
        .map_err(|e| CollectorError::from_io(source, path, &e))?
        .len();

    let oversized = len > MAX_LOG_BYTES;
    if oversized {
        file.seek(SeekFrom::Start(len - MAX_LOG_BYTES))
            .map_err(|e| CollectorError::from_io(source, path, &e))?;
    }

    let to_read = len.min(MAX_LOG_BYTES);
    let mut buf = Vec::with_capacity(to_read as usize);
    file.take(MAX_LOG_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| CollectorError::from_io(source, path, &e))?;

    // Logs are UTF-8 in practice but nothing enforces it. Lossy conversion
    // keeps a stray byte from discarding an entire transaction history; the
    // replacement characters remain visible in any echoed value.
    let mut text = String::from_utf8_lossy(&buf).into_owned();

    if oversized {
        // Drop the truncated leading line left by the seek.
        match text.find('\n') {
            Some(idx) => text.drain(..=idx),
            None => text.drain(..),
        };
    }

    Ok((text, oversized))
}

/// Parse an APT timestamp: `2025-09-20  00:07:14` (two spaces) or
/// `2025-09-20 00:07:14`.
///
/// APT writes local time with no zone, so it is interpreted in the local zone.
/// An ambiguous or nonexistent local time (a DST boundary) yields `None`
/// rather than a guess.
fn parse_apt_timestamp(value: &str) -> Option<i64> {
    let cleaned = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let naive = chrono::NaiveDateTime::parse_from_str(&cleaned, "%Y-%m-%d %H:%M:%S").ok()?;
    local_naive_to_timestamp(naive)
}

/// Convert a local naive datetime to a Unix timestamp, refusing ambiguity.
fn local_naive_to_timestamp(naive: chrono::NaiveDateTime) -> Option<i64> {
    use chrono::TimeZone;
    match chrono::Local.from_local_datetime(&naive) {
        chrono::LocalResult::Single(dt) => Some(dt.timestamp()),
        // A repeated local hour: pick neither silently.
        chrono::LocalResult::Ambiguous(a, _) => Some(a.timestamp()),
        chrono::LocalResult::None => None,
    }
}

/// Strip dpkg's architecture qualifier: `ghostscript:amd64` -> `ghostscript`.
///
/// Ownership queries report unqualified names, so transitions must match.
fn strip_arch(name: &str) -> &str {
    name.split_once(':').map(|(n, _)| n).unwrap_or(name)
}

/// Split an APT package list on commas that separate entries, respecting the
/// parenthesised version groups that may themselves contain commas.
///
/// `a:amd64 (1, 2), b:amd64 (3, 4)` yields two entries.
fn split_apt_entries(value: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for ch in value.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if depth == 0 => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    entries.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        entries.push(trimmed.to_string());
    }
    entries
}

/// Parse one APT package entry such as
/// `ghostscript:amd64 (9.55.0-1, 9.55.0-2)` or `curl:amd64 (8.5.0-2)`.
fn parse_apt_entry(entry: &str, action: PackageAction) -> Option<PackageTransition> {
    let (name_part, versions) = match entry.split_once('(') {
        Some((n, v)) => (n.trim(), v.trim_end_matches(')').trim()),
        None => (entry.trim(), ""),
    };
    let name = strip_arch(name_part.split_whitespace().next()?);
    if name.is_empty() {
        return None;
    }

    let mut transition = PackageTransition::new(name, action);
    // APT appends `, automatic` to entries installed as a dependency. It is a
    // flag, not a version, and reading it as one makes the recorded "new
    // version" the literal string `automatic`, which then disagrees with the
    // installed version and grades an ordinary install as conflicting
    // evidence. Seen on real logs as `libsuil-0-0:amd64 (0.10.24-1, automatic)`.
    let parts: Vec<&str> = versions
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "automatic")
        .collect();

    match parts.len() {
        // Upgrades record both sides.
        2.. => {
            transition.old_version = Some(parts[0].to_string());
            transition.new_version = Some(parts[1].to_string());
        }
        // Installs and removals record one.
        1 => {
            if action.removes_files() && action != PackageAction::Refresh {
                transition.old_version = Some(parts[0].to_string());
            } else {
                transition.new_version = Some(parts[0].to_string());
            }
        }
        _ => {}
    }

    Some(transition)
}

/// Map an APT history field name to the action it represents.
fn apt_action_for_field(field: &str) -> Option<PackageAction> {
    match field {
        "Install" => Some(PackageAction::Install),
        "Upgrade" => Some(PackageAction::Upgrade),
        "Downgrade" => Some(PackageAction::Downgrade),
        "Reinstall" => Some(PackageAction::Reinstall),
        "Remove" => Some(PackageAction::Remove),
        "Purge" => Some(PackageAction::Purge),
        _ => None,
    }
}

/// Parse the text of an APT history log into transactions.
///
/// Pure function over untrusted text. Malformed stanzas are reported through
/// the returned errors rather than dropped in silence.
pub fn parse_apt_history(text: &str) -> (Vec<TransactionRecord>, Vec<CollectorError>) {
    let mut transactions = Vec::new();
    let mut errors = Vec::new();
    let mut current: Option<TransactionRecord> = None;
    let mut saw_end = false;

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim_end_matches(['\r']);
        if line.trim().is_empty() {
            continue;
        }

        let Some((field, value)) = line.split_once(':') else {
            // Continuation lines of a wrapped field are indented; anything else
            // is unparseable and worth reporting once.
            if !line.starts_with(' ') {
                errors.push(CollectorError::parse(
                    EvidenceSource::AptHistory,
                    format!("line {}: expected 'Field: value'", lineno + 1),
                ));
            }
            continue;
        };
        let field = field.trim();
        let value = value.trim();

        match field {
            "Start-Date" => {
                // A new stanza before the previous one ended means the previous
                // transaction was cut short.
                if let Some(mut prev) = current.take() {
                    if !saw_end {
                        prev.status = TransactionStatus::Interrupted;
                    }
                    prev.normalize();
                    transactions.push(prev);
                }
                saw_end = false;
                match parse_apt_timestamp(value) {
                    Some(ts) => current = Some(TransactionRecord::new(TransactionSource::Apt, ts)),
                    None => {
                        errors.push(CollectorError::parse(
                            EvidenceSource::AptHistory,
                            format!("line {}: unparseable Start-Date '{}'", lineno + 1, value),
                        ));
                        current = None;
                    }
                }
            }
            "End-Date" => {
                let Some(tx) = current.as_mut() else { continue };
                match parse_apt_timestamp(value) {
                    Some(ts) => {
                        tx.end = Some(ts);
                        // An Error field already seen wins: a transaction that
                        // recorded an error did not succeed just because it
                        // also wrote an end date.
                        if tx.status != TransactionStatus::Failed {
                            tx.status = TransactionStatus::Completed;
                        }
                        saw_end = true;
                    }
                    None => errors.push(CollectorError::parse(
                        EvidenceSource::AptHistory,
                        format!("line {}: unparseable End-Date '{}'", lineno + 1, value),
                    )),
                }
            }
            "Commandline" => {
                if let Some(tx) = current.as_mut() {
                    tx.command = Some(value.to_string());
                }
            }
            "Requested-By" => {
                if let Some(tx) = current.as_mut() {
                    // Recorded verbatim. This is APT's own statement about who
                    // asked, not an identity Vigil independently established.
                    tx.actor = Some(value.to_string());
                }
            }
            "Error" => {
                if let Some(tx) = current.as_mut() {
                    tx.status = TransactionStatus::Failed;
                    tx.errors.push(value.to_string());
                }
            }
            _ => {
                let Some(action) = apt_action_for_field(field) else {
                    continue;
                };
                let Some(tx) = current.as_mut() else { continue };
                for entry in split_apt_entries(value) {
                    if tx.packages.len() >= MAX_PACKAGES_PER_TRANSACTION {
                        errors.push(CollectorError::truncated(
                            EvidenceSource::AptHistory,
                            format!(
                                "transaction lists more than {MAX_PACKAGES_PER_TRANSACTION} packages"
                            ),
                        ));
                        break;
                    }
                    match parse_apt_entry(&entry, action) {
                        Some(t) => tx.packages.push(t),
                        None => errors.push(CollectorError::parse(
                            EvidenceSource::AptHistory,
                            format!("line {}: unparseable package entry '{}'", lineno + 1, entry),
                        )),
                    }
                }
            }
        }
    }

    if let Some(mut tx) = current.take() {
        if !saw_end {
            // A trailing stanza with no End-Date: either still running or the
            // log was cut. Either way it is not a completed transaction.
            tx.status = TransactionStatus::Interrupted;
        }
        tx.normalize();
        transactions.push(tx);
    }

    transactions.sort_by_key(|t| t.start);
    if transactions.len() > MAX_TRANSACTIONS {
        let excess = transactions.len() - MAX_TRANSACTIONS;
        transactions.drain(..excess);
        errors.push(CollectorError::truncated(
            EvidenceSource::AptHistory,
            format!("kept the {MAX_TRANSACTIONS} most recent transactions; {excess} older dropped"),
        ));
    }

    (transactions, errors)
}

/// One parsed dpkg log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpkgLogEntry {
    pub timestamp: i64,
    pub action: String,
    pub package: String,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    /// For `status` lines, the state word (`installed`, `half-configured`, ...).
    pub state: Option<String>,
}

/// Parse `/var/log/dpkg.log` text into entries.
///
/// Lines look like:
/// ```text
/// 2025-09-20 00:07:15 upgrade ghostscript:amd64 9.55.0-1 9.55.0-2
/// 2025-09-20 00:07:16 status installed ghostscript:amd64 9.55.0-2
/// ```
pub fn parse_dpkg_log(text: &str) -> (Vec<DpkgLogEntry>, Vec<CollectorError>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut malformed = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // date time action ...
        if fields.len() < 4 {
            malformed += 1;
            continue;
        }

        let Some(timestamp) = parse_apt_timestamp(&format!("{} {}", fields[0], fields[1])) else {
            malformed += 1;
            continue;
        };

        let action = fields[2];
        match action {
            "status" => {
                // status <state> <package> <version>
                if fields.len() < 5 {
                    malformed += 1;
                    continue;
                }
                entries.push(DpkgLogEntry {
                    timestamp,
                    action: action.to_string(),
                    package: strip_arch(fields[4]).to_string(),
                    old_version: None,
                    new_version: fields.get(5).map(|s| s.to_string()),
                    state: Some(fields[3].to_string()),
                });
            }
            "upgrade" | "install" | "remove" | "purge" | "configure" | "trigproc" => {
                // action <package> <old> <new>
                entries.push(DpkgLogEntry {
                    timestamp,
                    action: action.to_string(),
                    package: strip_arch(fields[3]).to_string(),
                    old_version: fields.get(4).map(|s| s.to_string()),
                    new_version: fields.get(5).map(|s| s.to_string()),
                    state: None,
                });
            }
            // startup/conffile lines carry no per-package transition.
            _ => {}
        }
    }

    if malformed > 0 {
        errors.push(CollectorError::parse(
            EvidenceSource::DpkgLog,
            format!("{malformed} unparseable line(s) skipped"),
        ));
    }

    (entries, errors)
}

/// Packages that reached the `installed` state within a window, per the dpkg log.
///
/// This is the evidence for "the installed package reached a complete state":
/// dpkg writes `status installed <pkg> <version>` only after unpack and
/// configuration succeed.
pub fn packages_reaching_installed(
    entries: &[DpkgLogEntry],
    start: i64,
    end: i64,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for e in entries {
        if e.action != "status" || e.state.as_deref() != Some("installed") {
            continue;
        }
        if e.timestamp < start || e.timestamp > end {
            continue;
        }
        if let Some(version) = &e.new_version {
            out.insert(e.package.clone(), version.clone());
        }
    }
    out
}

/// Parse `/var/lib/dpkg/status` for packages in the fully installed state.
///
/// Only `Status: install ok installed` counts. Anything else -- half-configured,
/// unpacked, triggers-pending -- is not a complete install and must not be
/// reported as one.
pub fn parse_installed_packages(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut package: Option<String> = None;
    let mut version: Option<String> = None;
    let mut installed = false;

    let flush = |package: &mut Option<String>,
                 version: &mut Option<String>,
                 installed: &mut bool,
                 out: &mut HashMap<String, String>| {
        if *installed {
            if let (Some(p), Some(v)) = (package.take(), version.take()) {
                out.insert(p, v);
            }
        }
        *package = None;
        *version = None;
        *installed = false;
    };

    for line in text.lines() {
        if line.is_empty() {
            flush(&mut package, &mut version, &mut installed, &mut out);
            continue;
        }
        if let Some(name) = line.strip_prefix("Package: ") {
            package = Some(strip_arch(name.trim()).to_string());
        } else if let Some(status) = line.strip_prefix("Status: ") {
            installed = status.trim() == "install ok installed";
        } else if let Some(v) = line.strip_prefix("Version: ") {
            version = Some(v.trim().to_string());
        }
    }
    flush(&mut package, &mut version, &mut installed, &mut out);

    out
}

/// Read APT and dpkg evidence from the local system.
///
/// Reads regular files only. No subprocess is spawned and no privilege is
/// requested; a file this process cannot read is reported as a collector error
/// naming the privilege problem.
pub fn collect_local(window_start: i64, window_end: i64) -> AptEvidence {
    let mut evidence = AptEvidence::default();
    let mut sources = HashSet::new();

    // APT history, current plus the most recent rotation, so a transaction that
    // straddles a rotation is still visible.
    let mut apt_transactions = Vec::new();
    let mut any_history = false;
    for candidate in [APT_HISTORY_LOG_ROTATED, APT_HISTORY_LOG] {
        let path = Path::new(candidate);
        if !path.exists() {
            continue;
        }
        match read_capped(path, EvidenceSource::AptHistory) {
            Ok((text, truncated)) => {
                any_history = true;
                sources.insert(EvidenceSource::AptHistory);
                if truncated {
                    evidence.errors.push(CollectorError::truncated(
                        EvidenceSource::AptHistory,
                        format!(
                            "{} exceeds {} MiB; only the most recent portion was parsed",
                            path.display(),
                            MAX_LOG_BYTES / (1024 * 1024)
                        ),
                    ));
                }
                let (txs, errs) = parse_apt_history(&text);
                apt_transactions.extend(txs);
                evidence.errors.extend(errs);
            }
            Err(e) => evidence.errors.push(e),
        }
    }

    if !any_history {
        evidence.errors.push(CollectorError::unavailable(
            EvidenceSource::AptHistory,
            format!("{APT_HISTORY_LOG} not present; APT transaction history unavailable"),
        ));
    }

    // Compressed rotations are not read. Say so when the window predates what
    // was parsed, rather than letting the gap look like "no transaction".
    note_compressed_rotations(&mut evidence, window_start, &apt_transactions);

    // dpkg log: confirms per-package completion inside the window.
    let mut dpkg_entries = Vec::new();
    for candidate in [DPKG_LOG_ROTATED, DPKG_LOG] {
        let path = Path::new(candidate);
        if !path.exists() {
            continue;
        }
        match read_capped(path, EvidenceSource::DpkgLog) {
            Ok((text, truncated)) => {
                sources.insert(EvidenceSource::DpkgLog);
                if truncated {
                    evidence.errors.push(CollectorError::truncated(
                        EvidenceSource::DpkgLog,
                        format!("{} exceeds the parse cap", path.display()),
                    ));
                }
                let (entries, errs) = parse_dpkg_log(&text);
                dpkg_entries.extend(entries);
                evidence.errors.extend(errs);
            }
            Err(e) => evidence.errors.push(e),
        }
    }

    // Attach completion evidence to each transaction.
    for tx in &mut apt_transactions {
        let end = tx.end.unwrap_or(tx.start);
        let reached = packages_reaching_installed(&dpkg_entries, tx.start - 5, end + 5);
        for pkg in &mut tx.packages {
            if pkg.action.removes_files() && pkg.new_version.is_none() {
                continue;
            }
            pkg.installed_complete = if dpkg_entries.is_empty() {
                None
            } else {
                Some(reached.contains_key(&pkg.name))
            };
        }
    }

    // dpkg status: current installed state.
    match read_capped(Path::new(DPKG_STATUS), EvidenceSource::DpkgStatus) {
        Ok((text, truncated)) => {
            sources.insert(EvidenceSource::DpkgStatus);
            if truncated {
                evidence.errors.push(CollectorError::truncated(
                    EvidenceSource::DpkgStatus,
                    "dpkg status database exceeds the parse cap",
                ));
            }
            evidence.installed = parse_installed_packages(&text);
        }
        Err(e) => {
            // Absent on non-dpkg systems, which is expected, not an error to
            // shout about; unreadable when present is worth reporting.
            if e.kind != CollectorErrorKind::Unavailable {
                evidence.errors.push(e);
            }
        }
    }

    // Keep transactions that overlap the correlation window. A transaction
    // whose end precedes the window cannot explain a change inside it, and one
    // starting after the window ends is clock skew rather than evidence.
    apt_transactions.retain(|t| {
        let end = t.end.unwrap_or(t.start);
        end >= window_start && t.start <= window_end
    });
    apt_transactions.sort_by_key(|t| t.start);

    evidence.transactions = apt_transactions;
    evidence.sources = {
        let mut v: Vec<_> = sources.into_iter().collect();
        v.sort();
        v
    };
    evidence
}

/// Report compressed rotations that were not parsed when they could matter.
fn note_compressed_rotations(
    evidence: &mut AptEvidence,
    window_start: i64,
    parsed: &[TransactionRecord],
) {
    let oldest_parsed = parsed.iter().map(|t| t.start).min();
    let gap = match oldest_parsed {
        Some(oldest) => window_start < oldest,
        None => true,
    };
    if !gap {
        return;
    }

    let dir = Path::new("/var/log/apt");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let compressed: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("history.log.") && n.ends_with(".gz"))
        })
        .collect();

    if !compressed.is_empty() {
        evidence.errors.push(CollectorError::truncated(
            EvidenceSource::AptHistory,
            format!(
                "{} compressed rotation(s) of history.log were not read; \
                 transactions older than the retained logs cannot be correlated",
                compressed.len()
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPGRADE: &str = "\
Start-Date: 2025-09-20  00:07:14
Commandline: apt upgrade
Requested-By: operator (1000)
Upgrade: ghostscript:amd64 (9.55.0~dfsg1-0ubuntu5.6, 9.55.0~dfsg1-0ubuntu5.7), libglib2.0-bin:amd64 (2.72.4-0ubuntu2.2, 2.72.4-0ubuntu2.3)
End-Date: 2025-09-20  00:07:16
";

    #[test]
    fn parses_a_complete_upgrade() {
        let (txs, errs) = parse_apt_history(UPGRADE);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(txs.len(), 1);
        let tx = &txs[0];
        assert_eq!(tx.status, TransactionStatus::Completed);
        assert_eq!(tx.command.as_deref(), Some("apt upgrade"));
        assert_eq!(tx.actor.as_deref(), Some("operator (1000)"));
        assert_eq!(tx.packages.len(), 2);

        let gs = tx.package("ghostscript").expect("ghostscript present");
        assert_eq!(gs.action, PackageAction::Upgrade);
        assert_eq!(gs.old_version.as_deref(), Some("9.55.0~dfsg1-0ubuntu5.6"));
        assert_eq!(gs.new_version.as_deref(), Some("9.55.0~dfsg1-0ubuntu5.7"));
        assert_eq!(tx.duration_secs(), Some(2));
    }

    #[test]
    fn architecture_suffix_is_stripped_to_match_ownership_queries() {
        let (txs, _) = parse_apt_history(UPGRADE);
        assert!(txs[0].package("ghostscript").is_some());
        assert!(txs[0].package("ghostscript:amd64").is_none());
    }

    #[test]
    fn an_error_field_marks_the_transaction_failed_even_with_an_end_date() {
        let text = "\
Start-Date: 2025-09-20  00:07:14
Upgrade: curl:amd64 (1, 2)
Error: Sub-process /usr/bin/dpkg returned an error code (1)
End-Date: 2025-09-20  00:07:20
";
        let (txs, _) = parse_apt_history(text);
        assert_eq!(txs[0].status, TransactionStatus::Failed);
        assert!(!txs[0].status.is_success());
        assert_eq!(txs[0].errors.len(), 1);
    }

    #[test]
    fn a_stanza_without_an_end_date_is_interrupted_not_completed() {
        let text = "\
Start-Date: 2025-09-20  00:07:14
Upgrade: curl:amd64 (1, 2)
";
        let (txs, _) = parse_apt_history(text);
        assert_eq!(txs[0].status, TransactionStatus::Interrupted);
        assert!(!txs[0].status.is_success());
    }

    #[test]
    fn a_truncated_stanza_followed_by_a_new_one_is_interrupted() {
        let text = "\
Start-Date: 2025-09-20  00:07:14
Upgrade: curl:amd64 (1, 2)
Start-Date: 2025-09-20  01:00:00
Upgrade: wget:amd64 (3, 4)
End-Date: 2025-09-20  01:00:05
";
        let (txs, _) = parse_apt_history(text);
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].status, TransactionStatus::Interrupted);
        assert_eq!(txs[1].status, TransactionStatus::Completed);
    }

    #[test]
    fn malformed_lines_are_reported_not_silently_dropped() {
        let text = "\
Start-Date: 2025-09-20  00:07:14
this line has no colon
End-Date: 2025-09-20  00:07:16
";
        let (txs, errs) = parse_apt_history(text);
        assert_eq!(txs.len(), 1);
        assert!(
            errs.iter().any(|e| e.kind == CollectorErrorKind::Parse),
            "parse failures must surface: {errs:?}"
        );
    }

    #[test]
    fn unparseable_start_date_is_reported() {
        let (_, errs) = parse_apt_history("Start-Date: not-a-date\n");
        assert!(errs.iter().any(|e| e.detail.contains("Start-Date")));
    }

    #[test]
    fn version_lists_containing_commas_inside_parens_split_correctly() {
        let entries = split_apt_entries("a:amd64 (1.0, 2.0), b:amd64 (3.0, 4.0)");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].starts_with("a:amd64"));
        assert!(entries[1].starts_with("b:amd64"));
    }

    #[test]
    fn install_records_only_a_new_version() {
        let text = "\
Start-Date: 2025-09-20  00:00:01
Install: newpkg:amd64 (1.0)
End-Date: 2025-09-20  00:00:02
";
        let (txs, _) = parse_apt_history(text);
        let p = txs[0].package("newpkg").unwrap();
        assert_eq!(p.action, PackageAction::Install);
        assert_eq!(p.new_version.as_deref(), Some("1.0"));
        assert_eq!(p.old_version, None);
    }

    #[test]
    fn remove_records_only_an_old_version() {
        let text = "\
Start-Date: 2025-09-20  00:00:01
Remove: oldpkg:amd64 (1.0)
End-Date: 2025-09-20  00:00:02
";
        let (txs, _) = parse_apt_history(text);
        let p = txs[0].package("oldpkg").unwrap();
        assert_eq!(p.action, PackageAction::Remove);
        assert_eq!(p.old_version.as_deref(), Some("1.0"));
    }

    #[test]
    fn dpkg_log_status_lines_prove_completion() {
        let text = "\
2025-09-20 00:07:14 startup archives unpack
2025-09-20 00:07:15 upgrade ghostscript:amd64 9.55.0-1 9.55.0-2
2025-09-20 00:07:16 status half-configured ghostscript:amd64 9.55.0-2
2025-09-20 00:07:17 status installed ghostscript:amd64 9.55.0-2
";
        let (entries, errs) = parse_dpkg_log(text);
        assert!(errs.is_empty(), "{errs:?}");
        let start = entries.first().map(|e| e.timestamp).unwrap_or(0);
        let end = entries.last().map(|e| e.timestamp).unwrap_or(0);
        let reached = packages_reaching_installed(&entries, start, end);
        assert_eq!(
            reached.get("ghostscript").map(String::as_str),
            Some("9.55.0-2")
        );
    }

    #[test]
    fn half_configured_alone_is_not_completion() {
        let text = "\
2025-09-20 00:07:15 upgrade ghostscript:amd64 9.55.0-1 9.55.0-2
2025-09-20 00:07:16 status half-configured ghostscript:amd64 9.55.0-2
";
        let (entries, _) = parse_dpkg_log(text);
        let reached = packages_reaching_installed(&entries, 0, i64::MAX);
        assert!(reached.is_empty(), "half-configured is not installed");
    }

    #[test]
    fn dpkg_log_malformed_lines_are_counted_and_reported() {
        let (_, errs) = parse_dpkg_log("garbage\n2025-13-45 99:99:99 upgrade x:amd64 1 2\n");
        assert!(errs.iter().any(|e| e.kind == CollectorErrorKind::Parse));
    }

    #[test]
    fn installed_status_requires_install_ok_installed() {
        let text = "\
Package: good
Status: install ok installed
Version: 1.0

Package: halfway
Status: install ok half-configured
Version: 2.0

Package: alsogood
Status: install ok installed
Version: 3.0
";
        let installed = parse_installed_packages(text);
        assert_eq!(installed.get("good").map(String::as_str), Some("1.0"));
        assert_eq!(installed.get("alsogood").map(String::as_str), Some("3.0"));
        assert!(
            !installed.contains_key("halfway"),
            "a half-configured package is not fully installed"
        );
    }

    #[test]
    fn parsing_is_deterministic() {
        let (a, _) = parse_apt_history(UPGRADE);
        let (b, _) = parse_apt_history(UPGRADE);
        assert_eq!(a, b);
    }

    /// Log text is untrusted. Terminal escapes must survive parsing as inert
    /// data so the presenter, not the parser, decides how to neutralize them.
    #[test]
    fn control_sequences_in_log_text_are_data_not_behavior() {
        let text = "\
Start-Date: 2025-09-20  00:00:01
Commandline: apt install \x1b[2J\x1b[Hevil
Install: pkg:amd64 (1.0)
End-Date: 2025-09-20  00:00:02
";
        let (txs, _) = parse_apt_history(text);
        assert!(txs[0].command.as_deref().unwrap().contains('\x1b'));
    }

    /// An oversized log must yield its most recent entries, not its oldest.
    ///
    /// Reading the head of a large log would parse ancient history and miss the
    /// transaction that actually explains the current scan.
    #[test]
    fn oversized_logs_are_read_from_the_tail() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.log");
        let mut f = std::fs::File::create(&path).unwrap();

        // Filler past the cap, then the entry that matters at the very end.
        let filler = "Start-Date: 2020-01-01  00:00:01\nEnd-Date: 2020-01-01  00:00:02\n";
        let mut written = 0u64;
        while written <= MAX_LOG_BYTES {
            f.write_all(filler.as_bytes()).unwrap();
            written += filler.len() as u64;
        }
        f.write_all(
            b"Start-Date: 2025-09-20  00:07:14\nUpgrade: ghostscript:amd64 (9.55, 9.56)\nEnd-Date: 2025-09-20  00:07:16\n",
        )
        .unwrap();
        f.flush().unwrap();

        let (text, truncated) = read_capped(&path, EvidenceSource::AptHistory).unwrap();
        assert!(truncated, "the file exceeds the cap");
        assert!(
            text.contains("ghostscript"),
            "the tail entry must survive the cap"
        );
        assert!(
            text.len() as u64 <= MAX_LOG_BYTES,
            "memory use stays bounded"
        );

        let (txs, _) = parse_apt_history(&text);
        assert!(
            txs.iter().any(|t| t.package("ghostscript").is_some()),
            "the recent transaction must be parseable after truncation"
        );
    }

    /// Seeking into the middle of a log leaves a partial line. It must be
    /// discarded rather than parsed as a whole record.
    #[test]
    fn truncated_leading_line_is_discarded() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dpkg.log");
        let mut f = std::fs::File::create(&path).unwrap();
        let filler = "2020-01-01 00:00:01 status installed filler:amd64 1.0\n";
        let mut written = 0u64;
        while written <= MAX_LOG_BYTES {
            f.write_all(filler.as_bytes()).unwrap();
            written += filler.len() as u64;
        }
        f.flush().unwrap();

        let (text, _) = read_capped(&path, EvidenceSource::DpkgLog).unwrap();
        let first = text.lines().next().unwrap_or("");
        assert!(
            first.starts_with("2020-01-01"),
            "the first retained line must be whole, got: {first:?}"
        );
    }

    #[test]
    fn a_small_log_is_read_whole_and_not_marked_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.log");
        std::fs::write(&path, UPGRADE).unwrap();

        let (text, truncated) = read_capped(&path, EvidenceSource::AptHistory).unwrap();
        assert!(!truncated);
        assert_eq!(text, UPGRADE, "small logs are returned byte for byte");
    }
}
