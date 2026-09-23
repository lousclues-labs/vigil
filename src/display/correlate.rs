//! Event-first rendering for correlated detections.
//!
//! The contract of this module:
//!
//! - It renders. It never mutates evidence, never decides acceptance, and never
//!   changes a severity.
//! - Raw severity counts stay visible on every event, so grouping reduces
//!   scrolling without hiding what was observed.
//! - Explanation status is presented as its own dimension, worded so it cannot
//!   be read as a safety verdict.
//! - Unexplained and conflicting items stay prominent regardless of how tidy
//!   the rest of the event looks.
//! - Untrusted text -- paths, package names, log excerpts -- is sanitized
//!   before it reaches the terminal.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use crate::correlate::{
    CheckOutcome, Confidence, CorrelatedEvent, CorrelationResult, EventKind, MemberRole,
    TransactionStatus,
};
use crate::types::Severity;

use super::format::{sanitize_for_terminal, sanitize_path, Style, Styled};
use super::term::TermInfo;
use super::time::format_absolute;

/// Maximum members listed per package before the list is summarized.
/// Verbose mode lists every one.
const PACKAGE_PREVIEW_LIMIT: usize = 3;

/// Render the correlated-event section of a check report.
///
/// Returns an empty string when nothing was correlated, so the ordinary report
/// is unchanged on systems with no package-manager evidence.
pub fn render_events(result: &CorrelationResult, term: &TermInfo, verbose: bool) -> String {
    if result.events.is_empty() && result.collector_errors.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push('\n');
    out.push_str("  Correlated events\n");
    out.push_str("  ─────────────────\n");
    out.push_str(
        "  Grouping is an explanation, not a clearance. Every change below is\n\
         \x20 still recorded individually and still carries its raw severity.\n",
    );

    for event in &result.events {
        out.push('\n');
        out.push_str(&render_event(event, term, verbose));
    }

    if !result.collector_errors.is_empty() {
        out.push('\n');
        out.push_str(&render_collector_errors(result, term));
    }

    out
}

/// Style for a confidence level.
///
/// Deliberately never green. Green is this codebase's "all clear" colour, and
/// an explained transaction is not an all-clear: it means the evidence
/// consistently attributes the change to a package operation, which says
/// nothing about whether the delivered software is benign. Settled events are
/// rendered plain so attention goes to the ones that are not.
fn confidence_style(confidence: Confidence) -> Style {
    match confidence {
        Confidence::ConflictingEvidence => Style::BoldRed,
        Confidence::Unverified => Style::Yellow,
        Confidence::PartiallyExplained => Style::Yellow,
        Confidence::StronglyCorrelated => Style::Bold,
        Confidence::VerifiedTransaction => Style::Bold,
    }
}

/// Render one event: headline, verification, raw impact, packages, disposition.
pub fn render_event(event: &CorrelatedEvent, term: &TermInfo, verbose: bool) -> String {
    let mut out = String::new();

    // ── Headline ───────────────────────────────────────────
    let styled = Styled::new(term);
    let label = styled.paint(confidence_style(event.confidence), event.confidence.label());
    let kind = match event.kind {
        EventKind::AptTransaction => "APT/DPKG TRANSACTION",
        EventKind::SnapRefresh => "SNAP REFRESH",
        EventKind::UnknownBatch => "UNEXPLAINED BATCH",
    };
    out.push_str(&format!("  {} {}\n", label, kind));

    // Scope line: packages and how many raw detections it accounts for.
    let package_count = event.packages.len();
    out.push_str(&format!(
        "    {} package{} · {} filesystem detection{}\n",
        package_count,
        if package_count == 1 { "" } else { "s" },
        event.detection_count(),
        if event.detection_count() == 1 {
            ""
        } else {
            "s"
        },
    ));

    // Window and actor.
    let window = match (event.started_at, event.completed_at) {
        (Some(s), Some(e)) if s != e => {
            format!("{} – {}", format_absolute(s), format_absolute(e))
        }
        (Some(s), _) => format_absolute(s),
        _ => "time not recorded".to_string(),
    };
    out.push_str(&format!("    {}\n", window));

    if let Some(actor) = &event.actor {
        out.push_str(&format!(
            "    requested by {} (as recorded by the package manager)\n",
            sanitize_for_terminal(actor)
        ));
    }
    if let Some(id) = &event.transaction_id {
        out.push_str(&format!("    transaction {}\n", sanitize_for_terminal(id)));
    }
    if verbose {
        if let Some(cmd) = &event.command {
            out.push_str(&format!("    command: {}\n", sanitize_for_terminal(cmd)));
        }
        out.push_str(&format!("    event id: {}\n", event.event_id));
    }

    // ── Verification ───────────────────────────────────────
    out.push('\n');
    out.push_str("    Verification\n");
    if event.verification.checks.is_empty() {
        out.push_str("      (no checks could be performed)\n");
    }
    for check in &event.verification.checks {
        let marker = match check.outcome {
            CheckOutcome::Passed => styled.paint(Style::Bold, "+"),
            CheckOutcome::Failed => styled.paint(Style::Red, "x"),
            CheckOutcome::Unavailable => styled.paint(Style::Yellow, "?"),
        };
        let detail = if check.detail.is_empty() {
            String::new()
        } else {
            format!(" — {}", sanitize_for_terminal(&check.detail))
        };
        out.push_str(&format!(
            "      {} {}{}\n",
            marker,
            sanitize_for_terminal(&check.name),
            detail
        ));
    }

    // Transaction end state, stated plainly.
    if event.status != TransactionStatus::Completed {
        out.push_str(&format!("      transaction end state: {}\n", event.status));
    }

    // ── Raw impact ─────────────────────────────────────────
    out.push('\n');
    out.push_str("    Raw impact (unchanged by correlation)\n");
    for (severity, count) in event.raw_severity_counts() {
        let label = styled.paint(
            super::format::severity_style(&severity),
            &format!("{:<9}", severity.to_string().to_uppercase()),
        );
        out.push_str(&format!("      {} {}\n", label, count));
    }

    // ── Packages ───────────────────────────────────────────
    let by_package = event.members_by_package();
    if !by_package.is_empty() {
        out.push('\n');
        out.push_str("    Packages\n");
        for (package, members) in &by_package {
            let files = members
                .iter()
                .filter(|m| m.role != MemberRole::SymlinkAlias)
                .count();
            let aliases = members
                .iter()
                .filter(|m| m.role == MemberRole::SymlinkAlias)
                .count();

            let version = event
                .packages
                .iter()
                .find(|p| &p.name == package)
                .map(|p| p.version_summary())
                .unwrap_or_default();

            let detail = if aliases > 0 {
                format!(
                    "{} file{} + {} alias{}",
                    files,
                    plural(files),
                    aliases,
                    plural_es(aliases)
                )
            } else {
                format!("{} detection{}", files, plural(files))
            };

            out.push_str(&format!(
                "      {:<28} {:<24} {}\n",
                sanitize_for_terminal(package),
                sanitize_for_terminal(&version),
                detail
            ));

            // Individual paths: a preview normally, everything in verbose mode.
            let limit = if verbose {
                members.len()
            } else {
                PACKAGE_PREVIEW_LIMIT.min(members.len())
            };
            for member in members.iter().take(limit) {
                out.push_str(&render_member(member, term));
            }
            if !verbose && members.len() > limit {
                out.push_str(&format!(
                    "          … {} more (use --verbose to list every path)\n",
                    members.len() - limit
                ));
            }
        }
    }

    // ── Unexplained ────────────────────────────────────────
    // Always listed in full, never previewed away. These are the reason the
    // event is not a clean story.
    if !event.unexplained.is_empty() {
        out.push('\n');
        let heading = styled.paint(
            Style::Red,
            &format!(
                "    Unexplained by this transaction ({})",
                event.unexplained.len()
            ),
        );
        out.push_str(&format!("{}\n", heading));
        for item in &event.unexplained {
            let sev = styled.paint(
                super::format::severity_style(&item.raw.severity),
                &format!("{:<8}", item.raw.severity.to_string().to_uppercase()),
            );
            out.push_str(&format!(
                "      {} {}\n",
                sev,
                sanitize_path(&item.raw.path)
            ));
            out.push_str(&format!(
                "               {}\n",
                sanitize_for_terminal(&item.reason)
            ));
        }
    }

    // ── Collector errors ───────────────────────────────────
    if !event.collector_errors.is_empty() {
        out.push('\n');
        out.push_str("    Evidence gaps\n");
        for err in &event.collector_errors {
            out.push_str(&format!(
                "      ? {} [{}]: {}\n",
                err.source,
                err.kind,
                sanitize_for_terminal(&err.detail)
            ));
        }
    }

    // ── Disposition ────────────────────────────────────────
    out.push('\n');
    out.push_str("    Disposition\n");
    out.push_str(&format!(
        "      Explanation: {}\n",
        event.confidence.as_str()
    ));
    out.push_str("      Baseline:    not accepted — correlation never updates the baseline\n");
    if event.confidence.needs_investigation() {
        out.push_str("      Action:      review the items above individually\n");
    } else {
        out.push_str(
            "      Action:      accept explicitly with `vigil check --accept` if this\n\
             \x20                  transaction was expected\n",
        );
    }

    out
}

/// Render one member line beneath its package.
fn render_member(member: &crate::correlate::EventMember, term: &TermInfo) -> String {
    let sev = Styled::new(term).paint(
        super::format::severity_style(&member.raw.severity),
        &format!("{:<8}", member.raw.severity.to_string().to_uppercase()),
    );

    let mut line = format!("        {} {}", sev, sanitize_path(&member.raw.path));

    // Verification verdict per path, using the package module's vocabulary.
    line.push_str(&format!(" [{}]", member.verification.as_str()));

    if member.role == MemberRole::SymlinkAlias {
        if let Some(target) = &member.canonical_path {
            line.push('\n');
            line.push_str(&format!(
                "                 alias of {} (symlink object unchanged)",
                sanitize_path(target)
            ));
        }
    } else if member.role != MemberRole::PackageFile {
        line.push_str(&format!(" ({})", member.role.as_str()));
    }

    line.push('\n');
    line
}

/// Render run-wide collector failures.
fn render_collector_errors(result: &CorrelationResult, term: &TermInfo) -> String {
    let mut out = String::new();
    let heading = Styled::new(term).paint(Style::Yellow, "  Evidence unavailable");
    out.push_str(&format!("{}\n", heading));
    out.push_str(
        "  Correlation ran with incomplete evidence. Absent evidence is not a\n\
         \x20 clean result; the changes below were simply not explainable.\n",
    );
    for err in &result.collector_errors {
        out.push_str(&format!(
            "    ? {} [{}]: {}\n",
            err.source,
            err.kind,
            sanitize_for_terminal(&err.detail)
        ));
        if err.kind.is_privilege_problem() {
            out.push_str("      (this check needs privileges this process does not have)\n");
        }
    }
    out
}

/// One-line summary used by brief output.
pub fn render_brief_summary(result: &CorrelationResult) -> String {
    if result.events.is_empty() {
        return String::new();
    }
    let explained: usize = result.correlated_count();
    let needing: usize = result
        .events
        .iter()
        .filter(|e| e.confidence.needs_investigation())
        .count();

    let mut s = format!(
        "{} event{} explaining {} detection{}",
        result.events.len(),
        plural(result.events.len()),
        explained,
        plural(explained)
    );
    if needing > 0 {
        s.push_str(&format!("; {needing} need review"));
    }
    s
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn plural_es(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "es"
    }
}

/// One line of triage, before any detail.
///
/// This is the line that decides whether the tool is usable on a desktop. An
/// operator who runs a routine upgrade and is met with a bar chart reading
/// CRITICAL 22 learns, correctly, that the chart does not track anything they
/// need to act on -- and a signal that is always loud is one they will turn
/// off. So the headline states the split: how much is accounted for by
/// package activity, and how much still wants a human. Neither number is
/// softened, and the severities behind them are printed in full below.
pub fn render_triage_line(
    result: &CorrelationResult,
    total: usize,
    needs_review: usize,
    term: &TermInfo,
) -> String {
    if result.events.is_empty() {
        return String::new();
    }
    let styled = Styled::new(term);
    let explained = total.saturating_sub(needs_review);

    let kinds: Vec<&str> = {
        let mut k: Vec<&str> = result.events.iter().map(|e| e.kind.as_str()).collect();
        k.sort_unstable();
        k.dedup();
        k
    };
    let source = if kinds.len() == 1 {
        kinds[0].to_string()
    } else {
        "package activity".to_string()
    };

    let mut out = String::new();
    out.push_str(&format!(
        "  {} change{} · {} explained by {}",
        total,
        plural(total),
        explained,
        source,
    ));
    if needs_review == 0 {
        out.push_str(&format!(
            " · {}\n\n",
            styled.paint(Style::Bold, "nothing unaccounted for")
        ));
    } else {
        out.push_str(&format!(
            " · {}\n\n",
            styled.paint(
                Style::BoldYellow,
                &format!(
                    "{} need{} review",
                    needs_review,
                    if needs_review == 1 { "s" } else { "" }
                )
            )
        ));
    }
    out
}

/// Transaction window as one short line, with the actor when a log names one.
fn event_window(event: &CorrelatedEvent) -> Option<String> {
    let window = match (event.started_at, event.completed_at) {
        (Some(s), Some(e)) if s != e => format!("{} – {}", format_absolute(s), format_absolute(e)),
        (Some(s), _) => format_absolute(s),
        _ => return None,
    };
    Some(match &event.actor {
        Some(a) => format!("{} · requested by {}", window, sanitize_for_terminal(a)),
        None => window,
    })
}

/// The single verification result an operator most needs to see.
///
/// The full eight-line checklist is what `--verbose` prints. Surfacing only
/// the weakest outcome keeps the default view honest without making a routine
/// upgrade look like an incident report: a failure is named, and when nothing
/// failed the line says how much was actually verified rather than implying
/// more certainty than the evidence supports.
fn weakest_check(event: &CorrelatedEvent) -> Option<String> {
    let checks = &event.verification.checks;
    if checks.is_empty() {
        return Some("no verification checks could be performed".to_string());
    }
    // The unexplained-files check gets its own line below, worded for an
    // operator rather than as a check name. Surfacing both said the same
    // thing twice.
    let relevant = |c: &&crate::correlate::VerificationCheck| c.name != "no unexplained files";
    let checks: Vec<&crate::correlate::VerificationCheck> =
        checks.iter().filter(relevant).collect();
    if let Some(c) = checks.iter().find(|c| c.outcome == CheckOutcome::Failed) {
        return Some(sanitize_for_terminal(&c.detail));
    }
    if let Some(c) = checks
        .iter()
        .find(|c| c.outcome == CheckOutcome::Unavailable)
    {
        return Some(sanitize_for_terminal(&c.detail));
    }
    None
}

/// Paths this correlation accounts for, as raw-detection members of an event.
///
/// The check renderer uses this to avoid printing a path twice: once in the
/// raw detail list and again under the event that explains it. Unexplained
/// members are deliberately absent, so they keep rendering in the prominent
/// sections where they belong.
pub fn explained_paths(result: &CorrelationResult) -> HashSet<PathBuf> {
    result
        .events
        .iter()
        .flat_map(|e| e.members.iter())
        .map(|m| m.raw.path.clone())
        .collect()
}

/// Compact, event-first summary: a few lines per transaction instead of a
/// per-file wall.
///
/// The detailed form (`render_event`) is what `--verbose` prints. This one
/// exists because the default view was rendering every changed file in full
/// and *then* repeating all of them grouped by package, which was more text
/// than printing no correlation at all -- the opposite of the point. What an
/// operator needs by default is: something explains this, here is what, here
/// is what it does not explain.
pub fn render_events_summary(result: &CorrelationResult, term: &TermInfo) -> String {
    if result.events.is_empty() {
        return String::new();
    }
    let styled = Styled::new(term);
    let mut out = String::new();

    let explained: usize = result.events.iter().map(|e| e.members.len()).sum();
    out.push_str(&styled.paint(
        Style::Bold,
        &format!("  ▸ Explained by package activity ({})\n\n", explained),
    ));

    for event in &result.events {
        out.push_str(&render_event_summary(event, term));
    }

    out.push_str(&styled.paint(
        Style::Dim,
        "    An explanation is not a clearance, and nothing above has been\n\
         \x20   accepted into the baseline.\n\n",
    ));

    out
}

/// One event, condensed to its headline facts.
fn render_event_summary(event: &CorrelatedEvent, term: &TermInfo) -> String {
    let styled = Styled::new(term);
    let mut out = String::new();

    let mut headline = format!("    {} · {}", event.confidence.label(), event.kind.as_str());
    if !event.packages.is_empty() {
        headline.push_str(&format!(
            " · {} package{}",
            event.packages.len(),
            plural(event.packages.len())
        ));
    }
    headline.push_str(&format!(
        " · {} detection{}",
        event.members.len(),
        plural(event.members.len())
    ));
    out.push_str(&styled.paint(confidence_style(event.confidence), &headline));
    out.push('\n');

    if let Some(window) = event_window(event) {
        out.push_str(&format!("      {}\n", styled.paint(Style::Dim, &window)));
    }

    // Package names only. The per-file list is what --verbose is for.
    if !event.packages.is_empty() {
        let mut names: Vec<&str> = event.packages.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        let shown: Vec<&str> = names.iter().take(6).copied().collect();
        let mut line = shown.join(", ");
        if names.len() > shown.len() {
            line.push_str(&format!(" +{} more", names.len() - shown.len()));
        }
        out.push_str(&format!(
            "      {}\n",
            styled.paint(Style::Dim, &sanitize_for_terminal(&line))
        ));
    }

    // Raw severity is never restated as anything softer.
    let counts = member_severity_counts(event);
    if !counts.is_empty() {
        let rendered: Vec<String> = counts
            .iter()
            .map(|(sev, n)| format!("{} {}", severity_word(*sev), n))
            .collect();
        out.push_str(&format!(
            "      {}\n",
            styled.paint(
                Style::Dim,
                &format!("raw severity unchanged: {}", rendered.join(" · "))
            )
        ));
    }

    // The one verification line that matters most, not all eight.
    if let Some(weak) = weakest_check(event) {
        out.push_str(&format!("      {}\n", styled.paint(Style::Yellow, &weak)));
    }

    if !event.unexplained.is_empty() {
        out.push_str(&format!(
            "      {}\n",
            styled.paint(
                Style::BoldYellow,
                &format!(
                    "{} change{} in this window the transaction does not account for",
                    event.unexplained.len(),
                    plural(event.unexplained.len())
                )
            )
        ));
    }

    out.push('\n');
    out
}

/// Severity tally across an event's members, highest first.
fn member_severity_counts(event: &CorrelatedEvent) -> Vec<(Severity, usize)> {
    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for m in &event.members {
        *counts.entry(m.raw.severity).or_insert(0) += 1;
    }
    let mut v: Vec<(Severity, usize)> = counts.into_iter().collect();
    v.sort_by_key(|(sev, _)| std::cmp::Reverse(*sev));
    v
}

fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::{
        CorrelatedEventBuilder, EventMember, PackageAction, PackageTransition, RawRef,
        TransactionRecord, TransactionSource, UnexplainedChange, VerificationCheck,
    };
    use crate::package::PackageVerification;
    use crate::types::Severity;
    use std::path::PathBuf;

    fn plain_term() -> TermInfo {
        TermInfo {
            is_tty: false,
            supports_color: false,
            width: 100,
            height: 40,
        }
    }

    fn raw(index: usize, path: &str, severity: Severity) -> RawRef {
        RawRef {
            index,
            path: PathBuf::from(path),
            severity,
            changes: vec!["content_modified".into()],
            audit_sequence: None,
        }
    }

    fn member(index: usize, path: &str, severity: Severity) -> EventMember {
        EventMember {
            raw: raw(index, path, severity),
            role: MemberRole::PackageFile,
            package: Some("ghostscript".into()),
            verification: PackageVerification::Verified,
            canonical_path: None,
        }
    }

    fn transaction() -> TransactionRecord {
        let mut tx = TransactionRecord::new(TransactionSource::Apt, 1_700_000_000);
        tx.end = Some(1_700_000_002);
        tx.status = TransactionStatus::Completed;
        tx.actor = Some("operator (1000)".into());
        tx.packages.push(
            PackageTransition::new("ghostscript", PackageAction::Upgrade)
                .with_versions(Some("9.55"), Some("9.56")),
        );
        tx
    }

    fn verified_event() -> CorrelatedEvent {
        CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .member(member(1, "/usr/bin/gsc", Severity::Critical))
            .member(member(2, "/etc/systemd/system/x.service", Severity::High))
            .check(VerificationCheck::passed("transaction completed", "apt"))
            .confidence(Confidence::VerifiedTransaction)
            .build()
    }

    #[test]
    fn raw_severity_counts_remain_visible_on_a_verified_event() {
        let out = render_event(&verified_event(), &plain_term(), false);
        assert!(out.contains("Raw impact"));
        assert!(out.contains("CRITICAL"), "{out}");
        assert!(out.contains("HIGH"), "{out}");
    }

    #[test]
    fn explanation_status_is_separate_from_raw_severity() {
        let out = render_event(&verified_event(), &plain_term(), false);
        assert!(out.contains("Explanation: verified package transaction"));
        assert!(out.contains("Raw impact (unchanged by correlation)"));
    }

    #[test]
    fn baseline_state_is_stated_as_not_accepted() {
        let out = render_event(&verified_event(), &plain_term(), false);
        assert!(
            out.contains("not accepted"),
            "a verified event must still say the baseline was not touched: {out}"
        );
    }

    /// "Verified" must never be rendered as a safety claim.
    #[test]
    fn verified_wording_avoids_safety_language() {
        let out = render_event(&verified_event(), &plain_term(), false);
        for forbidden in ["safe", "harmless", "trusted", "clean"] {
            assert!(
                !out.to_lowercase().contains(forbidden),
                "output must not imply safety, found '{forbidden}': {out}"
            );
        }
    }

    #[test]
    fn unexplained_items_are_listed_in_full_even_when_not_verbose() {
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .unexplained(UnexplainedChange {
                raw: raw(1, "/tmp/dropper", Severity::Critical),
                reason: "not owned by any package in this transaction".into(),
            })
            .unexplained(UnexplainedChange {
                raw: raw(2, "/tmp/second", Severity::Critical),
                reason: "not owned by any package in this transaction".into(),
            })
            .confidence(Confidence::PartiallyExplained)
            .build();

        let out = render_event(&event, &plain_term(), false);
        assert!(out.contains("Unexplained by this transaction (2)"));
        assert!(out.contains("/tmp/dropper"));
        assert!(out.contains("/tmp/second"));
        assert!(out.contains("review the items above individually"));
    }

    #[test]
    fn verbose_lists_every_member_path() {
        let mut builder =
            CorrelatedEventBuilder::new(EventKind::AptTransaction).transaction(transaction());
        for i in 0..10 {
            builder = builder.member(member(i, &format!("/usr/share/gs/f{i}"), Severity::Low));
        }
        let event = builder.confidence(Confidence::VerifiedTransaction).build();

        let terse = render_event(&event, &plain_term(), false);
        let verbose = render_event(&event, &plain_term(), true);

        assert!(terse.contains("more (use --verbose"));
        for i in 0..10 {
            assert!(
                verbose.contains(&format!("/usr/share/gs/f{i}")),
                "verbose output must include every raw path"
            );
        }
        assert!(!verbose.contains("more (use --verbose"));
    }

    #[test]
    fn aliases_are_shown_beneath_their_target() {
        let alias = EventMember {
            raw: raw(
                0,
                "/etc/systemd/system/multi-user.target.wants/rsyslog.service",
                Severity::High,
            ),
            role: MemberRole::SymlinkAlias,
            package: Some("rsyslog".into()),
            verification: PackageVerification::Verified,
            canonical_path: Some(PathBuf::from("/lib/systemd/system/rsyslog.service")),
        };
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(alias)
            .confidence(Confidence::VerifiedTransaction)
            .build();

        let out = render_event(&event, &plain_term(), true);
        assert!(out.contains("alias of /lib/systemd/system/rsyslog.service"));
        assert!(out.contains("symlink object unchanged"));
        assert!(
            out.contains("1 file + 1 alias") || out.contains("0 files + 1 alias"),
            "{out}"
        );
    }

    /// A path crafted to rewrite the terminal must be rendered inert.
    #[test]
    fn control_characters_in_paths_cannot_alter_presentation() {
        let hostile = "/tmp/\x1b[2J\x1b[1;31mFAKE CLEAN\x1b[0m";
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, hostile, Severity::Critical))
            .confidence(Confidence::VerifiedTransaction)
            .build();

        let out = render_event(&event, &plain_term(), true);
        assert!(
            !out.contains('\x1b'),
            "no raw escape byte may reach the terminal"
        );
        assert!(out.contains("\\x1b"), "the escape must be shown literally");
    }

    #[test]
    fn control_characters_in_actor_and_command_are_escaped() {
        let mut tx = transaction();
        tx.actor = Some("root\x1b[2J".into());
        tx.command = Some("apt \x07 install".into());
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(tx)
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .confidence(Confidence::VerifiedTransaction)
            .build();

        let out = render_event(&event, &plain_term(), true);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
    }

    #[test]
    fn bidi_override_in_a_path_is_escaped() {
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/tmp/\u{202e}gnp.exe", Severity::Critical))
            .confidence(Confidence::VerifiedTransaction)
            .build();

        let out = render_event(&event, &plain_term(), true);
        assert!(!out.contains('\u{202e}'));
        assert!(out.contains("\\u{202e}"));
    }

    #[test]
    fn a_failed_transaction_states_its_end_state() {
        let mut tx = transaction();
        tx.status = TransactionStatus::Failed;
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(tx)
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .check(VerificationCheck::failed(
                "transaction completed",
                "apt recorded an error",
            ))
            .confidence(Confidence::ConflictingEvidence)
            .build();

        let out = render_event(&event, &plain_term(), false);
        assert!(out.contains("transaction end state: failed"));
        assert!(out.contains("CONFLICTING"));
        assert!(out.contains("Explanation: conflicting evidence"));
    }

    #[test]
    fn unavailable_checks_are_rendered_as_questions_not_passes() {
        let event = CorrelatedEventBuilder::new(EventKind::AptTransaction)
            .transaction(transaction())
            .member(member(0, "/usr/bin/gs", Severity::Critical))
            .check(VerificationCheck::unavailable(
                "content verification coverage",
                "no digest recorded",
            ))
            .confidence(Confidence::StronglyCorrelated)
            .build();

        let out = render_event(&event, &plain_term(), false);
        assert!(out.contains("? content verification coverage"));
        assert!(out.contains("no digest recorded"));
    }

    #[test]
    fn empty_result_renders_nothing() {
        let result = CorrelationResult::default();
        assert!(render_events(&result, &plain_term(), false).is_empty());
    }

    #[test]
    fn collector_errors_are_surfaced_even_without_events() {
        let result = CorrelationResult {
            events: Vec::new(),
            uncorrelated: vec![0],
            collector_errors: vec![crate::correlate::CollectorError::new(
                crate::correlate::EvidenceSource::SnapdChanges,
                crate::correlate::CollectorErrorKind::PermissionDenied,
                "requires administrator privileges",
            )],
        };
        let out = render_events(&result, &plain_term(), false);
        assert!(out.contains("Evidence unavailable"));
        assert!(out.contains("snapd change history"));
        assert!(out.contains("needs privileges"));
    }
}
