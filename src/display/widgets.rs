//! Display widgets: severity histogram and change comparison tables.

use std::collections::BTreeMap;

use super::format::{severity_style, Style, Styled};
use super::term::TermInfo;
use crate::types::{Change, Severity};

// ── Check Box Width ────────────────────────────────────────

/// Compute the fixed box width used by both the severity histogram and the
/// "Boundaries intact" clean-state box. Both call sites must use this so
/// the two box shapes are byte-identical in width and border style.
///
/// The width is capped at `min(term.width - 4, 80)`. When terminal width
/// cannot be determined (piping to a file, CI), `TermInfo::detect` defaults
/// to 80 columns, which yields a 60-column box after the leading indent.
pub fn check_box_width(term: &TermInfo) -> usize {
    let capped = (term.width as usize).saturating_sub(4).min(80);
    // Minimum width that fits the prefix columns + at least 4 squares
    capped.max(40)
}

// ── Severity Histogram ─────────────────────────────────────

/// Render a horizontal severity histogram where each `█` represents exactly
/// one alert. Overflow (count > capacity) is shown as `█…█+`.
pub fn render_histogram(severity_counts: &BTreeMap<Severity, u64>, term: &TermInfo) -> String {
    if severity_counts.is_empty() {
        return String::new();
    }

    let styled = Styled::new(term);
    let box_width = check_box_width(term);

    // Interior width between the two │ borders
    let interior = box_width - 2;

    // Fixed-width columns inside the box:
    //   2 leading spaces + 10 label + 1 space + count_width + 3 separator + 2 trailing
    let max_count = severity_counts.values().copied().max().unwrap_or(1).max(1);
    let count_width = max_count.to_string().len().max(2);
    let prefix_len = 2 + 10 + 1 + count_width + 3;
    let trailing = 2;
    let square_capacity = interior.saturating_sub(prefix_len + trailing).max(1);

    let mut out = String::new();
    out.push_str(&format!("  ╭{}╮\n", "─".repeat(interior)));

    let severity_order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    for sev in &severity_order {
        if let Some(&count) = severity_counts.get(sev) {
            if count == 0 {
                continue;
            }

            let label = match sev {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
            };

            let filled = if count as usize > square_capacity {
                // Overflow: show (capacity - 1) squares + "+"
                square_capacity - 1
            } else {
                count as usize
            };
            let overflow = count as usize > square_capacity;
            let empty = square_capacity - filled - if overflow { 1 } else { 0 };

            let style = severity_style(sev);
            let colored_label = styled.paint(style, &format!("{:<width$}", label, width = 10));
            let colored_bar = styled.paint(
                style,
                &format!("{}{}", "█".repeat(filled), if overflow { "+" } else { "" },),
            );

            let bar_pad = " ".repeat(empty);

            out.push_str(&format!(
                "  │  {} {:>width$}   {}{}  │\n",
                colored_label,
                count,
                colored_bar,
                bar_pad,
                width = count_width,
            ));
        }
    }

    out.push_str(&format!("  ╰{}╯", "─".repeat(interior)));
    out
}

/// Render the "Boundaries intact" clean-state box using the same fixed width
/// as the severity histogram.
pub fn render_clean_box(term: &TermInfo) -> String {
    let styled = Styled::new(term);
    let box_width = check_box_width(term);
    let interior = box_width - 2;

    let message = "● Boundaries intact";
    let visible_len = message.chars().count();
    let colored_message = styled.paint(Style::BoldGreen, message);

    // Pad content to fill interior: 2 leading + message + trailing to fill
    let content_pad = interior.saturating_sub(2 + visible_len);

    let mut out = String::new();
    out.push_str(&format!("  ╭{}╮\n", "─".repeat(interior)));
    out.push_str(&format!(
        "  │  {}{}│\n",
        colored_message,
        " ".repeat(content_pad),
    ));
    out.push_str(&format!("  ╰{}╯", "─".repeat(interior)));
    out
}

// ── Change Comparison Table ────────────────────────────────

/// Render a detail table for a file's changes (verbose mode).
pub fn render_change_table(changes: &[Change], term: &TermInfo) -> String {
    let styled = Styled::new(term);
    let mut out = String::new();

    for change in changes {
        let (property, old_val, new_val) = change_values(change);
        let col_width = if term.width > 80 {
            ((term.width as usize - 20) / 2).min(40)
        } else {
            25
        };
        let old_display = truncate_val(&old_val, col_width);
        let new_display = truncate_val(&new_val, col_width);

        out.push_str(&format!(
            "      {:<16} {} → {}\n",
            styled.paint(Style::Bold, property),
            old_display,
            new_display,
        ));
    }

    out
}

/// Render a compact single-line summary for a change.
pub fn render_change_oneline(change: &Change) -> String {
    let (property, old_val, new_val) = change_values(change);
    format!("{}: {} → {}", property, old_val, new_val)
}

/// Extract (property name, old value string, new value string) from a Change.
fn change_values(change: &Change) -> (&'static str, String, String) {
    match change {
        Change::ContentModified { old_hash, new_hash } => {
            ("content", truncate_hex(old_hash), truncate_hex(new_hash))
        }
        Change::PermissionsChanged { old, new } => (
            "permissions",
            format!("{:04o}", old),
            format!("{:04o}", new),
        ),
        Change::OwnerChanged {
            old_uid,
            new_uid,
            old_gid,
            new_gid,
        } => (
            "owner",
            format!("{}:{}", old_uid, old_gid),
            format!("{}:{}", new_uid, new_gid),
        ),
        Change::InodeChanged { old, new } => ("inode", old.to_string(), new.to_string()),
        Change::TypeChanged { old, new } => ("type", old.to_string(), new.to_string()),
        Change::SymlinkTargetChanged { old, new } => (
            "symlink",
            old.display().to_string(),
            new.display().to_string(),
        ),
        Change::CapabilitiesChanged { old, new } => (
            "capabilities",
            old.as_deref().unwrap_or("none").to_string(),
            new.as_deref().unwrap_or("none").to_string(),
        ),
        Change::XattrChanged { key, old, new } => (
            "xattr",
            format!("{}={}", key, old.as_deref().unwrap_or("none")),
            format!("{}={}", key, new.as_deref().unwrap_or("none")),
        ),
        Change::SecurityContextChanged { old, new } => ("security", old.clone(), new.clone()),
        Change::SizeChanged { old, new } => ("size", format!("{} B", old), format!("{} B", new)),
        Change::DeviceChanged { old, new } => ("device", old.to_string(), new.to_string()),
        Change::Deleted => ("status", "present".into(), "deleted".into()),
        Change::Created => ("status", "absent".into(), "created".into()),
    }
}

fn truncate_hex(hash: &str) -> String {
    if hash.len() > 16 {
        hash[..16].to_string()
    } else {
        hash.to_string()
    }
}

fn truncate_val(val: &str, max: usize) -> &str {
    if val.len() > max {
        &val[..max]
    } else {
        val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term_with_width(width: u16) -> TermInfo {
        TermInfo {
            width,
            height: 24,
            is_tty: false,
            supports_color: false,
        }
    }

    fn test_term() -> TermInfo {
        term_with_width(80)
    }

    /// Count visible characters in a line (excluding ANSI escape sequences).
    fn visible_width(line: &str) -> usize {
        let mut width = 0;
        let mut in_escape = false;
        for ch in line.chars() {
            if ch == '\x1b' {
                in_escape = true;
                continue;
            }
            if in_escape {
                if ch == 'm' {
                    in_escape = false;
                }
                continue;
            }
            width += 1;
        }
        width
    }

    /// Assert that every line in a rendered box has the same visible width.
    /// Returns the common width.
    fn assert_uniform_box_width(rendered: &str) -> usize {
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(!lines.is_empty(), "box should have at least one line");
        let widths: Vec<usize> = lines.iter().map(|l| visible_width(l)).collect();
        let first = widths[0];
        for (i, &w) in widths.iter().enumerate() {
            assert_eq!(
                w, first,
                "line {} has visible width {} but line 0 has {}:\n  line 0: {:?}\n  line {}: {:?}",
                i, w, first, lines[0], i, lines[i]
            );
        }
        first
    }

    // ── check_box_width ────────────────────────────────────

    #[test]
    fn box_width_capped_at_80() {
        let term = term_with_width(200);
        assert_eq!(check_box_width(&term), 80);
    }

    #[test]
    fn box_width_adapts_to_narrow_terminal() {
        let term = term_with_width(50);
        assert_eq!(check_box_width(&term), 46);
    }

    #[test]
    fn box_width_minimum_floor() {
        let term = term_with_width(20);
        assert_eq!(check_box_width(&term), 40);
    }

    // ── Clean-state box ────────────────────────────────────

    #[test]
    fn clean_box_uniform_width() {
        let term = test_term();
        let rendered = render_clean_box(&term);
        assert_uniform_box_width(&rendered);
    }

    #[test]
    fn clean_box_contains_message() {
        let term = test_term();
        let rendered = render_clean_box(&term);
        assert!(rendered.contains("Boundaries intact"));
    }

    // ── Histogram: empty ───────────────────────────────────

    #[test]
    fn empty_histogram() {
        let counts = BTreeMap::new();
        assert!(render_histogram(&counts, &test_term()).is_empty());
    }

    // ── Histogram: 1 critical ──────────────────────────────

    #[test]
    fn single_critical_one_square() {
        let term = test_term();
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, 1);
        let rendered = render_histogram(&counts, &term);
        assert_uniform_box_width(&rendered);

        // Exactly one filled square
        let content_line = rendered.lines().nth(1).unwrap();
        let squares: usize = content_line.matches('█').count();
        assert_eq!(squares, 1, "1 alert should produce exactly 1 square");
        assert!(!content_line.contains('+'), "no overflow for 1 alert");
    }

    // ── Histogram: exactly capacity ────────────────────────

    #[test]
    fn exact_capacity_no_overflow() {
        let term = test_term();
        let box_width = check_box_width(&term);
        let interior = box_width - 2;
        // For count=1, count_width is max(to_string().len(), 2) = 2
        // prefix_len = 2 + 10 + 1 + 2 + 3 = 18, trailing = 2
        let square_capacity = interior - 18 - 2;

        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, square_capacity as u64);
        let rendered = render_histogram(&counts, &term);
        assert_uniform_box_width(&rendered);

        let content_line = rendered.lines().nth(1).unwrap();
        let squares: usize = content_line.matches('█').count();
        assert_eq!(squares, square_capacity);
        assert!(!content_line.contains('+'), "exact capacity = no overflow");
    }

    // ── Histogram: capacity + 1 triggers overflow ──────────

    #[test]
    fn overflow_marker_shown() {
        let term = test_term();
        let box_width = check_box_width(&term);
        let interior = box_width - 2;
        // count > 9 so count_width may be 2; use a count that won't change width
        let count_width = 2usize;
        let prefix_len = 2 + 10 + 1 + count_width + 3;
        let trailing = 2;
        let square_capacity = interior - prefix_len - trailing;

        let overflow_count = (square_capacity + 1) as u64;
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, overflow_count);
        let rendered = render_histogram(&counts, &term);
        assert_uniform_box_width(&rendered);

        let content_line = rendered.lines().nth(1).unwrap();
        assert!(content_line.contains('+'), "overflow count should show +");
        let squares: usize = content_line.matches('█').count();
        assert_eq!(
            squares,
            square_capacity - 1,
            "overflow shows capacity-1 squares"
        );
    }

    // ── Histogram: mixed severities ────────────────────────

    #[test]
    fn mixed_severities_uniform_width() {
        let term = test_term();
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, 3);
        counts.insert(Severity::High, 7);
        counts.insert(Severity::Medium, 12);
        counts.insert(Severity::Low, 1);
        let rendered = render_histogram(&counts, &term);
        assert_uniform_box_width(&rendered);

        // All four severities present
        assert!(rendered.contains("CRITICAL"));
        assert!(rendered.contains("HIGH"));
        assert!(rendered.contains("MEDIUM"));
        assert!(rendered.contains("LOW"));
    }

    // ── Histogram: zero-count rows are not rendered ────────

    #[test]
    fn zero_count_rows_omitted() {
        let term = test_term();
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, 0);
        counts.insert(Severity::Medium, 5);
        let rendered = render_histogram(&counts, &term);
        assert!(
            !rendered.contains("CRITICAL"),
            "zero-count row should not appear"
        );
        assert!(rendered.contains("MEDIUM"));
    }

    // ── Histogram + clean box: same width ──────────────────

    #[test]
    fn histogram_and_clean_box_same_width() {
        let term = test_term();
        let mut counts = BTreeMap::new();
        counts.insert(Severity::High, 4);
        let hist = render_histogram(&counts, &term);
        let clean = render_clean_box(&term);
        let hist_w = assert_uniform_box_width(&hist);
        let clean_w = assert_uniform_box_width(&clean);
        assert_eq!(
            hist_w, clean_w,
            "histogram and clean box must have identical width"
        );
    }

    // ── Terminal width adaptivity ──────────────────────────

    #[test]
    fn narrow_terminal_40() {
        let term = term_with_width(40);
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, 3);
        let rendered = render_histogram(&counts, &term);
        assert_uniform_box_width(&rendered);
        let clean = render_clean_box(&term);
        assert_uniform_box_width(&clean);
    }

    #[test]
    fn wide_terminal_200() {
        let term = term_with_width(200);
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, 3);
        let rendered = render_histogram(&counts, &term);
        let w = assert_uniform_box_width(&rendered);
        // Box capped at 80 + 2 leading spaces = 82 visible chars
        assert!(w <= 82, "box width should be capped even on wide terminals");
    }

    // ── Existing tests ─────────────────────────────────────

    #[test]
    fn single_severity() {
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Low, 5);
        let result = render_histogram(&counts, &test_term());
        assert!(result.contains("LOW"));
        assert!(result.contains("5"));
        assert!(result.contains("█"));
    }

    #[test]
    fn multiple_severities() {
        let mut counts = BTreeMap::new();
        counts.insert(Severity::Critical, 1);
        counts.insert(Severity::Low, 10);
        let result = render_histogram(&counts, &test_term());
        assert!(result.contains("CRITICAL"));
        assert!(result.contains("LOW"));
    }

    #[test]
    fn oneline_content_change() {
        let c = Change::ContentModified {
            old_hash: "aabbccdd".into(),
            new_hash: "11223344".into(),
        };
        let result = render_change_oneline(&c);
        assert!(result.contains("content"));
        assert!(result.contains("→"));
    }
}
