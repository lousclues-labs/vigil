//! Display widgets: severity histogram and change comparison tables.

use std::collections::BTreeMap;

use super::format::{severity_style, Style, Styled};
use super::term::TermInfo;
use crate::types::{Change, Severity};

// ── Severity Histogram ─────────────────────────────────────

/// Render a horizontal severity histogram that adapts to terminal width.
pub fn render_histogram(severity_counts: &BTreeMap<Severity, u64>, term: &TermInfo) -> String {
    if severity_counts.is_empty() {
        return String::new();
    }

    let styled = Styled::new(term);
    let max_count = severity_counts.values().copied().max().unwrap_or(1).max(1);

    let label_width = 10;
    let count_width = max_count.to_string().len();
    let padding = 4 + label_width + 2 + count_width + 3;
    let bar_space = if term.width as usize > padding + 4 {
        term.width as usize - padding - 4
    } else {
        20
    };

    let box_inner = label_width + 2 + count_width + 3 + bar_space;
    let box_width = box_inner + 4;

    let mut out = String::new();
    out.push_str(&format!("  ╭{}╮\n", "─".repeat(box_width - 2)));

    let severity_order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    for sev in &severity_order {
        if let Some(&count) = severity_counts.get(sev) {
            let label = match sev {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
            };

            let bar_len = ((count as f64 / max_count as f64) * bar_space as f64).ceil() as usize;
            let bar_len = bar_len.max(1).min(bar_space);
            let bar = "█".repeat(bar_len);
            let bar_pad = " ".repeat(bar_space - bar_len);

            let style = severity_style(sev);
            let colored_label =
                styled.paint(style, &format!("{:<width$}", label, width = label_width));
            let colored_bar = styled.paint(style, &bar);

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

    out.push_str(&format!("  ╰{}╯", "─".repeat(box_width - 2)));
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

    fn test_term() -> TermInfo {
        TermInfo {
            width: 80,
            height: 24,
            is_tty: false,
            supports_color: false,
        }
    }

    #[test]
    fn empty_histogram() {
        let counts = BTreeMap::new();
        assert!(render_histogram(&counts, &test_term()).is_empty());
    }

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
