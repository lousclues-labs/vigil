//! Shared formatting utilities: number formatting, path truncation, hash display,
//! color/styling system, and severity display helpers.

use super::term::TermInfo;
use crate::types::Severity;

// ── ANSI Color System ──────────────────────────────────────

/// ANSI color codes carrying semantic meaning (not decoration).
#[derive(Debug, Clone, Copy)]
pub enum Style {
    /// Needs investigation: CRITICAL, HIGH severity
    Red,
    /// Should be aware: MEDIUM severity
    Yellow,
    /// Probably fine: LOW, package updates
    Dim,
    /// All clear: clean check verdict
    Green,
    /// Section headers and file paths
    Bold,
    /// Bold + Red combined
    BoldRed,
    /// Bold + Yellow combined
    BoldYellow,
    /// Bold + Green combined
    BoldGreen,
}

impl Style {
    fn ansi_code(self) -> &'static str {
        match self {
            Style::Red => "\x1b[31m",
            Style::Yellow => "\x1b[33m",
            Style::Dim => "\x1b[2m",
            Style::Green => "\x1b[32m",
            Style::Bold => "\x1b[1m",
            Style::BoldRed => "\x1b[1;31m",
            Style::BoldYellow => "\x1b[1;33m",
            Style::BoldGreen => "\x1b[1;32m",
        }
    }
}

const RESET: &str = "\x1b[0m";

/// Conditionally apply ANSI styling based on terminal support.
pub struct Styled<'a> {
    term: &'a TermInfo,
}

impl<'a> Styled<'a> {
    pub fn new(term: &'a TermInfo) -> Self {
        Styled { term }
    }

    /// Apply a style to text. Returns unstyled text if terminal doesn't support color.
    pub fn paint(&self, style: Style, text: &str) -> String {
        if self.term.supports_color {
            format!("{}{}{}", style.ansi_code(), text, RESET)
        } else {
            text.to_string()
        }
    }
}

/// Map severity to its semantic color.
pub fn severity_style(severity: &Severity) -> Style {
    match severity {
        Severity::Critical | Severity::High => Style::BoldRed,
        Severity::Medium => Style::Yellow,
        Severity::Low => Style::Dim,
    }
}

/// Map severity to its display marker and label.
pub fn severity_marker(severity: &Severity) -> (&'static str, &'static str) {
    match severity {
        Severity::Critical => ("✗", "CRITICAL"),
        Severity::High => ("✗", "HIGH"),
        Severity::Medium => ("⚠", "MEDIUM"),
        Severity::Low => ("○", "LOW"),
    }
}

// ── Number & Size Formatting ───────────────────────────────

/// Format a number with comma separators: 1234567 → "1,234,567".
pub fn format_count(value: u64) -> String {
    let s = value.to_string();
    let mut out = String::with_capacity(s.len() + (s.len() / 3));

    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }

    out.chars().rev().collect()
}

/// Format bytes as human-readable size, auto-scaling to appropriate unit.
///
/// Uses decimal units (KB, MB, GB, TB) with precision appropriate for
/// the scale: whole numbers at GB+, one decimal at MB/KB.
pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes < 1_099_511_627_776 {
        let gb = bytes as f64 / 1_073_741_824.0;
        if gb >= 100.0 {
            format!("{} GB", gb.round() as u64)
        } else {
            format!("{:.1} GB", gb)
        }
    } else {
        let tb = bytes as f64 / 1_099_511_627_776.0;
        if tb >= 100.0 {
            format!("{} TB", tb.round() as u64)
        } else {
            format!("{:.1} TB", tb)
        }
    }
}

/// Format a duration in seconds as a human-readable age (e.g., "2h 14m ago").
pub fn format_age(seconds: i64) -> String {
    if seconds < 0 {
        return "in the future".into();
    }
    let s = seconds as u64;
    if s < 60 {
        format!("{}s ago", s)
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        let h = s / 3600;
        let m = (s % 3600) / 60;
        if m > 0 {
            format!("{}h {}m ago", h, m)
        } else {
            format!("{}h ago", h)
        }
    } else {
        let d = s / 86400;
        format!("{} day{} ago", d, if d == 1 { "" } else { "s" })
    }
}

// ── Hash & Fingerprint ─────────────────────────────────────

/// Truncate a hash to 16 hex chars for display.
pub fn truncate_hash(hash: &str) -> &str {
    if hash.len() > 16 {
        &hash[..16]
    } else {
        hash
    }
}

/// Format a baseline fingerprint: first 16 hex chars as xxxx·xxxx·xxxx·xxxx.
pub fn format_fingerprint(hmac_hex: &str) -> String {
    let hex: String = hmac_hex
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(16)
        .collect();
    if hex.len() < 16 {
        return hex;
    }
    format!(
        "{}·{}·{}·{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

// ── Path Truncation ────────────────────────────────────────

/// Path truncation: preserves root indicator and filename,
/// collapses middle segments when path exceeds available width.
///
/// - Collapses `$HOME` to `~`.
/// - Uses middle-ellipsis when path exceeds `max_width`.
/// - Always shows the filename and root prefix.
pub fn truncate_path(path: &str, max_width: usize) -> String {
    let path = collapse_home(path);

    if path.len() <= max_width || max_width < 8 {
        return path;
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= 2 {
        return path;
    }

    let filename = parts.last().unwrap_or(&"");
    let root = if path.starts_with("~/") {
        "~"
    } else if path.starts_with('/') {
        parts
            .first()
            .map(|s| if s.is_empty() { "/" } else { *s })
            .unwrap_or("/")
    } else {
        parts.first().unwrap_or(&"")
    };

    let sep = "/";
    let ellipsis = "…";

    let prefix = if root == "/" {
        "/".to_string()
    } else {
        format!("{}/", root)
    };

    let suffix_parts: Vec<&str> = parts[1..].to_vec();
    let suffix_len = suffix_parts.len();

    for keep_trailing in (1..suffix_len).rev() {
        let trailing: String = suffix_parts[suffix_len - keep_trailing..].join(sep);
        let candidate = format!("{}{}{}{}", prefix, ellipsis, sep, trailing);
        if candidate.len() <= max_width {
            return candidate;
        }
    }

    let minimal = format!("{}{}{}{}", prefix, ellipsis, sep, filename);
    if minimal.len() <= max_width {
        return minimal;
    }

    path[..max_width].to_string()
}

/// Collapse $HOME to ~ in a path string.
fn collapse_home(path: &str) -> String {
    if let Some(home) = std::env::var_os("HOME") {
        let home_str = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home_str.as_ref()) {
            if rest.is_empty() || rest.starts_with('/') {
                return format!("~{}", rest);
            }
        }
    }
    path.to_string()
}

// ── Exit Code Description ──────────────────────────────────

/// Describe what an exit code means for self-documenting output.
pub fn exit_code_description(code: i32) -> &'static str {
    match code {
        0 => "no changes detected",
        1 => "changes found (low or medium severity)",
        2 => "high-severity changes found",
        3 => "critical changes found",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Color tests ────────────────────────────────────────

    fn tty_term() -> TermInfo {
        TermInfo {
            width: 120,
            height: 40,
            is_tty: true,
            supports_color: true,
        }
    }

    fn pipe_term() -> TermInfo {
        TermInfo {
            width: 80,
            height: 24,
            is_tty: false,
            supports_color: false,
        }
    }

    #[test]
    fn styled_emits_ansi_when_tty() {
        let term = tty_term();
        let s = Styled::new(&term);
        let result = s.paint(Style::Red, "alert");
        assert!(result.contains("\x1b[31m"));
        assert!(result.contains("\x1b[0m"));
        assert!(result.contains("alert"));
    }

    #[test]
    fn styled_no_ansi_when_piped() {
        let term = pipe_term();
        let s = Styled::new(&term);
        let result = s.paint(Style::Red, "alert");
        assert_eq!(result, "alert");
    }

    #[test]
    fn severity_style_mapping() {
        assert!(matches!(
            severity_style(&Severity::Critical),
            Style::BoldRed
        ));
        assert!(matches!(severity_style(&Severity::High), Style::BoldRed));
        assert!(matches!(severity_style(&Severity::Medium), Style::Yellow));
        assert!(matches!(severity_style(&Severity::Low), Style::Dim));
    }

    // ── Number formatting tests ────────────────────────────

    #[test]
    fn format_count_basic() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1,000");
        assert_eq!(format_count(1_234_567), "1,234,567");
    }

    #[test]
    fn format_size_basic() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1_048_576), "1.0 MB");
        assert_eq!(format_size(2_500_000), "2.4 MB");
    }

    #[test]
    fn format_age_intervals() {
        assert_eq!(format_age(30), "30s ago");
        assert_eq!(format_age(120), "2m ago");
        assert_eq!(format_age(3600), "1h ago");
        assert_eq!(format_age(7200 + 900), "2h 15m ago");
        assert_eq!(format_age(86400), "1 day ago");
        assert_eq!(format_age(172800), "2 days ago");
    }

    // ── Hash/fingerprint tests ─────────────────────────────

    #[test]
    fn truncate_hash_basic() {
        assert_eq!(
            truncate_hash("abcdef0123456789deadbeef"),
            "abcdef0123456789"
        );
        assert_eq!(truncate_hash("short"), "short");
    }

    #[test]
    fn format_fingerprint_basic() {
        assert_eq!(
            format_fingerprint("9c7ae3f182bd04a6deadbeef"),
            "9c7a·e3f1·82bd·04a6"
        );
    }

    #[test]
    fn format_fingerprint_short_input() {
        assert_eq!(format_fingerprint("abcd"), "abcd");
    }

    // ── Path truncation tests ──────────────────────────────

    #[test]
    fn truncate_path_short_unchanged() {
        assert_eq!(truncate_path("/etc/passwd", 80), "/etc/passwd");
    }

    #[test]
    fn truncate_path_long_gets_ellipsis() {
        let long = "/usr/share/some/deeply/nested/directory/structure/config.toml";
        let result = truncate_path(long, 40);
        assert!(result.len() <= 40, "got: {} (len {})", result, result.len());
        assert!(result.contains("…"));
        assert!(result.ends_with("config.toml"));
    }

    #[test]
    fn truncate_path_preserves_filename() {
        let path = "/home/user/.config/some/deeply/nested/path/to/file.conf";
        let result = truncate_path(path, 35);
        assert!(result.ends_with("file.conf"), "got: {}", result);
    }

    // ── Exit code description tests ────────────────────────

    #[test]
    fn exit_code_descriptions() {
        assert_eq!(exit_code_description(0), "no changes detected");
        assert_eq!(exit_code_description(3), "critical changes found");
    }
}
