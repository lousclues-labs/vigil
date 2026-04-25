//! Time formatting helpers for CLI output.

use chrono::{Local, TimeZone, Utc};

/// Format a duration in seconds as a compact string like "3d 14h" or "1h 30m".
pub fn format_compact_duration(seconds: i64) -> String {
    let s = seconds.max(0);
    let days = s / 86_400;
    let hours = (s % 86_400) / 3_600;
    let mins = (s % 3_600) / 60;

    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

/// Render timestamps as "HH:MM today", "HH:MM yesterday", or ISO-like date.
pub fn format_relative_timestamp(ts: i64) -> String {
    let Some(dt) = Local.timestamp_opt(ts, 0).single() else {
        return "unknown".to_string();
    };
    let now = Local::now();
    let today = now.date_naive();
    let yesterday = (now - chrono::Duration::days(1)).date_naive();

    if dt.date_naive() == today {
        format!("{} today", dt.format("%H:%M"))
    } else if dt.date_naive() == yesterday {
        format!("{} yesterday", dt.format("%H:%M"))
    } else {
        dt.format("%Y-%m-%d %H:%M").to_string()
    }
}

/// Format a past duration in seconds as a human-readable relative label.
pub fn format_age(age_secs: i64) -> String {
    let secs = age_secs.max(0);
    let days = secs / 86_400;
    if days > 0 {
        return format!("{}d ago", days);
    }

    let hours = secs / 3_600;
    if hours > 0 {
        return format!("{}h ago", hours);
    }

    let mins = secs / 60;
    if mins > 0 {
        return format!("{}m ago", mins);
    }

    "just now".to_string()
}

/// Parse systemd timer timestamp and return a relative duration like "in 1h 34m".
pub fn format_next_timer_relative(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "n/a" {
        return "unknown".to_string();
    }

    // systemd emits "Day YYYY-MM-DD HH:MM:SS TZ" or similar.
    // Try to parse something with chrono.
    let now = Local::now();
    // Try common systemd formats
    for fmt in [
        "%a %Y-%m-%d %H:%M:%S %Z",
        "%Y-%m-%d %H:%M:%S %Z",
        "%a %Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(trimmed.trim_end(), fmt) {
            let target = Local.from_local_datetime(&parsed).earliest();
            if let Some(target) = target {
                let delta = target.signed_duration_since(now).num_seconds();
                if delta <= 0 {
                    return "overdue".to_string();
                }
                return format!("in {}", format_compact_duration(delta));
            }
        }
    }

    // Fallback: try to extract just HH:MM and compute duration to next occurrence
    let shortened = shorten_next_timer(raw);
    if shortened.contains(':') && shortened.len() == 5 {
        if let (Ok(h), Ok(m)) = (shortened[..2].parse::<u32>(), shortened[3..].parse::<u32>()) {
            let today = now.date_naive();
            if let Some(target_time) = today.and_hms_opt(h, m, 0) {
                let target = Local.from_local_datetime(&target_time).earliest();
                if let Some(target) = target {
                    let mut delta = target.signed_duration_since(now).num_seconds();
                    if delta <= 0 {
                        // Next day
                        delta += 86_400;
                    }
                    return format!("in {}", format_compact_duration(delta));
                }
            }
        }
    }

    shortened
}

/// Format a past Unix timestamp as a relative duration like "30m ago".
pub fn format_relative_duration_from_timestamp(ts: i64) -> String {
    let now = Utc::now().timestamp();
    let delta = (now - ts).max(0);
    if delta == 0 {
        return "just now".to_string();
    }
    format!("{} ago", format_compact_duration(delta))
}

/// Extract HH:MM from a systemd timer timestamp string.
pub fn shorten_next_timer(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "n/a" {
        return "unknown".to_string();
    }

    if let Some(time_part) = trimmed.split_whitespace().nth(2) {
        let hhmm = time_part.chars().take(5).collect::<String>();
        if hhmm.len() == 5 && hhmm.contains(':') {
            return hhmm;
        }
    }

    trimmed.to_string()
}
