//! Operator-note validation and display sanitization.
//!
//! Operator notes are free-text annotations attached to acknowledgment
//! records. They are part of the audit chain (HMAC-bound to a sequence
//! number) and survive across exports, alert sinks, and backups.
//!
//! Two responsibilities, kept distinct:
//!
//! 1. [`validate_operator_note`] runs at the CLI boundary. It enforces
//!    the byte-length cap and rejects oversize input with a clear
//!    error. It does not modify the input. The exact bytes the
//!    operator typed are what get stored and HMAC-bound (Principle
//!    XIII: the audit trail records what actually happened).
//!
//! 2. [`sanitize_for_display`] runs at every render path (doctor,
//!    audit listing, ack confirmation, JSON-for-humans output). It
//!    replaces control characters, ANSI escape sequences, and bidi
//!    override codepoints with visible escape forms so a malicious
//!    note cannot rewrite the operator's terminal, spoof additional
//!    log lines, or visually reorder text. The stored bytes are
//!    untouched.
//!
//! Storing raw bytes and rendering safely is the same pattern git
//! uses for commit messages and the same pattern vigil uses for
//! filesystem paths: preserve truth, render with care.

/// Maximum byte length for an operator note. Notes longer than this
/// are rejected at the CLI boundary with an explicit error.
///
/// 1024 bytes is enough for a multi-sentence justification (e.g.
/// `"vapoursynth 75-2 rewrote vspipe as Python shim; pacman -Qkk
/// clean; reviewed 2026-05-08"`) and small enough that a malicious
/// privileged operator cannot pad the audit DB with megabyte notes.
pub const MAX_NOTE_LEN: usize = 1024;

/// Validate an optional operator note at the CLI boundary.
///
/// Returns the input unchanged on success. Returns a
/// `VigilError::Config` with a clear message if the note exceeds
/// [`MAX_NOTE_LEN`] bytes. Empty notes are rejected because clap
/// already filters those before reaching us; an explicit empty
/// `--note ""` is treated as no note.
pub fn validate_operator_note(note: Option<String>) -> crate::Result<Option<String>> {
    match note {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) if s.len() > MAX_NOTE_LEN => Err(crate::VigilError::Config(format!(
            "operator note too long: {} bytes (max {}). shorten the note or split context across multiple acknowledgments",
            s.len(),
            MAX_NOTE_LEN
        ))),
        Some(s) => Ok(Some(s)),
    }
}

/// Sanitize an operator note for terminal display.
///
/// Replaces three classes of dangerous bytes with visible escape
/// forms. The transformation is deterministic and idempotent on the
/// safe subset (printable ASCII, common Unicode letters/marks, simple
/// punctuation).
///
/// 1. C0 control bytes (`\x00..=\x1f`) and `DEL` (`\x7f`): rendered as
///    `\xNN` hex escapes. Newlines, carriage returns, and tabs are
///    included in this class because a note rendered inline on a
///    doctor row must not break the row layout, and a note piped to
///    journald must not introduce fake log lines via `\r\n<level>`.
/// 2. C1 control bytes (`\x80..=\x9f`): same treatment.
/// 3. Unicode bidi-override codepoints (the Trojan Source class):
///    `U+202A..=U+202E`, `U+2066..=U+2069`. Rendered as `\u{NNNN}`.
///
/// Other Unicode codepoints, including emoji, CJK, accented letters,
/// and ZWJ sequences, pass through unchanged. The goal is to neutralize
/// known terminal-rewriting and visual-reordering attacks, not to
/// flatten the operator's voice.
///
/// The output is always valid UTF-8 and contains only printable
/// codepoints plus space. Maximum expansion is ~6x (`\u{202E}` -> 8
/// chars for one codepoint), bounded because the input is bounded by
/// [`MAX_NOTE_LEN`].
pub fn sanitize_for_display(note: &str) -> String {
    let mut out = String::with_capacity(note.len());
    for c in note.chars() {
        match c {
            // C0 controls + DEL: always escape, including \n \r \t.
            '\x00'..='\x1f' | '\x7f' => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            // C1 controls.
            '\u{0080}'..='\u{009f}' => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            // Bidi overrides and isolates (Trojan Source).
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_passes_through_typical_note() {
        let n = "vapoursynth 75-2 shim; pacman -Qkk clean".to_string();
        let out = validate_operator_note(Some(n.clone())).unwrap();
        assert_eq!(out, Some(n));
    }

    #[test]
    fn validate_treats_none_and_empty_as_none() {
        assert_eq!(validate_operator_note(None).unwrap(), None);
        assert_eq!(validate_operator_note(Some(String::new())).unwrap(), None);
    }

    #[test]
    fn validate_rejects_oversize_note() {
        let big = "x".repeat(MAX_NOTE_LEN + 1);
        let err = validate_operator_note(Some(big)).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("too long"), "msg was: {}", msg);
        assert!(msg.contains(&MAX_NOTE_LEN.to_string()));
    }

    #[test]
    fn validate_accepts_exactly_max_len() {
        let exact = "x".repeat(MAX_NOTE_LEN);
        assert!(validate_operator_note(Some(exact)).is_ok());
    }

    #[test]
    fn sanitize_passthrough_printable_ascii() {
        let s = "package upgrade; ticket #1234 reviewed 2026-05-08";
        assert_eq!(sanitize_for_display(s), s);
    }

    #[test]
    fn sanitize_passthrough_unicode() {
        let s = "verified — ✓ — package signed by Łukasz";
        assert_eq!(sanitize_for_display(s), s);
    }

    #[test]
    fn sanitize_escapes_ansi_csi() {
        // \x1b[31mEVIL\x1b[0m -- attempts to color subsequent output red
        let s = "\x1b[31mEVIL\x1b[0m";
        let out = sanitize_for_display(s);
        assert!(!out.contains('\x1b'));
        assert!(out.contains("\\x1b"));
        assert!(out.contains("EVIL"));
    }

    #[test]
    fn sanitize_escapes_osc_window_title() {
        // \x1b]0;rm -rf ~\x07 -- attempts to set window title to a fake command
        let s = "\x1b]0;rm -rf ~\x07";
        let out = sanitize_for_display(s);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains("\\x1b"));
        assert!(out.contains("\\x07"));
    }

    #[test]
    fn sanitize_escapes_newlines_and_cr() {
        // \r\nCRITICAL: -- attempts to spoof a fake log line
        let s = "ok\r\nCRITICAL: spoofed";
        let out = sanitize_for_display(s);
        assert!(!out.contains('\r'));
        assert!(!out.contains('\n'));
        assert!(out.contains("\\x0d"));
        assert!(out.contains("\\x0a"));
    }

    #[test]
    fn sanitize_escapes_nul() {
        let s = "before\0after";
        let out = sanitize_for_display(s);
        assert!(!out.contains('\0'));
        assert!(out.contains("\\x00"));
    }

    #[test]
    fn sanitize_escapes_tab() {
        let s = "a\tb";
        let out = sanitize_for_display(s);
        assert_eq!(out, "a\\x09b");
    }

    #[test]
    fn sanitize_escapes_del() {
        let s = "x\x7fy";
        let out = sanitize_for_display(s);
        assert_eq!(out, "x\\x7fy");
    }

    #[test]
    fn sanitize_escapes_c1_controls() {
        // U+0085 NEL is treated as a line separator on some terminals.
        let s = "a\u{0085}b";
        let out = sanitize_for_display(s);
        assert!(!out.contains('\u{0085}'));
        assert!(out.contains("\\x85"));
    }

    #[test]
    fn sanitize_escapes_bidi_override() {
        // Trojan Source: U+202E RIGHT-TO-LEFT OVERRIDE flips display order.
        let s = "good\u{202e}live";
        let out = sanitize_for_display(s);
        assert!(!out.contains('\u{202e}'));
        assert!(out.contains("\\u{202e}"));
    }

    #[test]
    fn sanitize_escapes_bidi_isolate() {
        // U+2066 LEFT-TO-RIGHT ISOLATE — also part of Trojan Source class.
        let s = "x\u{2066}y\u{2069}z";
        let out = sanitize_for_display(s);
        assert!(out.contains("\\u{2066}"));
        assert!(out.contains("\\u{2069}"));
        assert!(!out.contains('\u{2066}'));
        assert!(!out.contains('\u{2069}'));
    }

    #[test]
    fn sanitize_is_idempotent_on_safe_input() {
        let safe = "no escapes here";
        assert_eq!(sanitize_for_display(&sanitize_for_display(safe)), safe);
    }

    #[test]
    fn sanitize_output_contains_no_control_chars() {
        // Property: sanitized output must never contain a control codepoint.
        let inputs = [
            "\x00\x01\x02\x07\x08\x09\x0a\x0b\x0c\x0d\x1b\x7f",
            "mixed \x1b[31m red \x07 bell",
            "\u{202e}\u{202d}\u{2066}\u{2069}",
        ];
        for s in inputs {
            let out = sanitize_for_display(s);
            for c in out.chars() {
                assert!(
                    !c.is_control(),
                    "sanitize produced control char {:?} from input {:?}",
                    c,
                    s
                );
            }
        }
    }

    #[test]
    fn sanitize_preserves_zwj_emoji() {
        // ZWJ sequences are not in the bidi-override class. The family
        // emoji should pass through. Tests guard against future
        // overzealous filtering.
        let s = "🧑‍🚀 reviewed";
        assert_eq!(sanitize_for_display(s), s);
    }
}
