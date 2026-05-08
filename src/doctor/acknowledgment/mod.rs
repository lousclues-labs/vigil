//! Acknowledgment submodule re-exports.

pub mod note;
pub mod types;

pub use note::{sanitize_for_display, validate_operator_note, MAX_NOTE_LEN};
pub use types::*;
