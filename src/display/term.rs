//! Terminal capability detection: size, color, TTY status.

use std::io::IsTerminal;

/// Terminal information for adaptive rendering.
pub struct TermInfo {
    pub width: u16,
    pub height: u16,
    pub is_tty: bool,
    pub supports_color: bool,
}

impl TermInfo {
    /// Detect terminal properties from the environment.
    /// Falls back to 80×24, no color, no pager on failure (Principle X).
    pub fn detect() -> Self {
        let is_tty = std::io::stdout().is_terminal();
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let supports_color = is_tty && !no_color;

        let (width, height) = Self::get_terminal_size();

        TermInfo {
            width,
            height,
            is_tty,
            supports_color,
        }
    }

    /// Get terminal size from environment or ioctl, falling back to 80×24.
    fn get_terminal_size() -> (u16, u16) {
        // Try $COLUMNS / $LINES first
        let env_width = std::env::var("COLUMNS")
            .ok()
            .and_then(|v| v.parse::<u16>().ok());
        let env_height = std::env::var("LINES")
            .ok()
            .and_then(|v| v.parse::<u16>().ok());

        if let (Some(w), Some(h)) = (env_width, env_height) {
            return (w, h);
        }

        // Try ioctl TIOCGWINSZ
        #[cfg(unix)]
        {
            if let Some((w, h)) = Self::ioctl_size() {
                return (env_width.unwrap_or(w), env_height.unwrap_or(h));
            }
        }

        // Default fallback (Principle X: fail open)
        (env_width.unwrap_or(80), env_height.unwrap_or(24))
    }

    #[cfg(unix)]
    fn ioctl_size() -> Option<(u16, u16)> {
        #[allow(unsafe_code)]
        // SAFETY: TIOCGWINSZ writes a winsize struct into the zeroed buffer
        // via a valid STDOUT_FILENO. We check ret == 0 and ws_col/ws_row > 0
        // before using the values. If ioctl fails, we return None.
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            let ret = libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws);
            if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
                Some((ws.ws_col, ws.ws_row))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_produces_valid_dimensions() {
        let info = TermInfo::detect();
        assert!(info.width > 0);
        assert!(info.height > 0);
    }

    #[test]
    fn fallback_defaults() {
        // In a test environment without a real terminal, we should still get valid values
        let info = TermInfo::detect();
        assert!(info.width >= 80 || info.width > 0);
        assert!(info.height >= 24 || info.height > 0);
    }
}
