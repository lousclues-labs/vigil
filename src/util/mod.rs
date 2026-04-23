//! Shared utilities: owned file descriptors, random bytes, and mount set diffs.

pub mod owned_fd;
pub mod random;

/// Return the correct singular or plural form based on count.
pub fn pluralize(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{} {}", n, singular)
    } else {
        format!("{} {}", n, plural)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pluralize_zero() {
        assert_eq!(pluralize(0, "warning", "warnings"), "0 warnings");
    }

    #[test]
    fn pluralize_one() {
        assert_eq!(pluralize(1, "warning", "warnings"), "1 warning");
    }

    #[test]
    fn pluralize_many() {
        assert_eq!(pluralize(2, "warning", "warnings"), "2 warnings");
        assert_eq!(pluralize(100, "entry", "entries"), "100 entries");
    }
}
