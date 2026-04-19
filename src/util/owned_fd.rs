//! RAII guard for raw file descriptors.
//!
//! Closes the fd on drop. Supports take() to transfer ownership
//! (sets the internal fd to -1 so drop is a no-op).

/// Owned raw file descriptor that closes on drop.
pub struct OwnedRawFd(pub(crate) i32);

impl OwnedRawFd {
    /// Take ownership of the fd, preventing the guard from closing it.
    pub fn take(&mut self) -> i32 {
        let fd = self.0;
        self.0 = -1;
        fd
    }
}

impl Drop for OwnedRawFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: fd is owned by this guard and has not been transferred
            // via take(). The >= 0 check prevents double-close after take()
            // sets it to -1.
            #[allow(unsafe_code)]
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn take_returns_fd_and_prevents_close() {
        // Open /dev/null to get a real fd.
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0);
        let mut guard = OwnedRawFd(fd);
        let taken = guard.take();
        assert_eq!(taken, fd);
        assert_eq!(guard.0, -1);
        // Clean up manually since take() prevents drop from closing.
        unsafe {
            libc::close(taken);
        }
    }
}
