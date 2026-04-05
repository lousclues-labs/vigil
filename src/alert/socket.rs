use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::alert::AlertSink;
use crate::error::Result;
use crate::types::{Alert, Severity};

pub struct SocketSink {
    socket_path: PathBuf,
}

impl SocketSink {
    pub fn new(path: &str) -> Self {
        Self {
            socket_path: PathBuf::from(path),
        }
    }
}

impl AlertSink for SocketSink {
    fn name(&self) -> &str {
        "socket"
    }

    fn dispatch(&self, alert: &Alert) -> Result<()> {
        if self.socket_path.as_os_str().is_empty() {
            return Ok(());
        }

        match UnixStream::connect(&self.socket_path) {
            Ok(mut stream) => {
                let payload = serde_json::to_vec(alert)?;
                if let Err(e) = stream.write_all(&payload) {
                    tracing::warn!(error = %e, path = %self.socket_path.display(), "socket sink write failed");
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, path = %self.socket_path.display(), "socket sink connect failed");
            }
        }

        Ok(())
    }

    fn min_severity(&self) -> Severity {
        Severity::Low
    }
}
