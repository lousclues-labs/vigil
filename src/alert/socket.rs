//! Unix domain socket alert sink for external consumers.

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
                let mut payload = serde_json::to_vec(alert)?;
                payload.push(b'\n');
                if let Err(e) = stream.write_all(&payload) {
                    tracing::warn!(error = %e, path = %self.socket_path.display(), "socket sink write failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %self.socket_path.display(), "socket sink connect failed");
            }
        }

        Ok(())
    }

    fn min_severity(&self) -> Severity {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    #[test]
    fn socket_message_has_newline_delimiter() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = UnixListener::bind(&sock_path).unwrap();
        let sink = SocketSink::new(sock_path.to_str().unwrap());

        let alert = Alert {
            version: 2,
            timestamp: chrono::Utc::now(),
            event_id: "test-id".into(),
            severity: crate::types::Severity::High,
            change_type: "created".into(),
            file: crate::types::AlertFileInfo {
                path: std::path::PathBuf::from("/tmp/test"),
                changes_json: "[]".into(),
                package: None,
                package_update: false,
                responsible_pid: None,
                responsible_exe: None,
            },
            context: crate::types::AlertContext {
                hostname: "test".into(),
                monitored_group: "test".into(),
                maintenance_window: false,
            },
        };

        sink.dispatch(&alert).unwrap();

        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).unwrap();

        // Must end with newline (NDJSON format)
        assert!(
            buf.last() == Some(&b'\n'),
            "socket message must end with newline"
        );

        // Stripping the newline should give valid JSON
        let json_part = &buf[..buf.len() - 1];
        let parsed: serde_json::Value = serde_json::from_slice(json_part).unwrap();
        assert_eq!(parsed["event_id"], "test-id");
    }
}
