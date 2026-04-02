use std::io::Write;
use std::os::unix::net::UnixStream;

use parking_lot::Mutex;

use crate::error::Result;
use crate::types::ChangeResult;

/// Signal socket writer — sends one-line JSON events to a Unix domain socket.
/// If nobody is listening, events are silently dropped.
pub struct SignalSocket {
    path: String,
    stream: Mutex<Option<UnixStream>>,
}

impl SignalSocket {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            path: path.to_string(),
            stream: Mutex::new(None),
        })
    }

    /// Send a change event to the socket. Silently drops if no listener.
    pub fn send_event(&self, change: &ChangeResult) {
        let event = serde_json::json!({
            "event": change.change_types.first().map(|c| c.to_string()).unwrap_or_default(),
            "path": change.path.to_string_lossy(),
            "severity": change.severity.to_string(),
            "timestamp": chrono::Utc::now().timestamp(),
            "hash": change.new_hash,
        });

        let json = match serde_json::to_string(&event) {
            Ok(j) => j,
            Err(_) => return,
        };

        let mut stream_guard = self.stream.lock();
        // Try to write to existing stream, or connect
        let write_result = if let Some(ref mut stream) = *stream_guard {
            writeln!(stream, "{}", json)
        } else {
            // Try to connect
            match UnixStream::connect(&self.path) {
                Ok(mut s) => {
                    let result = writeln!(s, "{}", json);
                    *stream_guard = Some(s);
                    result
                }
                Err(_) => return, // No listener — silently drop
            }
        };

        // If write failed, clear the stream so we reconnect next time
        if write_result.is_err() {
            *stream_guard = None;
        }
    }
}
