use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::error::Result;
use crate::types::ChangeResult;

/// Maximum simultaneous socket connections.
const MAX_CONNECTIONS: usize = 10;
/// Per-write timeout for connected clients.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Signal socket writer — accepts connections on a Unix domain socket and
/// broadcasts one-line JSON events to all connected, authorized clients.
pub struct SignalSocket {
    clients: Arc<Mutex<Vec<UnixStream>>>,
    listener_path: String,
}

/// Get peer UID via SO_PEERCRED on a Unix stream socket.
fn get_peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: fd is a valid file descriptor from as_raw_fd(). cred is
    // a zeroed ucred struct with correct size. getsockopt with SO_PEERCRED
    // fills the struct from kernel data.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

impl SignalSocket {
    pub fn new(path: &str) -> Result<Self> {
        // Remove stale socket file if it exists
        let _ = std::fs::remove_file(path);

        let listener = UnixListener::bind(path).map_err(|e| {
            crate::error::VigilError::Alert(format!("cannot bind signal socket {}: {}", path, e))
        })?;

        // Set socket file permissions to 0600 (owner-only)
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            crate::error::VigilError::Alert(format!(
                "cannot set socket permissions on {}: {}",
                path, e
            ))
        })?;

        // Set listener to non-blocking for accept loop
        listener.set_nonblocking(true).map_err(|e| {
            crate::error::VigilError::Alert(format!("cannot set non-blocking on socket: {}", e))
        })?;

        let listener_path = path.to_string();
        let clients: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
        let clients_for_acceptor = clients.clone();
        let daemon_uid = nix::unistd::getuid().as_raw();

        std::thread::Builder::new()
            .name("vigil-socket".into())
            .spawn(move || {
                loop {
                    match listener.accept() {
                        Ok((stream, _addr)) => {
                            // Verify peer credentials via SO_PEERCRED
                            match get_peer_uid(&stream) {
                                Ok(uid) => {
                                    if uid != 0 && uid != daemon_uid {
                                        log::warn!(
                                            "Rejecting socket connection from UID {}",
                                            uid
                                        );
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    log::warn!(
                                        "Cannot get peer credentials, rejecting: {}",
                                        e
                                    );
                                    continue;
                                }
                            }

                            let mut clients_guard = clients_for_acceptor.lock();
                            if clients_guard.len() >= MAX_CONNECTIONS {
                                log::warn!(
                                    "Maximum socket connections ({}) reached, rejecting new connection",
                                    MAX_CONNECTIONS
                                );
                                continue;
                            }

                            // Set write timeout on the client stream
                            let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                            clients_guard.push(stream);
                            log::debug!(
                                "Signal socket client connected ({} total)",
                                clients_guard.len()
                            );
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                        Err(e) => {
                            log::debug!("Socket accept error: {}", e);
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }
                    }
                }
            })
            .map_err(|e| {
                crate::error::VigilError::Alert(format!(
                    "cannot spawn socket acceptor thread: {}",
                    e
                ))
            })?;

        Ok(Self {
            clients,
            listener_path,
        })
    }

    /// Send a change event to all connected clients.
    /// Disconnects clients that fail to write within the timeout.
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

        let mut clients = self.clients.lock();

        // Write to all connected clients, removing failed ones
        clients.retain_mut(|stream| match writeln!(stream, "{}", json) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("Disconnecting slow/failed socket client: {}", e);
                false
            }
        });
    }
}

impl Drop for SignalSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.listener_path);
    }
}
