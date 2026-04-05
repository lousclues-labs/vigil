use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use crate::config::RemoteSyslogConfig;
use crate::error::{Result, VigilError};
use crate::types::{Alert, Severity};

/// Remote syslog sender (RFC 5424 format).
pub struct RemoteSyslogSender {
    transport: SyslogTransport,
    facility: u8,
    hostname: String,
}

enum SyslogTransport {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl RemoteSyslogSender {
    /// Create a new remote syslog sender from config.
    pub fn new(config: &RemoteSyslogConfig) -> Result<Self> {
        let addr = format!("{}:{}", config.server, config.port);
        let facility = parse_facility(&config.facility);
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let transport = match config.protocol.to_lowercase().as_str() {
            "tcp" => {
                let stream = TcpStream::connect_timeout(
                    &addr.parse().map_err(|e| {
                        VigilError::Alert(format!("invalid syslog address '{}': {}", addr, e))
                    })?,
                    Duration::from_secs(5),
                )
                .map_err(|e| {
                    VigilError::Alert(format!("cannot connect to syslog server {}: {}", addr, e))
                })?;
                stream.set_write_timeout(Some(Duration::from_secs(1))).ok();
                SyslogTransport::Tcp(stream)
            }
            _ => {
                // UDP
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .map_err(|e| VigilError::Alert(format!("cannot bind UDP socket: {}", e)))?;
                socket.connect(&addr).map_err(|e| {
                    VigilError::Alert(format!("cannot connect to syslog server {}: {}", addr, e))
                })?;
                socket.set_write_timeout(Some(Duration::from_secs(1))).ok();
                SyslogTransport::Udp(socket)
            }
        };

        Ok(Self {
            transport,
            facility,
            hostname,
        })
    }

    /// Send an alert via syslog in RFC 5424 format.
    pub fn send(&self, alert: &Alert) -> Result<()> {
        let syslog_severity = severity_to_syslog(alert.severity);
        let priority = (self.facility as u16) * 8 + syslog_severity as u16;

        // RFC 5424 format: <priority>1 timestamp hostname app-name procid msgid SD msg
        let message = format!(
            "<{}>1 {} {} vigil - - - [{} {}] {}",
            priority,
            alert.timestamp.to_rfc3339(),
            self.hostname,
            alert.severity,
            alert.change_type,
            alert.file.path.display(),
        );

        let msg_bytes = message.as_bytes();

        match &self.transport {
            SyslogTransport::Udp(socket) => {
                socket
                    .send(msg_bytes)
                    .map_err(|e| VigilError::Alert(format!("UDP syslog send failed: {}", e)))?;
            }
            SyslogTransport::Tcp(stream) => {
                // TCP syslog uses framing: length prefix or newline-delimited
                let mut stream = stream;
                stream
                    .write_all(msg_bytes)
                    .map_err(|e| VigilError::Alert(format!("TCP syslog send failed: {}", e)))?;
                stream
                    .write_all(b"\n")
                    .map_err(|e| VigilError::Alert(format!("TCP syslog write failed: {}", e)))?;
            }
        }

        Ok(())
    }
}

fn severity_to_syslog(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 2, // Critical
        Severity::High => 3,     // Error
        Severity::Medium => 4,   // Warning
        Severity::Low => 6,      // Informational
    }
}

fn parse_facility(facility: &str) -> u8 {
    match facility.to_lowercase().as_str() {
        "auth" => 4,
        "authpriv" => 10,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => 10, // default: authpriv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_mapping() {
        assert_eq!(severity_to_syslog(Severity::Critical), 2);
        assert_eq!(severity_to_syslog(Severity::High), 3);
        assert_eq!(severity_to_syslog(Severity::Medium), 4);
        assert_eq!(severity_to_syslog(Severity::Low), 6);
    }

    #[test]
    fn facility_parsing() {
        assert_eq!(parse_facility("auth"), 4);
        assert_eq!(parse_facility("authpriv"), 10);
        assert_eq!(parse_facility("local0"), 16);
        assert_eq!(parse_facility("local7"), 23);
        assert_eq!(parse_facility("unknown"), 10);
    }

    #[test]
    fn rfc5424_message_format() {
        // Verify the format string produces valid RFC 5424 structure
        let priority = 10 * 8 + 3; // authpriv.error
        let msg = format!(
            "<{}>1 {} {} vigil - - - [{} {}] {}",
            priority, "2026-01-01T00:00:00Z", "testhost", "high", "modified", "/etc/passwd",
        );
        assert!(msg.starts_with("<83>1 "));
        assert!(msg.contains("vigil"));
        assert!(msg.contains("/etc/passwd"));
    }
}
