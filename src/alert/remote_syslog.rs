use std::io::Write;
use std::net::{TcpStream, UdpSocket};

use crate::alert::AlertSink;
use crate::config::RemoteSyslogConfig;
use crate::error::{Result, VigilError};
use crate::types::{Alert, Severity};

pub struct RemoteSyslogSink {
    addr: String,
    protocol: String,
    facility: String,
}

impl RemoteSyslogSink {
    pub fn new(cfg: &RemoteSyslogConfig) -> Result<Self> {
        if cfg.server.is_empty() {
            return Err(VigilError::Syslog("remote syslog server is empty".into()));
        }

        Ok(Self {
            addr: format!("{}:{}", cfg.server, cfg.port),
            protocol: cfg.protocol.to_lowercase(),
            facility: cfg.facility.clone(),
        })
    }

    fn format_rfc5424(&self, alert: &Alert) -> String {
        let pri = match alert.severity {
            Severity::Critical => 2,
            Severity::High => 3,
            Severity::Medium => 4,
            Severity::Low => 6,
        };
        let timestamp = alert.timestamp.to_rfc3339();
        let hostname = &alert.context.hostname;
        let app = "vigil";
        let procid = "-";
        let msgid = &alert.event_id;
        let structured = "-";
        let msg = format!(
            "path={} severity={} change={} group={} facility={}",
            alert.file.path.display(),
            alert.severity,
            alert.change_type,
            alert.context.monitored_group,
            self.facility
        );

        format!(
            "<{}>1 {} {} {} {} {} {} {}",
            pri, timestamp, hostname, app, procid, msgid, structured, msg
        )
    }
}

impl AlertSink for RemoteSyslogSink {
    fn name(&self) -> &str {
        "remote_syslog"
    }

    fn dispatch(&self, alert: &Alert) -> Result<()> {
        let msg = self.format_rfc5424(alert);

        match self.protocol.as_str() {
            "tcp" => {
                let mut stream = TcpStream::connect(&self.addr).map_err(|e| {
                    VigilError::Syslog(format!("TCP connect {} failed: {}", self.addr, e))
                })?;
                stream
                    .write_all(msg.as_bytes())
                    .map_err(|e| VigilError::Syslog(format!("TCP write failed: {}", e)))?;
            }
            _ => {
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .map_err(|e| VigilError::Syslog(format!("UDP bind failed: {}", e)))?;
                socket
                    .send_to(msg.as_bytes(), &self.addr)
                    .map_err(|e| VigilError::Syslog(format!("UDP send failed: {}", e)))?;
            }
        }

        Ok(())
    }

    fn min_severity(&self) -> Severity {
        Severity::Medium
    }
}
