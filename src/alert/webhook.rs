//! Webhook alert sink -- HTTP POST to a configured URL.
//!
//! Bearer-token auth optional. Retry with exponential backoff on 5xx.
//! Opt-in via config; goes through coalescing and storm suppression.

use crate::error::{Result, VigilError};
use crate::types::Alert;

use super::AlertSink;

/// Maximum retry attempts for transient (5xx) failures.
const MAX_RETRIES: u32 = 3;

pub struct WebhookSink {
    url: String,
    bearer_token: Option<String>,
}

impl WebhookSink {
    pub fn new(url: String, bearer_token: Option<String>) -> Self {
        Self { url, bearer_token }
    }

    fn send_request(&self, body: &[u8]) -> std::result::Result<u16, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Parse URL for host:port (minimal HTTP client to avoid new deps).
        let url = &self.url;
        let (host, port, path) = parse_url(url).map_err(|e| format!("bad webhook URL: {}", e))?;

        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("webhook connect failed: {}", e))?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();

        let mut request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            path, host, body.len()
        );
        if let Some(ref token) = self.bearer_token {
            request.push_str(&format!("Authorization: Bearer {}\r\n", token));
        }
        request.push_str("Connection: close\r\n\r\n");

        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("webhook write failed: {}", e))?;
        stream
            .write_all(body)
            .map_err(|e| format!("webhook body write failed: {}", e))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("webhook read failed: {}", e))?;

        // Parse status code from first line.
        let response_str = String::from_utf8_lossy(&response);
        let status_line = response_str.lines().next().unwrap_or("");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        Ok(status)
    }
}

impl AlertSink for WebhookSink {
    fn name(&self) -> &str {
        "webhook"
    }

    fn dispatch(&self, alert: &Alert) -> Result<()> {
        let body = serde_json::to_vec(alert)
            .map_err(|e| VigilError::Alert(format!("webhook serialize failed: {}", e)))?;

        let mut last_err = String::new();
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * (1 << (attempt - 1)));
                std::thread::sleep(delay);
            }
            match self.send_request(&body) {
                Ok(status) if (200..300).contains(&status) => return Ok(()),
                Ok(status) if status >= 500 => {
                    last_err = format!("webhook returned {}", status);
                    tracing::warn!(
                        attempt = attempt + 1,
                        status,
                        "webhook 5xx response. retrying."
                    );
                }
                Ok(status) => {
                    return Err(VigilError::Alert(format!(
                        "webhook returned non-retryable status {}",
                        status
                    )));
                }
                Err(e) => {
                    last_err = e.clone();
                    tracing::warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "webhook request failed. retrying."
                    );
                }
            }
        }
        Err(VigilError::Alert(format!(
            "webhook gave up after {} retries: {}",
            MAX_RETRIES, last_err
        )))
    }

    fn min_severity(&self) -> crate::types::Severity {
        crate::types::Severity::Low
    }
}

fn parse_url(url: &str) -> std::result::Result<(String, u16, String), String> {
    let url = url
        .strip_prefix("http://")
        .ok_or("only http:// supported")?;
    let (host_port, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };
    let (host, port) = if let Some(pos) = host_port.find(':') {
        let h = &host_port[..pos];
        let p = host_port[pos + 1..]
            .parse::<u16>()
            .map_err(|_| "invalid port")?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), 80)
    };
    Ok((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_basic() {
        let (host, port, path) = parse_url("http://localhost:8080/webhook").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/webhook");
    }

    #[test]
    fn parse_url_default_port() {
        let (host, port, path) = parse_url("http://example.com/alerts").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/alerts");
    }
}
