use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Result, VigilError};
use crate::types::Alert;

/// Append-only JSON log writer for alert events.
pub struct JsonLogger {
    path: PathBuf,
    writer: Mutex<File>,
}

impl JsonLogger {
    pub fn new(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                VigilError::Alert(format!(
                    "cannot create log directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                VigilError::Alert(format!("cannot open log file {}: {}", path.display(), e))
            })?;

        Ok(Self {
            path: path.to_path_buf(),
            writer: Mutex::new(file),
        })
    }

    /// Write an alert as a single-line JSON entry.
    pub fn write(&self, alert: &Alert) {
        let json = match serde_json::to_string(alert) {
            Ok(j) => j,
            Err(e) => {
                log::error!("Cannot serialize alert to JSON: {}", e);
                return;
            }
        };

        if let Ok(mut writer) = self.writer.lock() {
            if let Err(e) = writeln!(writer, "{}", json) {
                log::error!("Cannot write to log file {}: {}", self.path.display(), e);
            }
        }
    }
}
