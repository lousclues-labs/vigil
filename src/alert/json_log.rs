use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

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

        let mut writer = self.writer.lock();
        if let Err(e) = writeln!(writer, "{}", json) {
            log::error!("Cannot write to log file {}: {}", self.path.display(), e);
        }
    }

    /// Rotate the log file if it exceeds `max_size` bytes.
    /// Renames the current file with a timestamp suffix and opens a new file.
    pub fn rotate_if_needed(&self, max_size: u64) {
        // Check current file size
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size < max_size {
            return;
        }

        let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let rotated = self.path.with_extension(format!("json.{}", ts));

        let mut writer = self.writer.lock();
        if let Err(e) = std::fs::rename(&self.path, &rotated) {
            log::warn!("Failed to rotate log file: {}", e);
            return;
        }
        log::info!("Rotated log file to {}", rotated.display());

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(new_file) => *writer = new_file,
            Err(e) => log::error!("Failed to open new log file: {}", e),
        }
    }
}
