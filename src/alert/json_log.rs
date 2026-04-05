use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use crate::alert::AlertSink;
use crate::error::{Result, VigilError};
use crate::types::{Alert, Severity};

pub struct JsonFileSink {
    file: Mutex<File>,
    path: PathBuf,
}

impl JsonFileSink {
    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                VigilError::Alert(format!("cannot open JSON log {}: {}", path.display(), e))
            })?;

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
        })
    }
}

impl AlertSink for JsonFileSink {
    fn name(&self) -> &str {
        "json_log"
    }

    fn dispatch(&self, alert: &Alert) -> Result<()> {
        let mut file = self.file.lock();
        let line = serde_json::to_string(alert)?;
        writeln!(file, "{}", line).map_err(|e| {
            VigilError::Alert(format!(
                "cannot write JSON log {}: {}",
                self.path.display(),
                e
            ))
        })?;
        Ok(())
    }

    fn min_severity(&self) -> Severity {
        Severity::Low
    }
}
