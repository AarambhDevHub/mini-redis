//! Persistence layer using append-only log

use crate::protocol::Command;
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions, create_dir_all};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info};

/// Persistence manager for append-only logging
pub struct Persistence {
    log_file: File,
    log_path: PathBuf,
}

impl Persistence {
    /// Create new persistence manager
    pub async fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let data_dir = data_dir.as_ref();
        create_dir_all(data_dir).await?;

        let log_path = data_dir.join("mini-redis.log");
        debug!("Opening log file: {:?}", log_path);

        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await?;

        info!("Persistence initialized: {:?}", log_path);

        Ok(Persistence { log_file, log_path })
    }

    /// Log an operation to the append-only log
    pub async fn log_operation(&mut self, command: &Command) -> Result<()> {
        // Only log operations that modify data
        match command {
            Command::Set { .. } | Command::Del { .. } => {
                let serialized = serde_json::to_string(command)
                    .map_err(|e| Error::Storage(format!("Serialization error: {}", e)))?;

                self.log_file.write_all(serialized.as_bytes()).await?;
                self.log_file.write_all(b"\n").await?;
                self.log_file.flush().await?;

                debug!("Logged operation: {}", command.name());
            }
            _ => {} // Don't log read operations
        }

        Ok(())
    }

    /// Load all operations from the log file
    pub async fn load_operations(&self) -> Result<Vec<Command>> {
        let file = File::open(&self.log_path).await;

        let file = match file {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!("Log file not found, starting fresh");
                return Ok(Vec::new());
            }
            Err(e) => return Err(Error::Io(e)),
        };

        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut operations = Vec::new();
        let mut line_num = 0;

        while let Some(line) = lines.next_line().await? {
            line_num += 1;

            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<Command>(&line) {
                Ok(command) => operations.push(command),
                Err(e) => {
                    error!("Failed to parse line {}: {} ({})", line_num, e, line);
                    // Continue loading other operations
                }
            }
        }

        info!("Loaded {} operations from log", operations.len());
        Ok(operations)
    }

    /// Compact the log file (remove redundant operations)
    pub async fn compact(&mut self) -> Result<()> {
        // This is a simplified compaction - in a real system you'd want
        // to be more sophisticated about this
        info!("Log compaction not implemented yet");
        Ok(())
    }
}
