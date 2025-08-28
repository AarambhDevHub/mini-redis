//! In-memory storage implementation

use crate::Result;
use crate::protocol::{Command, Response};
use crate::storage::Persistence;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// In-memory key-value store
pub struct MemoryStore {
    data: HashMap<String, String>,
    persistence: Persistence,
    ops_count: u64,
}

impl MemoryStore {
    /// Create new memory store with persistence
    pub async fn new(persistence: Persistence) -> Result<Self> {
        let mut store = MemoryStore {
            data: HashMap::new(),
            persistence,
            ops_count: 0,
        };

        // Load existing data from persistence
        store.load_from_persistence().await?;

        Ok(store)
    }

    /// Execute a command against the store
    pub async fn execute(&mut self, command: Command) -> Result<Response> {
        debug!("Executing command: {:?}", command);

        let response = match &command {
            Command::Set { key, value } => {
                self.data.insert(key.clone(), value.clone());
                self.ops_count += 1;

                // Persist the operation
                self.persistence.log_operation(&command).await?;

                debug!("SET {} = {}", key, value);
                Response::Ok
            }

            Command::Get { key } => match self.data.get(key.as_str()) {
                Some(value) => {
                    debug!("GET {} = {}", key, value);
                    Response::Value(value.clone())
                }
                None => {
                    debug!("GET {} = (nil)", key);
                    Response::Nil
                }
            },

            Command::Del { key } => {
                let deleted = self.data.remove(key.as_str()).is_some();
                if deleted {
                    self.ops_count += 1;
                    self.persistence.log_operation(&command).await?;
                    debug!("DEL {} = 1", key);
                    Response::Integer(1)
                } else {
                    debug!("DEL {} = 0", key);
                    Response::Integer(0)
                }
            }

            Command::Ping => {
                debug!("PING");
                Response::Pong
            }

            Command::Info => {
                let info = format!(
                    "# Server\r\nredis_version:mini-redis-0.1.0\r\n# Keyspace\r\ndb0:keys={},expires=0\r\n# Stats\r\ntotal_operations:{}\r\nuptime_seconds:{}",
                    self.data.len(),
                    self.ops_count,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                );
                Response::Info(info)
            }
        };

        Ok(response)
    }

    /// Get number of keys in store
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Load data from persistence layer
    async fn load_from_persistence(&mut self) -> Result<()> {
        let operations = self.persistence.load_operations().await?;

        for op in operations {
            match op {
                Command::Set { key, value } => {
                    self.data.insert(key, value);
                    self.ops_count += 1;
                }
                Command::Del { key } => {
                    self.data.remove(&key);
                    self.ops_count += 1;
                }
                _ => {} // Ignore other commands during replay
            }
        }

        debug!("Loaded {} operations from persistence", self.ops_count);
        Ok(())
    }
}
