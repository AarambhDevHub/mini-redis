//! Mini Redis - A simple key-value database implementation in Rust
//!
//! This crate provides a Redis-like key-value database with:
//! - In-memory storage with persistence
//! - TCP server for client connections
//! - Basic commands: SET, GET, DEL
//! - Append-only log for durability

pub mod client;
pub mod protocol;
pub mod server;
pub mod storage;

pub use client::TcpClient;
pub use protocol::{Command, Parser};
pub use server::TcpServer;
pub use storage::{MemoryStore, Persistence};

/// Result type for mini-redis operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for mini-redis
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Connection error: {0}")]
    Connection(String),
}
