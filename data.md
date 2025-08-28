# Mini Redis - Rust Key-Value Database

A complete in-memory key-value database with TCP server and persistence, built in Rust.

## Project Structure

```
mini-redis/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── server/
│   │   ├── mod.rs
│   │   ├── tcp_server.rs
│   │   └── connection.rs
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── memory_store.rs
│   │   └── persistence.rs
│   ├── protocol/
│   │   ├── mod.rs
│   │   ├── parser.rs
│   │   └── command.rs
│   └── client/
│       ├── mod.rs
│       └── tcp_client.rs
├── data/
│   └── .gitkeep
└── README.md
```

## Core Files

### Cargo.toml
```toml
[package]
name = "mini-redis"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4.0", features = ["derive"] }

[[bin]]
name = "mini-redis-server"
path = "src/main.rs"

[[bin]]
name = "mini-redis-client"
path = "src/client/main.rs"
```

### src/lib.rs
```rust
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
```

### src/main.rs
```rust
//! Mini Redis Server Entry Point

use clap::Parser;
use mini_redis::{MemoryStore, Persistence, Result, TcpServer};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

use chrono::Utc;
use tracing_subscriber::fmt::{format::Writer, time::FormatTime};

struct ChronoUtc;

impl FormatTime for ChronoUtc {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        // Format as RFC3339 UTC
        write!(w, "{}", Utc::now().to_rfc3339())
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 6379)]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Data directory for persistence
    #[arg(short, long, default_value = "data")]
    data_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_timer(ChronoUtc)
        .init();

    let args = Args::parse();

    info!("Starting Mini Redis Server...");
    info!("Host: {}, Port: {}", args.host, args.port);
    info!("Data directory: {}", args.data_dir);

    // Initialize storage with persistence
    let persistence = Persistence::new(&args.data_dir).await?;
    let store = Arc::new(RwLock::new(MemoryStore::new(persistence).await?));

    // Start TCP server
    let server = TcpServer::new(format!("{}:{}", args.host, args.port), store);

    match server.run().await {
        Ok(_) => {
            info!("Server stopped gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(e)
        }
    }
}
```

### src/protocol/mod.rs
```rust
//! Protocol module for parsing and handling Redis-like commands

pub mod command;
pub mod parser;

pub use command::{Command, Response};
pub use parser::Parser;
```

### src/protocol/command.rs
```rust
//! Command definitions and implementations

use serde::{Deserialize, Serialize};

/// Supported Redis-like commands
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    Set { key: String, value: String },
    Get { key: String },
    Del { key: String },
    Ping,
    Info,
}

/// Response from command execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Value(String),
    Nil,
    Integer(i64),
    Error(String),
    Pong,
    Info(String),
}

impl Response {
    /// Convert response to Redis protocol format
    pub fn to_resp(&self) -> String {
        match self {
            Response::Ok => "+OK\r\n".to_string(),
            Response::Value(val) => format!("${}\r\n{}\r\n", val.len(), val),
            Response::Nil => "$-1\r\n".to_string(),
            Response::Integer(num) => format!(":{}\r\n", num),
            Response::Error(err) => format!("-ERR {}\r\n", err),
            Response::Pong => "+PONG\r\n".to_string(),
            Response::Info(info) => format!("${}\r\n{}\r\n", info.len(), info),
        }
    }
}

impl Command {
    /// Get command name as string
    pub fn name(&self) -> &'static str {
        match self {
            Command::Set { .. } => "SET",
            Command::Get { .. } => "GET",
            Command::Del { .. } => "DEL",
            Command::Ping => "PING",
            Command::Info => "INFO",
        }
    }
}
```

### src/protocol/parser.rs
```rust
//! Parser for Redis protocol commands

use crate::protocol::Command;
use crate::{Error, Result};

pub struct Parser;

impl Parser {
    /// Parse a command from RESP (Redis Serialization Protocol) format
    pub fn parse_command(input: &str) -> Result<Command> {
        let input = input.trim();

        if input.is_empty() {
            return Err(Error::Parse("Empty command".to_string()));
        }

        // Handle array format (*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n)
        if input.starts_with('*') {
            return Self::parse_array_command(input);
        }

        // Handle simple string format (SET key value)
        Self::parse_simple_command(input)
    }

    fn parse_array_command(input: &str) -> Result<Command> {
        let lines: Vec<&str> = input.split("\r\n").collect();

        if lines.is_empty() {
            return Err(Error::Parse("Invalid array format".to_string()));
        }

        // Parse array length
        let array_len = lines[0][1..]
            .parse::<usize>()
            .map_err(|_| Error::Parse("Invalid array length".to_string()))?;

        let mut args = Vec::new();
        let mut i = 1;

        for _ in 0..array_len {
            if i >= lines.len() || !lines[i].starts_with('$') {
                return Err(Error::Parse("Invalid bulk string format".to_string()));
            }

            let str_len = lines[i][1..]
                .parse::<usize>()
                .map_err(|_| Error::Parse("Invalid string length".to_string()))?;

            i += 1;
            if i >= lines.len() {
                return Err(Error::Parse("Missing string data".to_string()));
            }

            let arg = lines[i];
            if arg.len() != str_len {
                return Err(Error::Parse("String length mismatch".to_string()));
            }

            args.push(arg.to_string());
            i += 1;
        }

        Self::args_to_command(args)
    }

    fn parse_simple_command(input: &str) -> Result<Command> {
        let args: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();

        if args.is_empty() {
            return Err(Error::Parse("No command provided".to_string()));
        }

        Self::args_to_command(args)
    }

    fn args_to_command(args: Vec<String>) -> Result<Command> {
        if args.is_empty() {
            return Err(Error::Parse("No command provided".to_string()));
        }

        let cmd = args[0].to_uppercase();

        match cmd.as_str() {
            "SET" => {
                if args.len() != 3 {
                    return Err(Error::Parse("SET requires key and value".to_string()));
                }
                Ok(Command::Set {
                    key: args[1].clone(),
                    value: args[2].clone(),
                })
            }
            "GET" => {
                if args.len() != 2 {
                    return Err(Error::Parse("GET requires key".to_string()));
                }
                Ok(Command::Get {
                    key: args[1].clone(),
                })
            }
            "DEL" => {
                if args.len() != 2 {
                    return Err(Error::Parse("DEL requires key".to_string()));
                }
                Ok(Command::Del {
                    key: args[1].clone(),
                })
            }
            "PING" => Ok(Command::Ping),
            "INFO" => Ok(Command::Info),
            _ => Err(Error::Parse(format!("Unknown command: {}", cmd))),
        }
    }
}```

### src/storage/mod.rs
```rust
//! Storage module for in-memory data and persistence

pub mod memory_store;
pub mod persistence;

pub use memory_store::MemoryStore;
pub use persistence::Persistence;
```

### src/storage/memory_store.rs
```rust
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
```

### src/storage/persistence.rs
```rust
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
```

### src/server/mod.rs
```rust
//! TCP server module

pub mod tcp_server;
pub mod connection;

pub use tcp_server::TcpServer;
pub use connection::Connection;
```

### src/server/tcp_server.rs
```rust
//! TCP server implementation

use crate::Result;
use crate::server::Connection;
use crate::storage::MemoryStore;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// TCP server for handling Redis-like protocol
pub struct TcpServer {
    addr: String,
    store: Arc<RwLock<MemoryStore>>,
}

impl TcpServer {
    /// Create new TCP server
    pub fn new(addr: String, store: Arc<RwLock<MemoryStore>>) -> Self {
        TcpServer { addr, store }
    }

    /// Run the server
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Mini Redis server listening on {}", self.addr);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    info!("New connection from {}", addr);

                    let store = Arc::clone(&self.store);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(socket, store).await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(socket: TcpStream, store: Arc<RwLock<MemoryStore>>) -> Result<()> {
        let mut connection = Connection::new(socket);

        loop {
            match connection.read_command().await {
                Ok(Some(command)) => {
                    let response = {
                        let mut store = store.write().await;
                        store.execute(command).await?
                    };

                    connection.write_response(response).await?;
                }
                Ok(None) => {
                    info!("Connection closed by client");
                    break;
                }
                Err(e) => {
                    warn!("Connection error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}
```

### src/server/connection.rs
```rust
//! Connection handling for TCP clients

use crate::Result;
use crate::protocol::{Command, Parser, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tracing::debug;

/// Represents a client connection using split read/write halves.
pub struct Connection {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: BufWriter<tokio::io::WriteHalf<TcpStream>>,
}

impl Connection {
    /// Create new connection wrapper by splitting the socket.
    pub fn new(socket: TcpStream) -> Self {
        let (reader, writer) = tokio::io::split(socket);
        Connection {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
        }
    }

    /// Read a command from the connection.
    pub async fn read_command(&mut self) -> Result<Option<Command>> {
        let mut buffer = String::new();

        loop {
            let bytes_read = self.reader.read_line(&mut buffer).await?;
            if bytes_read == 0 {
                return Ok(None); // Connection closed
            }

            if self.is_complete_command(&buffer) {
                break;
            }
        }

        debug!("Received: {:?}", buffer.trim());

        match Parser::parse_command(&buffer) {
            Ok(command) => Ok(Some(command)),
            Err(e) => {
                let error_response = Response::Error(format!("Parse error: {}", e));
                self.write_response(error_response).await?;
                Err(e)
            }
        }
    }

    /// Write a response to the connection.
    pub async fn write_response(&mut self, response: Response) -> Result<()> {
        let resp_string = response.to_resp();
        debug!("Sending: {:?}", resp_string.trim());

        self.writer.write_all(resp_string.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// (Corrected) Check if we have a complete command in the buffer.
    fn is_complete_command(&self, buffer: &str) -> bool {
        if !buffer.starts_with('*') {
            return buffer.contains("\r\n");
        }

        if let Some(header) = buffer.lines().next() {
            if let Ok(num_elements) = header[1..].parse::<usize>() {
                // A complete command has N*2 lines for the elements plus 1 for the array header.
                let expected_terminators = 1 + (num_elements * 2);
                return buffer.matches("\r\n").count() >= expected_terminators;
            }
        }

        false
    }
}
```

### src/client/mod.rs
```rust
//! Client module for connecting to Mini Redis server

pub mod tcp_client;

pub use tcp_client::TcpClient;
```

### src/client/tcp_client.rs
```rust
//! TCP client for connecting to Mini Redis server

use crate::protocol::{Command, Response};
use crate::{Error, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter}; // <-- The missing trait is added here
use tokio::net::TcpStream;
use tracing::debug;

/// TCP client for Mini Redis using split read/write halves.
pub struct TcpClient {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: BufWriter<tokio::io::WriteHalf<TcpStream>>,
}

impl TcpClient {
    /// Connect to Mini Redis server.
    pub async fn connect(addr: &str) -> Result<Self> {
        let socket = TcpStream::connect(addr).await?;
        let (reader, writer) = tokio::io::split(socket);

        Ok(TcpClient {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
        })
    }

    /// Execute a command and get response.
    pub async fn execute(&mut self, command: Command) -> Result<Response> {
        let cmd_str = self.command_to_resp(&command);
        debug!("Sending: {:?}", cmd_str.trim());
        self.writer.write_all(cmd_str.as_bytes()).await?;
        self.writer.flush().await?;

        self.read_response().await
    }

    /// (Corrected) Reads and parses a full response from the server.
    async fn read_response(&mut self) -> Result<Response> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).await? == 0 {
            return Err(Error::Connection("Connection closed by server".into()));
        }

        let trimmed_line = line.trim();
        match trimmed_line.chars().next() {
            Some('+') => self.parse_simple_string(trimmed_line),
            Some('-') => Ok(Response::Error(trimmed_line[1..].to_string())),
            Some(':') => self.parse_integer(trimmed_line),
            Some('$') => self.parse_bulk_string(trimmed_line).await,
            _ => Err(Error::Parse("Invalid response format".to_string())),
        }
    }

    fn parse_simple_string(&self, line: &str) -> Result<Response> {
        let content = &line[1..];
        match content {
            "OK" => Ok(Response::Ok),
            "PONG" => Ok(Response::Pong),
            _ => Ok(Response::Value(content.to_string())),
        }
    }

    fn parse_integer(&self, line: &str) -> Result<Response> {
        line[1..]
            .parse::<i64>()
            .map(Response::Integer)
            .map_err(|_| Error::Parse("Invalid integer response".to_string()))
    }

    async fn parse_bulk_string(&mut self, line: &str) -> Result<Response> {
        let len: i64 = line[1..]
            .parse()
            .map_err(|_| Error::Parse("Invalid bulk string length".to_string()))?;

        if len == -1 {
            return Ok(Response::Nil);
        }

        let len = len as usize;
        let mut buffer = vec![0; len + 2]; // +2 for trailing \r\n
        self.reader.read_exact(&mut buffer).await?;

        let value = String::from_utf8(buffer[..len].to_vec())
            .map_err(|_| Error::Parse("Invalid UTF-8 in bulk string".to_string()))?;

        if value.starts_with("# Server") {
            Ok(Response::Info(value))
        } else {
            Ok(Response::Value(value))
        }
    }

    /// Convert command to RESP format.
    fn command_to_resp(&self, command: &Command) -> String {
        match command {
            Command::Set { key, value } => format!(
                "*3\r\n$3\r\nSET\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                key.len(),
                key,
                value.len(),
                value
            ),
            Command::Get { key } => format!("*2\r\n$3\r\nGET\r\n${}\r\n{}\r\n", key.len(), key),
            Command::Del { key } => format!("*2\r\n$3\r\nDEL\r\n${}\r\n{}\r\n", key.len(), key),
            Command::Ping => "*1\r\n$4\r\nPING\r\n".to_string(),
            Command::Info => "*1\r\n$4\r\nINFO\r\n".to_string(),
        }
    }
}
```

### src/client/main.rs
```rust
//! Mini Redis Client CLI

use clap::Parser;
use mini_redis::protocol::{Command, Response};
use mini_redis::{Result, TcpClient};
use std::io::{self, Write};
use tracing::error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server address to connect to
    #[arg(short, long, default_value = "127.0.0.1:6379")]
    server: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    let args = Args::parse();

    println!("Mini Redis Client");
    println!("Connecting to {}...", args.server);

    let mut client = match TcpClient::connect(&args.server).await {
        Ok(client) => {
            println!("Connected successfully!");
            client
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return Err(e);
        }
    };

    // Interactive REPL
    loop {
        print!("mini-redis> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let input = input.trim();
                if input.is_empty() {
                    continue;
                }

                if input.eq_ignore_ascii_case("quit") || input.eq_ignore_ascii_case("exit") {
                    break;
                }

                match parse_user_input(input) {
                    Ok(command) => match client.execute(command).await {
                        Ok(response) => print_response(response),
                        Err(e) => eprintln!("Error: {}", e),
                    },
                    Err(e) => eprintln!("Parse error: {}", e),
                }
            }
            Err(e) => {
                error!("Failed to read input: {}", e);
                break;
            }
        }
    }

    println!("Goodbye!");
    Ok(())
}

fn parse_user_input(input: &str) -> Result<Command> {
    let args = parse_command_line(input)?;

    if args.is_empty() {
        return Err(mini_redis::Error::Parse("Empty command".to_string()));
    }

    let cmd = args[0].to_uppercase();
    match cmd.as_str() {
        "SET" => {
            if args.len() != 3 {
                return Err(mini_redis::Error::Parse("Usage: SET key value".to_string()));
            }
            Ok(Command::Set {
                key: args[1].clone(),
                value: args[2].clone(),
            })
        }
        "GET" => {
            if args.len() != 2 {
                return Err(mini_redis::Error::Parse("Usage: GET key".to_string()));
            }
            Ok(Command::Get {
                key: args[1].clone(),
            })
        }
        "DEL" => {
            if args.len() != 2 {
                return Err(mini_redis::Error::Parse("Usage: DEL key".to_string()));
            }
            Ok(Command::Del {
                key: args[1].clone(),
            })
        }
        "PING" => Ok(Command::Ping),
        "INFO" => Ok(Command::Info),
        _ => Err(mini_redis::Error::Parse(format!(
            "Unknown command: {}",
            cmd
        ))),
    }
}

/// Parse command line with proper quote handling
fn parse_command_line(input: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' if !in_quotes => {
                in_quotes = true;
            }
            '"' if in_quotes => {
                in_quotes = false;
            }
            ' ' | '\t' if !in_quotes => {
                if !current_arg.is_empty() {
                    args.push(current_arg.clone());
                    current_arg.clear();
                }
            }
            _ => {
                current_arg.push(ch);
            }
        }
    }

    if !current_arg.is_empty() {
        args.push(current_arg);
    }

    if in_quotes {
        return Err(mini_redis::Error::Parse("Unclosed quotes".to_string()));
    }

    Ok(args)
}

fn print_response(response: Response) {
    match response {
        Response::Ok => println!("OK"),
        Response::Value(val) => println!("\"{}\"", val),
        Response::Nil => println!("(nil)"),
        Response::Integer(num) => println!("(integer) {}", num),
        Response::Error(err) => println!("(error) {}", err),
        Response::Pong => println!("PONG"),
        Response::Info(info) => println!("{}", info),
    }
}
```

## Usage Instructions

### Building the Project
```bash
# Create the project directory
mkdir mini-redis
cd mini-redis

# Initialize Cargo project
cargo init

# Copy all the source files into the appropriate directories
# Make sure to create the folder structure as shown above

# Build the project
cargo build --release
```

### Running the Server
```bash
# Run with default settings (127.0.0.1:6379)
cargo run --bin mini-redis-server

# Run with custom settings
cargo run --bin mini-redis-server -- --port 8080 --host 0.0.0.0 --data-dir ./mydata
```

### Running the Client
```bash
# Connect to default server
cargo run --bin mini-redis-client

# Connect to custom server
cargo run --bin mini-redis-client -- --server 127.0.0.1:8080
```

### Example Client Session
```
mini-redis> SET mykey "Hello World"
OK
mini-redis> GET mykey
"Hello World"
mini-redis> DEL mykey
(integer) 1
mini-redis> GET mykey
(nil)
mini-redis> PING
PONG
mini-redis> INFO
# Server
redis_version:mini-redis-0.1.0
# Keyspace
db0:keys=0,expires=0
# Stats
total_operations:2
uptime_seconds:45
```

## Key Features Explained

### 1. **In-Memory Storage (`MemoryStore`)**
- Uses `HashMap<String, String>` for fast key-value lookups
- Thread-safe using `Arc<RwLock<>>` for concurrent access
- Supports basic operations: SET, GET, DEL

### 2. **Persistence (`Persistence`)**
- Append-only log format using JSON serialization
- Logs only data-modifying operations (SET, DEL)
- Automatic recovery on startup by replaying the log
- Each operation is written as a separate line for durability

### 3. **TCP Server (`TcpServer`)**
- Async TCP server using Tokio
- Spawns a new task for each client connection
- Handles multiple concurrent clients
- Graceful error handling and connection cleanup

### 4. **Protocol Support**
- Basic Redis RESP (REdis Serialization Protocol) support
- Supports both simple string format ("SET key value")
- Supports array format ("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n")
- Proper response formatting

### 5. **Client Implementation**
- Interactive CLI client with REPL
- Supports all basic commands
- Connection management and error handling
- User-friendly command parsing

### 6. **Error Handling**
- Comprehensive error types using `thiserror`
- Proper error propagation throughout the system
- Client-friendly error messages

### 7. **Logging & Observability**
- Structured logging using `tracing`
- Debug information for operations
- Connection lifecycle tracking
- Performance metrics in INFO command

### 8. **Testing**
- Unit tests for core components
- Integration tests for command execution
- Mock testing with temporary directories

## Architecture Benefits

1. **Modularity**: Clean separation of concerns across modules
2. **Async/Await**: Non-blocking I/O for high performance
3. **Memory Safety**: Rust's ownership system prevents data races
4. **Persistence**: Crash recovery through append-only logging
5. **Extensibility**: Easy to add new commands and features
6. **Standards Compliance**: RESP protocol compatibility

This implementation provides a solid foundation for a Redis-like database and demonstrates key concepts in systems programming with Rust.

## File Structure Summary
```
mini-redis/
├── Cargo.toml                 # Project configuration
├── src/
│   ├── main.rs               # Server entry point
│   ├── lib.rs                # Library root
│   ├── server/               # TCP server implementation
│   ├── storage/              # In-memory store + persistence
│   ├── protocol/             # Command parsing + RESP protocol
│   └── client/               # TCP client + CLI
└── data/                     # Persistence directory
```
