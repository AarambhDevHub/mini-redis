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
