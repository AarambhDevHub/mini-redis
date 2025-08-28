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
}
