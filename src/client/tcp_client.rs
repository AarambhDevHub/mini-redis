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
