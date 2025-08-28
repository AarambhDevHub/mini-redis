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
