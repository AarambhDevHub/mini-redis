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
