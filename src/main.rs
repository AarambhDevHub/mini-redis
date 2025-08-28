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
