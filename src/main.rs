//! DOH Proxy - Standalone executable

use doh_proxy::{DohProxyServer, ProxyConfig};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("doh_proxy=info".parse()?))
        .init();

    info!("Starting DOH Proxy Server");

    // Parse command line args (simple version)
    let args: Vec<String> = std::env::args().collect();

    let port = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let prefer_ipv6 = args.iter().any(|a| a == "--ipv6");

    // Parse --doh <url> argument
    let doh_server = args
        .iter()
        .position(|a| a == "--doh")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "cloudflare".to_string());

    let config = ProxyConfig {
        bind_port: port,
        prefer_ipv6,
        doh_server,
        ..Default::default()
    };

    info!("Config: {:?}", config);

    // Create and start server
    let server = DohProxyServer::new(config).await?;

    info!("Server starting...");

    // Handle Ctrl+C
    let server_handle = server;
    tokio::select! {
        result = server_handle.start() => {
            if let Err(e) = result {
                eprintln!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
            server_handle.stop();
        }
    }

    Ok(())
}
