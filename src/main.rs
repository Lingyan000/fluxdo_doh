//! DOH Proxy - Standalone executable

use doh_proxy::{DohProxyServer, ProxyConfig, UpstreamProxyConfig};
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
    let enable_doh = !args.iter().any(|a| a == "--no-doh");

    // Parse --doh <url> argument
    let doh_server = args
        .iter()
        .position(|a| a == "--doh")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "cloudflare".to_string());

    let upstream_host = args
        .iter()
        .position(|a| a == "--upstream-host")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let upstream_port = args
        .iter()
        .position(|a| a == "--upstream-port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u16>().ok());
    let upstream_protocol = args
        .iter()
        .position(|a| a == "--upstream-protocol")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "http".to_string());
    let upstream_username = args
        .iter()
        .position(|a| a == "--upstream-user")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let upstream_cipher = args
        .iter()
        .position(|a| a == "--upstream-cipher")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let upstream_password = args
        .iter()
        .position(|a| a == "--upstream-pass")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Parse --doh-server-ech <url> argument
    let doh_server_ech = args
        .iter()
        .position(|a| a == "--doh-server-ech")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Parse --server-ip <ip> argument
    let server_ip = args
        .iter()
        .position(|a| a == "--server-ip")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let upstream_proxy = match (upstream_host, upstream_port) {
        (Some(host), Some(port)) if !host.trim().is_empty() && port > 0 => Some(UpstreamProxyConfig {
            protocol: upstream_protocol,
            host,
            port,
            username: upstream_username,
            password: upstream_password,
            cipher: upstream_cipher,
        }),
        _ => None,
    };

    let config = ProxyConfig {
        bind_port: port,
        enable_doh,
        prefer_ipv6,
        doh_server,
        doh_server_ech,
        upstream_proxy,
        server_ip,
        ..Default::default()
    };

    let server_ip_str = config.server_ip.as_deref().unwrap_or("auto");
    let doh_ech_str = config.doh_server_ech.as_deref().unwrap_or("(same as dns)");
    if let Some(proxy) = config.upstream_proxy.as_ref() {
        info!(
            "Config: bind_port={}, enable_doh={}, prefer_ipv6={}, doh_server={}, doh_server_ech={}, server_ip={}, upstream={}://{}:{}",
            config.bind_port,
            config.enable_doh,
            config.prefer_ipv6,
            config.doh_server,
            doh_ech_str,
            server_ip_str,
            proxy.protocol(),
            proxy.host,
            proxy.port
        );
    } else {
        info!(
            "Config: bind_port={}, enable_doh={}, prefer_ipv6={}, doh_server={}, doh_server_ech={}, server_ip={}, upstream=disabled",
            config.bind_port, config.enable_doh, config.prefer_ipv6, config.doh_server, doh_ech_str, server_ip_str
        );
    }

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
