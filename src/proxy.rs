//! MITM HTTP/HTTPS proxy server with ECH support
//!
//! This proxy intercepts HTTPS connections, establishing:
//! 1. TLS connection with client using a generated certificate
//! 2. TLS+ECH connection with the target server
//! Then forwards data between them.

use crate::cert::CertManager;
use crate::dns::DnsResolver;
use crate::ech::DohTlsConnector;
use crate::error::{DohProxyError, Result};
use crate::ProxyConfig;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// DOH Proxy Server with MITM support
pub struct DohProxyServer {
    #[allow(dead_code)]
    config: ProxyConfig,
    #[allow(dead_code)]
    dns_resolver: Arc<DnsResolver>,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Arc<CertManager>,
    local_addr: Arc<RwLock<Option<SocketAddr>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DohProxyServer {
    /// Create a new DOH proxy server
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        info!("Creating MITM DOH proxy with DOH server: {}", config.doh_server);

        let dns_resolver = Arc::new(DnsResolver::new(&config.doh_server, config.prefer_ipv6).await?);
        let doh_tls_connector = Arc::new(DohTlsConnector::new(
            dns_resolver.clone(),
            Duration::from_secs(config.timeout_secs),
        ));
        let cert_manager = Arc::new(CertManager::new()?);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            dns_resolver,
            doh_tls_connector,
            cert_manager,
            local_addr: Arc::new(RwLock::new(None)),
            shutdown_tx,
        })
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.read()
    }

    /// Get the local port
    pub fn port(&self) -> Option<u16> {
        self.local_addr().map(|a| a.port())
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let bind_addr = format!("{}:{}", self.config.bind_addr, self.config.bind_port);
        let listener = TcpListener::bind(&bind_addr).await?;

        let local_addr = listener.local_addr()?;
        *self.local_addr.write() = Some(local_addr);

        info!("MITM DOH proxy server listening on {}", local_addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            debug!("New connection from {}", peer_addr);
                            let doh_tls_connector = self.doh_tls_connector.clone();
                            let cert_manager = self.cert_manager.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, doh_tls_connector, cert_manager).await {
                                    warn!("Connection error from {}: {}", peer_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down proxy server");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Stop the proxy server
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Handle a single connection
async fn handle_connection(
    client: TcpStream,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Arc<CertManager>,
) -> Result<()> {
    let (read_half, write_half) = client.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Read the first line to determine request type
    let mut first_line = String::new();
    reader.read_line(&mut first_line).await?;

    let parts: Vec<&str> = first_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(DohProxyError::Parse("Invalid request".to_string()));
    }

    let method = parts[0];
    let target = parts[1].to_string();

    if method == "CONNECT" {
        // HTTPS tunneling via CONNECT - use MITM
        handle_connect_mitm(reader, writer, &target, doh_tls_connector, cert_manager).await
    } else {
        // Plain HTTP proxy (not supported)
        writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT method is supported\r\n")
            .await?;
        Ok(())
    }
}

/// Handle CONNECT request with MITM
///
/// 1. Parse target host:port
/// 2. Consume remaining headers
/// 3. Connect to target server with ECH
/// 4. Send 200 Connection Established
/// 5. Perform TLS handshake with client using generated cert
/// 6. Forward data between client TLS and server TLS
async fn handle_connect_mitm(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Arc<CertManager>,
) -> Result<()> {
    // Parse host:port
    let (host, port) = parse_host_port(target)?;

    info!("MITM CONNECT {}:{}", host, port);

    // Read remaining headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Connect to target server with ECH
    let server_tls = match doh_tls_connector.connect(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}\r\n", e);
            writer.write_all(msg.as_bytes()).await?;
            return Err(e);
        }
    };

    info!("Connected to {}:{} with ECH/TLS", host, port);

    // Send 200 Connection Established
    writer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Reunite the client stream
    let read_half = reader.into_inner();
    let client_stream = read_half.reunite(writer).map_err(|_| {
        DohProxyError::Proxy("Failed to reunite TCP stream halves".to_string())
    })?;

    // Get server config for this host
    let server_config = cert_manager.get_server_config(&host)?;
    let acceptor = TlsAcceptor::from(server_config);

    // Perform TLS handshake with client
    let client_tls = match acceptor.accept(client_stream).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Client TLS handshake failed for {}: {}", host, e);
            return Err(DohProxyError::Io(e));
        }
    };

    info!("Client TLS handshake complete for {}", host);

    // Forward data between client and server
    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut server_read, mut server_write) = tokio::io::split(server_tls);

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    let result = tokio::try_join!(client_to_server, server_to_client);

    match result {
        Ok((to_server, to_client)) => {
            debug!(
                "MITM tunnel closed: {}:{} (sent: {}, received: {})",
                host, port, to_server, to_client
            );
        }
        Err(e) => {
            debug!("MITM tunnel error: {}:{} - {}", host, port, e);
        }
    }

    Ok(())
}

/// Parse host:port from CONNECT target
fn parse_host_port(target: &str) -> Result<(String, u16)> {
    // Handle IPv6 addresses like [::1]:443
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let host = &target[1..bracket_end];
            let port_str = &target[bracket_end + 1..];
            let port = if port_str.starts_with(':') {
                port_str[1..].parse().unwrap_or(443)
            } else {
                443
            };
            return Ok((host.to_string(), port));
        }
    }

    // Regular host:port
    if let Some(colon) = target.rfind(':') {
        let host = &target[..colon];
        let port = target[colon + 1..].parse().unwrap_or(443);
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}
