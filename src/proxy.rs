//! MITM HTTP/HTTPS proxy server with ECH support
//!
//! This proxy supports two modes:
//! 1. DoH/ECH MITM mode: generates certificates locally and performs TLS interception
//! 2. Plain tunnel mode: only establishes upstream CONNECT/SOCKS5 tunnels and forwards bytes

use crate::cert::CertManager;
use crate::dns::DnsResolver;
use crate::ech::DohTlsConnector;
use crate::error::{DohProxyError, Result};
use crate::ProxyConfig;
use parking_lot::RwLock;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Local proxy server
pub struct DohProxyServer {
    #[allow(dead_code)]
    config: ProxyConfig,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
    local_addr: Arc<RwLock<Option<SocketAddr>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DohProxyServer {
    /// Create a new proxy server
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        if config.gateway_mode && config.enable_doh {
            info!(
                "Creating local proxy in gateway (reverse proxy) mode with DoH server: {}",
                config.doh_server
            );
        } else if config.enable_doh {
            info!(
                "Creating local proxy in DoH/ECH MITM mode with DoH server: {}",
                config.doh_server
            );
        } else {
            info!("Creating local proxy in pure upstream tunnel mode");
        }

        let dns_resolver = if config.enable_doh {
            Some(Arc::new(
                DnsResolver::new(
                    &config.doh_server,
                    config.doh_server_ech.as_deref(),
                    config.prefer_ipv6,
                    config.upstream_proxy.clone(),
                )
                .await?,
            ))
        } else {
            None
        };

        let doh_tls_connector = Arc::new(DohTlsConnector::new(
            dns_resolver,
            config.enable_doh,
            Duration::from_secs(config.timeout_secs),
            config.upstream_proxy.clone(),
            config.server_ip.clone(),
        ));

        let cert_manager = if config.enable_doh && !config.gateway_mode {
            Some(Arc::new(CertManager::new()?))
        } else {
            None
        };
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
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

        info!("Local proxy server listening on {}", local_addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            debug!("New connection from {}", peer_addr);
                            let enable_doh = self.config.enable_doh;
                            let gateway_mode = self.config.gateway_mode;
                            let doh_tls_connector = self.doh_tls_connector.clone();
                            let cert_manager = self.cert_manager.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    enable_doh,
                                    gateway_mode,
                                    doh_tls_connector,
                                    cert_manager,
                                ).await {
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
    enable_doh: bool,
    gateway_mode: bool,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
) -> Result<()> {
    let (read_half, write_half) = client.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    let mut first_line = String::new();
    reader.read_line(&mut first_line).await?;

    let parts: Vec<&str> = first_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(DohProxyError::Parse("Invalid request".to_string()));
    }

    let method = parts[0];
    let target = parts[1].to_string();

    if method == "CONNECT" {
        if enable_doh {
            let cert_manager = cert_manager.ok_or_else(|| {
                DohProxyError::Proxy("MITM mode requires certificate manager".to_string())
            })?;
            handle_connect_mitm(reader, writer, &target, doh_tls_connector, cert_manager).await
        } else {
            handle_connect_tunnel(reader, writer, &target, doh_tls_connector).await
        }
    } else if gateway_mode && enable_doh {
        handle_gateway_forward(reader, writer, method, &target, doh_tls_connector).await
    } else {
        writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT method is supported\r\n")
            .await?;
        Ok(())
    }
}

/// Handle CONNECT request as a plain TCP tunnel.
async fn handle_connect_tunnel(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    doh_tls_connector: Arc<DohTlsConnector>,
) -> Result<()> {
    let (host, port) = parse_host_port(target)?;

    info!("Plain CONNECT {}:{}", host, port);

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    let server_stream = match doh_tls_connector.connect_tcp(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Failed to establish upstream tunnel for {}:{}: {}", host, port, e);
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}\r\n", e);
            writer.write_all(msg.as_bytes()).await?;
            return Err(e);
        }
    };

    writer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let buffered = reader.buffer().to_vec();
    let read_half = reader.into_inner();
    let client_stream = read_half.reunite(writer).map_err(|_| {
        DohProxyError::Proxy("Failed to reunite TCP stream halves".to_string())
    })?;
    let client_stream = PrefixedStream::new(client_stream, buffered);

    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut server_read, mut server_write) = tokio::io::split(server_stream);

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    match tokio::try_join!(client_to_server, server_to_client) {
        Ok((to_server, to_client)) => {
            debug!(
                "Plain tunnel closed: {}:{} (sent: {}, received: {})",
                host, port, to_server, to_client
            );
        }
        Err(e) => {
            debug!("Plain tunnel error: {}:{} - {}", host, port, e);
        }
    }

    Ok(())
}

/// Handle CONNECT request with MITM
async fn handle_connect_mitm(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    doh_tls_connector: Arc<DohTlsConnector>,
    cert_manager: Arc<CertManager>,
) -> Result<()> {
    let (host, port) = parse_host_port(target)?;

    info!("MITM CONNECT {}:{}", host, port);

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    let server_tls = match doh_tls_connector.connect(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Failed to establish MITM upstream for {}:{}: {}", host, port, e);
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}\r\n", e);
            writer.write_all(msg.as_bytes()).await?;
            return Err(e);
        }
    };

    info!("Connected to {}:{} with ECH/TLS", host, port);

    writer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let buffered = reader.buffer().to_vec();
    let read_half = reader.into_inner();
    let client_stream = read_half.reunite(writer).map_err(|_| {
        DohProxyError::Proxy("Failed to reunite TCP stream halves".to_string())
    })?;
    let client_stream = PrefixedStream::new(client_stream, buffered);

    let server_config = cert_manager.get_server_config(&host)?;
    let acceptor = TlsAcceptor::from(server_config);

    let client_tls = match acceptor.accept(client_stream).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Client TLS handshake failed for {}: {}", host, e);
            return Err(DohProxyError::Io(e));
        }
    };

    info!("Client TLS handshake complete for {}", host);

    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut server_read, mut server_write) = tokio::io::split(server_tls);

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    match tokio::try_join!(client_to_server, server_to_client) {
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

/// Handle a plain HTTP request in gateway (reverse proxy) mode.
///
/// Accepts plain HTTP from the client, reads the Host header to determine
/// the target server, connects with TLS+ECH, then byte-copies bidirectionally.
/// This eliminates the double TLS overhead of MITM mode.
async fn handle_gateway_forward(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    method: &str,
    target: &str,
    doh_tls_connector: Arc<DohTlsConnector>,
) -> Result<()> {
    // Read headers, extract Host
    let mut header_bytes = Vec::new();
    let mut host_value = String::new();

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            header_bytes.extend_from_slice(line.as_bytes());
            break;
        }
        if let Some(val) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            host_value = val.trim().to_string();
        }
        header_bytes.extend_from_slice(line.as_bytes());
    }

    if host_value.is_empty() {
        let mut writer = writer;
        writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header\r\n")
            .await?;
        return Ok(());
    }

    // Parse host (may include port)
    let (host, port) = if host_value.contains(':') {
        parse_host_port(&host_value)?
    } else {
        (host_value.clone(), 443)
    };

    info!("Gateway {} {} -> {}:{}", method, target, host, port);

    // Connect to real server with TLS+ECH
    let server_tls = match doh_tls_connector.connect(&host, port).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Gateway: failed to connect to {}:{}: {}", host, port, e);
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}\r\n", e);
            let mut writer = writer;
            writer.write_all(msg.as_bytes()).await?;
            return Err(e);
        }
    };

    info!("Gateway: TLS+ECH connected to {}:{}", host, port);

    // Build prefix: first line + headers (already read from client)
    let first_line = format!("{} {} HTTP/1.1\r\n", method, target);
    let mut prefix = Vec::with_capacity(first_line.len() + header_bytes.len());
    prefix.extend_from_slice(first_line.as_bytes());
    prefix.extend_from_slice(&header_bytes);
    // Include any remaining buffered data
    prefix.extend_from_slice(reader.buffer());

    // Reunite client stream and prepend already-read bytes
    let read_half = reader.into_inner();
    let client_stream = read_half.reunite(writer).map_err(|_| {
        DohProxyError::Proxy("Failed to reunite TCP stream halves".to_string())
    })?;
    let client_stream = PrefixedStream::new(client_stream, prefix);

    // Bidirectional byte copy: plain client ↔ TLS server
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut server_read, mut server_write) = tokio::io::split(server_tls);

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    match tokio::try_join!(client_to_server, server_to_client) {
        Ok((to_server, to_client)) => {
            debug!(
                "Gateway closed: {}:{} (sent: {}, received: {})",
                host, port, to_server, to_client
            );
        }
        Err(e) => {
            debug!("Gateway error: {}:{} - {}", host, port, e);
        }
    }

    Ok(())
}

/// Parse host:port from CONNECT target
fn parse_host_port(target: &str) -> Result<(String, u16)> {
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

    if let Some(colon) = target.rfind(':') {
        let host = &target[..colon];
        let port = target[colon + 1..].parse().unwrap_or(443);
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let position = self.prefix.position() as usize;
        let prefix = self.prefix.get_ref();

        if position < prefix.len() {
            let remaining = &prefix[position..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix.set_position((position + to_copy) as u64);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
