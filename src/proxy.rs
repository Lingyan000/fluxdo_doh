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
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as hyper_http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use std::convert::Infallible;
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
            Some(
                DnsResolver::shared(
                    &config.doh_server,
                    config.doh_server_ech.as_deref(),
                    config.prefer_ipv6,
                    config.upstream_proxy.clone(),
                )
                .await?,
            )
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

        // gateway 模式下仍需要 cert_manager：WebView 通过 CONNECT 走 MITM
        let cert_manager = if config.enable_doh {
            let cm = if let (Some(cert), Some(key)) = (&config.ca_cert_pem, &config.ca_key_pem) {
                CertManager::from_pem(cert, key)?   // 运行时 CA（per-device）
            } else {
                CertManager::new()?                  // 编译时 CA
            };
            Some(Arc::new(cm))
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
                            let mitm_connect = self.config.mitm_connect;
                            let doh_tls_connector = self.doh_tls_connector.clone();
                            let cert_manager = self.cert_manager.clone();

                            tokio::spawn(async move {
                                if gateway_mode && enable_doh {
                                    // Gateway 模式：用 hyper server 统一处理
                                    // CONNECT → MITM 或 tunnel（取决于 mitm_connect）
                                    // 其他方法 → HTTP/2 反向代理 (Dio)
                                    if let Err(e) = handle_gateway_connection(
                                        stream,
                                        doh_tls_connector,
                                        cert_manager,
                                        mitm_connect,
                                    ).await {
                                        debug!("Gateway connection error from {}: {}", peer_addr, e);
                                    }
                                } else if let Err(e) = handle_connection(
                                    stream,
                                    enable_doh,
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

/// Handle a gateway (reverse proxy) connection using hyper.
///
/// Uses hyper HTTP/1.1 server on the client side, hyper HTTP/2 (or HTTP/1.1)
/// client on the server side. Supports keep-alive with multi-host routing
/// and server-side connection pooling via HTTP/2 multiplexing.
async fn handle_gateway_connection(
    stream: TcpStream,
    connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
    mitm_connect: bool,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let pool: GatewayPool =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let service = service_fn(move |req: Request<Incoming>| {
        let connector = connector.clone();
        let cert_manager = cert_manager.clone();
        let pool = pool.clone();
        async move {
            if req.method() == hyper::Method::CONNECT {
                if mitm_connect {
                    gateway_handle_connect(req, connector, cert_manager).await
                } else {
                    gateway_handle_connect_tunnel(req, connector).await
                }
            } else {
                gateway_forward_request(req, connector, pool).await
            }
        }
    });

    hyper_http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(|e| DohProxyError::Proxy(format!("Gateway hyper error: {}", e)))
}

type GatewayBody = BoxBody<Bytes, hyper::Error>;
type GatewayResponse = std::result::Result<Response<GatewayBody>, Infallible>;

/// 只缓存 HTTP/2 sender（可 clone 多路复用），HTTP/1.1 不缓存。
type GatewayPool = Arc<tokio::sync::Mutex<std::collections::HashMap<String, hyper::client::conn::http2::SendRequest<Incoming>>>>;

enum GatewaySender {
    H2(hyper::client::conn::http2::SendRequest<Incoming>),
    H1(hyper::client::conn::http1::SendRequest<Incoming>),
}

fn gateway_error_response(status: u16, msg: &str) -> Response<GatewayBody> {
    let body = Full::new(Bytes::from(msg.to_owned()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(body)
        .unwrap()
}

/// Forward a plain HTTP request to the real server via TLS+ECH (HTTP/2 preferred).
async fn gateway_forward_request(
    req: Request<Incoming>,
    connector: Arc<DohTlsConnector>,
    pool: GatewayPool,
) -> GatewayResponse {
    let host_header = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();

    if host_header.is_empty() {
        return Ok(gateway_error_response(400, "Missing Host header"));
    }

    let (host, port) = match gateway_parse_host(&host_header) {
        Some(hp) => hp,
        None => return Ok(gateway_error_response(400, "Invalid Host header")),
    };
    let host_key = format!("{}:{}", host, port);

    debug!("Gateway {} {} -> {}", req.method(), req.uri(), host_key);

    // Try to get a pooled H2 sender (H1 is not pooled)
    let mut sender: Option<GatewaySender> = {
        let mut p = pool.lock().await;
        match p.get(&host_key) {
            Some(s) if s.is_ready() => Some(GatewaySender::H2(s.clone())),
            _ => {
                p.remove(&host_key);
                None
            }
        }
    };

    // Create new connection if needed
    if sender.is_none() {
        let tls = match connector.connect_h2(&host, port).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Gateway connect failed for {}: {}", host_key, e);
                return Ok(gateway_error_response(502, &format!("Connect failed: {}", e)));
            }
        };

        // Check negotiated ALPN
        let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        let is_h2 = alpn.as_deref() == Some(b"h2");
        let io = TokioIo::new(tls);

        if is_h2 {
            debug!("Gateway: HTTP/2 connection to {}", host_key);
            let (s, conn) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                io,
            )
            .await
            .map_err(|e| warn!("Gateway H2 handshake failed: {}", e))
            .unwrap_or_else(|_| unreachable!());
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Gateway H2 conn closed: {}", e);
                }
            });
            let s_clone = s.clone();
            sender = Some(GatewaySender::H2(s));
            pool.lock().await.insert(host_key.clone(), s_clone);
        } else {
            debug!("Gateway: HTTP/1.1 connection to {}", host_key);
            let (s, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| warn!("Gateway H1 handshake failed: {}", e))
                .unwrap_or_else(|_| unreachable!());
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Gateway H1 conn closed: {}", e);
                }
            });
            // H1 不能 clone/多路复用，不入池
            sender = Some(GatewaySender::H1(s));
        }
    }

    // Rewrite URI: 客户端发来的是相对路径 /path，HTTP/2 需要绝对 URI（:authority + :scheme）
    let mut req = req;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let authority = if port == 443 {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };
    if let Ok(new_uri) = format!("https://{}{}", authority, path_and_query).parse() {
        *req.uri_mut() = new_uri;
    }

    // Forward the request
    let result = match sender.unwrap() {
        GatewaySender::H2(mut s) => s.send_request(req).await,
        GatewaySender::H1(mut s) => s.send_request(req).await,
    };

    match result {
        Ok(resp) => Ok(resp.map(|b| b.boxed())),
        Err(e) => {
            warn!("Gateway forward failed for {}: {}", host_key, e);
            // Remove broken connection from pool
            pool.lock().await.remove(&host_key);
            Ok(gateway_error_response(502, &format!("Forward failed: {}", e)))
        }
    }
}

/// Handle CONNECT in gateway mode as a plain tunnel (DOH resolution + raw TCP forwarding).
/// Client does end-to-end TLS with the target server — no MITM, no custom CA needed.
async fn gateway_handle_connect_tunnel(
    req: Request<Incoming>,
    connector: Arc<DohTlsConnector>,
) -> GatewayResponse {
    let target = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
    let (host, port) = match gateway_parse_host(&target) {
        Some(hp) => hp,
        None => return Ok(gateway_error_response(400, "Invalid CONNECT target")),
    };

    info!("Gateway CONNECT (tunnel) {}:{}", host, port);

    let connector_clone = connector.clone();
    let host_clone = host.clone();

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                // Connect to remote via DOH-resolved address
                match connector_clone.connect_tcp(&host_clone, port).await {
                    Ok(server_stream) => {
                        let (mut cr, mut cw) = tokio::io::split(io);
                        let (mut sr, mut sw) = tokio::io::split(server_stream);
                        let _ = tokio::try_join!(
                            tokio::io::copy(&mut cr, &mut sw),
                            tokio::io::copy(&mut sr, &mut cw),
                        );
                    }
                    Err(e) => {
                        warn!("Gateway tunnel connect failed {}:{}: {}", host_clone, port, e);
                    }
                }
            }
            Err(e) => warn!("Gateway CONNECT tunnel upgrade failed: {}", e),
        }
    });

    // Return 200 to initiate the upgrade
    let body = Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed();
    Ok(Response::new(body))
}

/// Handle CONNECT in gateway mode (WebView MITM).
async fn gateway_handle_connect(
    req: Request<Incoming>,
    connector: Arc<DohTlsConnector>,
    cert_manager: Option<Arc<CertManager>>,
) -> GatewayResponse {
    let target = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
    let (host, port) = match gateway_parse_host(&target) {
        Some(hp) => hp,
        None => return Ok(gateway_error_response(400, "Invalid CONNECT target")),
    };

    info!("Gateway CONNECT (MITM) {}:{}", host, port);

    let cert_manager = match cert_manager {
        Some(cm) => cm,
        None => return Ok(gateway_error_response(502, "Certificate manager not available")),
    };

    let connector_clone = connector.clone();
    let host_clone = host.clone();

    // Spawn MITM handling after upgrade
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if let Err(e) =
                    gateway_mitm_upgraded(io, &host_clone, port, connector_clone, cert_manager).await
                {
                    warn!("Gateway MITM error {}:{}: {}", host_clone, port, e);
                }
            }
            Err(e) => warn!("Gateway CONNECT upgrade failed: {}", e),
        }
    });

    // Return 200 to initiate the upgrade
    let body = Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed();
    Ok(Response::new(body))
}

/// Run MITM on an upgraded CONNECT connection (WebView).
async fn gateway_mitm_upgraded<I>(
    client_io: I,
    host: &str,
    port: u16,
    connector: Arc<DohTlsConnector>,
    cert_manager: Arc<CertManager>,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Connect to real server with TLS+ECH
    let server_tls = connector.connect(host, port).await?;

    // TLS handshake with client (MITM)
    let server_config = cert_manager.get_server_config(host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let client_tls = acceptor.accept(client_io).await.map_err(DohProxyError::Io)?;

    // Bidirectional copy
    let (mut cr, mut cw) = tokio::io::split(client_tls);
    let (mut sr, mut sw) = tokio::io::split(server_tls);
    let _ = tokio::try_join!(
        tokio::io::copy(&mut cr, &mut sw),
        tokio::io::copy(&mut sr, &mut cw),
    );

    Ok(())
}

fn gateway_parse_host(host_header: &str) -> Option<(String, u16)> {
    if host_header.starts_with('[') {
        // IPv6: [::1]:443
        let bracket_end = host_header.find(']')?;
        let host = &host_header[1..bracket_end];
        let port = host_header[bracket_end + 1..]
            .strip_prefix(':')
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        Some((host.to_string(), port))
    } else if let Some(colon) = host_header.rfind(':') {
        let host = &host_header[..colon];
        let port = host_header[colon + 1..].parse().unwrap_or(443);
        Some((host.to_string(), port))
    } else {
        Some((host_header.to_string(), 443))
    }
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
