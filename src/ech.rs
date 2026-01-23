//! ECH (Encrypted Client Hello) TLS connection handling
//!
//! When the `ech` feature is enabled, this uses aws-lc-rs for HPKE support
//! and enables true ECH encryption of the SNI field.

use crate::dns::DnsResolver;
use crate::error::{DohProxyError, Result};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::{debug, info, warn};

#[cfg(feature = "ech")]
use rustls::client::EchConfig;

/// ECH-enabled TLS connector
pub struct DohTlsConnector {
    dns_resolver: Arc<DnsResolver>,
    root_store: RootCertStore,
    timeout: Duration,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    host_ip_cache: Arc<Mutex<HashMap<String, CachedHostIp>>>,
}

struct CachedHostIp {
    addr: std::net::IpAddr,
    expires_at: std::time::Instant,
}

impl DohTlsConnector {
    /// Create a new ECH connector
    pub fn new(dns_resolver: Arc<DnsResolver>, timeout: Duration) -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let crypto_provider = Arc::new(crate::tls_crypto::build_provider());

        Self {
            dns_resolver,
            root_store,
            timeout,
            crypto_provider,
            host_ip_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a reference to the DNS resolver
    pub fn dns_resolver(&self) -> &DnsResolver {
        &self.dns_resolver
    }

    /// Connect to a server using ECH if available
    /// Returns a TLS stream that can be used for bidirectional I/O
    pub async fn connect(&self, host: &str, port: u16) -> Result<TlsStream<TcpStream>> {
        let start = std::time::Instant::now();
        // 1. Lookup ECH config from DNS HTTPS records (best-effort)
        #[cfg(feature = "ech")]
        let ech_config = match self.dns_resolver.lookup_ech_config(host).await {
            Ok(config) => config,
            Err(e) => {
                warn!(
                    "ECH lookup failed for {}, proceeding without ECH: {}",
                    host, e
                );
                None
            }
        };
        #[cfg(not(feature = "ech"))]
        let ech_config: Option<rustls::pki_types::EchConfigListBytes<'static>> = None;

        #[cfg(feature = "ech")]
        if ech_config.is_some() {
            info!("ECH config found for {}, enabling ECH", host);
        } else {
            info!("No ECH config for {}, using standard TLS", host);
        }

        #[cfg(not(feature = "ech"))]
        if ech_config.is_some() {
            info!("ECH config found for {} but ECH feature not enabled", host);
        }

        // Build TLS config (with or without ECH)
        let tls_config = self.build_tls_config(
            #[cfg(feature = "ech")]
            ech_config.as_ref(),
        )?;
        let connector = TlsConnector::from(tls_config);

        // Prepare SNI
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| DohProxyError::InvalidUrl(format!("Invalid server name: {}", host)))?;

        // 2. Prefer recently successful IP for this host (avoid frequent IP switching)
        if let Some(cached_addr) = self.get_cached_host_ip(host).await {
            let socket_addr = SocketAddr::new(cached_addr, port);
            debug!(
                "Trying cached IP for {}:{} via {}",
                host, port, socket_addr
            );
            match self
                .try_connect(&connector, socket_addr, server_name.clone())
                .await
            {
                Ok(stream) => {
                    self.dns_resolver
                        .record_ip_rtt(socket_addr.ip(), start.elapsed());
                    #[cfg(feature = "ech")]
                    {
                        let (_, conn) = stream.get_ref();
                        let ech_status = conn.ech_status();
                        info!(
                            "Connected to {}:{} via {} (ECH status: {:?})",
                            host, port, socket_addr, ech_status
                        );
                    }
                    #[cfg(not(feature = "ech"))]
                    {
                        info!("Connected to {}:{} via {}", host, port, socket_addr);
                    }
                    debug!(
                        "TLS connect to {}:{} completed in {} ms",
                        host,
                        port,
                        start.elapsed().as_millis()
                    );
                    return Ok(stream);
                }
                Err(e) => {
                    warn!(
                        "Cached IP failed for {}:{} via {}: {}",
                        host, port, socket_addr, e
                    );
                    self.clear_cached_host_ip(host).await;
                }
            }
        }

        // 3. Lookup IP address using DOH
        let addrs = self.dns_resolver.lookup_ip(host).await?;
        if addrs.is_empty() {
            return Err(DohProxyError::Dns(format!("No IP found for {}", host)));
        }
        let addrs = self.dns_resolver.order_addrs_by_rtt(addrs);

        let (v6_addrs, v4_addrs): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());
        let prefer_ipv6 = self.dns_resolver.prefer_ipv6();
        let (primary, secondary) = if prefer_ipv6 {
            (v6_addrs, v4_addrs)
        } else {
            (v4_addrs, v6_addrs)
        };

        let result = if secondary.is_empty() {
            self.connect_to_addrs(&connector, server_name.clone(), host, port, primary)
                .await
        } else {
            let mut primary_fut = Box::pin(self.connect_to_addrs(
                &connector,
                server_name.clone(),
                host,
                port,
                primary,
            ));

            let mut secondary_fut = Box::pin(async {
                tokio::time::sleep(Duration::from_millis(250)).await;
                self.connect_to_addrs(&connector, server_name.clone(), host, port, secondary)
                    .await
            });

            let mut primary_done = false;
            let mut secondary_done = false;
            let mut primary_err: Option<DohProxyError> = None;
            let mut secondary_err: Option<DohProxyError> = None;

            loop {
                tokio::select! {
                    res = &mut primary_fut, if !primary_done => {
                        primary_done = true;
                        match res {
                            Ok(ok) => break Ok(ok),
                            Err(e) => {
                                primary_err = Some(e);
                                if secondary_done {
                                    break Err(primary_err.or(secondary_err).unwrap_or_else(|| {
                                        DohProxyError::Proxy(format!("Failed to connect to {}:{}", host, port))
                                    }));
                                }
                            }
                        }
                    }
                    res = &mut secondary_fut, if !secondary_done => {
                        secondary_done = true;
                        match res {
                            Ok(ok) => break Ok(ok),
                            Err(e) => {
                                secondary_err = Some(e);
                                if primary_done {
                                    break Err(primary_err.or(secondary_err).unwrap_or_else(|| {
                                        DohProxyError::Proxy(format!("Failed to connect to {}:{}", host, port))
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        };

        match result {
            Ok((stream, socket_addr, rtt)) => {
                self.set_cached_host_ip(host, socket_addr.ip()).await;
                self.dns_resolver.record_ip_rtt(socket_addr.ip(), rtt);
                #[cfg(feature = "ech")]
                {
                    let (_, conn) = stream.get_ref();
                    let ech_status = conn.ech_status();
                    info!(
                        "Connected to {}:{} via {} (ECH status: {:?})",
                        host, port, socket_addr, ech_status
                    );
                }
                #[cfg(not(feature = "ech"))]
                {
                    info!("Connected to {}:{} via {}", host, port, socket_addr);
                }
                debug!(
                    "TLS connect to {}:{} completed in {} ms",
                    host,
                    port,
                    start.elapsed().as_millis()
                );
                Ok(stream)
            }
            Err(e) => Err(e),
        }
    }

    /// Build TLS config with optional ECH
    #[cfg(feature = "ech")]
    fn build_tls_config(
        &self,
        ech_config_bytes: Option<&rustls::pki_types::EchConfigListBytes<'static>>,
    ) -> Result<Arc<ClientConfig>> {
        use rustls::client::EchMode;

        if let Some(ech_bytes) = ech_config_bytes {
            // Try to parse and use ECH config
            let hpke_suites = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

            match EchConfig::new(ech_bytes.clone(), hpke_suites) {
                Ok(ech_config) => {
                    let ech_mode = EchMode::Enable(ech_config);

                    // with_ech sets TLS 1.3 implicitly (ECH requires TLS 1.3)
                    let config = ClientConfig::builder_with_provider(self.crypto_provider.clone())
                        .with_ech(ech_mode)
                        .map_err(|e| DohProxyError::Proxy(format!("ECH config error: {}", e)))?
                        .with_root_certificates(self.root_store.clone())
                        .with_no_client_auth();

                    return Ok(Arc::new(config));
                }
                Err(e) => {
                    warn!("Failed to parse ECH config, falling back to standard TLS: {}", e);
                }
            }
        }

        // Fall back to standard TLS 1.3
        let config = ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(DohProxyError::Tls)?
            .with_root_certificates(self.root_store.clone())
            .with_no_client_auth();

        Ok(Arc::new(config))
    }

    /// Build TLS config without ECH support
    #[cfg(not(feature = "ech"))]
    fn build_tls_config(&self) -> Result<Arc<ClientConfig>> {
        let config = ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(DohProxyError::Tls)?
            .with_root_certificates(self.root_store.clone())
            .with_no_client_auth();

        Ok(Arc::new(config))
    }

    /// Try to establish a TLS connection
    async fn try_connect(
        &self,
        connector: &TlsConnector,
        addr: SocketAddr,
        server_name: ServerName<'static>,
    ) -> Result<TlsStream<TcpStream>> {
        // TCP connect with timeout
        let tcp_stream = tokio::time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(DohProxyError::Io)?;

        // TLS handshake with timeout
        let tls_stream = tokio::time::timeout(
            self.timeout,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| DohProxyError::Timeout)?
        .map_err(|e| DohProxyError::Io(e))?;

        // Log connection info
        let (_, conn) = tls_stream.get_ref();
        debug!(
            "TLS connection established, protocol: {:?}",
            conn.protocol_version()
        );

        Ok(tls_stream)
    }

    async fn connect_to_addrs(
        &self,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
        host: &str,
        port: u16,
        addrs: Vec<std::net::IpAddr>,
    ) -> Result<(TlsStream<TcpStream>, SocketAddr, Duration)> {
        let mut last_error = None;
        for addr in addrs {
            let socket_addr = SocketAddr::new(addr, port);
            debug!("Trying to connect to {}:{} via {}", host, port, socket_addr);
            let attempt_start = std::time::Instant::now();
            match self
                .try_connect(connector, socket_addr, server_name.clone())
                .await
            {
                Ok(stream) => {
                    let rtt = attempt_start.elapsed();
                    return Ok((stream, socket_addr, rtt));
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", socket_addr, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DohProxyError::Proxy(format!("Failed to connect to {}:{}", host, port))
        }))
    }

    async fn get_cached_host_ip(&self, host: &str) -> Option<std::net::IpAddr> {
        let now = std::time::Instant::now();
        let cache = self.host_ip_cache.lock().await;
        cache
            .get(host)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.addr)
    }

    async fn set_cached_host_ip(&self, host: &str, addr: std::net::IpAddr) {
        let now = std::time::Instant::now();
        let mut cache = self.host_ip_cache.lock().await;
        if let Some(entry) = cache.get(host) {
            if entry.expires_at > now {
                return;
            }
        }
        cache.insert(
            host.to_string(),
            CachedHostIp {
                addr,
                expires_at: now + Duration::from_secs(600),
            },
        );
    }

    async fn clear_cached_host_ip(&self, host: &str) {
        let mut cache = self.host_ip_cache.lock().await;
        cache.remove(host);
    }
}

/// Trait for streams that support bidirectional I/O
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
