//! ECH (Encrypted Client Hello) TLS connection handling
//!
//! When the `ech` feature is enabled, this uses aws-lc-rs for HPKE support
//! and enables true ECH encryption of the SNI field.

use crate::dns::DnsResolver;
use crate::error::{DohProxyError, Result};
use crate::upstream::connect_tunnel;
use crate::{BoxStream, UpstreamProxyConfig};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::{debug, info, warn};

#[cfg(feature = "ech")]
use rustls::client::EchConfig;

/// ECH-enabled TLS connector
pub struct DohTlsConnector {
    dns_resolver: Option<Arc<DnsResolver>>,
    enable_doh: bool,
    root_store: RootCertStore,
    timeout: Duration,
    upstream_proxy: Option<UpstreamProxyConfig>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    host_ip_cache: Arc<Mutex<HashMap<String, CachedHostIp>>>,
    /// 用户指定的服务端 IP，跳过 DNS 解析
    server_ip: Option<std::net::IpAddr>,
    /// TLS ClientConfig 缓存，复用以启用 TLS 会话恢复
    tls_config_cache: Arc<Mutex<HashMap<String, Arc<ClientConfig>>>>,
}

struct CachedHostIp {
    addr: std::net::IpAddr,
    expires_at: std::time::Instant,
}

impl DohTlsConnector {
    /// Create a new ECH connector
    pub fn new(
        dns_resolver: Option<Arc<DnsResolver>>,
        enable_doh: bool,
        timeout: Duration,
        upstream_proxy: Option<UpstreamProxyConfig>,
        server_ip: Option<String>,
    ) -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let crypto_provider = Arc::new(crate::tls_crypto::build_provider());

        let parsed_ip = server_ip
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| {
                s.parse::<std::net::IpAddr>().ok().or_else(|| {
                    warn!("Invalid server_ip '{}', ignoring", s);
                    None
                })
            });

        Self {
            dns_resolver,
            enable_doh,
            root_store,
            timeout,
            upstream_proxy,
            crypto_provider,
            host_ip_cache: Arc::new(Mutex::new(HashMap::new())),
            server_ip: parsed_ip,
            tls_config_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Establish raw TCP tunnel to target host
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<BoxStream> {
        let stream = if let Some(proxy) = self.upstream_proxy.as_ref().filter(|proxy| proxy.is_valid()) {
            tokio::time::timeout(self.timeout, connect_tunnel(proxy, host, port))
                .await
                .map_err(|_| DohProxyError::Timeout)??
        } else {
            let stream = tokio::time::timeout(self.timeout, TcpStream::connect((host, port)))
                .await
                .map_err(|_| DohProxyError::Timeout)?
                .map_err(DohProxyError::Io)?;
            Box::new(stream)
        };
        Ok(stream)
    }

    /// Connect to a server using ECH if available
    /// Returns a TLS stream that can be used for bidirectional I/O
    pub async fn connect(&self, host: &str, port: u16) -> Result<TlsStream<BoxStream>> {
        let start = std::time::Instant::now();
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| DohProxyError::InvalidUrl(format!("Invalid server name: {}", host)))?;

        if !self.enable_doh {
            info!("DoH disabled for {}, using upstream/direct tunnel only", host);
            let tls_config = self.get_or_build_tls_config(
                #[cfg(feature = "ech")]
                None,
            ).await?;
            let connector = TlsConnector::from(tls_config);
            let tcp_stream = self.connect_tcp(host, port).await?;
            let tls_stream = self
                .finish_tls(&connector, server_name, tcp_stream, host, port)
                .await?;
            debug!(
                "TLS connect to {}:{} completed in {} ms",
                host,
                port,
                start.elapsed().as_millis()
            );
            return Ok(tls_stream);
        }

        let dns_resolver = self
            .dns_resolver
            .as_ref()
            .ok_or_else(|| DohProxyError::Dns("DoH resolver is not initialized".to_string()))?;

        // 1. 并行查询 ECH 配置和 IP 地址
        let (ech_config, ip_result) = if self.server_ip.is_some() {
            // server_ip 已指定，只需查 ECH 配置
            let ech_result = match dns_resolver.lookup_ech_config(host).await {
                Ok(config) => config,
                Err(e) => {
                    warn!("ECH lookup failed for {}, proceeding without ECH: {}", host, e);
                    None
                }
            };
            (ech_result, Ok(vec![self.server_ip.unwrap()]))
        } else {
            dns_resolver.lookup_ech_and_ip(host).await
        };

        #[cfg(feature = "ech")]
        if ech_config.is_some() {
            info!("ECH config found for {}, enabling ECH", host);
        } else {
            info!("No ECH config for {}, using standard TLS", host);
        }

        #[cfg(not(feature = "ech"))]
        {
            let _ = &ech_config;
        }

        // Build TLS config (with or without ECH), 使用缓存以启用 TLS 会话恢复
        let tls_config = self.get_or_build_tls_config(
            #[cfg(feature = "ech")]
            ech_config.as_ref(),
        ).await?;
        let connector = TlsConnector::from(tls_config);

        if self.upstream_proxy.as_ref().filter(|proxy| proxy.is_valid()).is_some() {
            let tcp_stream = self.connect_tcp(host, port).await?;
            let tls_stream = self
                .finish_tls(&connector, server_name, tcp_stream, host, port)
                .await?;
            debug!(
                "TLS connect to {}:{} via upstream proxy completed in {} ms",
                host,
                port,
                start.elapsed().as_millis()
            );
            return Ok(tls_stream);
        }

        // 2. Prefer recently successful IP for this host (avoid frequent IP switching)
        if let Some(cached_addr) = self.get_cached_host_ip(host).await {
            let socket_addr = SocketAddr::new(cached_addr, port);
            debug!(
                "Trying cached IP for {}:{} via {}",
                host, port, socket_addr
            );
            match self
                .try_connect(&connector, socket_addr, host, server_name.clone())
                .await
            {
                Ok(stream) => {
                    dns_resolver
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

        // 3. 使用 IP 列表连接
        let addrs = ip_result?;
        if addrs.is_empty() {
            return Err(DohProxyError::Dns(format!("No IP found for {}", host)));
        }
        let addrs = dns_resolver.order_addrs_by_rtt(addrs);

        let (v6_addrs, v4_addrs): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());
        let prefer_ipv6 = dns_resolver.prefer_ipv6();
        let (primary, secondary) = if prefer_ipv6 {
            (v6_addrs, v4_addrs)
        } else {
            (v4_addrs, v6_addrs)
        };

        // Happy Eyeballs: 主协议族先行，50ms 后启动备用协议族
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
                tokio::time::sleep(Duration::from_millis(50)).await;
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
                dns_resolver.record_ip_rtt(socket_addr.ip(), rtt);
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

    /// 获取或构建 TLS 配置（带缓存，复用以启用 TLS 会话恢复）
    #[cfg(feature = "ech")]
    async fn get_or_build_tls_config(
        &self,
        ech_config_bytes: Option<&rustls::pki_types::EchConfigListBytes<'static>>,
    ) -> Result<Arc<ClientConfig>> {
        let cache_key = match ech_config_bytes {
            Some(bytes) => format!("ech:{:?}", bytes.as_ref()),
            None => "no_ech".to_string(),
        };

        {
            let cache = self.tls_config_cache.lock().await;
            if let Some(config) = cache.get(&cache_key) {
                return Ok(config.clone());
            }
        }

        let config = self.build_tls_config(ech_config_bytes)?;

        let mut cache = self.tls_config_cache.lock().await;
        cache.insert(cache_key, config.clone());
        // 限制缓存大小
        if cache.len() > 32 {
            let keys: Vec<String> = cache.keys().cloned().collect();
            if let Some(key) = keys.first() {
                cache.remove(key);
            }
        }

        Ok(config)
    }

    /// 获取或构建 TLS 配置（无 ECH 支持版本）
    #[cfg(not(feature = "ech"))]
    async fn get_or_build_tls_config(&self) -> Result<Arc<ClientConfig>> {
        let cache_key = "no_ech".to_string();

        {
            let cache = self.tls_config_cache.lock().await;
            if let Some(config) = cache.get(&cache_key) {
                return Ok(config.clone());
            }
        }

        let config = self.build_tls_config()?;

        let mut cache = self.tls_config_cache.lock().await;
        cache.insert(cache_key, config.clone());

        Ok(config)
    }

    /// Try to establish a TLS connection with separate TCP/TLS timeouts
    async fn try_connect(
        &self,
        connector: &TlsConnector,
        addr: SocketAddr,
        tunnel_host: &str,
        server_name: ServerName<'static>,
    ) -> Result<TlsStream<BoxStream>> {
        // TCP 连接阶段：5s 超时
        let tcp_stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr),
        )
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(DohProxyError::Io)?;

        // TLS 握手阶段：10s 超时
        tokio::time::timeout(
            Duration::from_secs(10),
            self.finish_tls(
                connector,
                server_name,
                Box::new(tcp_stream),
                tunnel_host,
                addr.port(),
            ),
        )
            .await
            .map_err(|_| DohProxyError::Timeout)?
    }

    /// 交错并行连接多个地址，每个地址间 250ms 延迟启动，先成功者胜出
    async fn connect_to_addrs(
        &self,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
        host: &str,
        port: u16,
        addrs: Vec<std::net::IpAddr>,
    ) -> Result<(TlsStream<BoxStream>, SocketAddr, Duration)> {
        if addrs.is_empty() {
            return Err(DohProxyError::Proxy(format!("No addresses for {}:{}", host, port)));
        }

        // 只有一个地址时直接连接
        if addrs.len() == 1 {
            let socket_addr = SocketAddr::new(addrs[0], port);
            debug!("Trying to connect to {}:{} via {}", host, port, socket_addr);
            let attempt_start = std::time::Instant::now();
            let stream = self.try_connect(connector, socket_addr, host, server_name).await?;
            return Ok((stream, socket_addr, attempt_start.elapsed()));
        }

        // 多地址交错并行：每个地址延迟 250ms 启动
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::channel(1);
        let attempt_start = std::time::Instant::now();

        for (i, addr) in addrs.iter().enumerate() {
            let socket_addr = SocketAddr::new(*addr, port);
            let connector = connector.clone();
            let server_name = server_name.clone();
            let host = host.to_string();
            let tx = tx.clone();

            tokio::spawn(async move {
                if i > 0 {
                    tokio::time::sleep(Duration::from_millis(250 * i as u64)).await;
                }
                debug!("Trying to connect to {}:{} via {}", host, port, socket_addr);
                let start = std::time::Instant::now();
                // TCP 连接：5s 超时
                let tcp_result = tokio::time::timeout(
                    Duration::from_secs(5),
                    TcpStream::connect(socket_addr),
                ).await;
                let tcp_stream = match tcp_result {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!("TCP connect failed to {}: {}", socket_addr, e);
                        let _ = tx.send(Err(DohProxyError::Io(e))).await;
                        return;
                    }
                    Err(_) => {
                        warn!("TCP connect timed out to {}", socket_addr);
                        let _ = tx.send(Err(DohProxyError::Timeout)).await;
                        return;
                    }
                };
                // TLS 握手：10s 超时
                let tls_result = tokio::time::timeout(
                    Duration::from_secs(10),
                    connector.connect(server_name, Box::new(tcp_stream) as BoxStream),
                ).await;
                match tls_result {
                    Ok(Ok(stream)) => {
                        let rtt = start.elapsed();
                        let _ = tx.send(Ok((stream, socket_addr, rtt))).await;
                    }
                    Ok(Err(e)) => {
                        warn!("TLS handshake failed to {}: {}", socket_addr, e);
                        let _ = tx.send(Err(DohProxyError::Io(e))).await;
                    }
                    Err(_) => {
                        warn!("TLS handshake timed out to {}", socket_addr);
                        let _ = tx.send(Err(DohProxyError::Timeout)).await;
                    }
                }
            });
        }
        drop(tx);

        let mut last_error = None;
        let total = addrs.len();
        let mut received = 0;
        while let Some(result) = rx.recv().await {
            received += 1;
            match result {
                Ok((stream, socket_addr, rtt)) => {
                    debug!(
                        "Connected to {}:{} via {} in {} ms",
                        host, port, socket_addr, attempt_start.elapsed().as_millis()
                    );
                    return Ok((stream, socket_addr, rtt));
                }
                Err(e) => {
                    last_error = Some(e);
                    if received >= total {
                        break;
                    }
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

    async fn finish_tls(
        &self,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
        tcp_stream: BoxStream,
        host: &str,
        port: u16,
    ) -> Result<TlsStream<BoxStream>> {
        let tls_stream = tokio::time::timeout(self.timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| DohProxyError::Timeout)?
            .map_err(|e| DohProxyError::Io(e))?;

        let (_, conn) = tls_stream.get_ref();
        debug!(
            "TLS connection established for {}:{}, protocol: {:?}",
            host,
            port,
            conn.protocol_version()
        );

        Ok(tls_stream)
    }
}
