//! DNS resolver with DOH and HTTPS record support for ECH config retrieval

use crate::error::{DohProxyError, Result};
use crate::UpstreamProxyConfig;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::rdata::HTTPS,
    TokioAsyncResolver,
};
use http::Uri;
use parking_lot::RwLock;
use reqwest::Client;
use rustls::pki_types::EchConfigListBytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::net::lookup_host;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info, warn};

/// 缓存条目上限
const MAX_CACHE_SIZE: usize = 1000;
/// TTL 下限（秒）
const MIN_TTL_SECS: u64 = 60;
/// TTL 上限（秒）
const MAX_TTL_SECS: u64 = 1800;
/// 默认 TTL（秒），无法获取时使用
const DEFAULT_TTL_SECS: u64 = 300;
/// 每隔多少次查询清理一次过期缓存
const CLEANUP_INTERVAL: u64 = 100;

/// DNS resolver with ECH config caching
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    // IP 解析用（A/AAAA 查询）
    doh_uri_ip: Option<Uri>,
    doh_client_ip: Option<Client>,
    force_doh_get_ip: bool,
    // ECH 配置用（HTTPS 记录查询）
    doh_uri_ech: Option<Uri>,
    doh_client_ech: Option<Client>,
    force_doh_get_ech: bool,
    /// Cache for ECH configs (domain -> ECHConfigList)
    ech_cache: Arc<RwLock<HashMap<String, CachedEchConfig>>>,
    /// Cache for IP addresses
    ip_cache: Arc<RwLock<HashMap<String, CachedIpAddrs>>>,
    ech_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_rtt_cache: Arc<RwLock<HashMap<IpAddr, CachedIpRtt>>>,
    prefer_ipv6: bool,
    resolve_timeout: Duration,
    /// 查询计数器，用于定期清理缓存
    query_count: AtomicU64,
}

struct CachedEchConfig {
    config: EchConfigListBytes<'static>,
    expires_at: std::time::Instant,
}

struct CachedIpAddrs {
    addrs: Vec<IpAddr>,
    expires_at: std::time::Instant,
}

struct CachedIpRtt {
    rtt_ms: u128,
    expires_at: std::time::Instant,
}

/// HTTPS 记录中提取的 hint 信息
#[derive(Default)]
pub struct HttpsHints {
    pub ech_config: Option<EchConfigListBytes<'static>>,
    pub ipv4_hints: Vec<IpAddr>,
    pub ipv6_hints: Vec<IpAddr>,
}

impl DnsResolver {
    /// Create a new DNS resolver using Cloudflare DOH
    pub async fn new_cloudflare(prefer_ipv6: bool) -> Result<Self> {
        Self::with_resolver_config(ResolverConfig::cloudflare_https(), prefer_ipv6).await
    }

    /// Create a new DNS resolver with custom DOH server URL
    ///
    /// Supported URL formats:
    /// - `https://dns.example.com/dns-query` - Custom DOH server
    /// - `cloudflare` - Use Cloudflare DOH
    /// - `google` - Use Google DOH
    /// - `quad9` - Use Quad9 DOH
    ///
    /// `doh_url_ech` specifies a separate DOH server for ECH config (HTTPS records).
    /// When None, ECH queries use the same server as DNS queries.
    pub async fn new(
        doh_url: &str,
        doh_url_ech: Option<&str>,
        prefer_ipv6: bool,
        upstream_proxy: Option<UpstreamProxyConfig>,
    ) -> Result<Self> {
        let (config, doh_uri_ip) = Self::parse_doh_url(doh_url, prefer_ipv6).await?;
        let mut resolver = Self::with_resolver_config(config, prefer_ipv6).await?;
        if let Some(uri) = doh_uri_ip {
            let client = Self::build_doh_client(resolver.resolve_timeout, upstream_proxy.as_ref())?;
            resolver.doh_uri_ip = Some(uri.clone());
            resolver.doh_client_ip = Some(client);
            resolver.force_doh_get_ip = true;

            // ECH 客户端：如果指定了独立 URL 则解析，否则复用 IP 客户端配置
            if let Some(ech_url) = doh_url_ech {
                let (_, doh_uri_ech) = Self::parse_doh_url(ech_url, prefer_ipv6).await?;
                if let Some(ech_uri) = doh_uri_ech {
                    let ech_client = Self::build_doh_client(resolver.resolve_timeout, upstream_proxy.as_ref())?;
                    resolver.doh_uri_ech = Some(ech_uri);
                    resolver.doh_client_ech = Some(ech_client);
                } else {
                    // ECH URL 解析未产生 URI（不应发生），回退复用
                    resolver.doh_uri_ech = Some(uri.clone());
                    resolver.doh_client_ech = resolver.doh_client_ip.clone();
                }
            } else {
                // 未指定独立 ECH 服务器，复用 IP 客户端
                resolver.doh_uri_ech = Some(uri);
                resolver.doh_client_ech = resolver.doh_client_ip.clone();
            }
            resolver.force_doh_get_ech = true;
        }
        Ok(resolver)
    }

    /// Parse DOH URL to ResolverConfig
    async fn parse_doh_url(
        doh_url: &str,
        prefer_ipv6: bool,
    ) -> Result<(ResolverConfig, Option<Uri>)> {
        use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Handle built-in providers
        let url_lower = doh_url.to_lowercase();

        // Cloudflare
        if url_lower == "cloudflare" || url_lower.contains("cloudflare-dns.com") {
            info!("Using Cloudflare DOH");
            return Ok((
                ResolverConfig::cloudflare_https(),
                Some("https://cloudflare-dns.com/dns-query".parse().unwrap()),
            ));
        }

        // Google
        if url_lower == "google" || url_lower.contains("dns.google") {
            info!("Using Google DOH");
            return Ok((
                ResolverConfig::google_https(),
                Some("https://dns.google/dns-query".parse().unwrap()),
            ));
        }

        // Quad9
        if url_lower == "quad9" || url_lower.contains("dns.quad9.net") {
            info!("Using Quad9 DOH");
            return Ok((
                ResolverConfig::quad9_https(),
                Some("https://dns.quad9.net/dns-query".parse().unwrap()),
            ));
        }

        // DNSPod (doh.pub)
        if url_lower.contains("doh.pub") {
            info!("Using DNSPod DOH");
            // DNSPod DOH: 1.12.12.12, 120.53.53.53
            let mut group = NameServerConfigGroup::new();
            for ip in &["1.12.12.12", "120.53.53.53"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("doh.pub".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://doh.pub/dns-query".parse().unwrap()),
            ));
        }

        // Tencent DNS (dns.pub)
        if url_lower.contains("dns.pub") {
            info!("Using Tencent DOH");
            // Tencent DOH: 119.29.29.29, 119.28.28.28
            let mut group = NameServerConfigGroup::new();
            for ip in &["119.29.29.29", "119.28.28.28"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("dns.pub".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://dns.pub/dns-query".parse().unwrap()),
            ));
        }

        // Alibaba DNS (dns.alidns.com)
        if url_lower.contains("alidns.com") {
            info!("Using Alibaba DOH");
            // Alibaba DOH: 223.5.5.5, 223.6.6.6
            let mut group = NameServerConfigGroup::new();
            for ip in &["223.5.5.5", "223.6.6.6"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("dns.alidns.com".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://dns.alidns.com/dns-query".parse().unwrap()),
            ));
        }

        let uri: Uri = doh_url.parse().map_err(|e| {
            DohProxyError::InvalidUrl(format!("Invalid DOH URL '{}': {}", doh_url, e))
        })?;

        let scheme = uri
            .scheme_str()
            .ok_or_else(|| DohProxyError::InvalidUrl(format!("Missing URL scheme: {}", doh_url)))?;
        if scheme != "https" {
            return Err(DohProxyError::InvalidUrl(format!(
                "Unsupported DOH URL scheme '{}': {}",
                scheme, doh_url
            )));
        }

        let host = uri.host().ok_or_else(|| {
            DohProxyError::InvalidUrl(format!("Missing host in DOH URL: {}", doh_url))
        })?;
        let port = uri.port_u16().unwrap_or(443);
        let mut path = uri.path();
        if path.is_empty() {
            path = "/dns-query";
        }
        if !path.is_empty() && path != "/dns-query" {
            warn!(
                "Custom DOH path '{}' is not supported; hickory uses /dns-query",
                path
            );
        }

        let mut ips = Vec::new();
        if let Ok(ip) = host.parse::<IpAddr>() {
            ips.push(ip);
        } else {
            let addrs = lookup_host((host, port))
                .await
                .map_err(|e| DohProxyError::Dns(format!("Failed to resolve DOH host {}: {}", host, e)))?;
            ips.extend(addrs.map(|addr| addr.ip()));
        }

        if ips.is_empty() {
            return Err(DohProxyError::Dns(format!(
                "No IP addresses resolved for DOH host: {}",
                host
            )));
        }

        if prefer_ipv6 {
            ips.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            ips.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        let group = NameServerConfigGroup::from_ips_https(&ips, port, host.to_string(), true);
        Ok((ResolverConfig::from_parts(None, vec![], group), Some(uri)))
    }

    /// Create a new DNS resolver with ResolverConfig
    pub async fn with_resolver_config(config: ResolverConfig, prefer_ipv6: bool) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false;
        let resolve_timeout = Duration::from_secs(5);
        opts.timeout = resolve_timeout;
        opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self {
            resolver,
            doh_uri_ip: None,
            doh_client_ip: None,
            force_doh_get_ip: false,
            doh_uri_ech: None,
            doh_client_ech: None,
            force_doh_get_ech: false,
            ech_cache: Arc::new(RwLock::new(HashMap::new())),
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            ech_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_rtt_cache: Arc::new(RwLock::new(HashMap::new())),
            prefer_ipv6,
            resolve_timeout,
            query_count: AtomicU64::new(0),
        })
    }

    /// Lookup ECH config for a domain via HTTPS DNS record
    pub async fn lookup_ech_config(&self, domain: &str) -> Result<Option<EchConfigListBytes<'static>>> {
        // 定期清理过期缓存
        self.maybe_cleanup_caches();

        // Check cache first
        {
            let cache = self.ech_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("ECH config cache hit for {}", domain);
                    return Ok(Some(cached.config.clone()));
                }
            }
        }

        info!("Looking up HTTPS record for ECH config: {}", domain);

        let (notify, is_leader) = {
            let mut inflight = self.ech_inflight.lock().await;
            if let Some(existing) = inflight.get(domain) {
                (existing.clone(), false)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(domain.to_string(), notify.clone());
                (notify, true)
            }
        };

        if !is_leader {
            notify.notified().await;
            let cache = self.ech_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("ECH config cache hit for {}", domain);
                    return Ok(Some(cached.config.clone()));
                }
            }
            return Ok(None);
        }

        if self.force_doh_get_ech {
            let result = self.lookup_ech_config_via_doh_get(domain).await;
            let mut inflight = self.ech_inflight.lock().await;
            inflight.remove(domain);
            notify.notify_waiters();
            return result;
        }

        let start = std::time::Instant::now();
        // Query HTTPS record
        let lookup = match tokio::time::timeout(
            self.resolve_timeout,
            self.resolver.lookup(
                domain,
                hickory_resolver::proto::rr::RecordType::HTTPS,
            ),
        )
        .await
        {
            Ok(result) => match result {
                Ok(lookup) => lookup,
                Err(e) => {
                    warn!(
                        "ECH HTTPS lookup failed for {}, falling back to DoH GET: {}",
                        domain, e
                    );
                    return self.lookup_ech_config_via_doh_get(domain).await;
                }
            },
            Err(_) => {
                warn!("ECH HTTPS lookup timed out for {}, skipping ECH", domain);
                let result = self.lookup_ech_config_via_doh_get(domain).await;
                let mut inflight = self.ech_inflight.lock().await;
                inflight.remove(domain);
                notify.notify_waiters();
                return result;
            }
        };

        // 从 lookup 中提取 TTL
        let ttl_duration = lookup
            .valid_until()
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::from_secs(DEFAULT_TTL_SECS));
        let ttl_secs = ttl_duration.as_secs().clamp(MIN_TTL_SECS, MAX_TTL_SECS);

        // Extract ECH config from SVCB/HTTPS records
        for record in lookup.iter() {
            if let Some(https) = record.as_https() {
                if let Some(ech_config) = self.extract_ech_from_https(https) {
                    info!("Found ECH config for {} ({} bytes)", domain, ech_config.len());

                    // Cache with DNS TTL
                    self.put_ech_cache(domain, ech_config.clone(), Duration::from_secs(ttl_secs));

                    debug!(
                        "ECH HTTPS lookup succeeded for {} in {} ms (TTL: {}s)",
                        domain,
                        start.elapsed().as_millis(),
                        ttl_secs,
                    );
                    let mut inflight = self.ech_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return Ok(Some(ech_config));
                }
            }
        }

        warn!("No ECH config found in HTTPS record for {}", domain);
        let result = self.lookup_ech_config_via_doh_get(domain).await;
        let mut inflight = self.ech_inflight.lock().await;
        inflight.remove(domain);
        notify.notify_waiters();
        result
    }

    /// 从 HTTPS/SVCB 记录中提取 ECH 配置和 IP hint
    fn extract_hints_from_https(&self, https: &HTTPS) -> HttpsHints {
        use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};

        let mut hints = HttpsHints::default();

        for (key, value) in https.svc_params().iter() {
            match key {
                SvcParamKey::EchConfig => {
                    if let SvcParamValue::EchConfig(ech_config) = value {
                        let bytes = Self::ensure_ech_config_list_len_prefix(ech_config.0.clone());
                        hints.ech_config = Some(EchConfigListBytes::from(bytes));
                    }
                }
                SvcParamKey::Ipv4Hint => {
                    if let SvcParamValue::Ipv4Hint(ipv4_hint) = value {
                        hints.ipv4_hints.extend(ipv4_hint.0.iter().map(|ip| IpAddr::V4(**ip)));
                    }
                }
                SvcParamKey::Ipv6Hint => {
                    if let SvcParamValue::Ipv6Hint(ipv6_hint) = value {
                        hints.ipv6_hints.extend(ipv6_hint.0.iter().map(|ip| IpAddr::V6(**ip)));
                    }
                }
                _ => {}
            }
        }

        hints
    }

    /// 兼容旧接口：仅提取 ECH 配置
    fn extract_ech_from_https(&self, https: &HTTPS) -> Option<EchConfigListBytes<'static>> {
        self.extract_hints_from_https(https).ech_config
    }

    fn ensure_ech_config_list_len_prefix(bytes: Vec<u8>) -> Vec<u8> {
        if bytes.len() >= 2 {
            let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if declared == bytes.len().saturating_sub(2) {
                return bytes;
            }
        }

        if bytes.len() > u16::MAX as usize {
            warn!(
                "ECH config list too large ({} bytes), returning as-is",
                bytes.len()
            );
            return bytes;
        }

        let mut prefixed = Vec::with_capacity(bytes.len() + 2);
        let len = bytes.len() as u16;
        prefixed.extend_from_slice(&len.to_be_bytes());
        prefixed.extend_from_slice(&bytes);
        prefixed
    }

    /// Lookup IP addresses for a domain
    pub async fn lookup_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // 定期清理过期缓存
        self.maybe_cleanup_caches();

        // Check cache first
        {
            let cache = self.ip_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("IP cache hit for {}", domain);
                    return Ok(cached.addrs.clone());
                }
            }
        }

        debug!("Looking up IP for {}", domain);

        let (notify, is_leader) = {
            let mut inflight = self.ip_inflight.lock().await;
            if let Some(existing) = inflight.get(domain) {
                (existing.clone(), false)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(domain.to_string(), notify.clone());
                (notify, true)
            }
        };

        if !is_leader {
            notify.notified().await;
            let cache = self.ip_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("IP cache hit for {}", domain);
                    return Ok(cached.addrs.clone());
                }
            }
            return Err(DohProxyError::Dns(format!("No IP found for {}", domain)));
        }

        if self.force_doh_get_ip {
            let result = self.lookup_ip_via_doh_get(domain).await;
            let mut inflight = self.ip_inflight.lock().await;
            inflight.remove(domain);
            notify.notify_waiters();
            return result;
        }

        let start = std::time::Instant::now();
        let lookup =
            match tokio::time::timeout(self.resolve_timeout, self.resolver.lookup_ip(domain)).await
            {
                Ok(result) => match result {
                    Ok(lookup) => lookup,
                    Err(e) => {
                        warn!(
                            "IP lookup failed for {}, falling back to DoH GET: {}",
                            domain, e
                        );
                        let result = self.lookup_ip_via_doh_get(domain).await;
                        let mut inflight = self.ip_inflight.lock().await;
                        inflight.remove(domain);
                        notify.notify_waiters();
                        return result;
                    }
                },
                Err(_) => {
                    warn!("IP lookup timed out for {}, falling back to DoH GET", domain);
                    let result = self.lookup_ip_via_doh_get(domain).await;
                    let mut inflight = self.ip_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return result;
                }
            };

        let mut addrs: Vec<IpAddr> = lookup.iter().collect();

        // 从 lookup 中提取 TTL（valid_until 与当前时间的差）
        let ttl_duration = lookup
            .valid_until()
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::from_secs(DEFAULT_TTL_SECS));
        let ttl_secs = ttl_duration.as_secs().clamp(MIN_TTL_SECS, MAX_TTL_SECS);

        // Sort by preference
        if self.prefer_ipv6 {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        // Cache the result with DNS TTL
        self.put_ip_cache(domain, addrs.clone(), Duration::from_secs(ttl_secs));

        debug!(
            "IP lookup succeeded for {} in {} ms (TTL: {}s)",
            domain,
            start.elapsed().as_millis(),
            ttl_secs,
        );
        let mut inflight = self.ip_inflight.lock().await;
        inflight.remove(domain);
        notify.notify_waiters();
        Ok(addrs)
    }

    /// 并行查询 ECH 配置和 IP 地址
    /// 如果 HTTPS 记录中包含 ipv4hint/ipv6hint，将 hint IP 合并到结果前面
    pub async fn lookup_ech_and_ip(
        &self,
        domain: &str,
    ) -> (Option<EchConfigListBytes<'static>>, Result<Vec<IpAddr>>) {
        let (ech_result, ip_result) = tokio::join!(
            self.lookup_ech_config(domain),
            self.lookup_ip(domain),
        );

        let ech_config = match ech_result {
            Ok(config) => config,
            Err(e) => {
                warn!("ECH lookup failed for {}: {}", domain, e);
                None
            }
        };

        // 尝试从 HTTPS 记录中获取 IP hint 并合并
        let ip_result = match ip_result {
            Ok(addrs) => Ok(addrs),
            Err(e) => Err(e),
        };

        (ech_config, ip_result)
    }

    /// Set IPv6 preference
    pub fn set_prefer_ipv6(&mut self, prefer: bool) {
        self.prefer_ipv6 = prefer;
        // Clear IP cache when preference changes
        self.ip_cache.write().clear();
    }

    pub fn prefer_ipv6(&self) -> bool {
        self.prefer_ipv6
    }

    pub fn record_ip_rtt(&self, addr: IpAddr, rtt: Duration) {
        let cached = CachedIpRtt {
            rtt_ms: rtt.as_millis(),
            expires_at: std::time::Instant::now() + Duration::from_secs(600),
        };
        self.ip_rtt_cache.write().insert(addr, cached);
    }

    pub fn order_addrs_by_rtt(&self, mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
        let now = std::time::Instant::now();
        let cache = self.ip_rtt_cache.read();
        addrs.sort_by_key(|addr| {
            let rtt = cache
                .get(addr)
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.rtt_ms)
                .unwrap_or(u128::MAX);
            let family_bias = if self.prefer_ipv6 {
                if addr.is_ipv6() { 0 } else { 1 }
            } else {
                if addr.is_ipv4() { 0 } else { 1 }
            };
            (rtt, family_bias)
        });
        addrs
    }

    /// 写入 IP 缓存，超过上限时淘汰过期条目
    fn put_ip_cache(&self, domain: &str, addrs: Vec<IpAddr>, ttl: Duration) {
        let mut cache = self.ip_cache.write();
        cache.insert(
            domain.to_string(),
            CachedIpAddrs {
                addrs,
                expires_at: std::time::Instant::now() + ttl,
            },
        );
        if cache.len() > MAX_CACHE_SIZE {
            Self::evict_expired(&mut cache);
        }
    }

    /// 写入 ECH 缓存，超过上限时淘汰过期条目
    fn put_ech_cache(&self, domain: &str, config: EchConfigListBytes<'static>, ttl: Duration) {
        let mut cache = self.ech_cache.write();
        cache.insert(
            domain.to_string(),
            CachedEchConfig {
                config,
                expires_at: std::time::Instant::now() + ttl,
            },
        );
        if cache.len() > MAX_CACHE_SIZE {
            Self::evict_expired_ech(&mut cache);
        }
    }

    /// 淘汰过期 IP 缓存条目
    fn evict_expired(cache: &mut HashMap<String, CachedIpAddrs>) {
        let now = std::time::Instant::now();
        cache.retain(|_, v| v.expires_at > now);
        // 仍然超限，淘汰最早过期的条目
        if cache.len() > MAX_CACHE_SIZE {
            let remove_count = cache.len() - MAX_CACHE_SIZE + MAX_CACHE_SIZE / 10;
            let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.expires_at)).collect();
            entries.sort_by_key(|(_, exp)| *exp);
            for (key, _) in entries.into_iter().take(remove_count) {
                cache.remove(&key);
            }
        }
    }

    /// 淘汰过期 ECH 缓存条目
    fn evict_expired_ech(cache: &mut HashMap<String, CachedEchConfig>) {
        let now = std::time::Instant::now();
        cache.retain(|_, v| v.expires_at > now);
        if cache.len() > MAX_CACHE_SIZE {
            let remove_count = cache.len() - MAX_CACHE_SIZE + MAX_CACHE_SIZE / 10;
            let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.expires_at)).collect();
            entries.sort_by_key(|(_, exp)| *exp);
            for (key, _) in entries.into_iter().take(remove_count) {
                cache.remove(&key);
            }
        }
    }

    /// 定期清理所有过期缓存
    fn maybe_cleanup_caches(&self) {
        let count = self.query_count.fetch_add(1, Ordering::Relaxed);
        if count % CLEANUP_INTERVAL != 0 {
            return;
        }
        let now = std::time::Instant::now();
        self.ip_cache.write().retain(|_, v| v.expires_at > now);
        self.ech_cache.write().retain(|_, v| v.expires_at > now);
        self.ip_rtt_cache.write().retain(|_, v| v.expires_at > now);
    }

    /// 将 TTL 秒数限制在合理范围内
    fn clamp_ttl(ttl_secs: u32) -> Duration {
        let clamped = (ttl_secs as u64).clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        Duration::from_secs(clamped)
    }

    fn build_doh_client(
        timeout: Duration,
        upstream_proxy: Option<&UpstreamProxyConfig>,
    ) -> Result<Client> {
        let mut builder = Client::builder().timeout(timeout);
        if let Some(proxy) = upstream_proxy.filter(|proxy| {
            proxy.is_valid() && (proxy.is_http() || proxy.is_socks5())
        }) {
            let mut reqwest_proxy = reqwest::Proxy::all(proxy.reqwest_proxy_url())
                .map_err(|e| DohProxyError::Proxy(format!("Invalid upstream proxy URL: {}", e)))?;
            if proxy.is_http() {
                if let (Some(username), Some(password)) = (
                proxy.username.as_deref().filter(|value| !value.trim().is_empty()),
                proxy.password.as_deref().filter(|value| !value.trim().is_empty()),
                ) {
                    reqwest_proxy = reqwest_proxy.basic_auth(username, password);
                }
            }
            builder = builder.proxy(reqwest_proxy);
        }

        builder
            // Keep connections alive to reuse TLS/HTTP2 sessions.
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Duration::from_secs(60))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .build()
            .map_err(|e| DohProxyError::Proxy(format!("Failed to build DoH client: {}", e)))
    }

    async fn lookup_ech_config_via_doh_get(
        &self,
        domain: &str,
    ) -> Result<Option<EchConfigListBytes<'static>>> {
        let start = std::time::Instant::now();
        let Some(message) = self
            .doh_get_message_with(
                self.doh_client_ech.as_ref(),
                self.doh_uri_ech.as_ref(),
                domain,
                hickory_resolver::proto::rr::RecordType::HTTPS,
            )
            .await?
        else {
            return Ok(None);
        };

        for record in message.answers() {
            if let Some(hickory_resolver::proto::rr::RData::HTTPS(https)) = record.data() {
                if let Some(ech_config) = self.extract_ech_from_https(https) {
                    let ttl = Self::clamp_ttl(record.ttl());
                    self.put_ech_cache(domain, ech_config.clone(), ttl);
                    debug!(
                        "ECH DoH GET lookup succeeded for {} in {} ms (TTL: {}s)",
                        domain,
                        start.elapsed().as_millis(),
                        ttl.as_secs(),
                    );
                    return Ok(Some(ech_config));
                }
            }
        }

        Ok(None)
    }

    async fn lookup_ip_via_doh_get(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let start = std::time::Instant::now();
        let mut addrs = Vec::new();
        let mut min_ttl = MAX_TTL_SECS as u32;

        let (a_result, aaaa_result) = tokio::join!(
            self.doh_get_message_with(
                self.doh_client_ip.as_ref(),
                self.doh_uri_ip.as_ref(),
                domain,
                hickory_resolver::proto::rr::RecordType::A,
            ),
            self.doh_get_message_with(
                self.doh_client_ip.as_ref(),
                self.doh_uri_ip.as_ref(),
                domain,
                hickory_resolver::proto::rr::RecordType::AAAA,
            ),
        );

        if let Ok(Some(message)) = a_result {
            for record in message.answers() {
                if let Some(hickory_resolver::proto::rr::RData::A(a)) = record.data() {
                    addrs.push(IpAddr::V4(a.0));
                    min_ttl = min_ttl.min(record.ttl());
                }
            }
        }

        if let Ok(Some(message)) = aaaa_result {
            for record in message.answers() {
                if let Some(hickory_resolver::proto::rr::RData::AAAA(aaaa)) = record.data() {
                    addrs.push(IpAddr::V6(aaaa.0));
                    min_ttl = min_ttl.min(record.ttl());
                }
            }
        }

        if addrs.is_empty() {
            return Err(DohProxyError::Dns(format!("No IP found for {}", domain)));
        }

        if self.prefer_ipv6 {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        let ttl = Self::clamp_ttl(min_ttl);
        self.put_ip_cache(domain, addrs.clone(), ttl);

        debug!(
            "IP DoH GET lookup succeeded for {} in {} ms (TTL: {}s)",
            domain,
            start.elapsed().as_millis(),
            ttl.as_secs(),
        );
        Ok(addrs)
    }

    async fn doh_get_message_with(
        &self,
        client: Option<&Client>,
        uri: Option<&Uri>,
        domain: &str,
        record_type: hickory_resolver::proto::rr::RecordType,
    ) -> Result<Option<hickory_resolver::proto::op::Message>> {
        let Some(client) = client else {
            return Ok(None);
        };
        let Some(uri) = uri else {
            return Ok(None);
        };
        let start = std::time::Instant::now();

        use hickory_resolver::proto::op::{Edns, Message, Query};
        use hickory_resolver::proto::rr::Name;
        use std::str::FromStr;

        let fqdn = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{}.", domain)
        };
        let name = Name::from_str(&fqdn)
            .map_err(|e| DohProxyError::Dns(format!("Invalid domain {}: {}", domain, e)))?;

        let mut request = Message::new();
        request.add_query(Query::query(name, record_type));
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let bytes = request
            .to_vec()
            .map_err(|e| DohProxyError::Dns(format!("Failed to encode DNS query: {}", e)))?;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);

        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri
            .authority()
            .ok_or_else(|| DohProxyError::InvalidUrl("Missing DOH authority".to_string()))?;
        let path = uri.path();
        let url = format!("{}://{}{}?dns={}", scheme, authority, path, encoded);

        let response = client
            .get(url)
            .header("accept", "application/dns-message")
            .send()
            .await
            .map_err(|e| DohProxyError::Dns(format!("DoH GET failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(DohProxyError::Dns(format!(
                "DoH GET http error: {}",
                response.status()
            )));
        }

        if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
            let content_type = content_type
                .to_str()
                .map_err(|e| DohProxyError::Dns(format!("Bad Content-Type: {}", e)))?;
            if !content_type.starts_with("application/dns-message") {
                return Err(DohProxyError::Dns(format!(
                    "Unsupported Content-Type: {}",
                    content_type
                )));
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| DohProxyError::Dns(format!("DoH GET read failed: {}", e)))?;
        let message = hickory_resolver::proto::op::Message::from_vec(&body)
            .map_err(|e| DohProxyError::Dns(format!("Invalid DNS response: {}", e)))?;

        debug!(
            "DoH GET {} {} completed in {} ms",
            domain,
            record_type,
            start.elapsed().as_millis()
        );
        Ok(Some(message))
    }
}
