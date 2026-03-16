//! DOH Proxy - DNS over HTTPS proxy with ECH support
//!
//! This library provides a local HTTP/HTTPS proxy that uses DOH for DNS
//! resolution and supports ECH to encrypt the SNI field in TLS handshakes.

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod cert;
pub mod dns;
pub mod ech;
pub mod error;
pub mod ffi;
pub mod proxy;
pub mod tls_crypto;
pub mod upstream;

pub use error::DohProxyError;
pub use proxy::DohProxyServer;

/// Upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxyConfig {
    /// Upstream proxy protocol. Supports `http`, `socks5` and `shadowsocks`.
    #[serde(default = "default_upstream_protocol")]
    pub protocol: String,
    /// Upstream proxy host
    pub host: String,
    /// Upstream proxy port
    pub port: u16,
    /// Optional username
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password
    #[serde(default)]
    pub password: Option<String>,
    /// Optional cipher for Shadowsocks
    #[serde(default)]
    pub cipher: Option<String>,
}

impl UpstreamProxyConfig {
    pub fn is_valid(&self) -> bool {
        if self.host.trim().is_empty() || self.port == 0 {
            return false;
        }

        if self.is_shadowsocks() {
            let cipher = self
                .cipher
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            let password = self
                .password
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            if cipher.is_empty() || password.is_empty() {
                return false;
            }

            if cipher.eq_ignore_ascii_case("2022-blake3-aes-256-gcm") {
                let normalized_password = normalize_base64_padding(password);
                let decoded = STANDARD
                    .decode(normalized_password.as_bytes())
                    .or_else(|_| URL_SAFE.decode(normalized_password.as_bytes()));
                let Ok(decoded) = decoded else {
                    return false;
                };
                return decoded.len() == 32;
            }

            return true;
        }

        true
    }

    pub fn protocol(&self) -> &str {
        let protocol = self.protocol.trim();
        if protocol.is_empty() {
            "http"
        } else {
            protocol
        }
    }

    pub fn is_http(&self) -> bool {
        self.protocol().eq_ignore_ascii_case("http")
    }

    pub fn is_socks5(&self) -> bool {
        matches!(
            self.protocol().to_ascii_lowercase().as_str(),
            "socks" | "socks5" | "socks5h"
        )
    }

    pub fn is_shadowsocks(&self) -> bool {
        matches!(
            self.protocol().to_ascii_lowercase().as_str(),
            "ss" | "shadowsocks"
        )
    }
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Local address to bind (default: 127.0.0.1)
    pub bind_addr: String,
    /// Local port to bind (default: 0 for auto-select)
    pub bind_port: u16,
    /// Whether local gateway should use DoH/ECH MITM mode
    #[serde(default = "default_enable_doh")]
    pub enable_doh: bool,
    /// DOH server URL for DNS queries
    pub doh_server: String,
    /// Whether to prefer IPv6
    pub prefer_ipv6: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Optional upstream proxy configuration
    #[serde(default)]
    pub upstream_proxy: Option<UpstreamProxyConfig>,
    /// Optional server IP address to connect directly, skipping DNS resolution
    #[serde(default)]
    pub server_ip: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 0,
            enable_doh: true,
            doh_server: "https://cloudflare-dns.com/dns-query".to_string(),
            prefer_ipv6: false,
            timeout_secs: 30,
            upstream_proxy: None,
            server_ip: None,
        }
    }
}

fn default_upstream_protocol() -> String {
    "http".to_string()
}

fn default_enable_doh() -> bool {
    true
}

fn normalize_base64_padding(input: &str) -> String {
    let trimmed = input.trim();
    let remainder = trimmed.len() % 4;
    if remainder == 0 {
        return trimmed.to_string();
    }

    let mut normalized = String::with_capacity(trimmed.len() + (4 - remainder));
    normalized.push_str(trimmed);
    for _ in 0..(4 - remainder) {
        normalized.push('=');
    }
    normalized
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

pub type BoxStream = Box<dyn AsyncReadWrite>;
