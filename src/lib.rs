//! DOH Proxy - DNS over HTTPS proxy with ECH support
//!
//! This library provides a local HTTP/HTTPS proxy that uses DOH for DNS
//! resolution and supports ECH to encrypt the SNI field in TLS handshakes.

pub mod cert;
pub mod dns;
pub mod ech;
pub mod error;
pub mod ffi;
pub mod proxy;
pub mod tls_crypto;

pub use error::DohProxyError;
pub use proxy::DohProxyServer;

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Local address to bind (default: 127.0.0.1)
    pub bind_addr: String,
    /// Local port to bind (default: 0 for auto-select)
    pub bind_port: u16,
    /// DOH server URL for DNS queries
    pub doh_server: String,
    /// Whether to prefer IPv6
    pub prefer_ipv6: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 0,
            doh_server: "https://cloudflare-dns.com/dns-query".to_string(),
            prefer_ipv6: false,
            timeout_secs: 30,
        }
    }
}
