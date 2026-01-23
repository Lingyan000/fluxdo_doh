//! Error types for DOH proxy

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DohProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("ECH config not found for domain: {0}")]
    EchConfigNotFound(String),

    #[error("ECH not supported by server: {0}")]
    EchNotSupported(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Certificate error: {0}")]
    Certificate(String),
}

pub type Result<T> = std::result::Result<T, DohProxyError>;
