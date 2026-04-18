//! Certificate generation for MITM proxy
//!
//! This module handles:
//! - Loading the embedded CA certificate
//! - Dynamically generating certificates for target domains

use crate::error::{DohProxyError, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, info};

/// Embedded CA certificate (PEM format)
/// This is generated once and bundled with the app
const CA_CERT_PEM: &str = include_str!("../certs/ca.crt");
const CA_KEY_PEM: &str = include_str!("../certs/ca.key");

/// Certificate manager for MITM proxy
pub struct CertManager {
    /// CA key pair for signing
    ca_key_pair: KeyPair,
    /// CA certificate for signing
    ca_cert: Certificate,
    /// CA cert in DER format
    ca_cert_der: CertificateDer<'static>,
    /// Cache of generated certificates
    cert_cache: RwLock<HashMap<String, Arc<ServerConfig>>>,
    /// Crypto provider for rustls
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CertManager {
    /// Create a new certificate manager with embedded CA
    pub fn new() -> Result<Self> {
        info!("Loading embedded CA certificate");

        // Parse CA private key
        let ca_key_pair = KeyPair::from_pem(CA_KEY_PEM)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA key: {}", e)))?;

        // 从 PEM 解析参数后用同一个 key 重建 Certificate 对象（rcgen 签发叶子证书需要）
        let ca_cert = CertificateParams::from_ca_cert_pem(CA_CERT_PEM)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA cert: {}", e)))?
            .self_signed(&ca_key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to load CA cert: {}", e)))?;

        // 使用重建后的证书 DER，确保和 signed_by 使用的 issuer 一致
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        let crypto_provider = Arc::new(crate::tls_crypto::build_provider());

        info!("CA certificate loaded successfully");

        Ok(Self {
            ca_key_pair,
            ca_cert,
            ca_cert_der,
            cert_cache: RwLock::new(HashMap::new()),
            crypto_provider,
        })
    }

    /// Get or create a server config for the given hostname
    pub fn get_server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        // Check cache first
        {
            let cache = self.cert_cache.read();
            if let Some(config) = cache.get(hostname) {
                debug!("Using cached certificate for {}", hostname);
                return Ok(config.clone());
            }
        }

        // Generate new certificate
        debug!("Generating certificate for {}", hostname);
        let config = self.generate_cert_config(hostname)?;
        let config = Arc::new(config);

        // Cache it
        {
            let mut cache = self.cert_cache.write();
            cache.insert(hostname.to_string(), config.clone());
        }

        Ok(config)
    }

    /// Generate a certificate for the given hostname
    fn generate_cert_config(&self, hostname: &str) -> Result<ServerConfig> {
        // Create certificate parameters
        let mut params = CertificateParams::default();

        // 显式设置有效期 ≤ 398 天（Apple ATS/CFNetwork 策略，macOS 26 Tahoe / WKWebView 严格执行）
        // rcgen 默认 not_before=1975 / not_after=4096，会被 WKWebView 判定为非法证书
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(397);

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        // Set SAN (Subject Alternative Name)
        params.subject_alt_names = vec![SanType::DnsName(hostname.try_into().map_err(|e| {
            DohProxyError::Certificate(format!("Invalid hostname: {}", e))
        })?)];

        // Set key usage for server certificate
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Not a CA
        params.is_ca = IsCa::NoCa;

        // 启用 Authority Key Identifier 扩展，让 macOS SecTrust 能通过 AKI→CA 的 SKI
        // 构建证书链。缺少 AKI 会导致 MissingIntermediate 错误，WKWebView 拒绝信任。
        params.use_authority_key_identifier_extension = true;

        // Generate key pair for this certificate
        let key_pair = KeyPair::generate()
            .map_err(|e| DohProxyError::Certificate(format!("Failed to generate key: {}", e)))?;

        // Create the certificate signed by CA
        let cert = params
            .signed_by(&key_pair, &self.ca_cert, &self.ca_key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to sign cert: {}", e)))?;

        // Convert to rustls types
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        // Build server config with cert chain (leaf + CA)
        let mut config = ServerConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(DohProxyError::Tls)?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der, self.ca_cert_der.clone()], key_der)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to build config: {}", e)))?;

        // ALPN: 仅提供 http/1.1，MITM 做 raw byte copy 无法翻译 h2↔h1
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(config)
    }

    /// 从运行时 PEM 创建 CertManager（用于 per-device CA）
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        info!("Loading runtime CA certificate from PEM");

        let ca_key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA key: {}", e)))?;

        let ca_cert = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA cert: {}", e)))?
            .self_signed(&ca_key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to load CA cert: {}", e)))?;

        // 使用重建后的证书 DER，确保和 signed_by 使用的 issuer 一致
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        let crypto_provider = Arc::new(crate::tls_crypto::build_provider());

        info!("Runtime CA certificate loaded successfully");

        Ok(Self {
            ca_key_pair,
            ca_cert,
            ca_cert_der,
            cert_cache: RwLock::new(HashMap::new()),
            crypto_provider,
        })
    }

    /// 生成新的 CA 证书，返回 (cert_pem, key_pem)
    pub fn generate_ca_pem() -> Result<(String, String)> {
        info!("Generating new CA certificate");

        let key_pair = KeyPair::generate()
            .map_err(|e| DohProxyError::Certificate(format!("Failed to generate CA key: {}", e)))?;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "DOH Proxy CA");
        dn.push(DnType::OrganizationName, "DOH Proxy");
        dn.push(DnType::CountryName, "CN");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // 有效期 10 年
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(3650);

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to self-sign CA: {}", e)))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        info!("CA certificate generated successfully");
        Ok((cert_pem, key_pem))
    }

    /// Get CA certificate PEM for export (to install on device)
    pub fn get_ca_cert_pem(&self) -> &'static str {
        CA_CERT_PEM
    }

    /// 获取编译时嵌入的 CA 证书 PEM（静态方法，无需实例）
    pub fn get_embedded_ca_pem() -> &'static str {
        CA_CERT_PEM
    }
}
