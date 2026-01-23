//! Certificate generation for MITM proxy
//!
//! This module handles:
//! - Loading the embedded CA certificate
//! - Dynamically generating certificates for target domains

use crate::error::{DohProxyError, Result};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
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

        // Load CA certificate from PEM (NOT regenerate!)
        // This ensures we use the exact same certificate that Android trusts
        let ca_cert = CertificateParams::from_ca_cert_pem(CA_CERT_PEM)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA cert: {}", e)))?
            .self_signed(&ca_key_pair)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to load CA cert: {}", e)))?;

        // Parse CA cert DER from PEM
        let pem = pem::parse(CA_CERT_PEM)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to parse CA cert PEM: {}", e)))?;
        let ca_cert_der = CertificateDer::from(pem.contents().to_vec());

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
        let config = ServerConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(DohProxyError::Tls)?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der, self.ca_cert_der.clone()], key_der)
            .map_err(|e| DohProxyError::Certificate(format!("Failed to build config: {}", e)))?;

        Ok(config)
    }

    /// Get CA certificate PEM for export (to install on device)
    pub fn get_ca_cert_pem(&self) -> &'static str {
        CA_CERT_PEM
    }
}
