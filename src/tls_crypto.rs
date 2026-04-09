use rustls::crypto::CryptoProvider;
use rustls::CipherSuite;

#[cfg(feature = "ech")]
use rustls::crypto::SupportedKxGroup;
#[cfg(feature = "ech")]
use rustls::NamedGroup;

/// 构建 TLS 加密提供者，cipher suite 顺序对齐 Chrome/BoringSSL：
/// TLS 1.3: AES_128_GCM → AES_256_GCM → CHACHA20_POLY1305
/// TLS 1.2: ECDHE_*_AES_128_GCM → ECDHE_*_AES_256_GCM → ECDHE_*_CHACHA20
///
/// Key exchange groups 顺序：X25519 → secp256r1 → secp384r1（与 Chrome 一致）
pub fn build_provider() -> CryptoProvider {
    #[cfg(feature = "ech")]
    {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        // 过滤 MLKEM groups（Chrome 当前不使用）
        provider.kx_groups = filter_kx_groups_chrome_style(provider.kx_groups);
        // cipher suite 顺序对齐 Chrome
        provider.cipher_suites = reorder_cipher_suites_chrome_style(provider.cipher_suites);
        return provider;
    }

    #[cfg(not(feature = "ech"))]
    {
        let mut provider = rustls::crypto::ring::default_provider();
        // ring 默认 ChaCha20 优先，重排为 Chrome 风格 AES 优先
        provider.cipher_suites = reorder_cipher_suites_chrome_style(provider.cipher_suites);
        return provider;
    }
}

/// 将 cipher suites 重排为 Chrome/BoringSSL 风格。
///
/// Chrome 的 cipher suite 偏好（基于 BoringSSL）：
/// - TLS 1.3: AES-128-GCM(4865) → AES-256-GCM(4866) → ChaCha20(4867)
/// - TLS 1.2: ECDHE_ECDSA/RSA_AES_128_GCM → ECDHE_ECDSA/RSA_AES_256_GCM
///            → ECDHE_ECDSA/RSA_CHACHA20
///
/// rustls ring 默认把 ChaCha20 放最前面，这会导致 JA3 指纹明显不同于浏览器，
/// 可能被 Cloudflare Bot Management 标记为非浏览器客户端。
fn reorder_cipher_suites_chrome_style(
    suites: Vec<rustls::SupportedCipherSuite>,
) -> Vec<rustls::SupportedCipherSuite> {
    let priority = |suite: &rustls::SupportedCipherSuite| -> u32 {
        match suite.suite() {
            // TLS 1.3 — Chrome 顺序
            CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
            CipherSuite::TLS13_AES_256_GCM_SHA384 => 1,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2,
            // TLS 1.2 — Chrome 顺序
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 10,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 11,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 12,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 13,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 14,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 15,
            _ => 100,
        }
    };

    let mut sorted = suites;
    sorted.sort_by_key(|s| priority(s));
    sorted
}

/// 过滤 key exchange groups，移除 Chrome 当前不使用的 MLKEM 相关 groups，
/// 保持 X25519 → secp256r1 → secp384r1 顺序（与 Chrome 一致）。
#[cfg(feature = "ech")]
fn filter_kx_groups_chrome_style(
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Vec<&'static dyn SupportedKxGroup> {
    groups
        .into_iter()
        .filter(|group| {
            !matches!(
                group.name(),
                NamedGroup::X25519MLKEM768
                    | NamedGroup::secp256r1MLKEM768
                    | NamedGroup::MLKEM768
            )
        })
        .collect()
}
