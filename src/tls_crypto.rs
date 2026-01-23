use rustls::crypto::CryptoProvider;

#[cfg(feature = "ech")]
use rustls::NamedGroup;

pub fn build_provider() -> CryptoProvider {
    #[cfg(feature = "ech")]
    {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = provider
            .kx_groups
            .into_iter()
            .filter(|group| {
                !matches!(
                    group.name(),
                    NamedGroup::X25519MLKEM768
                        | NamedGroup::secp256r1MLKEM768
                        | NamedGroup::MLKEM768
                )
            })
            .collect();
        return provider;
    }

    #[cfg(not(feature = "ech"))]
    {
        return rustls::crypto::ring::default_provider();
    }
}
