//! Generate CA certificate for MITM proxy
//!
//! Run this once to generate the CA certificate:
//! cargo run --bin gen_ca

use std::fs;
use std::path::Path;

fn main() {
    println!("Generating CA certificate for DOH Proxy...");

    // Generate CA using rcgen
    let (cert_pem, key_pem) = generate_ca().expect("Failed to generate CA");

    // Create certs directory
    let certs_dir = Path::new("certs");
    fs::create_dir_all(certs_dir).expect("Failed to create certs directory");

    // Write certificate
    let cert_path = certs_dir.join("ca.crt");
    fs::write(&cert_path, &cert_pem).expect("Failed to write CA certificate");
    println!("CA certificate written to: {}", cert_path.display());

    // Write private key
    let key_path = certs_dir.join("ca.key");
    fs::write(&key_path, &key_pem).expect("Failed to write CA key");
    println!("CA private key written to: {}", key_path.display());

    // Also create a DER version for Android
    let pem_parsed = pem::parse(&cert_pem).expect("Failed to parse PEM");
    let der_path = certs_dir.join("ca.der");
    fs::write(&der_path, pem_parsed.contents()).expect("Failed to write CA DER");
    println!("CA certificate (DER) written to: {}", der_path.display());

    println!("\nDone! Copy certs/ca.der to android/app/src/main/res/raw/proxy_ca.der");
}

fn generate_ca() -> Result<(String, String), Box<dyn std::error::Error>> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let mut params = CertificateParams::default();

    // Set CA distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "DOH Proxy CA");
    dn.push(DnType::OrganizationName, "DOH Proxy");
    dn.push(DnType::CountryName, "CN");
    params.distinguished_name = dn;

    // CA settings
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    // Valid for 10 years
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(3650);

    // Generate key pair
    let key_pair = KeyPair::generate()?;

    // Self-sign the CA certificate
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}
