//! Generate CA certificate for MITM proxy
//!
//! Run this once to generate the CA certificate:
//! cargo run --bin gen_ca

use std::fs;
use std::path::Path;

fn main() {
    println!("Generating CA certificate for DOH Proxy...");

    // 复用 CertManager::generate_ca_pem()
    let (cert_pem, key_pem) =
        doh_proxy::cert::CertManager::generate_ca_pem().expect("Failed to generate CA");

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

    // Also create PEM for Flutter assets
    let assets_dir = Path::new("../../assets/certs");
    fs::create_dir_all(assets_dir).expect("Failed to create assets/certs directory");
    let assets_pem_path = assets_dir.join("proxy_ca.pem");
    fs::write(&assets_pem_path, &cert_pem).expect("Failed to write assets PEM");
    println!("CA certificate (PEM) written to: {}", assets_pem_path.display());

    // Also copy DER for Android res/raw (network_security_config.xml references it)
    let android_raw_dir = Path::new("../../android/app/src/main/res/raw");
    fs::create_dir_all(android_raw_dir).expect("Failed to create android res/raw directory");
    let android_der_path = android_raw_dir.join("proxy_ca.der");
    fs::write(&android_der_path, pem_parsed.contents()).expect("Failed to write Android DER");
    println!("CA certificate (DER) written to: {}", android_der_path.display());

    println!("\nDone!");
}
