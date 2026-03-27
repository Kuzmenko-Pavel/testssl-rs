//! Integration tests for cipher enumeration
//!
//! Uses badssl.com subdomains:
//!   rc4.badssl.com   — serves RC4 ciphers
//!   3des.badssl.com  — serves 3DES ciphers
//!   badssl.com       — modern server, no weak ciphers

use testssl_core::checks::ciphers::enumerate_ciphers;
use testssl_core::tls::client_hello::TlsVersion;

use super::helpers::target;
use crate::require_integration;

#[tokio::test]
async fn test_rc4_cipher_found_on_rc4_server() {
    require_integration!();

    let t = target("rc4.badssl.com", 443);
    // RC4 is TLS 1.0/1.1/1.2 era — enumerate TLS 1.2 ciphers
    let result = enumerate_ciphers(&t, TlsVersion::Tls12)
        .await
        .expect("cipher enumeration failed");

    let has_rc4 = result
        .supported
        .iter()
        .any(|c| c.ossl_name.contains("RC4") || c.enc.contains("RC4"));
    assert!(
        has_rc4,
        "rc4.badssl.com must have at least one RC4 cipher, found: {:?}",
        result
            .supported
            .iter()
            .map(|c| &c.ossl_name)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_3des_cipher_found_on_3des_server() {
    require_integration!();

    let t = target("3des.badssl.com", 443);
    let result = enumerate_ciphers(&t, TlsVersion::Tls12)
        .await
        .expect("cipher enumeration failed");

    let has_3des = result
        .supported
        .iter()
        .any(|c| c.ossl_name.contains("3DES") || c.enc.contains("3DES"));
    assert!(
        has_3des,
        "3des.badssl.com must have at least one 3DES cipher, found: {:?}",
        result
            .supported
            .iter()
            .map(|c| &c.ossl_name)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_no_rc4_cipher_on_modern_server() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = enumerate_ciphers(&t, TlsVersion::Tls12)
        .await
        .expect("cipher enumeration failed");

    let has_rc4 = result
        .supported
        .iter()
        .any(|c| c.ossl_name.contains("RC4") || c.enc.contains("RC4"));
    assert!(!has_rc4, "badssl.com must not serve RC4 ciphers");
}
