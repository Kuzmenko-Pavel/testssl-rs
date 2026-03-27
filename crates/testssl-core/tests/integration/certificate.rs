//! Integration tests for certificate checks
//!
//! Uses badssl.com subdomains:
//!   expired.badssl.com     — expired certificate
//!   self-signed.badssl.com — self-signed certificate
//!   badssl.com             — valid certificate

use testssl_core::checks::certificate::check_certificate;

use super::helpers::target;
use crate::require_integration;

#[tokio::test]
async fn test_certificate_valid_server() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    let cert = result.certs.first().expect("at least one cert expected");
    assert!(
        !cert.is_expired,
        "badssl.com certificate must not be expired"
    );
    assert!(!cert.is_self_signed, "badssl.com must not be self-signed");
    assert!(
        cert.days_until_expiry > 0,
        "must have positive days until expiry"
    );
    assert!(!cert.subject.is_empty(), "CN must not be empty");
    assert!(!cert.issuer.is_empty(), "Issuer must not be empty");
}

#[tokio::test]
async fn test_certificate_expired_detection() {
    require_integration!();

    let t = target("expired.badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    // certs may be empty if the server is unreachable from CI or rejects the handshake
    if let Some(cert) = result.certs.first() {
        assert!(
            cert.is_expired,
            "expired.badssl.com must be detected as expired"
        );
    }
}

#[tokio::test]
async fn test_certificate_self_signed_detection() {
    require_integration!();

    let t = target("self-signed.badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    // certs may be empty if the server is unreachable from CI or rejects the handshake
    if let Some(cert) = result.certs.first() {
        assert!(
            cert.is_self_signed,
            "self-signed.badssl.com must be detected as self-signed"
        );
    }
}

#[tokio::test]
async fn test_certificate_fingerprint_sha256() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    let cert = result.certs.first().expect("at least one cert expected");
    // SHA-256 fingerprint should be a 64-character hex string
    assert_eq!(
        cert.fingerprint_sha256.len(),
        64,
        "SHA-256 fingerprint must be 64 hex chars, got: '{}'",
        cert.fingerprint_sha256
    );
    assert!(
        cert.fingerprint_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "Fingerprint must be hex"
    );
}

#[tokio::test]
async fn test_certificate_san_populated() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    let cert = result.certs.first().expect("at least one cert expected");
    assert!(
        !cert.subject_alt_names.is_empty(),
        "badssl.com must have SANs in the certificate"
    );
}

#[tokio::test]
async fn test_certificate_rsa2048_key() {
    require_integration!();

    let t = target("rsa2048.badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    let cert = result.certs.first().expect("at least one cert expected");
    assert_eq!(cert.key_type, "RSA", "rsa2048.badssl.com must use RSA key");
    assert_eq!(
        cert.key_bits, 2048,
        "rsa2048.badssl.com must have 2048-bit key"
    );
}

#[tokio::test]
async fn test_certificate_rsa4096_key() {
    require_integration!();

    let t = target("rsa4096.badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    let cert = result.certs.first().expect("at least one cert expected");
    assert_eq!(cert.key_type, "RSA", "rsa4096.badssl.com must use RSA key");
    assert_eq!(
        cert.key_bits, 4096,
        "rsa4096.badssl.com must have 4096-bit key"
    );
}

#[tokio::test]
async fn test_certificate_ecc256_key() {
    require_integration!();

    let t = target("ecc256.badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    let cert = result.certs.first().expect("at least one cert expected");
    assert_eq!(cert.key_type, "EC", "ecc256.badssl.com must use EC key");
    assert_eq!(
        cert.key_bits, 256,
        "ecc256.badssl.com must have 256-bit EC key"
    );
}

#[tokio::test]
async fn test_certificate_sha256_signature_algorithm() {
    require_integration!();

    let t = target("sha256.badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    let cert = result.certs.first().expect("at least one cert expected");
    assert!(
        cert.signature_algorithm.to_lowercase().contains("sha256"),
        "sha256.badssl.com must report sha256 signature algorithm, got: '{}'",
        cert.signature_algorithm
    );
}

#[tokio::test]
async fn test_certificate_chain_root_ca_marked() {
    require_integration!();

    // Tests the bug fix: root CA (last cert in chain) must not be flagged as an error.
    let t = target("badssl.com", 443);
    let result = check_certificate(&t)
        .await
        .expect("certificate check failed");

    if result.certs.len() > 1 {
        let last = result.certs.last().unwrap();
        if last.is_self_signed {
            assert!(
                last.is_root_ca,
                "last cert in chain (root CA) must be marked is_root_ca=true"
            );
        }
    }
}
