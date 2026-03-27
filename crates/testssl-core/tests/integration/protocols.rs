//! Integration tests for protocol checks
//!
//! Uses badssl.com which maintains subdomains for various TLS states:
//!   tls-v1-2.badssl.com — TLS 1.2
//!   badssl.com          — TLS 1.2 + TLS 1.3

use testssl_core::checks::protocols::check_protocols;

use super::helpers::target;
use crate::require_integration;

#[tokio::test]
async fn test_tls12_supported_on_badssl() {
    require_integration!();

    let t = target("tls-v1-2.badssl.com", 443);
    let result = check_protocols(&t).await.expect("protocol check failed");

    assert_eq!(
        result.tls12,
        Some(true),
        "TLS 1.2 must be supported on tls-v1-2.badssl.com"
    );
}

#[tokio::test]
async fn test_sslv2_not_offered_on_modern_server() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = check_protocols(&t).await.expect("protocol check failed");

    assert_eq!(
        result.ssl2,
        Some(false),
        "SSLv2 must not be offered by badssl.com"
    );
    assert_eq!(
        result.ssl3,
        Some(false),
        "SSLv3 must not be offered by badssl.com"
    );
    assert_eq!(
        result.tls12,
        Some(true),
        "TLS 1.2 must be offered by badssl.com"
    );
}

#[tokio::test]
async fn test_tls10_supported_on_dedicated_server() {
    require_integration!();

    let t = target("tls-v1-0.badssl.com", 1010);
    let result = check_protocols(&t).await.expect("protocol check failed");

    assert_eq!(
        result.tls10,
        Some(true),
        "TLS 1.0 must be supported on tls-v1-0.badssl.com:1010"
    );
}

#[tokio::test]
async fn test_tls11_supported_on_dedicated_server() {
    require_integration!();

    let t = target("tls-v1-1.badssl.com", 1011);
    let result = check_protocols(&t).await.expect("protocol check failed");

    assert_eq!(
        result.tls11,
        Some(true),
        "TLS 1.1 must be supported on tls-v1-1.badssl.com:1011"
    );
}
