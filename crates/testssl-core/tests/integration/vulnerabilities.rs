//! Integration tests for vulnerability checks
//!
//! Uses badssl.com subdomains:
//!   rc4.badssl.com — serves RC4 ciphers
//!   badssl.com     — modern, should not be vulnerable to any classic CVEs

use testssl_core::checks::vulnerabilities::VulnStatus;
use testssl_core::checks::vulnerabilities::{heartbleed, poodle, rc4, sweet32, tls_fallback};

use super::helpers::target;
use crate::require_integration;

#[tokio::test]
async fn test_heartbleed_not_vulnerable_on_modern_server() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = heartbleed::check_heartbleed(&t)
        .await
        .expect("heartbleed check failed");

    assert_ne!(
        result.status,
        VulnStatus::Vulnerable,
        "badssl.com should not be vulnerable to Heartbleed"
    );
}

#[tokio::test]
async fn test_poodle_not_vulnerable_on_modern_server() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = poodle::check_poodle(&t).await.expect("poodle check failed");

    assert_ne!(
        result.status,
        VulnStatus::Vulnerable,
        "badssl.com should not be vulnerable to POODLE"
    );
}

#[tokio::test]
async fn test_tls_fallback_returns_defined_status() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = tls_fallback::check_tls_fallback(&t)
        .await
        .expect("tls_fallback check failed");

    assert!(
        matches!(
            result.status,
            VulnStatus::Vulnerable
                | VulnStatus::NotVulnerable
                | VulnStatus::Unknown
                | VulnStatus::NotApplicable
        ),
        "tls_fallback must return a valid status"
    );
}

#[tokio::test]
async fn test_rc4_detected_on_rc4_server() {
    require_integration!();

    // rc4.badssl.com explicitly serves RC4 ciphers
    let t = target("rc4.badssl.com", 443);
    let result = rc4::check_rc4(&t).await.expect("rc4 check failed");

    assert_eq!(
        result.status,
        VulnStatus::Vulnerable,
        "rc4.badssl.com must be detected as vulnerable to RC4"
    );
}

#[tokio::test]
async fn test_rc4_not_on_modern_server() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = rc4::check_rc4(&t).await.expect("rc4 check failed");

    assert_ne!(
        result.status,
        VulnStatus::Vulnerable,
        "badssl.com should not be vulnerable to RC4"
    );
}

#[tokio::test]
async fn test_sweet32_detected_on_3des_server() {
    require_integration!();

    // 3des.badssl.com explicitly serves 3DES ciphers (SWEET32 / CVE-2016-2183)
    let t = target("3des.badssl.com", 443);
    let result = sweet32::check_sweet32(&t)
        .await
        .expect("sweet32 check failed");

    assert_eq!(
        result.status,
        VulnStatus::Vulnerable,
        "3des.badssl.com must be detected as SWEET32 vulnerable"
    );
}

#[tokio::test]
async fn test_tls_fallback_not_vulnerable_on_tls12_only_server() {
    require_integration!();

    // tls-v1-2.badssl.com only supports TLS 1.2. Sending a TLS 1.1 ClientHello with
    // FALLBACK_SCSV should result in an alert (rejection), not acceptance.
    let t = target("tls-v1-2.badssl.com", 1012);
    let result = tls_fallback::check_tls_fallback(&t)
        .await
        .expect("tls_fallback check failed");

    assert_ne!(
        result.status,
        VulnStatus::Vulnerable,
        "tls-v1-2.badssl.com must not accept TLS 1.1 downgrade without rejection"
    );
}
