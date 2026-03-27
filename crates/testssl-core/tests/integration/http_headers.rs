//! Integration tests for HTTP security header checks
//!
//! Uses badssl.com subdomains:
//!   hsts.badssl.com — server with HSTS header
//!   badssl.com      — baseline modern server

use testssl_core::checks::http_headers::check_http_headers;

use super::helpers::target;
use crate::require_integration;

#[tokio::test]
async fn test_hsts_present_on_hsts_server() {
    require_integration!();

    let t = target("hsts.badssl.com", 443);
    let result = check_http_headers(&t)
        .await
        .expect("http_headers check failed");

    let hsts = result
        .hsts
        .as_ref()
        .expect("hsts.badssl.com must have HSTS header");
    assert!(
        hsts.max_age > 0,
        "HSTS max-age must be positive, got: {}",
        hsts.max_age
    );
}

#[tokio::test]
async fn test_http_headers_fetch_succeeds() {
    require_integration!();

    let t = target("badssl.com", 443);
    let result = check_http_headers(&t)
        .await
        .expect("http_headers check must not error on badssl.com");

    // Server header is commonly set; at minimum the check should not crash
    let _ = result.server;
}
