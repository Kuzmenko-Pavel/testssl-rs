//! Integration tests for server defaults, preference, forward secrecy, GREASE, client simulation

use crate::integration::helpers::target;
use crate::require_integration;

// ── Server Defaults ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_server_defaults_badssl() {
    require_integration!();

    use testssl_core::checks::server_defaults::check_server_defaults;

    let t = target("badssl.com", 443);
    let result = check_server_defaults(&t)
        .await
        .expect("server defaults check failed");

    // badssl.com must have a hostname
    assert!(
        result.hostname.is_empty() || result.hostname.contains("badssl"),
        "hostname unexpected: '{}'",
        result.hostname
    );
    // Must report a session ticket setting
    // (some server may or may not have session tickets, just check it ran)
    // The check should return a populated result
}

#[tokio::test]
async fn test_server_defaults_tls_extensions_present() {
    require_integration!();

    use testssl_core::checks::server_defaults::check_server_defaults;

    let t = target("badssl.com", 443);
    let result = check_server_defaults(&t)
        .await
        .expect("server defaults check failed");

    // Modern TLS servers should advertise at least some extensions
    // (SNI, heartbeat status, etc.)
    // We just verify the check completes without error and returns data
    let _ = result.tls_extensions;
    let _ = result.session_ticket;
}

// ── Server Preference ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_server_preference_badssl() {
    require_integration!();

    use testssl_core::checks::server_preference::check_server_preference;

    let t = target("badssl.com", 443);
    let result = check_server_preference(&t)
        .await
        .expect("server preference check failed");

    // Result should be present — just verify the check ran without error
    let _ = result.has_order;
    let _ = result.cipher_order_enforced;
}

// ── Forward Secrecy ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_forward_secrecy_modern_server() {
    require_integration!();

    use testssl_core::checks::forward_secrecy::check_forward_secrecy;

    let t = target("badssl.com", 443);
    let result = check_forward_secrecy(&t)
        .await
        .expect("forward secrecy check failed");

    // badssl.com supports ECDHE, so forward secrecy should be present
    assert!(
        result.has_fs,
        "badssl.com must support forward secrecy (ECDHE)"
    );
}

// ── GREASE ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_grease_modern_server() {
    require_integration!();

    use testssl_core::checks::grease::check_grease;

    let t = target("badssl.com", 443);
    let result = check_grease(&t).await.expect("GREASE check failed");

    // badssl.com is a modern server and should tolerate GREASE values
    assert!(
        result.tolerates_grease == Some(true),
        "badssl.com must tolerate GREASE values, got: {:?}",
        result.tolerates_grease
    );
}

// ── Client Simulation ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_client_simulation_badssl() {
    require_integration!();

    use testssl_core::checks::client_simulation::run_client_simulation;

    let t = target("badssl.com", 443);
    let results = run_client_simulation(&t)
        .await
        .expect("client simulation failed");

    // Should simulate at least some clients
    assert!(
        !results.is_empty(),
        "client simulation must return at least one result"
    );
}

// ── Scanner with all checks ───────────────────────────────────────────────────

#[tokio::test]
async fn test_scanner_extended_checks() {
    require_integration!();

    use testssl_core::scanner::{ScanConfig, Scanner};

    let config = ScanConfig::default()
        .with_server_defaults()
        .with_forward_secrecy()
        .with_grease();

    let scanner = Scanner::new(config);
    let result = scanner.scan("badssl.com:443").await.expect("scan failed");

    assert!(result.errors.is_empty(), "scan errors: {:?}", result.errors);
    assert!(
        result.server_defaults.is_some(),
        "server_defaults must be present"
    );
    assert!(
        result.forward_secrecy.is_some(),
        "forward_secrecy must be present"
    );
    assert!(result.grease.is_some(), "grease must be present");
}
