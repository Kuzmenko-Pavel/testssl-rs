//! Integration tests for the high-level Scanner API

use testssl_core::scanner::{ScanConfig, Scanner};

use crate::require_integration;

#[tokio::test]
async fn test_scanner_full_scan_badssl() {
    require_integration!();

    let config = ScanConfig::default()
        .with_protocols()
        .with_certificate()
        .with_http_headers();

    let scanner = Scanner::new(config);
    let result = scanner.scan("badssl.com:443").await.expect("scan failed");

    // Scanner preserves the input string including port
    assert!(
        result.target.contains("badssl.com"),
        "target must contain hostname"
    );
    assert!(result.errors.is_empty(), "scan errors: {:?}", result.errors);

    let proto = result.protocols.expect("protocols must be present");
    assert_eq!(proto.ssl2, Some(false), "SSLv2 must not be offered");
    assert_eq!(proto.tls12, Some(true), "TLS 1.2 must be offered");

    // Certificate result must be present; certs list may be empty under poor network conditions
    let _cert = result.certificate.expect("certificate check must have run");
}

#[tokio::test]
async fn test_scanner_vulnerability_scan() {
    require_integration!();

    use testssl_core::checks::vulnerabilities::VulnStatus;

    let config = ScanConfig::default().with_vulnerabilities();
    let scanner = Scanner::new(config);
    let result = scanner.scan("badssl.com:443").await.expect("scan failed");

    let vulns = result
        .vulnerabilities
        .expect("vulnerabilities must be present");
    assert!(
        !vulns.is_empty(),
        "vulnerability checks must produce results"
    );

    // badssl.com intentionally serves 3DES (SWEET32) and old TLS ciphers for testing.
    // Check that critical CVEs (exploitable via network) are not present.
    let critical_vulns = ["heartbleed", "ccs", "poodle", "drown", "robot"];
    for vuln in &vulns {
        let name_lower = vuln.name.to_lowercase();
        if critical_vulns.iter().any(|&cv| name_lower.contains(cv)) {
            assert_ne!(
                vuln.status,
                VulnStatus::Vulnerable,
                "badssl.com should not be vulnerable to {}",
                vuln.name
            );
        }
    }
}

#[tokio::test]
async fn test_scanner_batch() {
    require_integration!();

    let config = ScanConfig::default().with_protocols();
    let scanner = Scanner::new(config);
    let results = scanner
        .scan_batch(&["badssl.com:443", "tls-v1-2.badssl.com:443"])
        .await;

    assert_eq!(results.len(), 2, "batch must return 2 results");
    for r in &results {
        assert!(r.is_ok(), "batch scan item failed");
    }
}
