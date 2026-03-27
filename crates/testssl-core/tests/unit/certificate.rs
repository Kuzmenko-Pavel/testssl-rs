//! Unit tests for certificate module — oid_to_sig_name, VulnResult helpers

use testssl_core::checks::certificate::oid_to_sig_name;
use testssl_core::checks::vulnerabilities::{VulnResult, VulnStatus};

// ── oid_to_sig_name ───────────────────────────────────────────────────────────

#[test]
fn test_oid_md5_with_rsa() {
    assert_eq!(
        oid_to_sig_name("1.2.840.113549.1.1.4"),
        "md5WithRSAEncryption"
    );
}

#[test]
fn test_oid_sha1_with_rsa() {
    assert_eq!(
        oid_to_sig_name("1.2.840.113549.1.1.5"),
        "sha1WithRSAEncryption"
    );
}

#[test]
fn test_oid_sha256_with_rsa() {
    assert_eq!(
        oid_to_sig_name("1.2.840.113549.1.1.11"),
        "sha256WithRSAEncryption"
    );
}

#[test]
fn test_oid_sha384_with_rsa() {
    assert_eq!(
        oid_to_sig_name("1.2.840.113549.1.1.12"),
        "sha384WithRSAEncryption"
    );
}

#[test]
fn test_oid_sha512_with_rsa() {
    assert_eq!(
        oid_to_sig_name("1.2.840.113549.1.1.13"),
        "sha512WithRSAEncryption"
    );
}

#[test]
fn test_oid_ecdsa_sha224() {
    assert_eq!(oid_to_sig_name("1.2.840.10045.4.3.1"), "ecdsa-with-SHA224");
}

#[test]
fn test_oid_ecdsa_sha256() {
    assert_eq!(oid_to_sig_name("1.2.840.10045.4.3.2"), "ecdsa-with-SHA256");
}

#[test]
fn test_oid_ecdsa_sha384() {
    assert_eq!(oid_to_sig_name("1.2.840.10045.4.3.3"), "ecdsa-with-SHA384");
}

#[test]
fn test_oid_ecdsa_sha512() {
    assert_eq!(oid_to_sig_name("1.2.840.10045.4.3.4"), "ecdsa-with-SHA512");
}

#[test]
fn test_oid_ed25519() {
    assert_eq!(oid_to_sig_name("1.3.101.112"), "Ed25519");
}

#[test]
fn test_oid_ed448() {
    assert_eq!(oid_to_sig_name("1.3.101.113"), "Ed448");
}

#[test]
fn test_oid_rsassa_pss() {
    assert_eq!(oid_to_sig_name("1.2.840.113549.1.1.10"), "rsassaPss");
}

#[test]
fn test_oid_unknown_returns_oid() {
    assert_eq!(oid_to_sig_name("9.9.9.9.9"), "9.9.9.9.9");
}

// ── VulnResult helpers ────────────────────────────────────────────────────────

#[test]
fn test_vuln_result_vulnerable() {
    let v = VulnResult::vulnerable("heartbleed", vec!["CVE-2014-0160".to_string()], "affected");
    assert_eq!(v.status, VulnStatus::Vulnerable);
    assert_eq!(v.name, "heartbleed");
    assert_eq!(v.details, "affected");
    assert!(v.cve.contains(&"CVE-2014-0160".to_string()));
}

#[test]
fn test_vuln_result_not_vulnerable() {
    let v = VulnResult::not_vulnerable("heartbleed");
    assert_eq!(v.status, VulnStatus::NotVulnerable);
    assert_eq!(v.name, "heartbleed");
    assert!(v.details.is_empty());
    assert!(v.cve.is_empty());
}

#[test]
fn test_vuln_result_unknown() {
    let v = VulnResult::unknown("beast", "timeout");
    assert_eq!(v.status, VulnStatus::Unknown);
    assert_eq!(v.details, "timeout");
}

#[test]
fn test_vuln_status_display() {
    assert_eq!(VulnStatus::Vulnerable.to_string(), "VULNERABLE");
    assert_eq!(VulnStatus::NotVulnerable.to_string(), "not vulnerable");
    assert_eq!(VulnStatus::Unknown.to_string(), "unknown");
    assert_eq!(VulnStatus::NotApplicable.to_string(), "N/A");
}
