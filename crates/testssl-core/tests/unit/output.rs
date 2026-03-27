//! Unit tests for output formatters (JSON, CSV, HTML)

use testssl_core::checks::certificate::{CertCheckResult, CertInfo};
use testssl_core::checks::protocols::ProtocolSupport;
use testssl_core::checks::rating::{Grade, RatingResult};
use testssl_core::checks::vulnerabilities::{VulnResult, VulnStatus};
use testssl_core::output::ScanResults;

fn make_scan_results() -> ScanResults {
    ScanResults::new("example.com".to_string(), 443)
}

fn make_protocol_support() -> ProtocolSupport {
    ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(true),
    }
}

fn make_cert_info() -> CertInfo {
    CertInfo {
        subject: "CN=example.com".to_string(),
        issuer: "CN=Let's Encrypt".to_string(),
        serial: "12345".to_string(),
        not_before: "2024-01-01".to_string(),
        not_after: "2025-01-01".to_string(),
        days_until_expiry: 365,
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        key_type: "RSA".to_string(),
        key_bits: 2048,
        subject_alt_names: vec!["example.com".to_string(), "www.example.com".to_string()],
        ocsp_stapled: false,
        ct_scts: vec![],
        is_expired: false,
        is_self_signed: false,
        is_root_ca: false,
        fingerprint_sha256: "abcdef1234567890".to_string(),
        trust_stores: vec![],
    }
}

// ── JSON tests ──────────────────────────────────────────────────────────────

mod json {
    use super::*;
    use testssl_core::output::json::{build_json_findings, write_json};

    #[test]
    fn test_write_json_empty_results() {
        let results = make_scan_results();
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("example.com"));
        assert!(json.contains("443"));
        assert!(json.contains("testssl-rs"));
        assert!(json.contains("scanResult"));
    }

    #[test]
    fn test_write_json_pretty() {
        let results = make_scan_results();
        let json = write_json(&results, true).expect("json serialization failed");
        assert!(json.contains('\n'));
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_write_json_with_protocols() {
        let mut results = make_scan_results();
        results.protocols = Some(make_protocol_support());
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("TLS1_2"));
        assert!(json.contains("TLS1_3"));
        assert!(json.contains("SSLv2"));
    }

    #[test]
    fn test_write_json_with_ip() {
        let mut results = make_scan_results();
        results.ip = Some("93.184.216.34".to_string());
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("93.184.216.34"));
    }

    #[test]
    fn test_write_json_with_vulnerabilities() {
        let mut results = make_scan_results();
        results.vulnerabilities.push(VulnResult {
            name: "heartbleed".to_string(),
            cve: vec!["CVE-2014-0160".to_string()],
            status: VulnStatus::NotVulnerable,
            details: String::new(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "poodle".to_string(),
            cve: vec!["CVE-2014-3566".to_string()],
            status: VulnStatus::Vulnerable,
            details: "SSLv3 offered".to_string(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "robot".to_string(),
            cve: vec![],
            status: VulnStatus::Unknown,
            details: "timeout".to_string(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "breach".to_string(),
            cve: vec![],
            status: VulnStatus::NotApplicable,
            details: "HTTP not used".to_string(),
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("heartbleed"));
        assert!(json.contains("VULNERABLE"));
        assert!(json.contains("CVE-2014-0160"));
    }

    #[test]
    fn test_write_json_with_certificate() {
        let mut results = make_scan_results();
        results.certificate = Some(CertCheckResult {
            certs: vec![make_cert_info()],
            chain_complete: true,
            chain_order_ok: true,
            ocsp_must_staple: false,
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("cert_commonName"));
        assert!(json.contains("example.com"));
        assert!(json.contains("cert_keySize"));
    }

    #[test]
    fn test_write_json_with_expired_certificate() {
        let mut results = make_scan_results();
        let mut cert = make_cert_info();
        cert.is_expired = true;
        cert.days_until_expiry = -10;
        results.certificate = Some(CertCheckResult {
            certs: vec![cert],
            chain_complete: true,
            chain_order_ok: true,
            ocsp_must_staple: false,
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("CRITICAL"));
        assert!(json.contains("expired"));
    }

    #[test]
    fn test_write_json_with_expiring_certificate() {
        let mut results = make_scan_results();
        let mut cert = make_cert_info();
        cert.days_until_expiry = 15;
        results.certificate = Some(CertCheckResult {
            certs: vec![cert],
            chain_complete: true,
            chain_order_ok: true,
            ocsp_must_staple: false,
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("HIGH"));
        assert!(json.contains("expires in"));
    }

    #[test]
    fn test_write_json_with_expiring_60_days() {
        let mut results = make_scan_results();
        let mut cert = make_cert_info();
        cert.days_until_expiry = 45;
        results.certificate = Some(CertCheckResult {
            certs: vec![cert],
            chain_complete: true,
            chain_order_ok: true,
            ocsp_must_staple: false,
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("MEDIUM"));
    }

    #[test]
    fn test_write_json_self_signed_cert() {
        let mut results = make_scan_results();
        let mut cert = make_cert_info();
        cert.is_self_signed = true;
        results.certificate = Some(CertCheckResult {
            certs: vec![cert],
            chain_complete: true,
            chain_order_ok: true,
            ocsp_must_staple: false,
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("self-signed"));
    }

    #[test]
    fn test_write_json_with_rating() {
        let mut results = make_scan_results();
        let mut rating = RatingResult::new();
        rating.base_grade = Grade::A;
        rating.overall_score = 95;
        results.rating = Some(rating);
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("rating"));
    }

    #[test]
    fn test_write_json_rating_b_grade() {
        let mut results = make_scan_results();
        let mut rating = RatingResult::new();
        rating.base_grade = Grade::B;
        rating.overall_score = 80;
        results.rating = Some(rating);
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("LOW"));
    }

    #[test]
    fn test_write_json_rating_c_grade() {
        let mut results = make_scan_results();
        let mut rating = RatingResult::new();
        rating.base_grade = Grade::C;
        rating.overall_score = 65;
        results.rating = Some(rating);
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("MEDIUM"));
    }

    #[test]
    fn test_write_json_rating_f_grade() {
        let mut results = make_scan_results();
        let mut rating = RatingResult::new();
        rating.base_grade = Grade::F;
        rating.overall_score = 20;
        results.rating = Some(rating);
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("HIGH"));
    }

    #[test]
    fn test_build_json_findings_ssl2_offered() {
        let mut results = make_scan_results();
        results.protocols = Some(ProtocolSupport {
            ssl2: Some(true),
            ssl3: Some(false),
            tls10: Some(false),
            tls11: Some(false),
            tls12: Some(true),
            tls13: Some(false),
        });
        let findings = build_json_findings(&results);
        let ssl2 = findings
            .iter()
            .find(|f| f["id"] == "SSLv2")
            .expect("SSLv2 finding expected");
        assert_eq!(ssl2["severity"], "CRITICAL");
    }

    #[test]
    fn test_build_json_findings_ssl3_offered() {
        let mut results = make_scan_results();
        results.protocols = Some(ProtocolSupport {
            ssl2: Some(false),
            ssl3: Some(true),
            tls10: Some(false),
            tls11: Some(false),
            tls12: Some(true),
            tls13: Some(false),
        });
        let findings = build_json_findings(&results);
        let ssl3 = findings
            .iter()
            .find(|f| f["id"] == "SSLv3")
            .expect("SSLv3 finding expected");
        assert_eq!(ssl3["severity"], "HIGH");
    }

    #[test]
    fn test_build_json_with_ocsp_must_staple() {
        let mut results = make_scan_results();
        results.certificate = Some(CertCheckResult {
            certs: vec![make_cert_info()],
            chain_complete: true,
            chain_order_ok: true,
            ocsp_must_staple: true,
        });
        let findings = build_json_findings(&results);
        assert!(findings
            .iter()
            .any(|f| f["id"] == "cert_mustStapleExtension"));
    }

    #[test]
    fn test_build_json_protocol_none_not_tested() {
        let mut results = make_scan_results();
        results.protocols = Some(ProtocolSupport {
            ssl2: None,
            ssl3: None,
            tls10: None,
            tls11: None,
            tls12: None,
            tls13: None,
        });
        // None protocol entries are skipped
        let findings = build_json_findings(&results);
        assert!(findings.iter().all(|f| f["id"] != "SSLv2"));
    }

    #[test]
    fn test_write_json_with_http_headers() {
        use testssl_core::checks::http_headers::{HstsInfo, HttpHeadersResult};
        let mut results = make_scan_results();
        results.http_headers = Some(HttpHeadersResult {
            hsts: Some(HstsInfo {
                max_age: 31536000,
                include_subdomains: true,
                preload: true,
                raw_value: "max-age=31536000; includeSubDomains; preload".to_string(),
            }),
            server: Some("nginx/1.24".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            content_security_policy: Some("default-src 'self'".to_string()),
            ..HttpHeadersResult::default()
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("HSTS"));
        assert!(json.contains("31536000"));
        assert!(json.contains("nginx"));
    }

    #[test]
    fn test_write_json_hsts_not_set() {
        use testssl_core::checks::http_headers::HttpHeadersResult;
        let mut results = make_scan_results();
        results.http_headers = Some(HttpHeadersResult {
            hsts: None,
            server: None,
            x_frame_options: None,
            x_content_type_options: None,
            content_security_policy: None,
            ..HttpHeadersResult::default()
        });
        let json = write_json(&results, false).expect("json serialization failed");
        assert!(json.contains("HSTS"));
        assert!(json.contains("not set"));
    }
}

// ── CSV tests ───────────────────────────────────────────────────────────────

mod csv {
    use super::*;
    use testssl_core::output::csv::write_csv;

    #[test]
    fn test_write_csv_empty_results() {
        let results = make_scan_results();
        let csv = write_csv(&results).expect("csv serialization failed");
        assert!(csv.contains("target,port,id,severity,finding"));
    }

    #[test]
    fn test_write_csv_with_protocols() {
        let mut results = make_scan_results();
        results.protocols = Some(make_protocol_support());
        let csv = write_csv(&results).expect("csv serialization failed");
        assert!(csv.contains("SSLv2"));
        assert!(csv.contains("TLS1_2"));
        assert!(csv.contains("example.com"));
    }

    #[test]
    fn test_write_csv_protocol_ssl2_offered() {
        let mut results = make_scan_results();
        results.protocols = Some(ProtocolSupport {
            ssl2: Some(true),
            ssl3: Some(false),
            tls10: None,
            tls11: None,
            tls12: Some(true),
            tls13: None,
        });
        let csv = write_csv(&results).expect("csv serialization failed");
        assert!(csv.contains("CRITICAL"));
    }

    #[test]
    fn test_write_csv_protocol_not_tested() {
        let mut results = make_scan_results();
        results.protocols = Some(ProtocolSupport {
            ssl2: None,
            ssl3: None,
            tls10: None,
            tls11: None,
            tls12: None,
            tls13: None,
        });
        let csv = write_csv(&results).expect("csv serialization failed");
        assert!(csv.contains("not tested"));
    }

    #[test]
    fn test_write_csv_with_vulnerabilities() {
        let mut results = make_scan_results();
        results.vulnerabilities.push(VulnResult {
            name: "heartbleed".to_string(),
            cve: vec!["CVE-2014-0160".to_string()],
            status: VulnStatus::NotVulnerable,
            details: String::new(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "poodle".to_string(),
            cve: vec![],
            status: VulnStatus::Vulnerable,
            details: "SSLv3 offered".to_string(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "robot".to_string(),
            cve: vec![],
            status: VulnStatus::Unknown,
            details: "timeout".to_string(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "breach".to_string(),
            cve: vec![],
            status: VulnStatus::NotApplicable,
            details: "no HTTP".to_string(),
        });
        let csv = write_csv(&results).expect("csv serialization failed");
        assert!(csv.contains("heartbleed"));
        assert!(csv.contains("poodle"));
        assert!(csv.contains("VULNERABLE"));
        assert!(csv.contains("WARN"));
        assert!(csv.contains("INFO"));
    }

    #[test]
    fn test_write_csv_vuln_with_details() {
        let mut results = make_scan_results();
        results.vulnerabilities.push(VulnResult {
            name: "crime".to_string(),
            cve: vec![],
            status: VulnStatus::Vulnerable,
            details: "compression enabled".to_string(),
        });
        let csv = write_csv(&results).expect("csv serialization failed");
        assert!(csv.contains("VULNERABLE: compression enabled"));
    }

    #[test]
    fn test_write_csv_vuln_no_details() {
        let mut results = make_scan_results();
        results.vulnerabilities.push(VulnResult {
            name: "rc4".to_string(),
            cve: vec![],
            status: VulnStatus::NotVulnerable,
            details: String::new(),
        });
        let csv = write_csv(&results).expect("csv serialization failed");
        assert!(csv.contains("not vulnerable"));
    }
}

// ── HTML tests ──────────────────────────────────────────────────────────────

mod html {
    use super::*;
    use testssl_core::output::html::write_html;

    #[test]
    fn test_write_html_empty_results() {
        let results = make_scan_results();
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("example.com"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_write_html_with_ip() {
        let mut results = make_scan_results();
        results.ip = Some("1.2.3.4".to_string());
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("1.2.3.4"));
    }

    #[test]
    fn test_write_html_with_protocols() {
        let mut results = make_scan_results();
        results.protocols = Some(make_protocol_support());
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("Protocol Support"));
        assert!(html.contains("SSLv2"));
        assert!(html.contains("TLS 1.2"));
        assert!(html.contains("TLS 1.3"));
    }

    #[test]
    fn test_write_html_ssl_offered_gets_high_class() {
        let mut results = make_scan_results();
        results.protocols = Some(ProtocolSupport {
            ssl2: Some(true),
            ssl3: Some(true),
            tls10: Some(false),
            tls11: Some(false),
            tls12: Some(true),
            tls13: Some(false),
        });
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("NOT ok"));
    }

    #[test]
    fn test_write_html_protocol_not_tested() {
        let mut results = make_scan_results();
        results.protocols = Some(ProtocolSupport {
            ssl2: None,
            ssl3: None,
            tls10: None,
            tls11: None,
            tls12: None,
            tls13: None,
        });
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("not tested"));
    }

    #[test]
    fn test_write_html_with_vulnerabilities() {
        let mut results = make_scan_results();
        results.vulnerabilities.push(VulnResult {
            name: "heartbleed".to_string(),
            cve: vec!["CVE-2014-0160".to_string()],
            status: VulnStatus::Vulnerable,
            details: "server affected".to_string(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "rc4".to_string(),
            cve: vec![],
            status: VulnStatus::NotVulnerable,
            details: String::new(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "beast".to_string(),
            cve: vec![],
            status: VulnStatus::Unknown,
            details: "could not determine".to_string(),
        });
        results.vulnerabilities.push(VulnResult {
            name: "breach".to_string(),
            cve: vec![],
            status: VulnStatus::NotApplicable,
            details: "n/a".to_string(),
        });
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("Vulnerabilities"));
        assert!(html.contains("heartbleed"));
        assert!(html.contains("VULNERABLE"));
        assert!(html.contains("CVE-2014-0160"));
    }

    #[test]
    fn test_write_html_rating_a_grade() {
        let mut results = make_scan_results();
        let mut rating = RatingResult::new();
        rating.base_grade = Grade::APlus;
        rating.overall_score = 100;
        results.rating = Some(rating);
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("Overall Grade"));
        assert!(html.contains("A+"));
    }

    #[test]
    fn test_write_html_rating_b_grade() {
        let mut results = make_scan_results();
        let mut rating = RatingResult::new();
        rating.base_grade = Grade::B;
        rating.overall_score = 80;
        results.rating = Some(rating);
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("B"));
        assert!(html.contains("info"));
    }

    #[test]
    fn test_write_html_rating_f_grade() {
        let mut results = make_scan_results();
        let mut rating = RatingResult::new();
        rating.base_grade = Grade::F;
        rating.overall_score = 10;
        results.rating = Some(rating);
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("high"));
    }

    #[test]
    fn test_write_html_html_escaping() {
        // Target with special HTML characters
        let mut results = ScanResults::new("example<test>&co".to_string(), 443);
        results.ip = Some("<script>".to_string());
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn test_write_html_title_contains_host_port() {
        let results = ScanResults::new("myserver.com".to_string(), 8443);
        let html = write_html(&results).expect("html serialization failed");
        assert!(html.contains("myserver.com"));
        assert!(html.contains("8443"));
    }
}
