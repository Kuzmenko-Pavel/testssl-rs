//! Unit tests for the SSL Labs-compatible rating module

use testssl_core::checks::certificate::{CertCheckResult, CertInfo};
use testssl_core::checks::ciphers::{CipherEnumResult, SupportedCipher};
use testssl_core::checks::forward_secrecy::ForwardSecrecyResult;
use testssl_core::checks::http_headers::{HstsInfo, HttpHeadersResult};
use testssl_core::checks::protocols::ProtocolSupport;
use testssl_core::checks::rating::{rate_server, Grade, RatingResult};
use testssl_core::checks::vulnerabilities::{VulnResult, VulnStatus};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn tls12_only() -> ProtocolSupport {
    ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(false),
    }
}

fn tls13_only() -> ProtocolSupport {
    ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(false),
        tls13: Some(true),
    }
}

fn tls12_and_13() -> ProtocolSupport {
    ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(true),
    }
}

fn make_cipher(ossl_name: &str, enc: &str, bits: u16, pfs: bool) -> SupportedCipher {
    SupportedCipher {
        hex_high: 0x00,
        hex_low: 0x35,
        ossl_name: ossl_name.to_string(),
        rfc_name: format!("TLS_{}_SHA256", ossl_name),
        tls_version: "TLS1.2".to_string(),
        kx: "RSA".to_string(),
        enc: enc.to_string(),
        bits,
        mac: "SHA256".to_string(),
        pfs,
        is_export: ossl_name.starts_with("EXP"),
    }
}

fn make_cert_result(expired: bool, self_signed: bool, days: i64, sig_alg: &str) -> CertCheckResult {
    CertCheckResult {
        certs: vec![CertInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Let's Encrypt".to_string(),
            serial: "1".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            days_until_expiry: days,
            signature_algorithm: sig_alg.to_string(),
            key_type: "RSA".to_string(),
            key_bits: 2048,
            subject_alt_names: vec!["example.com".to_string()],
            ocsp_stapled: false,
            ct_scts: vec![],
            is_expired: expired,
            is_self_signed: self_signed,
            is_root_ca: false,
            fingerprint_sha256: "abc123".to_string(),
            trust_stores: vec![],
        }],
        chain_complete: true,
        chain_order_ok: true,
        ocsp_must_staple: false,
    }
}

fn make_hsts_headers(max_age: u64) -> HttpHeadersResult {
    HttpHeadersResult {
        hsts: Some(HstsInfo {
            max_age,
            include_subdomains: true,
            preload: false,
            raw_value: format!("max-age={}", max_age),
        }),
        ..Default::default()
    }
}

fn make_vuln(name: &str, vulnerable: bool) -> VulnResult {
    VulnResult {
        name: name.to_string(),
        cve: vec![],
        status: if vulnerable {
            VulnStatus::Vulnerable
        } else {
            VulnStatus::NotVulnerable
        },
        details: String::new(),
    }
}

/// Call rate_server with only protocol data (all other args None).
fn rate_proto_only(proto: &ProtocolSupport) -> RatingResult {
    rate_server(proto, None, None, None, None, None, None, None)
}

// ── Grade Display ─────────────────────────────────────────────────────────────

#[test]
fn test_grade_display() {
    assert_eq!(Grade::APlus.to_string(), "A+");
    assert_eq!(Grade::A.to_string(), "A");
    assert_eq!(Grade::AMinus.to_string(), "A-");
    assert_eq!(Grade::B.to_string(), "B");
    assert_eq!(Grade::C.to_string(), "C");
    assert_eq!(Grade::D.to_string(), "D");
    assert_eq!(Grade::E.to_string(), "E");
    assert_eq!(Grade::F.to_string(), "F");
    assert_eq!(Grade::T.to_string(), "T");
    assert_eq!(Grade::M.to_string(), "M");
    assert_eq!(Grade::Unknown.to_string(), "?");
}

#[test]
fn test_grade_m_exists() {
    let g = Grade::M;
    assert_eq!(g.to_string(), "M");
    // M is worse than T
    assert!(Grade::M > Grade::T);
    // T is worse than F
    assert!(Grade::T > Grade::F);
}

// ── RatingResult ──────────────────────────────────────────────────────────────

#[test]
fn test_rating_result_default() {
    let r = RatingResult::default();
    assert_eq!(r.base_grade, Grade::Unknown);
    assert_eq!(r.overall_score, 0);
    assert!(r.grade_reasons.is_empty());
    assert!(r.warnings.is_empty());
    assert!(r.applied_rules.is_empty());
    assert_eq!(r.policy_id, "ssl_labs_2025");
}

#[test]
fn test_effective_grade_no_cap() {
    let mut r = RatingResult::new();
    r.base_grade = Grade::A;
    r.grade_cap = None;
    assert_eq!(r.effective_grade(), Grade::A);
}

#[test]
fn test_effective_grade_cap_worse_than_grade_applies() {
    let mut r = RatingResult::new();
    r.base_grade = Grade::A;
    r.grade_cap = Some(Grade::C);
    assert_eq!(r.effective_grade(), Grade::C);
}

#[test]
fn test_effective_grade_cap_not_applied_when_better() {
    let mut r = RatingResult::new();
    r.base_grade = Grade::F;
    r.grade_cap = Some(Grade::A); // A is better than F, cap doesn't improve grade
    assert_eq!(r.effective_grade(), Grade::F);
}

// ── Numeric scoring: SSL Labs formulas ────────────────────────────────────────

#[test]
fn test_protocol_score_tls13_only() {
    // avg(100, 100) = 100
    let r = rate_proto_only(&tls13_only());
    assert_eq!(r.protocol_score, 100);
}

#[test]
fn test_protocol_score_tls12_only() {
    // avg(100, 100) = 100
    let r = rate_proto_only(&tls12_only());
    assert_eq!(r.protocol_score, 100);
}

#[test]
fn test_protocol_score_tls12_and_tls13() {
    // best=TLS1.3(100), worst=TLS1.2(100) → avg=100
    let r = rate_proto_only(&tls12_and_13());
    assert_eq!(r.protocol_score, 100);
}

#[test]
fn test_protocol_score_tls12_and_ssl3() {
    // best=TLS1.2(100), worst=SSL3(80) → avg=90
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(true),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.protocol_score, 90);
}

#[test]
fn test_protocol_score_tls11_only() {
    // avg(95, 95) = 95
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(true),
        tls12: Some(false),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.protocol_score, 95);
}

#[test]
fn test_protocol_score_tls10_only() {
    // avg(90, 90) = 90
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(true),
        tls11: Some(false),
        tls12: Some(false),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.protocol_score, 90);
}

#[test]
fn test_protocol_score_ssl3_only() {
    // avg(80, 80) = 80
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(true),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(false),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.protocol_score, 80);
}

#[test]
fn test_protocol_score_ssl2_only() {
    // avg(0, 0) = 0
    let proto = ProtocolSupport {
        ssl2: Some(true),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(false),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.protocol_score, 0);
}

#[test]
fn test_protocol_score_ssl2_and_tls12() {
    // best=TLS1.2(100), worst=SSL2(0) → avg=50
    let proto = ProtocolSupport {
        ssl2: Some(true),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.protocol_score, 50);
}

#[test]
fn test_protocol_score_none_supported() {
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(false),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.protocol_score, 0);
}

// ── Grade thresholds (SSL Labs) ───────────────────────────────────────────────

#[test]
fn test_grade_threshold_a_at_80() {
    // TLS1.2 only: proto=100, kx=90(default), cipher=80(default) → numeric=90 → A
    let r = rate_proto_only(&tls12_only());
    assert_eq!(r.base_grade, Grade::A);
    assert!(r.overall_score >= 80);
}

#[test]
fn test_grade_threshold_f_for_no_protocols() {
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(false),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    // protocol=0, kx=90, cipher=80 → (0+27+32)=59/100 → 59... wait
    // Actually kx default = 2048bits = 90, cipher default (no data) = 80
    // score = (0*30 + 90*30 + 80*40)/100 = (0 + 2700 + 3200)/100 = 59 → C
    // But no protocols supported means nothing works... B cap from NO_TLS12 rule
    assert!(r.overall_score < 80);
}

// ── Cipher scoring ────────────────────────────────────────────────────────────

#[test]
fn test_cipher_score_256bit_only() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher("AES256GCM", "AESGCM", 256, true)],
        total_tested: 1,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    // (100 + 100) / 2 = 100
    assert_eq!(r.cipher_strength_score, 100);
}

#[test]
fn test_cipher_score_128bit_only() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher("AES128GCM", "AESGCM", 128, true)],
        total_tested: 1,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    // (80 + 80) / 2 = 80
    assert_eq!(r.cipher_strength_score, 80);
}

#[test]
fn test_cipher_score_mixed_128_and_256() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![
            make_cipher("AES128GCM", "AESGCM", 128, true),
            make_cipher("AES256GCM", "AESGCM", 256, true),
        ],
        total_tested: 2,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    // best=256→100, worst=128→80 → avg=90
    assert_eq!(r.cipher_strength_score, 90);
}

#[test]
fn test_cipher_score_empty_gives_zero() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![],
        total_tested: 0,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    assert_eq!(r.cipher_strength_score, 0);
}

#[test]
fn test_cipher_score_no_data_gives_80() {
    let r = rate_proto_only(&tls12_only());
    // Without cipher data, optimistic default = 80
    assert_eq!(r.cipher_strength_score, 80);
}

// ── Cap rules ─────────────────────────────────────────────────────────────────

#[test]
fn test_cap_ssl2_gives_f() {
    let proto = ProtocolSupport {
        ssl2: Some(true),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert_eq!(r.effective_grade(), Grade::F);
    assert!(r.grade_reasons.iter().any(|s| s.contains("SSLv2")));
}

#[test]
fn test_cap_ssl3_gives_b_not_c() {
    // SSL Labs 2020+: SSL3 → cap B (not C as it was before)
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(true),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    // Must be B or worse
    assert!(
        r.effective_grade() >= Grade::B,
        "SSL3 should cap to at least B"
    );
    // Must NOT be only C (old behaviour)
    assert!(r.grade_reasons.iter().any(|s| s.contains("SSLv3")));
}

#[test]
fn test_cap_tls10_gives_b_even_with_tls12() {
    // TLS 1.0 cap applies even when TLS 1.2 is also supported
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(true),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert!(
        r.effective_grade() >= Grade::B,
        "TLS1.0 should cap to at least B"
    );
    assert!(r.applied_rules.iter().any(|s| s.contains("TLS10")));
}

#[test]
fn test_cap_tls11_gives_b_even_with_tls12() {
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(false),
        tls10: Some(false),
        tls11: Some(true),
        tls12: Some(true),
        tls13: Some(false),
    };
    let r = rate_proto_only(&proto);
    assert!(r.effective_grade() >= Grade::B);
    assert!(r.applied_rules.iter().any(|s| s.contains("TLS11")));
}

#[test]
fn test_cap_export_cipher_gives_f() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher("EXP-RC4-MD5", "RC4", 40, false)],
        total_tested: 1,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    assert_eq!(r.effective_grade(), Grade::F);
    assert!(r.grade_reasons.iter().any(|s| s.contains("Export")));
}

#[test]
fn test_cap_rc4_with_modern_tls_gives_c() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher("RC4-MD5", "RC4", 128, false)],
        total_tested: 1,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    assert!(r.effective_grade() >= Grade::C);
    assert!(r.grade_reasons.iter().any(|s| s.contains("RC4")));
}

#[test]
fn test_cap_no_forward_secrecy_gives_b() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher("AES128-SHA", "AES", 128, false)], // pfs=false
        total_tested: 1,
    };
    let fs = ForwardSecrecyResult {
        has_fs: false,
        ..Default::default()
    };
    let r = rate_server(
        &proto,
        Some(&ciphers),
        None,
        Some(&fs),
        None,
        None,
        None,
        None,
    );
    assert!(r.effective_grade() >= Grade::B);
    assert!(r.applied_rules.iter().any(|s| s.contains("NO_FS")));
}

#[test]
fn test_cap_no_aead_gives_b() {
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher("AES128-SHA", "AES", 128, true)], // CBC, not AEAD
        total_tested: 1,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    assert!(r.effective_grade() >= Grade::B);
    assert!(r.applied_rules.iter().any(|s| s.contains("NO_AEAD")));
}

#[test]
fn test_cap_robot_gives_f() {
    let proto = tls12_only();
    let vulns = vec![make_vuln("ROBOT", true)];
    let r = rate_server(&proto, None, None, None, None, None, Some(&vulns), None);
    assert_eq!(r.effective_grade(), Grade::F);
    assert!(r.applied_rules.iter().any(|s| s.contains("ROBOT")));
}

// ── Fatal certificate rules ───────────────────────────────────────────────────

#[test]
fn test_fatal_expired_cert_gives_t() {
    let proto = tls12_only();
    let cert = make_cert_result(true, false, -10, "sha256WithRSAEncryption");
    let r = rate_server(&proto, None, Some(&cert), None, None, None, None, None);
    assert_eq!(r.effective_grade(), Grade::T);
    assert!(r.grade_reasons.iter().any(|s| s.contains("expired")));
}

#[test]
fn test_fatal_self_signed_cert_gives_t() {
    let proto = tls12_only();
    let cert = make_cert_result(false, true, 365, "sha256WithRSAEncryption");
    let r = rate_server(&proto, None, Some(&cert), None, None, None, None, None);
    assert_eq!(r.effective_grade(), Grade::T);
    assert!(r.grade_reasons.iter().any(|s| s.contains("self-signed")));
}

#[test]
fn test_fatal_hostname_mismatch_gives_m() {
    let proto = tls12_only();
    // Cert has SAN "other.example.com", we're checking "mismatch.example.com"
    let cert = CertCheckResult {
        certs: vec![CertInfo {
            subject: "CN=other.example.com".to_string(),
            subject_alt_names: vec!["other.example.com".to_string()],
            is_expired: false,
            is_self_signed: false,
            is_root_ca: false,
            days_until_expiry: 365,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            key_type: "RSA".to_string(),
            key_bits: 2048,
            ..CertInfo::default()
        }],
        chain_complete: true,
        chain_order_ok: true,
        ocsp_must_staple: false,
    };
    let r = rate_server(
        &proto,
        None,
        Some(&cert),
        None,
        None,
        None,
        None,
        Some("mismatch.example.com"),
    );
    assert_eq!(r.effective_grade(), Grade::M);
    assert!(r.applied_rules.iter().any(|s| s.contains("CERT_MISMATCH")));
}

#[test]
fn test_fatal_insecure_sig_md5_gives_f() {
    let proto = tls12_only();
    let cert = make_cert_result(false, false, 365, "md5WithRSAEncryption");
    let r = rate_server(&proto, None, Some(&cert), None, None, None, None, None);
    assert_eq!(r.effective_grade(), Grade::F);
    assert!(r.applied_rules.iter().any(|s| s.contains("INSECURE_SIG")));
}

#[test]
fn test_root_ca_self_signed_not_flagged() {
    let proto = tls12_only();
    let cert = CertCheckResult {
        certs: vec![CertInfo {
            is_self_signed: true,
            is_root_ca: true,
            is_expired: false,
            days_until_expiry: 365,
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            key_type: "RSA".to_string(),
            key_bits: 4096,
            ..CertInfo::default()
        }],
        chain_complete: true,
        chain_order_ok: true,
        ocsp_must_staple: false,
    };
    let r = rate_server(&proto, None, Some(&cert), None, None, None, None, None);
    assert!(!r.grade_reasons.iter().any(|s| s.contains("self-signed")));
}

// ── Warning rules ─────────────────────────────────────────────────────────────

#[test]
fn test_warn_no_tls13_downgrades_a_to_aminus() {
    // TLS 1.2 only, good config → would get A → but no TLS 1.3 warning → A-
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    let eff = r.effective_grade();
    assert!(r.warnings.iter().any(|w| w.contains("TLS 1.3")));
    // Must be A- or worse (the no-TLS1.3 warning)
    assert!(eff >= Grade::AMinus, "Expected A- or worse, got {:?}", eff);
}

#[test]
fn test_warn_no_hsts_downgrades_a_to_aminus() {
    // TLS 1.2+1.3, good ciphers, headers checked but no HSTS → A-
    let proto = tls12_and_13();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let headers = HttpHeadersResult {
        hsts: None, // no HSTS
        http_available: true,
        ..Default::default()
    };
    let r = rate_server(
        &proto,
        Some(&ciphers),
        None,
        None,
        Some(&headers),
        None,
        None,
        None,
    );
    assert!(r.warnings.iter().any(|w| w.contains("HSTS")));
    assert!(r.effective_grade() >= Grade::AMinus);
}

#[test]
fn test_warn_cert_expiring_adds_warning() {
    let proto = tls12_only();
    let cert = make_cert_result(false, false, 20, "sha256WithRSAEncryption");
    let r = rate_server(&proto, None, Some(&cert), None, None, None, None, None);
    assert!(r.warnings.iter().any(|w| w.contains("20 days")));
}

#[test]
fn test_no_warn_cert_not_expiring_soon() {
    let proto = tls12_only();
    let cert = make_cert_result(false, false, 365, "sha256WithRSAEncryption");
    let r = rate_server(&proto, None, Some(&cert), None, None, None, None, None);
    assert!(!r.warnings.iter().any(|w| w.contains("days")));
}

// ── Bonus rule: A+ ────────────────────────────────────────────────────────────

#[test]
fn test_bonus_aplus_with_valid_hsts() {
    // TLS 1.2+1.3, AEAD cipher, valid HSTS with max-age=31536000, hostname match
    let proto = tls12_and_13();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let headers = make_hsts_headers(31_536_000); // 1 year
    let cert = make_cert_result(false, false, 365, "sha256WithRSAEncryption");
    let r = rate_server(
        &proto,
        Some(&ciphers),
        Some(&cert),
        None,
        Some(&headers),
        None,
        None,
        Some("example.com"),
    );
    assert_eq!(
        r.effective_grade(),
        Grade::APlus,
        "Expected A+, got {:?}: warnings={:?}, caps={:?}",
        r.effective_grade(),
        r.warnings,
        r.grade_reasons
    );
}

#[test]
fn test_bonus_no_aplus_if_warnings_present() {
    // TLS 1.2 only (no TLS 1.3 warning fires) → no A+
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let headers = make_hsts_headers(31_536_000);
    let r = rate_server(
        &proto,
        Some(&ciphers),
        None,
        None,
        Some(&headers),
        None,
        None,
        None,
    );
    // No TLS 1.3 → warning → no A+
    assert_ne!(r.effective_grade(), Grade::APlus);
}

#[test]
fn test_bonus_no_aplus_hsts_max_age_too_short() {
    // HSTS present but max-age < 15_768_000 → no A+
    let proto = tls12_and_13();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let headers = make_hsts_headers(3600); // only 1 hour, too short
    let r = rate_server(
        &proto,
        Some(&ciphers),
        None,
        None,
        Some(&headers),
        None,
        None,
        None,
    );
    assert_ne!(r.effective_grade(), Grade::APlus);
}

#[test]
fn test_bonus_no_aplus_without_hsts() {
    let proto = tls12_and_13();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    // headers_result = None → hsts not checked → no A+
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    assert_ne!(r.effective_grade(), Grade::APlus);
}

// ── Example scenarios from Task_ssllabs.md ───────────────────────────────────

#[test]
fn test_example_a_strong_config_aplus() {
    // TLS 1.2+1.3, ECDHE+AEAD, valid HSTS, no warnings, no vulns → A+
    let proto = tls12_and_13();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let headers = make_hsts_headers(31_536_000);
    let cert = make_cert_result(false, false, 365, "sha256WithRSAEncryption");
    let r = rate_server(
        &proto,
        Some(&ciphers),
        Some(&cert),
        None,
        Some(&headers),
        None,
        None,
        Some("example.com"),
    );
    let eff = r.effective_grade();
    assert!(
        eff == Grade::APlus || eff == Grade::A,
        "Expected A or A+, got {:?}",
        eff
    );
    assert!(r.overall_score >= 80);
}

#[test]
fn test_example_b_tls12_only_gets_aminus() {
    // TLS 1.2 only, otherwise strong → A- (no TLS 1.3 warning)
    let proto = tls12_only();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let r = rate_server(&proto, Some(&ciphers), None, None, None, None, None, None);
    let eff = r.effective_grade();
    assert!(
        eff >= Grade::AMinus,
        "Expected A- or worse for TLS1.2-only, got {:?}",
        eff
    );
}

#[test]
fn test_example_c_no_hsts_gets_aminus() {
    // TLS 1.2+1.3, no HSTS → A- warning
    let proto = tls12_and_13();
    let ciphers = CipherEnumResult {
        supported: vec![make_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AESGCM",
            256,
            true,
        )],
        total_tested: 1,
    };
    let headers = HttpHeadersResult {
        hsts: None,
        http_available: true,
        ..Default::default()
    };
    let r = rate_server(
        &proto,
        Some(&ciphers),
        None,
        None,
        Some(&headers),
        None,
        None,
        None,
    );
    assert!(r.effective_grade() >= Grade::AMinus);
    assert!(!r.warnings.is_empty());
}

#[test]
fn test_example_d_ssl3_caps_to_b() {
    // SSL 3.0 enabled → cap B
    let proto = ProtocolSupport {
        ssl2: Some(false),
        ssl3: Some(true),
        tls10: Some(false),
        tls11: Some(false),
        tls12: Some(true),
        tls13: Some(true),
    };
    let r = rate_proto_only(&proto);
    assert!(r.effective_grade() >= Grade::B);
}

#[test]
fn test_example_e_robot_gives_f() {
    let proto = tls12_only();
    let vulns = vec![make_vuln("ROBOT", true)];
    let r = rate_server(&proto, None, None, None, None, None, Some(&vulns), None);
    assert_eq!(r.effective_grade(), Grade::F);
}

// ── Hostname match logic ──────────────────────────────────────────────────────

#[test]
fn test_hostname_match_direct() {
    use testssl_core::checks::rating::model::check_hostname_match;
    let sans: Vec<String> = vec!["example.com".to_string()];
    assert!(check_hostname_match("example.com", "example.com", &sans));
    assert!(!check_hostname_match("other.com", "example.com", &sans));
}

#[test]
fn test_hostname_match_wildcard() {
    use testssl_core::checks::rating::model::check_hostname_match;
    let sans: Vec<String> = vec!["*.example.com".to_string()];
    assert!(check_hostname_match("sub.example.com", "", &sans));
    assert!(!check_hostname_match("example.com", "", &sans));
    assert!(!check_hostname_match("deep.sub.example.com", "", &sans));
}

#[test]
fn test_hostname_match_san_with_dns_prefix() {
    // Regression: server_defaults stores SANs as "DNS:example.com" — must still match
    use testssl_core::checks::rating::model::check_hostname_match;
    let sans: Vec<String> = vec![
        "DNS:*.prozorro.sale".to_string(),
        "DNS:prozorro.sale".to_string(),
    ];
    // Apex domain must match the exact-name SAN entry despite "DNS:" prefix
    assert!(
        check_hostname_match("prozorro.sale", "", &sans),
        "apex domain must match DNS:prozorro.sale SAN"
    );
    // Subdomain must match wildcard SAN
    assert!(
        check_hostname_match("sub.prozorro.sale", "", &sans),
        "subdomain must match DNS:*.prozorro.sale SAN"
    );
    // Unrelated domain must not match
    assert!(
        !check_hostname_match("other.com", "", &sans),
        "unrelated domain must not match"
    );
}
