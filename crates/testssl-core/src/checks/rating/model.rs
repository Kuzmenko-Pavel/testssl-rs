//! Normalized rating input model — collects facts from all check results

use crate::checks::certificate::CertCheckResult;
use crate::checks::ciphers::CipherEnumResult;
use crate::checks::forward_secrecy::ForwardSecrecyResult;
use crate::checks::http_headers::HttpHeadersResult;
use crate::checks::protocols::ProtocolSupport;
use crate::checks::server_defaults::{ServerDefaults, TrustStatus};
use crate::checks::vulnerabilities::{VulnResult, VulnStatus};

/// Normalized set of facts used as input to the rating engine.
/// Consumed by scoring and rule-engine layers.
#[derive(Debug, Clone, Default)]
pub struct RatingFacts {
    // ── Certificate facts ───────────────────────────────────────────────────
    pub cert_expired: bool,
    pub cert_self_signed: bool, // true only when self-signed AND not a root CA
    pub cert_trusted: bool,     // trusted in at least one CA store
    pub cert_hostname_match: bool, // CN or SAN matches the target hostname
    pub cert_sig_algorithm: String, // e.g. "sha256WithRSAEncryption"
    pub cert_key_bits: u32,
    pub cert_key_type: String, // "RSA", "EC", …
    pub chain_complete: bool,
    pub cert_days_until_expiry: i64, // 0 means unknown / not checked

    // ── Protocol facts ──────────────────────────────────────────────────────
    pub has_ssl2: bool,
    pub has_ssl3: bool,
    pub has_tls10: bool,
    pub has_tls11: bool,
    pub has_tls12: bool,
    pub has_tls13: bool,
    pub best_protocol: String,
    pub worst_protocol: String,

    // ── Cipher facts ────────────────────────────────────────────────────────
    pub min_cipher_bits: u16,
    pub max_cipher_bits: u16,
    pub has_aead: bool,
    pub has_export: bool,
    pub has_rc4: bool,
    pub has_null: bool,
    pub has_anon: bool,
    pub cipher_data_available: bool,

    // ── Key exchange facts ──────────────────────────────────────────────────
    pub effective_kx_bits: u32, // RSA-equivalent bits used for KX scoring
    pub has_forward_secrecy: bool,
    pub fs_data_available: bool,

    // ── HTTP header facts ───────────────────────────────────────────────────
    pub hsts_present: bool,
    pub hsts_max_age: u64,
    pub hsts_valid: bool, // present AND max_age > 0
    pub headers_data_available: bool,

    // ── Vulnerability facts ─────────────────────────────────────────────────
    pub robot_vulnerable: bool,
    pub heartbleed_vulnerable: bool,
    pub poodle_vulnerable: bool,
    pub ccs_vulnerable: bool,
    pub drown_vulnerable: bool,
}

struct ProtoEntry {
    name: &'static str,
    score: u32,
    supported: bool,
}

/// Collect and normalize all rating-relevant facts from available check results.
#[allow(clippy::too_many_arguments)]
pub fn collect_rating_facts(
    proto: &ProtocolSupport,
    cipher_result: Option<&CipherEnumResult>,
    cert_result: Option<&CertCheckResult>,
    fs_result: Option<&ForwardSecrecyResult>,
    headers_result: Option<&HttpHeadersResult>,
    server_defaults: Option<&ServerDefaults>,
    vulnerabilities: Option<&[VulnResult]>,
    target_hostname: Option<&str>,
) -> RatingFacts {
    let mut f = RatingFacts {
        // Optimistic defaults — absence of data must not penalize
        cert_trusted: true,
        cert_hostname_match: true,
        chain_complete: true,
        cert_key_bits: 2048,
        effective_kx_bits: 2048,
        cert_key_type: "RSA".to_string(),
        has_aead: true,
        has_forward_secrecy: true,
        min_cipher_bits: 128,
        max_cipher_bits: 128,
        ..Default::default()
    };

    // ── Protocol facts ──────────────────────────────────────────────────────
    f.has_ssl2 = proto.ssl2 == Some(true);
    f.has_ssl3 = proto.ssl3 == Some(true);
    f.has_tls10 = proto.tls10 == Some(true);
    f.has_tls11 = proto.tls11 == Some(true);
    f.has_tls12 = proto.tls12 == Some(true);
    f.has_tls13 = proto.tls13 == Some(true);

    // SSL Labs protocol scores (used for ordering only; calc_protocol_score uses these names)
    let protos = [
        ProtoEntry {
            name: "SSL2",
            score: 0,
            supported: f.has_ssl2,
        },
        ProtoEntry {
            name: "SSL3",
            score: 80,
            supported: f.has_ssl3,
        },
        ProtoEntry {
            name: "TLS1.0",
            score: 90,
            supported: f.has_tls10,
        },
        ProtoEntry {
            name: "TLS1.1",
            score: 95,
            supported: f.has_tls11,
        },
        ProtoEntry {
            name: "TLS1.2",
            score: 100,
            supported: f.has_tls12,
        },
        ProtoEntry {
            name: "TLS1.3",
            score: 100,
            supported: f.has_tls13,
        },
    ];

    let supported: Vec<&ProtoEntry> = protos.iter().filter(|p| p.supported).collect();
    if let Some(best) = supported.iter().max_by_key(|p| p.score) {
        f.best_protocol = best.name.to_string();
    }
    if let Some(worst) = supported.iter().min_by_key(|p| p.score) {
        f.worst_protocol = worst.name.to_string();
    }
    if f.best_protocol.is_empty() {
        f.best_protocol = "none".to_string();
        f.worst_protocol = "none".to_string();
    }

    // ── Cipher facts ────────────────────────────────────────────────────────
    if let Some(ciphers) = cipher_result {
        f.cipher_data_available = true;
        if ciphers.supported.is_empty() {
            f.min_cipher_bits = 0;
            f.max_cipher_bits = 0;
            f.has_aead = false;
        } else {
            f.min_cipher_bits = ciphers.supported.iter().map(|c| c.bits).min().unwrap_or(0);
            f.max_cipher_bits = ciphers.supported.iter().map(|c| c.bits).max().unwrap_or(0);
            // TLS 1.3 mandates AEAD ciphers
            f.has_aead = f.has_tls13 || ciphers.supported.iter().any(|c| is_aead_enc(&c.enc));
            f.has_export = ciphers
                .supported
                .iter()
                .any(|c| c.is_export || c.ossl_name.starts_with("EXP"));
            f.has_rc4 = ciphers
                .supported
                .iter()
                .any(|c| c.enc.to_uppercase().contains("RC4"));
            f.has_null = ciphers.supported.iter().any(|c| {
                c.bits == 0 || c.enc.to_uppercase() == "NULL" || c.ossl_name.contains("NULL")
            });
            f.has_anon = ciphers.supported.iter().any(|c| {
                c.kx.to_lowercase().contains("anon") || c.ossl_name.to_lowercase().contains("anon")
            });
        }
    } else {
        // No cipher data — assume AEAD only when TLS 1.3 is available
        f.has_aead = f.has_tls13;
    }

    // ── Certificate facts ───────────────────────────────────────────────────
    let leaf_cert = cert_result.and_then(|c| c.certs.first());

    if let Some(leaf) = leaf_cert {
        f.cert_expired = leaf.is_expired;
        f.cert_self_signed = leaf.is_self_signed && !leaf.is_root_ca;
        f.cert_sig_algorithm = leaf.signature_algorithm.clone();
        f.cert_key_bits = leaf.key_bits;
        f.cert_key_type = leaf.key_type.clone();
        if leaf.days_until_expiry > 0 {
            f.cert_days_until_expiry = leaf.days_until_expiry;
        }
    }

    if let Some(cert) = cert_result {
        f.chain_complete = cert.chain_complete;
    }

    // ── Trust and hostname match from server_defaults ───────────────────────
    if let Some(sd) = server_defaults {
        if !sd.trust.is_empty() {
            f.cert_trusted = sd.trust.values().any(|s| matches!(s, TrustStatus::Trusted));
        }
        // Fill in key info if cert_result didn't provide it
        if f.cert_key_bits == 0 {
            f.cert_key_bits = sd.server_key_bits.unwrap_or(2048);
        }
        if f.cert_key_type.is_empty() || f.cert_key_type == "RSA" {
            if let Some(ref kt) = sd.server_key_type {
                f.cert_key_type = kt.clone();
            }
        }
        if f.cert_days_until_expiry == 0 {
            if let Some(days) = sd.cert_days_left {
                if days > 0 {
                    f.cert_days_until_expiry = days;
                }
            }
        }
        if f.cert_sig_algorithm.is_empty() {
            if let Some(ref alg) = sd.cert_signature_algorithm {
                f.cert_sig_algorithm = alg.clone();
            }
        }
        // Hostname match: check CN and SAN from server_defaults
        if let Some(hostname) = target_hostname {
            let cn = sd.cn.as_deref().unwrap_or("");
            f.cert_hostname_match = check_hostname_match(hostname, cn, &sd.san);
        }
    } else if let Some(leaf) = leaf_cert {
        // Fallback: extract CN from subject DN
        if let Some(hostname) = target_hostname {
            let cn = extract_cn_from_dn(&leaf.subject);
            f.cert_hostname_match = check_hostname_match(hostname, &cn, &leaf.subject_alt_names);
        }
    }

    // ── Key exchange facts ──────────────────────────────────────────────────
    let rsa_equiv = kx_rsa_equiv_bits(&f.cert_key_type, f.cert_key_bits);
    let dh_bits = fs_result.and_then(|fs| fs.best_dhe_bits).map(|b| b as u32);
    f.effective_kx_bits = match dh_bits {
        Some(dh) => rsa_equiv.min(dh),
        None => rsa_equiv,
    };
    if f.effective_kx_bits == 0 {
        f.effective_kx_bits = 2048; // safe fallback
    }

    // ── Forward secrecy ─────────────────────────────────────────────────────
    f.fs_data_available = fs_result.is_some() || cipher_result.is_some() || f.has_tls13;
    f.has_forward_secrecy = if let Some(fs) = fs_result {
        fs.has_fs
    } else if f.has_tls13 {
        true // TLS 1.3 mandates ECDHE
    } else if let Some(ciphers) = cipher_result {
        ciphers.supported.iter().any(|c| c.pfs)
    } else {
        true // optimistic: no penalty without data
    };

    // ── HSTS facts ──────────────────────────────────────────────────────────
    f.headers_data_available = headers_result.is_some();
    if let Some(headers) = headers_result {
        if let Some(ref hsts) = headers.hsts {
            f.hsts_present = true;
            f.hsts_max_age = hsts.max_age;
            f.hsts_valid = hsts.max_age > 0;
        }
    }

    // ── Vulnerability facts ─────────────────────────────────────────────────
    if let Some(vulns) = vulnerabilities {
        for v in vulns {
            if matches!(v.status, VulnStatus::Vulnerable) {
                let up = v.name.to_uppercase();
                if up.contains("ROBOT") {
                    f.robot_vulnerable = true;
                } else if up.contains("HEARTBLEED") {
                    f.heartbleed_vulnerable = true;
                } else if up.contains("POODLE") {
                    f.poodle_vulnerable = true;
                } else if up.contains("CCS") {
                    f.ccs_vulnerable = true;
                } else if up.contains("DROWN") {
                    f.drown_vulnerable = true;
                }
            }
        }
    }

    f
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Returns true if the encryption algorithm is AEAD (authenticated encryption).
fn is_aead_enc(enc: &str) -> bool {
    let u = enc.to_uppercase();
    u.contains("GCM") || u.contains("CCM") || u.contains("CHACHA20") || u.contains("POLY1305")
}

/// Convert EC key bits to approximate RSA-equivalent bits for KX strength scoring.
/// NIST recommendations: P-256 ≈ 3072-bit RSA, P-384 ≈ 7680-bit RSA.
fn kx_rsa_equiv_bits(key_type: &str, bits: u32) -> u32 {
    let kt = key_type.to_uppercase();
    if kt == "EC" || kt.contains("ECDSA") || kt.contains("ECDH") {
        match bits {
            0..=159 => 512,
            160..=223 => 1024,
            224..=255 => 2048,
            256..=383 => 3072,
            384..=511 => 7680,
            _ => 15360,
        }
    } else {
        bits
    }
}

/// Returns true if `hostname` matches `cn` or any entry in `sans`.
/// Handles simple wildcards: `*.example.com` matches `sub.example.com`.
pub fn check_hostname_match(hostname: &str, cn: &str, sans: &[impl AsRef<str>]) -> bool {
    let h = hostname.to_lowercase();
    // SANs take priority
    for san in sans {
        if wildcard_match(&h, &san.as_ref().to_lowercase()) {
            return true;
        }
    }
    // Fall back to CN if no SANs or SANs didn't match
    if !cn.is_empty() {
        wildcard_match(&h, &cn.to_lowercase())
    } else {
        false
    }
}

fn wildcard_match(hostname: &str, pattern: &str) -> bool {
    // Strip optional "TYPE:" prefix produced by server_defaults SAN parsing
    // (e.g. "DNS:example.com" → "example.com", "IP:1.2.3.4" → "1.2.3.4")
    let pattern = if let Some(pos) = pattern.find(':') {
        &pattern[pos + 1..]
    } else {
        pattern
    };

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // *.example.com matches sub.example.com but not example.com or a.b.example.com
        if !hostname.ends_with(&format!(".{suffix}")) {
            return false;
        }
        let prefix = &hostname[..hostname.len() - suffix.len() - 1];
        !prefix.contains('.')
    } else {
        hostname == pattern
    }
}

/// Extract the CN value from an X.509 subject DN string like "CN=example.com, O=Acme".
fn extract_cn_from_dn(subject: &str) -> String {
    for part in subject.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.trim().to_string();
        }
    }
    String::new()
}
