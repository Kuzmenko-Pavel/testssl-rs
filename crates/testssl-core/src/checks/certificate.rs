//! Certificate chain analysis using x509-parser

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;
use x509_parser::prelude::*;

/// Map a signature algorithm OID string to its human-readable name.
pub fn oid_to_sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".to_string(),
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_string(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        "1.2.840.113549.1.1.10" => "rsassaPss".to_string(),
        other => other.to_string(),
    }
}

use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::server_hello::ServerHelloParser;
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Certificate information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub signature_algorithm: String,
    pub key_type: String,
    pub key_bits: u32,
    pub subject_alt_names: Vec<String>,
    pub ocsp_stapled: bool,
    pub ct_scts: Vec<String>,
    pub is_expired: bool,
    pub is_self_signed: bool,
    /// True if this is the root CA (last cert in chain, self-signed by definition).
    /// Should not be flagged as an error.
    pub is_root_ca: bool,
    pub fingerprint_sha256: String,
    pub trust_stores: Vec<TrustResult>,
}

/// Trust store verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResult {
    pub store: String,
    pub trusted: bool,
    pub error: Option<String>,
}

/// Certificate chain check result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertCheckResult {
    pub certs: Vec<CertInfo>,
    pub chain_complete: bool,
    pub chain_order_ok: bool,
    pub ocsp_must_staple: bool,
}

/// Fetch certificates from server
pub async fn fetch_certificates(target: &ScanTarget) -> Result<Vec<Vec<u8>>> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = TlsSocket::connect(&host, target.port, target.timeout_secs).await?;

    if let Some(ref starttls) = target.starttls {
        starttls.negotiate(&mut socket).await?;
    }

    let mut builder = ClientHelloBuilder::new(TlsVersion::Tls12);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello_bytes = builder.build();
    socket.send(&hello_bytes).await?;

    let response = socket.recv_multiple_records(8000).await?;
    if response.is_empty() {
        return Ok(Vec::new());
    }

    let result = ServerHelloParser::parse(&response)?;
    Ok(result.certificates)
}

/// Parse a DER-encoded certificate
pub fn parse_certificate(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).context("Failed to parse certificate")?;

    let mut info = CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: format!("{}", cert.serial),
        ..CertInfo::default()
    };

    // Validity
    info.not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
    info.not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();

    // Check expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let not_after_ts = cert.validity().not_after.timestamp();
    let now_i64 = now as i64;
    info.days_until_expiry = (not_after_ts - now_i64) / 86400;
    if not_after_ts <= now_i64 {
        info.is_expired = true;
    }

    // Signature algorithm
    info.signature_algorithm = oid_to_sig_name(&cert.signature_algorithm.algorithm.to_string());

    // Public key info
    let spki = cert.public_key();
    match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            info.key_type = "RSA".to_string();
            info.key_bits = rsa.key_size() as u32;
        }
        Ok(x509_parser::public_key::PublicKey::EC(ec)) => {
            info.key_type = "EC".to_string();
            // Estimate bits from key data length
            info.key_bits = match ec.data().len() {
                33 | 65 => 256,  // P-256
                49 | 97 => 384,  // P-384
                67 | 133 => 521, // P-521
                _ => (ec.data().len() * 4) as u32,
            };
        }
        _ => {
            info.key_type = "Unknown".to_string();
        }
    }

    // Subject Alternative Names
    if let Ok(Some(san_ext)) =
        cert.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
    {
        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => info.subject_alt_names.push(dns.to_string()),
                    GeneralName::IPAddress(ip) => {
                        if ip.len() == 4 {
                            info.subject_alt_names
                                .push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Check if self-signed
    info.is_self_signed = cert.subject() == cert.issuer();

    // Fingerprint SHA-256
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    info.fingerprint_sha256 = digest
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");

    Ok(info)
}

/// Run full certificate check
pub async fn check_certificate(target: &ScanTarget) -> Result<CertCheckResult> {
    let mut result = CertCheckResult::default();

    info!("Checking certificate for {}:{}", target.host, target.port);

    let cert_ders = fetch_certificates(target).await?;

    for der in &cert_ders {
        match parse_certificate(der) {
            Ok(info) => result.certs.push(info),
            Err(e) => tracing::warn!("Failed to parse certificate: {}", e),
        }
    }

    // Mark root CA: last cert in chain that is self-signed is expected to be self-signed
    if result.certs.len() > 1 {
        if let Some(last) = result.certs.last_mut() {
            if last.is_self_signed {
                last.is_root_ca = true;
            }
        }
    }

    // Check chain completeness (at least 1 cert)
    result.chain_complete = !result.certs.is_empty();

    // Check chain order (first cert should be server cert, rest intermediates)
    if result.certs.len() > 1 {
        // Simple check: each cert's issuer should match the next cert's subject
        result.chain_order_ok = true;
        for i in 0..result.certs.len() - 1 {
            if result.certs[i].issuer != result.certs[i + 1].subject {
                result.chain_order_ok = false;
                break;
            }
        }
    } else {
        result.chain_order_ok = result.certs.len() == 1;
    }

    Ok(result)
}
