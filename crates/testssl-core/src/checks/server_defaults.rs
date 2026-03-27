//! Server default settings check
//!
//! Collects server certificate information, TLS extension support,
//! session ticket/resumption capabilities, clock skew, and trust status.

use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;
use x509_parser::prelude::*;

use crate::checks::certificate::oid_to_sig_name;
use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::server_hello::ServerHelloParser;
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Full server default settings result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerDefaults {
    // Connection info
    pub hostname: String,
    pub ip: String,

    // TLS extensions offered by the server
    pub tls_extensions: Vec<String>,

    // Session management
    pub session_ticket: Option<bool>,
    pub session_resumption_id: Option<bool>,
    pub session_resumption_ticket: Option<bool>,

    // TLS features
    pub heartbeat: Option<bool>,
    pub alpn: Option<String>,
    pub clock_skew: Option<i64>,
    pub tls_timestamp: Option<u32>,
    pub compression: Option<bool>,
    pub client_auth: Option<String>,
    pub certificate_compression: Vec<String>,

    // Certificate details (leaf certificate)
    pub cert_signature_algorithm: Option<String>,
    pub server_key_type: Option<String>,
    pub server_key_bits: Option<u32>,
    pub fingerprint_sha1: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub cn: Option<String>,
    pub san: Vec<String>,
    pub issuer: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_days_left: Option<i64>,
    pub ocsp_uri: Option<String>,
    pub crl_uri: Option<String>,
    pub must_staple: bool,
    pub certificate_transparency: Option<String>,

    // Trust status per CA store
    pub trust: HashMap<String, TrustStatus>,
}

/// Trust status for a particular CA store
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum TrustStatus {
    Trusted,
    NotTrusted,
    #[default]
    Unknown,
}

/// Map TLS extension type to a human-readable name
fn ext_type_name(ext_type: u16) -> String {
    match ext_type {
        0x0000 => "server_name".to_string(),
        0x0001 => "max_fragment_length".to_string(),
        0x000a => "supported_groups".to_string(),
        0x000b => "ec_point_formats".to_string(),
        0x000d => "signature_algorithms".to_string(),
        0x000f => "heartbeat".to_string(),
        0x0010 => "application_layer_protocol_negotiation".to_string(),
        0x0011 => "status_request".to_string(),
        0x0012 => "signed_certificate_timestamp".to_string(),
        0x0015 => "padding".to_string(),
        0x0017 => "extended_master_secret".to_string(),
        0x001c => "record_size_limit".to_string(),
        0x0023 => "session_ticket".to_string(),
        0x0029 => "pre_shared_key".to_string(),
        0x002a => "early_data".to_string(),
        0x002b => "supported_versions".to_string(),
        0x002c => "cookie".to_string(),
        0x002d => "psk_key_exchange_modes".to_string(),
        0x0031 => "post_handshake_auth".to_string(),
        0x0033 => "key_share".to_string(),
        0x3374 => "next_protocol_negotiation".to_string(),
        0xff01 => "renegotiation_info".to_string(),
        other => format!("unknown(0x{:04x})", other),
    }
}

/// Internal cert info extracted from a DER-encoded certificate
#[derive(Debug, Default)]
struct ParsedCertInfo {
    cn: Option<String>,
    issuer: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    days_left: Option<i64>,
    sig_algorithm: Option<String>,
    key_type: Option<String>,
    key_bits: Option<u32>,
    san: Vec<String>,
    ocsp_uri: Option<String>,
    crl_uri: Option<String>,
    must_staple: bool,
    certificate_transparency: Option<String>,
}

/// Extract certificate info from DER bytes using x509-parser
fn extract_cert_info(der: &[u8]) -> ParsedCertInfo {
    let mut info = ParsedCertInfo::default();

    let parsed = match X509Certificate::from_der(der) {
        Ok((_, cert)) => cert,
        Err(_) => return info,
    };

    // Subject CN
    for rdn in parsed.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Ok(val) = attr.attr_value().as_str() {
                    info.cn = Some(val.to_string());
                }
            }
        }
    }

    // Issuer (full string)
    info.issuer = Some(parsed.issuer().to_string());

    // Validity dates
    let validity = parsed.validity();
    info.not_before = Some(validity.not_before.to_rfc2822().unwrap_or_default());
    info.not_after = Some(validity.not_after.to_rfc2822().unwrap_or_default());

    // Days remaining — use .timestamp() the same way certificate.rs does
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let not_after_ts = validity.not_after.timestamp();
    let days_left = (not_after_ts - now_secs) / 86400;
    info.days_left = Some(days_left);

    // Signature algorithm
    info.sig_algorithm = Some(oid_to_sig_name(
        &parsed.signature_algorithm.algorithm.to_string(),
    ));

    // Public key type and bits
    let spki = parsed.public_key();
    match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            info.key_type = Some("RSA".to_string());
            info.key_bits = Some((rsa.key_size() * 8) as u32);
        }
        Ok(x509_parser::public_key::PublicKey::EC(ec)) => {
            info.key_type = Some("EC".to_string());
            info.key_bits = Some(match ec.data().len() {
                33 | 65 => 256,
                49 | 97 => 384,
                67 | 133 => 521,
                n => (n * 4) as u32,
            });
        }
        _ => {
            info.key_type = Some("Unknown".to_string());
        }
    }

    // SAN extension — use the same approach as certificate.rs
    if let Ok(Some(san_ext)) =
        parsed.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
    {
        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            for name in &san.general_names {
                let san_str = match name {
                    GeneralName::DNSName(s) => format!("DNS:{}", s),
                    GeneralName::IPAddress(ip) => {
                        if ip.len() == 4 {
                            format!("IP:{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                        } else {
                            // IPv6 or other — encode as hex pairs
                            let hex: String = ip
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(":");
                            format!("IP:{}", hex)
                        }
                    }
                    GeneralName::RFC822Name(s) => format!("email:{}", s),
                    GeneralName::URI(s) => format!("URI:{}", s),
                    _ => continue,
                };
                info.san.push(san_str);
            }
        }
    }

    // Authority Information Access (OCSP URI)
    // OID: 1.3.6.1.5.5.7.1.1
    if let Ok(Some(aia_ext)) =
        parsed.get_extension_unique(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
    {
        if let ParsedExtension::AuthorityInfoAccess(aia) = aia_ext.parsed_extension() {
            for access in aia.accessdescs.iter() {
                // OCSP OID: 1.3.6.1.5.5.7.48.1
                if access.access_method == oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
                    if let GeneralName::URI(uri) = &access.access_location {
                        info.ocsp_uri = Some(uri.to_string());
                    }
                }
            }
        }
    }

    // CRL Distribution Points — OID: 2.5.29.31
    if let Ok(Some(cdp_ext)) =
        parsed.get_extension_unique(&oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
    {
        if let ParsedExtension::CRLDistributionPoints(cdps) = cdp_ext.parsed_extension() {
            'outer: for dp in cdps.points.iter() {
                if let Some(DistributionPointName::FullName(ref gns)) = dp.distribution_point {
                    for gn in gns {
                        if let GeneralName::URI(uri) = gn {
                            info.crl_uri = Some(uri.to_string());
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    // Scan all extensions for Must-Staple and CT SCTs
    for ext in parsed.extensions() {
        let oid_str = ext.oid.to_string();
        // Must-Staple / TLS Feature extension OID: 1.3.6.1.5.5.7.1.24
        if oid_str == "1.3.6.1.5.5.7.1.24" {
            info.must_staple = true;
        }
        // Certificate Transparency SCT list: 1.3.6.1.4.1.11129.2.4.2
        if oid_str == "1.3.6.1.4.1.11129.2.4.2" {
            info.certificate_transparency = Some("embedded SCTs present".to_string());
        }
    }

    info
}

/// Compute SHA-256 fingerprint of DER bytes, returned as colon-separated uppercase hex.
fn sha256_fingerprint(der: &[u8]) -> String {
    use ring::digest;
    let d = digest::digest(&digest::SHA256, der);
    d.as_ref()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Compute SHA-1 fingerprint of DER bytes, returned as colon-separated uppercase hex.
fn sha1_fingerprint(der: &[u8]) -> String {
    use ring::digest;
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, der);
    d.as_ref()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Check whether a DER-encoded leaf certificate is signed by any CA in a PEM bundle.
///
/// Uses a simple issuer/subject match — this is not a full chain validation.
fn is_trusted_by_bundle(cert_der: &[u8], bundle_pem: &[u8]) -> bool {
    let leaf = match X509Certificate::from_der(cert_der) {
        Ok((_, c)) => c,
        Err(_) => return false,
    };

    let issuer_raw = leaf.issuer().as_raw();
    let ca_certs = crate::data::parse_pem_bundle(bundle_pem);

    for ca_der in &ca_certs {
        if let Ok((_, ca_cert)) = X509Certificate::from_der(ca_der) {
            if ca_cert.subject().as_raw() == issuer_raw {
                return true;
            }
        }
    }

    false
}

/// Compute trust status of a certificate chain against all 5 built-in CA stores.
fn compute_trust(cert_chain: &[Vec<u8>]) -> HashMap<String, TrustStatus> {
    let mut trust = HashMap::new();

    if cert_chain.is_empty() {
        for name in crate::data::ca_stores::CA_STORE_NAMES {
            trust.insert(name.to_string(), TrustStatus::Unknown);
        }
        return trust;
    }

    let bundles: &[(&str, &[u8])] = &[
        ("mozilla", crate::data::CA_MOZILLA),
        ("microsoft", crate::data::CA_MICROSOFT),
        ("apple", crate::data::CA_APPLE),
        ("java", crate::data::CA_JAVA),
        ("linux", crate::data::CA_LINUX),
    ];

    for (name, bundle) in bundles {
        // Check every cert in the chain — any match means the chain is trusted
        let trusted = cert_chain
            .iter()
            .any(|der| is_trusted_by_bundle(der, bundle));
        trust.insert(
            name.to_string(),
            if trusted {
                TrustStatus::Trusted
            } else {
                TrustStatus::NotTrusted
            },
        );
    }

    trust
}

/// Run server defaults check
pub async fn check_server_defaults(target: &ScanTarget) -> Result<ServerDefaults> {
    let mut defaults = ServerDefaults::default();

    info!(
        "Checking server defaults for {}:{}",
        target.host, target.port
    );

    defaults.hostname = target.host.clone();
    defaults.ip = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let host = defaults.ip.clone();

    let mut socket = TlsSocket::connect(&host, target.port, target.timeout_secs).await?;

    if let Some(ref starttls) = target.starttls {
        starttls.negotiate(&mut socket).await?;
    }

    // Build a full ClientHello with heartbeat + ALPN extensions
    let mut builder = ClientHelloBuilder::new(TlsVersion::Tls12)
        .with_heartbeat()
        .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()]);

    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }

    let hello_bytes = builder.build();
    socket.send(&hello_bytes).await?;

    let response = socket.recv_multiple_records(5000).await?;

    if response.is_empty() {
        return Ok(defaults);
    }

    let result = ServerHelloParser::parse(&response)?;

    // --- TLS extension detection ---
    for ext in &result.extensions {
        let name = ext_type_name(ext.ext_type);
        if !defaults.tls_extensions.contains(&name) {
            defaults.tls_extensions.push(name);
        }
    }

    // --- Session ticket ---
    defaults.session_ticket = Some(result.extensions.iter().any(|e| e.ext_type == 0x0023));

    // --- Heartbeat ---
    defaults.heartbeat = Some(result.heartbeat_offered);

    // --- ALPN ---
    defaults.alpn = result.alpn_protocol.clone();

    // --- Compression ---
    defaults.compression = Some(result.compression_method != 0);

    // --- TLS timestamp / clock skew ---
    if result.random.len() >= 4 {
        let ts = ((result.random[0] as u32) << 24)
            | ((result.random[1] as u32) << 16)
            | ((result.random[2] as u32) << 8)
            | (result.random[3] as u32);
        defaults.tls_timestamp = Some(ts);

        // Clock skew only meaningful for TLS < 1.3 (TLS 1.3 uses fully random)
        let negotiated = result.negotiated_version.unwrap_or(0x0303);
        if negotiated < 0x0304 {
            let local_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            defaults.clock_skew = Some(ts as i64 - local_ts);
        }
    }

    // --- Certificate info ---
    if !result.certificates.is_empty() {
        let leaf_der = &result.certificates[0];

        let cert_info = extract_cert_info(leaf_der);

        defaults.cn = cert_info.cn;
        defaults.san = cert_info.san;
        defaults.issuer = cert_info.issuer;
        defaults.cert_not_before = cert_info.not_before;
        defaults.cert_not_after = cert_info.not_after;
        defaults.cert_days_left = cert_info.days_left;
        defaults.cert_signature_algorithm = cert_info.sig_algorithm;
        defaults.server_key_type = cert_info.key_type;
        defaults.server_key_bits = cert_info.key_bits;
        defaults.ocsp_uri = cert_info.ocsp_uri;
        defaults.crl_uri = cert_info.crl_uri;
        defaults.must_staple = cert_info.must_staple;
        defaults.certificate_transparency = cert_info.certificate_transparency;

        // Fingerprints
        defaults.fingerprint_sha1 = Some(sha1_fingerprint(leaf_der));
        defaults.fingerprint_sha256 = Some(sha256_fingerprint(leaf_der));

        // Trust per CA store
        defaults.trust = compute_trust(&result.certificates);
    }

    Ok(defaults)
}
