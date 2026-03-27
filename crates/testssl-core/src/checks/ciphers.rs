//! Cipher suite enumeration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::data::cipher_mapping::CipherSuite;
use crate::data::CIPHER_SUITES;
use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::server_hello::ServerHelloParser;
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Result of cipher enumeration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherEnumResult {
    pub supported: Vec<SupportedCipher>,
    pub total_tested: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedCipher {
    pub hex_high: u8,
    pub hex_low: u8,
    pub ossl_name: String,
    pub rfc_name: String,
    pub tls_version: String,
    pub kx: String,
    pub enc: String,
    pub bits: u16,
    pub mac: String,
    /// Whether cipher provides Perfect Forward Secrecy
    pub pfs: bool,
    /// Whether this is an export-grade cipher
    pub is_export: bool,
}

impl From<&CipherSuite> for SupportedCipher {
    fn from(cs: &CipherSuite) -> Self {
        // Look up extended info from CipherInfo if available
        let (pfs, is_export) = crate::data::find_cipher_info(cs.hex_high, cs.hex_low)
            .map(|ci| (ci.pfs, ci.is_export))
            .unwrap_or((false, cs.is_export()));

        Self {
            hex_high: cs.hex_high,
            hex_low: cs.hex_low,
            ossl_name: cs.ossl_name.to_string(),
            rfc_name: cs.rfc_name.to_string(),
            tls_version: cs.tls_version.to_string(),
            kx: cs.kx.to_string(),
            enc: cs.enc.to_string(),
            bits: cs.bits,
            mac: cs.mac.to_string(),
            pfs,
            is_export,
        }
    }
}

/// Cipher categories discovered during enumeration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherCategories {
    /// No encryption (NULL ciphers)
    pub null_ciphers: Vec<SupportedCipher>,
    /// Anonymous (no auth — ADH, AECDH)
    pub anull_ciphers: Vec<SupportedCipher>,
    /// EXPORT-grade (40/56-bit)
    pub export_ciphers: Vec<SupportedCipher>,
    /// Low-grade (<64 bit, e.g. DES, RC2)
    pub low_ciphers: Vec<SupportedCipher>,
    /// 3DES / 64-bit block ciphers (SWEET32 candidate)
    pub triple_des: Vec<SupportedCipher>,
    /// Vulnerable to SWEET32 (3DES or Blowfish in use)
    pub sweet32_vuln: bool,
    /// RC4 stream ciphers
    pub rc4_ciphers: Vec<SupportedCipher>,
    /// Strong AEAD ciphers (AES-GCM, ChaCha20-Poly1305, ≥128 bit)
    pub strong_ciphers: Vec<SupportedCipher>,
    /// Ciphers that provide Perfect Forward Secrecy
    pub pfs_ciphers: Vec<SupportedCipher>,
}

// ────────────────────────────────────────────────────────────────────────────
// Internal connection helpers
// ────────────────────────────────────────────────────────────────────────────

/// Open a plain TCP connection, optionally perform STARTTLS.
async fn open_connection(target: &ScanTarget) -> Result<TlsSocket> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = TlsSocket::connect(&host, target.port, target.timeout_secs).await?;

    if let Some(ref starttls) = target.starttls {
        starttls.negotiate(&mut socket).await?;
    }

    Ok(socket)
}

/// Test if a specific cipher suite is supported (one-cipher-per-connection, used by
/// `test_cipher_direct` and the old enumerate path).
async fn test_cipher(target: &ScanTarget, version: TlsVersion, cipher: [u8; 2]) -> Result<bool> {
    let mut socket = match open_connection(target).await {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    let mut builder = ClientHelloBuilder::new(version).with_cipher_suites(vec![cipher]);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello_bytes = builder.build();

    if socket.send(&hello_bytes).await.is_err() {
        return Ok(false);
    }

    let response = match socket.recv_multiple_records(2000).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(false),
    };

    let result = ServerHelloParser::parse(&response)?;

    let supported = result.cipher_suite == cipher
        && ServerHelloParser::is_successful(&result)
        && !ServerHelloParser::has_fatal_alert(&result);

    if supported {
        debug!("Cipher {:02x}{:02x} is supported", cipher[0], cipher[1]);
    }

    Ok(supported)
}

// ────────────────────────────────────────────────────────────────────────────
// Efficient enumeration (testssl.sh algorithm)
// ────────────────────────────────────────────────────────────────────────────

/// Enumerate all supported cipher suites for a given protocol version.
///
/// Uses the efficient O(n) algorithm:
/// 1. Send ALL remaining ciphers in a single ClientHello.
/// 2. Server picks one → record it, remove from list.
/// 3. Repeat until server sends Alert or connection fails.
pub async fn enumerate_ciphers_for_protocol(
    target: &ScanTarget,
    version: TlsVersion,
) -> Result<Vec<SupportedCipher>> {
    // Collect all cipher codes that apply to this protocol version.
    let mut remaining_ciphers: Vec<[u8; 2]> = match version {
        TlsVersion::Tls13 => {
            // TLS 1.3 defines exactly five cipher suites.
            vec![
                [0x13, 0x01], // TLS_AES_128_GCM_SHA256
                [0x13, 0x02], // TLS_AES_256_GCM_SHA384
                [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
                [0x13, 0x04], // TLS_AES_128_CCM_SHA256
                [0x13, 0x05], // TLS_AES_128_CCM_8_SHA256
            ]
        }
        TlsVersion::Tls12 => CIPHER_SUITES
            .iter()
            .filter(|cs| cs.tls_version != "TLSv1.3")
            .map(|cs| [cs.hex_high, cs.hex_low])
            .collect(),
        TlsVersion::Tls11 | TlsVersion::Tls10 => CIPHER_SUITES
            .iter()
            .filter(|cs| cs.tls_version == "SSLv3" || cs.tls_version == "TLSv1")
            .map(|cs| [cs.hex_high, cs.hex_low])
            .collect(),
        TlsVersion::Ssl30 => CIPHER_SUITES
            .iter()
            .filter(|cs| cs.tls_version == "SSLv3")
            .map(|cs| [cs.hex_high, cs.hex_low])
            .collect(),
    };

    let total = remaining_ciphers.len();
    info!(
        "Enumerating ciphers for {}:{} ({:?}) — {} candidates",
        target.host, target.port, version, total
    );

    let mut supported: Vec<SupportedCipher> = Vec::new();

    loop {
        if remaining_ciphers.is_empty() {
            break;
        }

        // Open a fresh connection for each round.
        let mut socket = match open_connection(target).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Connection failed during cipher enumeration: {}", e);
                break;
            }
        };

        // Build ClientHello with ALL remaining ciphers.
        let mut builder =
            ClientHelloBuilder::new(version).with_cipher_suites(remaining_ciphers.clone());
        if let Some(ref sni) = target.sni {
            builder = builder.with_sni(sni.as_str());
        }
        let hello_bytes = builder.build();

        if socket.send(&hello_bytes).await.is_err() {
            debug!("Send failed during cipher enumeration");
            break;
        }

        let response = match socket.recv_multiple_records(3000).await {
            Ok(data) if !data.is_empty() => data,
            _ => {
                debug!("No response during cipher enumeration — server rejected remaining ciphers");
                break;
            }
        };

        let result = match ServerHelloParser::parse(&response) {
            Ok(r) => r,
            Err(e) => {
                debug!("Parse error during cipher enumeration: {}", e);
                break;
            }
        };

        // Server sent a fatal alert → no more ciphers accepted.
        if ServerHelloParser::has_fatal_alert(&result) {
            debug!("Fatal alert received — stopping cipher enumeration");
            break;
        }

        // Server did not send a ServerHello → stop.
        if !ServerHelloParser::is_successful(&result) {
            debug!("No ServerHello received — stopping cipher enumeration");
            break;
        }

        let chosen = result.cipher_suite;

        // Look up the chosen cipher in our mapping.
        let cipher_info = CIPHER_SUITES
            .iter()
            .find(|cs| cs.hex_high == chosen[0] && cs.hex_low == chosen[1]);

        match cipher_info {
            Some(cs) => {
                debug!(
                    "Server chose cipher {:02x}{:02x} ({})",
                    chosen[0], chosen[1], cs.ossl_name
                );
                supported.push(SupportedCipher::from(cs));
            }
            None => {
                // Cipher not in our mapping — record a minimal entry so we still
                // remove it and continue.
                warn!(
                    "Server chose unknown cipher {:02x}{:02x} — recording minimal info",
                    chosen[0], chosen[1]
                );
                supported.push(SupportedCipher {
                    hex_high: chosen[0],
                    hex_low: chosen[1],
                    ossl_name: format!("0x{:02X}0x{:02X}", chosen[0], chosen[1]),
                    rfc_name: String::new(),
                    tls_version: version.as_str().to_string(),
                    kx: String::new(),
                    enc: String::new(),
                    bits: 0,
                    mac: String::new(),
                    pfs: false,
                    is_export: false,
                });
            }
        }

        // Remove the chosen cipher from the remaining list.
        remaining_ciphers.retain(|c| c != &chosen);
    }

    info!(
        "Enumeration complete for {:?}: {}/{} ciphers supported",
        version,
        supported.len(),
        total
    );

    Ok(supported)
}

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/// Enumerate all supported cipher suites for the given protocol version.
///
/// Uses the efficient testssl.sh O(n) algorithm internally.
/// Backward-compatible signature.
pub async fn enumerate_ciphers(
    target: &ScanTarget,
    version: TlsVersion,
) -> Result<CipherEnumResult> {
    info!(
        "Enumerating ciphers for {}:{} with {:?}",
        target.host, target.port, version
    );

    // Count total candidates (for total_tested field).
    let total_tested = match version {
        TlsVersion::Tls13 => 5,
        TlsVersion::Tls12 => CIPHER_SUITES
            .iter()
            .filter(|cs| cs.tls_version != "TLSv1.3")
            .count(),
        TlsVersion::Tls11 | TlsVersion::Tls10 => CIPHER_SUITES
            .iter()
            .filter(|cs| cs.tls_version == "SSLv3" || cs.tls_version == "TLSv1")
            .count(),
        TlsVersion::Ssl30 => CIPHER_SUITES
            .iter()
            .filter(|cs| cs.tls_version == "SSLv3")
            .count(),
    };

    let supported = enumerate_ciphers_for_protocol(target, version).await?;

    Ok(CipherEnumResult {
        supported,
        total_tested,
    })
}

/// Check for specific cipher categories (NULL, aNULL, EXPORT, LOW, 3DES, RC4, strong, PFS).
///
/// Enumerates ciphers across all relevant protocol versions and classifies them.
pub async fn check_cipher_categories(target: &ScanTarget) -> Result<CipherCategories> {
    // Collect all ciphers across all protocol versions.
    // We use TLS 1.2 as the broadest sweep (covers SSLv3 through TLS 1.2 ciphers).
    // TLS 1.3 has its own small set.
    let versions = [
        TlsVersion::Tls13,
        TlsVersion::Tls12,
        TlsVersion::Tls10,
        TlsVersion::Ssl30,
    ];

    let mut all_supported: Vec<SupportedCipher> = Vec::new();

    for ver in versions {
        match enumerate_ciphers_for_protocol(target, ver).await {
            Ok(mut ciphers) => all_supported.append(&mut ciphers),
            Err(e) => {
                debug!("Cipher enumeration failed for {:?}: {}", ver, e);
            }
        }
    }

    // De-duplicate by hex code.
    let mut seen = std::collections::HashSet::new();
    all_supported.retain(|c| seen.insert((c.hex_high, c.hex_low)));

    let mut cats = CipherCategories::default();

    for cipher in &all_supported {
        let name_upper = cipher.ossl_name.to_uppercase();

        // NULL — no encryption
        let is_null = cipher.kx == "None"
            || cipher.enc == "None"
            || cipher.enc.is_empty() && cipher.bits == 0
            || name_upper.contains("NULL");

        // aNULL — anonymous (no server auth)
        let is_anull = name_upper.contains("ADH")
            || name_upper.contains("AECDH")
            || (cipher.kx.contains("DH") && cipher.kx.contains("anon"));

        // EXPORT
        let is_export = cipher.is_export || name_upper.starts_with("EXP");

        // 3DES / SWEET32
        let is_3des = cipher.enc.contains("3DES")
            || cipher.enc.contains("DES-CBC3")
            || name_upper.contains("3DES")
            || name_upper.contains("DES_EDE");

        // LOW (<64 bit, not NULL)
        let is_low = !is_null && cipher.bits > 0 && cipher.bits < 64;

        // RC4
        let is_rc4 = cipher.enc.contains("RC4")
            || name_upper.contains("RC4")
            || name_upper.contains("ARCFOUR");

        // STRONG: ≥128 bit AEAD (AES-GCM, ChaCha20-Poly1305) or similar
        let is_strong = cipher.bits >= 128
            && (cipher.mac.contains("AEAD")
                || cipher.enc.contains("GCM")
                || cipher.enc.contains("ChaCha20")
                || name_upper.contains("GCM")
                || name_upper.contains("CHACHA20"));

        // PFS
        let is_pfs = cipher.pfs;

        if is_null {
            cats.null_ciphers.push(cipher.clone());
        }
        if is_anull {
            cats.anull_ciphers.push(cipher.clone());
        }
        if is_export {
            cats.export_ciphers.push(cipher.clone());
        }
        if is_low {
            cats.low_ciphers.push(cipher.clone());
        }
        if is_3des {
            cats.triple_des.push(cipher.clone());
        }
        if is_rc4 {
            cats.rc4_ciphers.push(cipher.clone());
        }
        if is_strong {
            cats.strong_ciphers.push(cipher.clone());
        }
        if is_pfs {
            cats.pfs_ciphers.push(cipher.clone());
        }
    }

    // SWEET32: any 3DES or Blowfish cipher being negotiated is sufficient.
    cats.sweet32_vuln = !cats.triple_des.is_empty()
        || all_supported.iter().any(|c| {
            c.enc.contains("BF")
                || c.enc.contains("Blowfish")
                || c.ossl_name.to_uppercase().contains("IDEA")
        });

    Ok(cats)
}

// ────────────────────────────────────────────────────────────────────────────
// Helper filter functions (kept for backward compatibility)
// ────────────────────────────────────────────────────────────────────────────

/// Check for weak cipher suites
pub fn find_weak_ciphers(ciphers: &[SupportedCipher]) -> Vec<&SupportedCipher> {
    ciphers
        .iter()
        .filter(|c| {
            c.bits < 128
                || c.enc.contains("RC4")
                || c.enc.contains("DES")
                || c.enc == "None"
                || c.enc.contains("NULL")
        })
        .collect()
}

/// Check for export ciphers
pub fn find_export_ciphers(ciphers: &[SupportedCipher]) -> Vec<&SupportedCipher> {
    ciphers
        .iter()
        .filter(|c| c.ossl_name.starts_with("EXP"))
        .collect()
}

/// Check for anonymous ciphers
pub fn find_anon_ciphers(ciphers: &[SupportedCipher]) -> Vec<&SupportedCipher> {
    ciphers
        .iter()
        .filter(|c| {
            c.kx == "DH" && c.ossl_name.contains("ADH")
                || c.ossl_name.contains("AECDH")
                || c.ossl_name.contains("NULL")
        })
        .collect()
}

/// Public helper to test a single cipher (used by forward_secrecy module)
pub async fn test_cipher_direct(
    target: &ScanTarget,
    version: TlsVersion,
    cipher: [u8; 2],
) -> Result<bool> {
    test_cipher(target, version, cipher).await
}
