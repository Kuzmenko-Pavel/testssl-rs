//! ROBOT vulnerability check (Return Of Bleichenbacher's Oracle Threat)
//! CVE-2017-13099, CVE-2017-17382, CVE-2017-17427, CVE-2017-17428

use anyhow::Result;
use std::time::Instant;
use tracing::{debug, info};

use super::VulnResult;
use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// RSA key exchange cipher suites (non-PSK)
const RSA_KEY_TRANSPORT_CIPHERS: &[[u8; 2]] = &[
    [0x00, 0x9d], // AES256-GCM-SHA384
    [0x00, 0x9c], // AES128-GCM-SHA256
    [0x00, 0x3d], // AES256-SHA256
    [0x00, 0x3c], // AES128-SHA256
    [0x00, 0x35], // AES256-SHA
    [0x00, 0x2f], // AES128-SHA
];

/// PKCS#1 v1.5 padding oracle test variants
#[derive(Debug, Clone, Copy)]
enum PaddingVariant {
    /// Correct PKCS#1 v1.5 padding: 00 02 <rnd> 00 <version> <pms>
    Correct,
    /// Wrong first two bytes: 41 17 instead of 00 02
    WrongFirstBytes,
    /// Zero byte in wrong position
    ZeroInWrongPlace,
    /// No zero separator byte between padding and data
    NoZeroSeparator,
    /// Wrong version bytes after separator
    WrongVersion,
}

/// Build a padded premaster secret for testing ROBOT
/// The padded_pms will be of length `key_bytes`
fn build_padded_pms(variant: PaddingVariant, key_bytes: usize) -> Vec<u8> {
    // Fixed random padding bytes (no 0x00 allowed in padding area)
    let rnd_pms = &[
        0xaa, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x11, 0x22,
    ];

    // The TLS version in the premaster secret (TLS 1.2 = 0x03, 0x03)
    let tls_ver = [0x03u8, 0x03u8];

    // Padding: 00 02 <random non-zero bytes> 00
    // Total = key_bytes, so random padding = key_bytes - 3 - 2 (for tls_ver) - 46 (pms length)
    // minimum: key_bytes - 51 non-zero random bytes
    let pms_data_len = tls_ver.len() + rnd_pms.len(); // 2 + 46 = 48
    let random_pad_len = key_bytes.saturating_sub(3 + pms_data_len); // key_bytes - 51

    // Build random padding bytes (non-zero, repeating pattern)
    let mut random_pad = vec![0xabu8; random_pad_len];
    for (i, b) in random_pad.iter_mut().enumerate() {
        *b = (0xab_u8).wrapping_add((i & 0xff) as u8);
        if *b == 0x00 {
            *b = 0x01; // avoid 0x00 in random padding
        }
    }

    let mut pms = Vec::with_capacity(key_bytes);
    match variant {
        PaddingVariant::Correct => {
            pms.push(0x00);
            pms.push(0x02);
            pms.extend_from_slice(&random_pad);
            pms.push(0x00);
            pms.extend_from_slice(&tls_ver);
            pms.extend_from_slice(rnd_pms);
        }
        PaddingVariant::WrongFirstBytes => {
            pms.push(0x41);
            pms.push(0x17);
            pms.extend_from_slice(&random_pad);
            pms.push(0x00);
            pms.extend_from_slice(&tls_ver);
            pms.extend_from_slice(rnd_pms);
        }
        PaddingVariant::ZeroInWrongPlace => {
            pms.push(0x00);
            pms.push(0x02);
            pms.extend_from_slice(&random_pad);
            pms.push(0x11); // wrong: no zero separator
            pms.extend_from_slice(rnd_pms);
            pms.push(0x00);
            pms.push(0x11);
        }
        PaddingVariant::NoZeroSeparator => {
            pms.push(0x00);
            pms.push(0x02);
            pms.extend_from_slice(&random_pad);
            // no 0x00 separator, just data directly
            pms.push(0x11);
            pms.push(0x11);
            pms.push(0x11);
            pms.extend_from_slice(rnd_pms);
        }
        PaddingVariant::WrongVersion => {
            pms.push(0x00);
            pms.push(0x02);
            pms.extend_from_slice(&random_pad);
            pms.push(0x00);
            pms.push(0x02); // wrong version (0x0202 instead of 0x0303)
            pms.push(0x02);
            pms.extend_from_slice(rnd_pms);
        }
    }

    // Pad to key_bytes length if needed
    while pms.len() < key_bytes {
        pms.push(0x00);
    }
    if pms.len() > key_bytes {
        pms.truncate(key_bytes);
    }
    pms
}

/// Check for ROBOT vulnerability
pub async fn check_robot(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for ROBOT vulnerability on {}:{}",
        target.host, target.port
    );

    let cves = vec![
        "CVE-2017-13099".to_string(),
        "CVE-2017-17382".to_string(),
        "CVE-2017-17427".to_string(),
        "CVE-2017-17428".to_string(),
        "CVE-2016-6883".to_string(),
        "CVE-2012-5081".to_string(),
    ];

    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    // Step 1: Check if server supports RSA key exchange ciphers
    let rsa_supported = check_rsa_cipher_support(target).await;
    if !rsa_supported {
        return Ok(VulnResult::not_applicable(
            "ROBOT",
            "No RSA key transport cipher suites supported",
        ));
    }

    debug!("RSA key exchange supported, proceeding with ROBOT check");

    // Step 2: Get the server certificate to extract RSA public key
    // We do this by doing a partial handshake with RSA ciphers
    let cert_and_key_size = get_rsa_key_size(target, &host).await;
    let key_bytes = match cert_and_key_size {
        Some(kb) => kb,
        None => {
            return Ok(VulnResult::unknown(
                "ROBOT",
                "Could not determine RSA key size from certificate",
            ));
        }
    };

    debug!("RSA key size: {} bytes ({} bits)", key_bytes, key_bytes * 8);

    // Step 3: Send 5 different padded CKE messages and measure response times / types
    let variants = [
        PaddingVariant::Correct,
        PaddingVariant::WrongFirstBytes,
        PaddingVariant::ZeroInWrongPlace,
        PaddingVariant::NoZeroSeparator,
        PaddingVariant::WrongVersion,
    ];

    let mut responses: Vec<Option<Vec<u8>>> = Vec::new();
    let mut timings: Vec<u64> = Vec::new();

    for variant in &variants {
        let padded_pms = build_padded_pms(*variant, key_bytes);
        let (resp, elapsed_ms) = send_robot_probe(target, &host, padded_pms).await;
        debug!(
            "Variant {:?}: elapsed={}ms, got_response={}",
            variant,
            elapsed_ms,
            resp.is_some()
        );
        responses.push(resp);
        timings.push(elapsed_ms);
    }

    // Step 4: Analyze responses
    // If responses differ between valid/invalid padding → oracle exists → VULNERABLE
    // If all are the same (all timeouts or all same alert) → NOT VULNERABLE

    // Check if any responses differ
    let first = &responses[0];
    let all_same = responses.iter().all(|r| responses_equal(r, first));

    if !all_same {
        // Check if timing differs significantly between correct and wrong padding
        let correct_time = timings[0];
        let avg_wrong: u64 = timings[1..].iter().sum::<u64>() / (timings.len() as u64 - 1);

        if correct_time > avg_wrong + 500 || avg_wrong > correct_time + 500 {
            return Ok(VulnResult::vulnerable(
                "ROBOT",
                cves,
                format!(
                    "Strong Bleichenbacher oracle detected: timing difference {}ms vs {}ms average",
                    correct_time, avg_wrong
                ),
            ));
        }

        // Responses differ in content (not just timing)
        return Ok(VulnResult::vulnerable(
            "ROBOT",
            cves,
            "Bleichenbacher oracle: server returns different responses for different padding variants".to_string(),
        ));
    }

    // Check if all timed out (could be a weak oracle - retry needed)
    let all_timeout = responses.iter().all(|r| r.is_none());
    if all_timeout {
        return Ok(VulnResult::unknown(
            "ROBOT",
            "All probes timed out, inconclusive",
        ));
    }

    Ok(VulnResult::not_vulnerable("ROBOT"))
}

/// Compare two optional response buffers for equality
fn responses_equal(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            // Compare first 7 bytes (TLS record header + alert type) to normalize variable-length data
            let len = std::cmp::min(7, std::cmp::min(a.len(), b.len()));
            a[..len] == b[..len]
        }
        _ => false,
    }
}

/// Check if server supports RSA key exchange (non-ECDHE, non-DHE) cipher suites
async fn check_rsa_cipher_support(target: &ScanTarget) -> bool {
    for cipher in RSA_KEY_TRANSPORT_CIPHERS {
        if let Ok(true) =
            crate::checks::ciphers::test_cipher_direct(target, TlsVersion::Tls12, *cipher).await
        {
            return true;
        }
    }
    false
}

/// Get RSA public key size by parsing the server certificate during a partial handshake
async fn get_rsa_key_size(target: &ScanTarget, host: &str) -> Option<usize> {
    let mut socket = TlsSocket::connect(host, target.port, target.timeout_secs)
        .await
        .ok()?;

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return None;
        }
    }

    // Build ClientHello with RSA ciphers only (so server sends Certificate)
    let rsa_ciphers: Vec<[u8; 2]> = RSA_KEY_TRANSPORT_CIPHERS.to_vec();
    let mut builder = ClientHelloBuilder::new(TlsVersion::Tls12).with_cipher_suites(rsa_ciphers);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello = builder.build();
    socket.send(&hello).await.ok()?;

    let response = match tokio::time::timeout(
        tokio::time::Duration::from_secs(target.timeout_secs),
        socket.recv(65536),
    )
    .await
    {
        Ok(Ok(data)) if !data.is_empty() => data,
        _ => return None,
    };

    // Parse the server hello to get the certificate
    let sh_result = crate::tls::server_hello::ServerHelloParser::parse(&response).ok()?;

    // Extract key size from certificate using x509-parser
    for cert_der in &sh_result.certificates {
        if let Some(key_size) = parse_rsa_key_size_from_cert(cert_der) {
            return Some(key_size);
        }
    }

    None
}

/// Parse the RSA public key size (in bytes) from a DER-encoded certificate
fn parse_rsa_key_size_from_cert(cert_der: &[u8]) -> Option<usize> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let pk = cert.public_key();

    match pk.parsed().ok()? {
        x509_parser::public_key::PublicKey::RSA(rsa) => {
            // key_size() returns the size of the modulus in bytes
            Some(rsa.key_size())
        }
        _ => {
            // Not an RSA key
            None
        }
    }
}

/// Send a Robot probe (ClientHello + fake ClientKeyExchange with crafted padding)
/// Returns (response_bytes, elapsed_ms)
async fn send_robot_probe(
    target: &ScanTarget,
    host: &str,
    padded_pms: Vec<u8>,
) -> (Option<Vec<u8>>, u64) {
    let mut socket = match TlsSocket::connect(host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(_) => return (None, 0),
    };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return (None, 0);
        }
    }

    // Send ClientHello with RSA ciphers
    let rsa_ciphers: Vec<[u8; 2]> = RSA_KEY_TRANSPORT_CIPHERS.to_vec();
    let mut builder = ClientHelloBuilder::new(TlsVersion::Tls12).with_cipher_suites(rsa_ciphers);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello = builder.build();

    if socket.send(&hello).await.is_err() {
        return (None, 0);
    }

    // Read ServerHello + Certificate + ServerHelloDone
    let _server_response = match tokio::time::timeout(
        tokio::time::Duration::from_secs(target.timeout_secs),
        socket.recv(65536),
    )
    .await
    {
        Ok(Ok(data)) if !data.is_empty() => data,
        _ => return (None, 0),
    };

    // Build a fake ClientKeyExchange with the crafted padded_pms
    // The padded_pms is NOT actually RSA-encrypted (we don't have the private key),
    // but we send it raw to observe the oracle response
    let cke = build_client_key_exchange(&padded_pms);
    let ccs = build_change_cipher_spec();
    let finished = build_fake_finished();

    let mut payload = Vec::new();
    payload.extend_from_slice(&cke);
    payload.extend_from_slice(&ccs);
    payload.extend_from_slice(&finished);

    let start = Instant::now();

    if socket.send(&payload).await.is_err() {
        return (None, start.elapsed().as_millis() as u64);
    }

    // Read the response (alert or other)
    let timeout_dur = tokio::time::Duration::from_secs(target.timeout_secs.min(3));
    let resp = match tokio::time::timeout(timeout_dur, socket.recv(4096)).await {
        Ok(Ok(data)) if !data.is_empty() => Some(data),
        _ => None,
    };

    let elapsed = start.elapsed().as_millis() as u64;
    (resp, elapsed)
}

/// Build a TLS ClientKeyExchange message with the given encrypted PMS
fn build_client_key_exchange(encrypted_pms: &[u8]) -> Vec<u8> {
    let pms_len = encrypted_pms.len() as u16;
    // Inner: length prefix (2 bytes) + data
    let inner_len = (2 + pms_len) as u32;

    // Handshake message: type (1) + length (3) + length_prefix (2) + data
    let hs_len = 4 + 2 + pms_len as usize;
    let record_len = hs_len as u16;

    let mut record = vec![
        0x16u8, // handshake
        0x03,   // TLS major
        0x03,   // TLS 1.2 minor
        (record_len >> 8) as u8,
        (record_len & 0xff) as u8,
        // Handshake header
        0x10, // ClientKeyExchange type
        ((inner_len >> 16) & 0xff) as u8,
        ((inner_len >> 8) & 0xff) as u8,
        (inner_len & 0xff) as u8,
        // EncryptedPreMasterSecret: length (2) + data
        (pms_len >> 8) as u8,
        (pms_len & 0xff) as u8,
    ];
    record.extend_from_slice(encrypted_pms);

    record
}

/// Build a TLS ChangeCipherSpec message
fn build_change_cipher_spec() -> Vec<u8> {
    vec![
        0x14, // ChangeCipherSpec content type
        0x03, 0x03, // TLS 1.2
        0x00, 0x01, // length = 1
        0x01, // value
    ]
}

/// Build a fake (garbage) TLS Finished message
fn build_fake_finished() -> Vec<u8> {
    // Finished message (will be rejected but triggers server to respond)
    let fake_finished_data = [
        0x16u8, 0x03, 0x03, // TLS 1.2
        0x00, 0x40, // length = 64 bytes
        // Fake finished content (will be garbage after MAC)
        0x6e, 0x49, 0x65, 0x68, 0x00, 0x46, 0x79, 0xfd, 0x5a, 0x57, 0xdc, 0x3e, 0xef, 0xb2, 0xd2,
        0xac, 0xe0, 0x8c, 0x54, 0x2d, 0x5f, 0x00, 0x87, 0xdb, 0xb6, 0xe3, 0x77, 0x2c, 0x9d, 0x88,
        0x27, 0x38, 0x98, 0x7d, 0xcd, 0x7e, 0xac, 0xdd, 0x5d, 0x72, 0xbe, 0x24, 0x0d, 0x20, 0x36,
        0x14, 0x0e, 0x94, 0x51, 0xde, 0xa0, 0xb6, 0xc7, 0x56, 0x28, 0xd8, 0xa1, 0xcb, 0x24, 0xb9,
        0x03, 0xd0, 0x7c, 0x50,
    ];
    fake_finished_data.to_vec()
}
