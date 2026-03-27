//! CCS Injection vulnerability check (CVE-2014-0224)
//!
//! Based on testssl.sh run_ccs_injection() implementation.
//! See: https://www.openssl.org/news/secadv_20140605.txt

use anyhow::Result;
use tracing::{debug, info};

use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

use super::VulnResult;

/// Build a ChangeCipherSpec message for a given TLS version
fn build_ccs(major: u8, minor: u8) -> Vec<u8> {
    vec![
        0x14, // ChangeCipherSpec content type
        major, minor, 0x00, 0x01, // length = 1
        0x01, // ChangeCipherSpec message
    ]
}

/// Build the ClientHello for CCS injection test
/// Uses a fixed cipher suite list matching testssl.sh's ccs_injection client hello
fn build_ccs_client_hello(tls_major: u8, tls_minor: u8, sni: Option<&str>) -> Vec<u8> {
    // Fixed cipher suites from testssl.sh run_ccs_injection (51 suites)
    // This is the exact cipher list from lines 17488-17500 of testssl.sh
    let cipher_bytes: Vec<u8> = vec![
        0xc0, 0x13, 0xc0, 0x12, 0xc0, 0x11, 0xc0, 0x10, 0xc0, 0x0f, 0xc0, 0x0e, 0xc0, 0x0d, 0xc0,
        0x0c, 0xc0, 0x0b, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x08, 0xc0, 0x07, 0xc0, 0x06, 0xc0, 0x05,
        0xc0, 0x04, 0xc0, 0x03, 0xc0, 0x02, 0xc0, 0x01, 0x00, 0x39, 0x00, 0x38, 0x00, 0x37, 0x00,
        0x36, 0x00, 0x35, 0x00, 0x34, 0x00, 0x33, 0x00, 0x32, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2f,
        0x00, 0x16, 0x00, 0x15, 0x00, 0x14, 0x00, 0x13, 0x00, 0x12, 0x00, 0x11, 0x00, 0x10, 0x00,
        0x0f, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x0c, 0x00, 0x0b, 0x00, 0x0a, 0x00, 0x09, 0x00, 0x08,
        0x00, 0x07, 0x00, 0x06, 0x00, 0x05, 0x00, 0x04, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01, 0x01,
        0x00,
    ];
    let cipher_len = cipher_bytes.len() as u16;

    // Fixed random (32 bytes) from testssl.sh
    let random = [
        0x53u8, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48,
        0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0b, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33,
        0xd4, 0xde,
    ];

    // Build ClientHello body
    let mut body = Vec::new();
    body.push(tls_major);
    body.push(tls_minor);
    body.extend_from_slice(&random);
    body.push(0x00); // session ID length = 0
    body.push((cipher_len >> 8) as u8);
    body.push((cipher_len & 0xff) as u8);
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01); // compression methods length
    body.push(0x00); // null compression

    // Add SNI extension so modern servers accept the ClientHello
    if let Some(hostname) = sni {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = name_len + 3; // name_type(1) + name_len(2) + name
        let ext_len = list_len + 2; // list_len(2) + list

        let mut extensions = Vec::new();
        // Extension type: server_name (0x0000)
        extensions.extend_from_slice(&[0x00, 0x00]);
        // Extension data length
        extensions.push((ext_len >> 8) as u8);
        extensions.push((ext_len & 0xff) as u8);
        // Server name list length
        extensions.push((list_len >> 8) as u8);
        extensions.push((list_len & 0xff) as u8);
        // Name type: host_name (0)
        extensions.push(0x00);
        // Hostname length
        extensions.push((name_len >> 8) as u8);
        extensions.push((name_len & 0xff) as u8);
        extensions.extend_from_slice(name_bytes);

        let exts_total = extensions.len() as u16;
        body.push((exts_total >> 8) as u8);
        body.push((exts_total & 0xff) as u8);
        body.extend_from_slice(&extensions);
    }

    let body_len = body.len() as u32;

    // Build handshake message
    let mut handshake = vec![
        0x01u8, // ClientHello type
        ((body_len >> 16) & 0xff) as u8,
        ((body_len >> 8) & 0xff) as u8,
        (body_len & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);

    // Build TLS record (record layer version is always TLS 1.0 = 0x0301 unless SSLv3)
    let rec_minor = if tls_minor == 0x00 { 0x00u8 } else { 0x01u8 };
    let hs_len = handshake.len() as u16;
    let mut record = vec![
        0x16u8, // Handshake content type
        0x03,
        rec_minor,
        (hs_len >> 8) as u8,
        (hs_len & 0xff) as u8,
    ];
    record.extend_from_slice(&handshake);
    record
}

/// Check for CCS injection vulnerability
pub async fn check_ccs_injection(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for CCS Injection (CVE-2014-0224) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2014-0224".to_string()];

    // Try TLS versions in order of preference (matching testssl.sh logic)
    for (tls_major, tls_minor) in &[(0x03u8, 0x03u8), (0x03, 0x02), (0x03, 0x01), (0x03, 0x00)] {
        match test_ccs_version(target, *tls_major, *tls_minor, &cve).await {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => {
                // This version didn't give a conclusive result, try next
                debug!(
                    "CCS injection: no conclusive result for TLS {:02x}{:02x}",
                    tls_major, tls_minor
                );
            }
            Err(e) => {
                debug!(
                    "CCS injection error for TLS {:02x}{:02x}: {}",
                    tls_major, tls_minor, e
                );
            }
        }
    }

    Ok(VulnResult::unknown(
        "CCS Injection",
        "Could not establish TLS connection for testing",
    ))
}

async fn test_ccs_version(
    target: &ScanTarget,
    tls_major: u8,
    tls_minor: u8,
    cve: &[String],
) -> Result<Option<VulnResult>> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(None);
        }
    }

    // Send ClientHello with the exact cipher list from testssl.sh (+ SNI for modern servers)
    let hello = build_ccs_client_hello(tls_major, tls_minor, target.sni.as_deref());
    socket.send(&hello).await?;

    // Read ServerHello
    let response = match tokio::time::timeout(
        tokio::time::Duration::from_secs(target.timeout_secs),
        socket.recv(32768),
    )
    .await
    {
        Ok(Ok(data)) if !data.is_empty() => data,
        _ => return Ok(None),
    };

    // Check if we got a valid server hello (first byte should be 0x16 = handshake)
    if response.is_empty() || response[0] != 0x16 {
        // Got alert or nothing useful - this TLS version not supported
        return Ok(None);
    }

    debug!(
        "CCS: Got ServerHello for TLS {:02x}{:02x}, sending CCS payload #1",
        tls_major, tls_minor
    );

    // Send CCS payload #1 (before ServerHelloDone)
    let ccs = build_ccs(tls_major, tls_minor);
    if socket.send(&ccs).await.is_err() {
        // Connection reset - not vulnerable
        return Ok(Some(VulnResult::not_vulnerable("CCS Injection")));
    }

    // Read response after first CCS
    let response1 =
        match tokio::time::timeout(tokio::time::Duration::from_millis(5000), socket.recv(4096))
            .await
        {
            Ok(Ok(data)) => data,
            Ok(Err(_)) => {
                // Connection reset after first CCS → not vulnerable
                return Ok(Some(VulnResult::not_vulnerable("CCS Injection")));
            }
            Err(_) => {
                // Timeout after first CCS
                debug!("CCS: Timeout after first CCS, sending second CCS");
                Vec::new()
            }
        };

    debug!(
        "CCS: first response ({} bytes): {:02x?}",
        response1.len(),
        &response1[..response1.len().min(8)]
    );

    // Send CCS payload #2
    if socket.send(&ccs).await.is_err() {
        // Connection closed after first CCS → not vulnerable (server rejected it)
        return Ok(Some(VulnResult::not_vulnerable("CCS Injection")));
    }

    // Read response after second CCS
    let response2 =
        match tokio::time::timeout(tokio::time::Duration::from_millis(5000), socket.recv(4096))
            .await
        {
            Ok(Ok(data)) => data,
            Ok(Err(_)) => {
                // Connection reset after second CCS → not vulnerable
                return Ok(Some(VulnResult::not_vulnerable("CCS Injection")));
            }
            Err(_) => {
                // Both CCS accepted (no response at all) → VULNERABLE
                debug!("CCS: Timeout after second CCS - server accepted both, likely VULNERABLE");
                return Ok(Some(VulnResult::vulnerable(
                    "CCS Injection",
                    cve.to_vec(),
                    "Server accepted early ChangeCipherSpec (timed out waiting for response)"
                        .to_string(),
                )));
            }
        };

    debug!(
        "CCS: second response ({} bytes): {:02x?}",
        response2.len(),
        &response2[..response2.len().min(14)]
    );

    // Analyze the response per testssl.sh logic (lines 17551-17607):
    //
    // Empty reply → NOT vulnerable (connection reset = server rejected CCS)
    // Alert 0x15 with content_type=0x15 (decryption_failed=21) → VULNERABLE
    // Alert with unexpected_message(0x0a) or handshake_failure(0x28) → probably NOT vulnerable
    // Alert with bad_record_mac(0x14) → likely VULNERABLE
    // Other alerts → likely VULNERABLE

    if response2.is_empty() {
        // Empty reply = connection reset = normal rejection of early CCS
        debug!("CCS: Empty reply after CCS - not vulnerable");
        return Ok(Some(VulnResult::not_vulnerable("CCS Injection")));
    }

    // Check if it's an alert (content type 0x15)
    if response2[0] == 0x15 && response2.len() >= 5 {
        // Verify it's a proper TLS record (version byte should be 0x03)
        if response2[1] != 0x03 {
            // Not a proper TLS reply
            return Ok(None);
        }

        // Get the alert description (byte 6, 0-indexed = byte at position 6)
        // Alert record: type(1) + version(2) + length(2) + level(1) + description(1)
        let alert_desc = if response2.len() >= 7 {
            response2[6]
        } else {
            0
        };

        debug!("CCS: Alert description: 0x{:02x}", alert_desc);

        match alert_desc {
            0x15 => {
                // decryption_failed (21) → VULNERABLE
                return Ok(Some(VulnResult::vulnerable(
                    "CCS Injection",
                    cve.to_vec(),
                    format!("Server sent decryption_failed alert (0x{:02x}) - VULNERABLE to CCS injection", alert_desc),
                )));
            }
            0x0a | 0x28 => {
                // unexpected_message (10) or handshake_failure (40) → NOT vulnerable
                return Ok(Some(VulnResult::not_vulnerable("CCS Injection")));
            }
            0x14 => {
                // bad_record_mac (20) → likely VULNERABLE
                return Ok(Some(VulnResult::vulnerable(
                    "CCS Injection",
                    cve.to_vec(),
                    format!("Server sent bad_record_mac alert (0x{:02x}) - likely VULNERABLE to CCS injection", alert_desc),
                )));
            }
            _ => {
                // Other alerts → check if server accepted CCS
                // Other alert descriptions generally indicate VULNERABLE
                return Ok(Some(VulnResult::vulnerable(
                    "CCS Injection",
                    cve.to_vec(),
                    format!("Server sent suspicious alert (0x{:02x}) instead of rejecting CCS - likely VULNERABLE", alert_desc),
                )));
            }
        }
    }

    // Got non-alert response → server may have accepted the CCS
    debug!("CCS: Non-alert response after CCS - server accepted CCS, VULNERABLE");
    Ok(Some(VulnResult::vulnerable(
        "CCS Injection",
        cve.to_vec(),
        "Server accepted early ChangeCipherSpec without proper alert".to_string(),
    )))
}
