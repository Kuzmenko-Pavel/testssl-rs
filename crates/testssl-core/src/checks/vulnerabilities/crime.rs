//! CRIME vulnerability check (CVE-2012-4929)
//! TLS compression leads to information leakage

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::tls::client_hello::TlsVersion;
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Build ClientHello with compression methods offered
fn build_compression_hello(sni: Option<&str>, version: TlsVersion) -> Vec<u8> {
    // We'll build a raw hello that offers compression
    // Standard hello offers null(0) + DEFLATE(1) compression
    build_hello_with_compression(sni, version)
}

fn build_hello_with_compression(sni: Option<&str>, version: TlsVersion) -> Vec<u8> {
    let (major, minor) = version.to_wire_version();

    let ciphers = crate::tls::client_hello::tls12_default_ciphers();
    let mut cipher_bytes = Vec::new();
    for c in &ciphers {
        cipher_bytes.push(c[0]);
        cipher_bytes.push(c[1]);
    }
    cipher_bytes.push(0x00);
    cipher_bytes.push(0xff); // SCSV

    let cipher_len = cipher_bytes.len() as u16;

    // Random
    let random = [0x42u8; 32];

    let mut body = Vec::new();
    body.push(major);
    body.push(minor);
    body.extend_from_slice(&random);
    body.push(0x00); // session ID length = 0
    body.push((cipher_len >> 8) as u8);
    body.push((cipher_len & 0xff) as u8);
    body.extend_from_slice(&cipher_bytes);

    // Compression methods: offer both null AND deflate
    body.push(0x02); // 2 methods
    body.push(0x01); // DEFLATE compression
    body.push(0x00); // null compression

    // Extensions
    if let Some(sni_str) = sni {
        let sni_ext = crate::tls::extensions::build_sni_extension(sni_str);
        let ext_len = sni_ext.len() as u16;
        body.push((ext_len >> 8) as u8);
        body.push((ext_len & 0xff) as u8);
        body.extend_from_slice(&sni_ext);
    }

    let body_len = body.len();
    let mut handshake = vec![
        0x01u8, // ClientHello
        ((body_len >> 16) & 0xff) as u8,
        ((body_len >> 8) & 0xff) as u8,
        (body_len & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);

    let hs_len = handshake.len() as u16;
    let mut record = vec![
        0x16u8, // handshake
        0x03,
        0x01,
        (hs_len >> 8) as u8,
        (hs_len & 0xff) as u8,
    ];
    record.extend_from_slice(&handshake);

    record
}

/// Check for CRIME vulnerability (TLS compression)
pub async fn check_crime(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for CRIME (CVE-2012-4929) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2012-4929".to_string()];

    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(_) => return Ok(VulnResult::unknown("CRIME", "Connection failed")),
    };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(VulnResult::unknown("CRIME", "STARTTLS failed"));
        }
    }

    let hello = build_compression_hello(target.sni.as_deref(), TlsVersion::Tls12);
    socket.send(&hello).await?;

    let response = match socket.recv_multiple_records(3000).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(VulnResult::unknown("CRIME", "No response")),
    };

    let sh_result = crate::tls::server_hello::ServerHelloParser::parse(&response)?;

    if !crate::tls::server_hello::ServerHelloParser::is_successful(&sh_result) {
        return Ok(VulnResult::not_vulnerable("CRIME"));
    }

    // Check compression method - if server accepted DEFLATE (0x01), it's vulnerable
    if sh_result.compression_method == 0x01 {
        Ok(VulnResult::vulnerable(
            "CRIME",
            cve,
            "Server negotiated DEFLATE compression (compression_method=1)".to_string(),
        ))
    } else {
        Ok(VulnResult::not_vulnerable("CRIME"))
    }
}
