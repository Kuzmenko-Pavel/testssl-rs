//! GREASE (Generate Random Extensions And Sustain Extensibility) check
//! RFC 8701 - Tests if servers properly handle unknown values

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// GREASE check result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GreaseResult {
    pub tolerates_grease: Option<bool>,
    pub details: String,
}

/// GREASE cipher suite values (RFC 8701)
pub const GREASE_CIPHERS: &[[u8; 2]] = &[
    [0x0A, 0x0A],
    [0x1A, 0x1A],
    [0x2A, 0x2A],
    [0x3A, 0x3A],
    [0x4A, 0x4A],
    [0x5A, 0x5A],
    [0x6A, 0x6A],
    [0x7A, 0x7A],
    [0x8A, 0x8A],
    [0x9A, 0x9A],
    [0xAA, 0xAA],
    [0xBA, 0xBA],
    [0xCA, 0xCA],
    [0xDA, 0xDA],
    [0xEA, 0xEA],
    [0xFA, 0xFA],
];

/// Build a ClientHello with GREASE values
fn build_grease_hello(sni: Option<&str>) -> Vec<u8> {
    // Build cipher suite list: one GREASE cipher + normal ciphers
    let mut ciphers = vec![[0x0A, 0x0Au8]]; // GREASE cipher
    ciphers.extend_from_slice(&crate::tls::client_hello::tls12_default_ciphers());

    let mut builder = crate::tls::client_hello::ClientHelloBuilder::new(
        crate::tls::client_hello::TlsVersion::Tls12,
    )
    .with_cipher_suites(ciphers);

    if let Some(s) = sni {
        builder = builder.with_sni(s);
    }

    builder.build()
}

/// Check if server properly handles GREASE values
pub async fn check_grease(target: &ScanTarget) -> Result<GreaseResult> {
    let mut result = GreaseResult::default();

    info!(
        "Checking GREASE tolerance for {}:{}",
        target.host, target.port
    );

    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(e) => {
            result.details = format!("Connection failed: {}", e);
            return Ok(result);
        }
    };

    if let Some(ref starttls) = target.starttls {
        if let Err(e) = starttls.negotiate(&mut socket).await {
            result.details = format!("STARTTLS failed: {}", e);
            return Ok(result);
        }
    }

    let hello = build_grease_hello(target.sni.as_deref());
    if socket.send(&hello).await.is_err() {
        result.tolerates_grease = Some(false);
        result.details = "Failed to send GREASE ClientHello".to_string();
        return Ok(result);
    }

    let response = match socket.recv_multiple_records(3000).await {
        Ok(data) if !data.is_empty() => data,
        _ => {
            result.tolerates_grease = Some(false);
            result.details = "No response".to_string();
            return Ok(result);
        }
    };

    let sh_result = crate::tls::server_hello::ServerHelloParser::parse(&response)?;

    if crate::tls::server_hello::ServerHelloParser::is_successful(&sh_result) {
        result.tolerates_grease = Some(true);
        result.details = "Server accepted GREASE values correctly".to_string();
    } else if crate::tls::server_hello::ServerHelloParser::has_fatal_alert(&sh_result) {
        result.tolerates_grease = Some(false);
        if let Some((_, desc)) = sh_result.alert {
            result.details = format!("Server rejected GREASE with alert {}", desc);
        }
    } else {
        result.tolerates_grease = None;
        result.details = "Inconclusive".to_string();
    }

    Ok(result)
}
