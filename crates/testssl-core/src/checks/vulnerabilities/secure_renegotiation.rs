//! Secure renegotiation check (CVE-2009-3555)

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Check for secure renegotiation support (RFC 5746)
pub async fn check_secure_renegotiation(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking secure renegotiation on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2009-3555".to_string()];

    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(_) => {
            return Ok(VulnResult::unknown(
                "Secure Renegotiation",
                "Connection failed",
            ))
        }
    };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(VulnResult::unknown(
                "Secure Renegotiation",
                "STARTTLS failed",
            ));
        }
    }

    // Send ClientHello WITH renegotiation_info extension (empty initial)
    let mut builder = ClientHelloBuilder::new(TlsVersion::Tls12);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello = builder.build();
    socket.send(&hello).await?;

    let response = match socket.recv_multiple_records(3000).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(VulnResult::unknown("Secure Renegotiation", "No response")),
    };

    let sh_result = crate::tls::server_hello::ServerHelloParser::parse(&response)?;

    if !crate::tls::server_hello::ServerHelloParser::is_successful(&sh_result) {
        return Ok(VulnResult::unknown(
            "Secure Renegotiation",
            "Handshake failed",
        ));
    }

    // Check if server included renegotiation_info extension (0xff01)
    let has_reneg_info = sh_result.extensions.iter().any(|e| e.ext_type == 0xff01);

    // Also check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff) in ciphers
    // A server that supports RFC 5746 should respond with renegotiation_info
    if has_reneg_info {
        Ok(VulnResult::not_vulnerable("Secure Renegotiation"))
    } else {
        Ok(VulnResult::vulnerable(
            "Secure Renegotiation",
            cve,
            "Server does not support RFC 5746 secure renegotiation",
        ))
    }
}
