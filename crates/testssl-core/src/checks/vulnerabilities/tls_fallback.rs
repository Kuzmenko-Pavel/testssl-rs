//! TLS Fallback SCSV check (RFC 7507)

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Check TLS Fallback SCSV support
pub async fn check_tls_fallback(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking TLS Fallback SCSV on {}:{}",
        target.host, target.port
    );

    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(_) => {
            return Ok(VulnResult::unknown(
                "TLS Fallback SCSV",
                "Connection failed",
            ))
        }
    };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(VulnResult::unknown("TLS Fallback SCSV", "STARTTLS failed"));
        }
    }

    // Send a TLS 1.1 ClientHello with TLS_FALLBACK_SCSV
    // A server that supports TLS 1.2+ should reject this with inappropriate_fallback alert
    let mut builder = ClientHelloBuilder::new(TlsVersion::Tls11).with_fallback_scsv();
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello = builder.build();
    socket.send(&hello).await?;

    let response = match socket.recv_server_hello().await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(VulnResult::unknown("TLS Fallback SCSV", "No response")),
    };

    // Check if we got an inappropriate_fallback alert (86) — server properly rejects downgrade
    let has_fallback_alert = response.windows(5).any(|w| {
        w[0] == 0x15 // alert
            && w[1] == 0x03
            && w[4] == 86 // inappropriate_fallback
    });

    if has_fallback_alert {
        return Ok(VulnResult::not_vulnerable("TLS Fallback SCSV"));
    }

    // Any other alert (handshake_failure=40, protocol_version=70, etc.) means the server
    // rejected the downgrade attempt — it won't accept the attack either way
    let has_any_alert = response.windows(2).any(|w| w[0] == 0x15 && w[1] == 0x03);
    if has_any_alert {
        return Ok(VulnResult::not_vulnerable("TLS Fallback SCSV"));
    }

    let sh_result = crate::tls::server_hello::ServerHelloParser::parse(&response);
    match sh_result {
        Ok(sh) if crate::tls::server_hello::ServerHelloParser::is_successful(&sh) => {
            // Server accepted the downgraded connection without rejecting SCSV
            Ok(VulnResult::vulnerable(
                "TLS Fallback SCSV",
                vec![],
                "Server does not implement TLS Fallback SCSV (RFC 7507)".to_string(),
            ))
        }
        _ => Ok(VulnResult::unknown(
            "TLS Fallback SCSV",
            "Inconclusive result",
        )),
    }
}
