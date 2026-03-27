//! Ticketbleed vulnerability check (CVE-2016-9244)
//! F5 BIG-IP vulnerability that leaks memory via session ticket IDs

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// Check for Ticketbleed vulnerability
pub async fn check_ticketbleed(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for Ticketbleed (CVE-2016-9244) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2016-9244".to_string()];

    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    // Ticketbleed: send ClientHello with session ticket extension and small session ID
    // Server should echo back the same session ID length, but F5 bugs would echo more
    let mut socket =
        match crate::tls::socket::TlsSocket::connect(&host, target.port, target.timeout_secs).await
        {
            Ok(s) => s,
            Err(_) => return Ok(VulnResult::unknown("Ticketbleed", "Connection failed")),
        };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(VulnResult::unknown("Ticketbleed", "STARTTLS failed"));
        }
    }

    // Build ClientHello with a specific session ID (length 1 - smaller than server padding)
    // If server echoes back 32 bytes for a 1-byte session ID, it's vulnerable
    let hello = build_ticketbleed_hello(target.sni.as_deref());
    socket.send(&hello).await?;

    let response =
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), socket.recv(16384)).await {
            Ok(Ok(data)) if !data.is_empty() => data,
            _ => return Ok(VulnResult::unknown("Ticketbleed", "No response")),
        };

    // Parse ServerHello and check session ID
    let sh_result = match crate::tls::server_hello::ServerHelloParser::parse(&response) {
        Ok(r) => r,
        Err(_) => return Ok(VulnResult::unknown("Ticketbleed", "Parse failed")),
    };

    if !crate::tls::server_hello::ServerHelloParser::is_successful(&sh_result) {
        return Ok(VulnResult::not_vulnerable("Ticketbleed"));
    }

    // We sent a 1-byte session ID (0xAB). A vulnerable F5 BIG-IP server echoes our byte
    // in position 0 but pads the rest with uninitialized heap memory. A normal server
    // generates a completely fresh session ID (first byte will differ from 0xAB).
    if sh_result.session_id.len() > 1 && sh_result.session_id[0] == 0xAB {
        // Server preserved our specific byte — check if extra bytes look like a memory leak
        let extra = &sh_result.session_id[1..];
        let non_zero = extra.iter().filter(|&&b| b != 0).count();
        if non_zero > 2 {
            return Ok(VulnResult::vulnerable(
                "Ticketbleed",
                cve,
                format!(
                    "Server echoed {} extra bytes in session ID (potential memory leak)",
                    non_zero
                ),
            ));
        }
    }

    Ok(VulnResult::not_vulnerable("Ticketbleed"))
}

fn build_ticketbleed_hello(sni: Option<&str>) -> Vec<u8> {
    // Use a 1-byte session ID to trigger the bug
    let session_id = vec![0xAB];

    let mut builder = crate::tls::client_hello::ClientHelloBuilder::new(
        crate::tls::client_hello::TlsVersion::Tls12,
    )
    .with_session_id(session_id);

    if let Some(s) = sni {
        builder = builder.with_sni(s);
    }

    builder.build()
}
