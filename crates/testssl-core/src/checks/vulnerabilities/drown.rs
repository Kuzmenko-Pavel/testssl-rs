//! DROWN vulnerability check (CVE-2016-0800)
//! Decrypting RSA with Obsolete and Weakened eNcryption

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// Check for DROWN vulnerability (SSLv2 support with RSA)
pub async fn check_drown(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for DROWN (CVE-2016-0800) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2016-0800".to_string(), "CVE-2015-3197".to_string()];

    // DROWN requires SSLv2 support
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket =
        match crate::tls::socket::TlsSocket::connect(&host, target.port, target.timeout_secs).await
        {
            Ok(s) => s,
            Err(_) => return Ok(VulnResult::unknown("DROWN", "Connection failed")),
        };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(VulnResult::unknown("DROWN", "STARTTLS failed"));
        }
    }

    let sslv2_hello = crate::tls::sslv2::build_sslv2_client_hello(None);
    socket.send(&sslv2_hello).await?;

    let response = match socket.recv(16384).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(VulnResult::not_vulnerable("DROWN")),
    };

    let sslv2_result = crate::tls::sslv2::parse_sslv2_server_hello(&response)?;

    if sslv2_result.supported {
        Ok(VulnResult::vulnerable(
            "DROWN",
            cve,
            "SSLv2 is supported - server is potentially vulnerable to DROWN".to_string(),
        ))
    } else {
        Ok(VulnResult::not_vulnerable("DROWN"))
    }
}
