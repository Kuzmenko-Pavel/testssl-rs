//! POODLE vulnerability check (CVE-2014-3566)
//! Padding Oracle On Downgraded Legacy Encryption

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::tls::client_hello::TlsVersion;
use crate::ScanTarget;

/// Check for POODLE vulnerability (SSLv3 support)
pub async fn check_poodle(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for POODLE (CVE-2014-3566) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2014-3566".to_string()];

    // POODLE requires SSLv3 support
    let ssl3_supported = test_ssl3(target).await?;

    if ssl3_supported {
        Ok(VulnResult::vulnerable(
            "POODLE",
            cve,
            "SSLv3 is supported - server is vulnerable to POODLE".to_string(),
        ))
    } else {
        Ok(VulnResult::not_vulnerable("POODLE"))
    }
}

async fn test_ssl3(target: &ScanTarget) -> Result<bool> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket =
        match crate::tls::socket::TlsSocket::connect(&host, target.port, target.timeout_secs).await
        {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(false);
        }
    }

    let mut builder = crate::tls::client_hello::ClientHelloBuilder::new(TlsVersion::Ssl30);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    // No extensions for SSLv3
    let hello = builder.without_extensions().build();
    socket.send(&hello).await?;

    let response = match socket.recv_multiple_records(3000).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(false),
    };

    let sh_result = crate::tls::server_hello::ServerHelloParser::parse(&response)?;
    Ok(
        crate::tls::server_hello::ServerHelloParser::is_successful(&sh_result)
            && !crate::tls::server_hello::ServerHelloParser::has_fatal_alert(&sh_result),
    )
}
