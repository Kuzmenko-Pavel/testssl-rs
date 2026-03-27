//! WINSHOCK vulnerability check (CVE-2014-6321)
//! Microsoft SChannel vulnerability

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// Check for WINSHOCK vulnerability
/// This is specific to Microsoft SChannel implementations
pub async fn check_winshock(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for WINSHOCK (CVE-2014-6321) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2014-6321".to_string()];

    // WINSHOCK is a memory corruption vulnerability in SChannel
    // It's triggered by crafted handshake packets
    // Detection is difficult without actually triggering the crash

    // Test with specific cipher patterns known to trigger the bug
    // (0x00A8 through 0x00B0 range in some implementations)
    let test_ciphers: Vec<[u8; 2]> = vec![
        [0x00, 0xA8], // PSK-AES128-GCM-SHA256
        [0x00, 0xA9], // PSK-AES256-GCM-SHA384
        [0x00, 0xAE], // PSK-AES128-CBC-SHA256
        [0x00, 0xAF], // PSK-AES256-CBC-SHA384
    ];

    // Try to connect with potentially triggering ciphers
    // A patched server should handle these normally or reject them
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket =
        match crate::tls::socket::TlsSocket::connect(&host, target.port, target.timeout_secs).await
        {
            Ok(s) => s,
            Err(_) => return Ok(VulnResult::unknown("WINSHOCK", "Connection failed")),
        };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(VulnResult::unknown("WINSHOCK", "STARTTLS failed"));
        }
    }

    let mut builder = crate::tls::client_hello::ClientHelloBuilder::new(
        crate::tls::client_hello::TlsVersion::Tls12,
    )
    .with_cipher_suites(test_ciphers);

    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }

    let hello = builder.build();
    socket.send(&hello).await?;

    let _response =
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), socket.recv(4096)).await {
            Ok(Ok(data)) => data,
            Ok(Err(_)) | Err(_) => {
                // Connection reset or timeout - possibly triggered crash
                return Ok(VulnResult {
                    name: "WINSHOCK".to_string(),
                    cve,
                    status: super::VulnStatus::Unknown,
                    details: "Connection was reset - inconclusive".to_string(),
                });
            }
        };

    // If we get a normal response, the server handled it
    Ok(VulnResult::unknown(
        "WINSHOCK",
        "Unable to determine - WINSHOCK requires version-specific Microsoft SChannel analysis",
    ))
}
