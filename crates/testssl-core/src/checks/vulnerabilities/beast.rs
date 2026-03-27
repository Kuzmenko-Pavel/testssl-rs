//! BEAST vulnerability check (CVE-2011-3389)
//! Browser Exploit Against SSL/TLS (CBC mode with TLS 1.0)

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// CBC ciphers for TLS 1.0 (BEAST-relevant)
const BEAST_CIPHERS: &[[u8; 2]] = &[
    [0xC0, 0x14], // ECDHE-RSA-AES256-SHA
    [0xC0, 0x0A], // ECDHE-ECDSA-AES256-SHA
    [0x00, 0x39], // DHE-RSA-AES256-SHA
    [0x00, 0x38], // DHE-DSS-AES256-SHA
    [0x00, 0x35], // AES256-SHA
    [0xC0, 0x13], // ECDHE-RSA-AES128-SHA
    [0xC0, 0x09], // ECDHE-ECDSA-AES128-SHA
    [0x00, 0x33], // DHE-RSA-AES128-SHA
    [0x00, 0x32], // DHE-DSS-AES128-SHA
    [0x00, 0x2F], // AES128-SHA
    [0x00, 0x0A], // DES-CBC3-SHA
];

/// Check for BEAST vulnerability (TLS 1.0 with CBC ciphers)
pub async fn check_beast(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for BEAST (CVE-2011-3389) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2011-3389".to_string()];

    // First check if TLS 1.0 is supported
    let mut tls10_supported = false;
    for cipher in BEAST_CIPHERS {
        if let Ok(true) = crate::checks::ciphers::test_cipher_direct(
            target,
            crate::tls::client_hello::TlsVersion::Tls10,
            *cipher,
        )
        .await
        {
            tls10_supported = true;
            break;
        }
    }

    if tls10_supported {
        Ok(VulnResult::vulnerable(
            "BEAST",
            cve,
            "TLS 1.0 with CBC cipher suites is supported. BEAST attack is theoretical in practice."
                .to_string(),
        ))
    } else {
        Ok(VulnResult::not_vulnerable("BEAST"))
    }
}
