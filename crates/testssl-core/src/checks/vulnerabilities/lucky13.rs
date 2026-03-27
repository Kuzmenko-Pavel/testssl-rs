//! LUCKY13 vulnerability check (CVE-2013-0169)
//! Timing attack against CBC-mode encryption in TLS

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// CBC cipher suites relevant to LUCKY13
const CBC_CIPHERS: &[[u8; 2]] = &[
    [0xC0, 0x28], // ECDHE-RSA-AES256-SHA384
    [0xC0, 0x24], // ECDHE-ECDSA-AES256-SHA384
    [0xC0, 0x14], // ECDHE-RSA-AES256-SHA
    [0xC0, 0x0A], // ECDHE-ECDSA-AES256-SHA
    [0x00, 0x6B], // DHE-RSA-AES256-SHA256
    [0x00, 0x39], // DHE-RSA-AES256-SHA
    [0x00, 0x35], // AES256-SHA
    [0xC0, 0x27], // ECDHE-RSA-AES128-SHA256
    [0xC0, 0x23], // ECDHE-ECDSA-AES128-SHA256
    [0xC0, 0x13], // ECDHE-RSA-AES128-SHA
    [0x00, 0x67], // DHE-RSA-AES128-SHA256
    [0x00, 0x33], // DHE-RSA-AES128-SHA
    [0x00, 0x2F], // AES128-SHA
];

/// Check for LUCKY13 (CBC cipher support)
pub async fn check_lucky13(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for LUCKY13 (CVE-2013-0169) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2013-0169".to_string()];

    // LUCKY13 affects all CBC-mode ciphers
    // It's a timing attack that's hard to fully prevent
    let mut cbc_supported = false;
    let mut found_cipher = "";

    for cipher in CBC_CIPHERS {
        if let Ok(true) = crate::checks::ciphers::test_cipher_direct(
            target,
            crate::tls::client_hello::TlsVersion::Tls12,
            *cipher,
        )
        .await
        {
            cbc_supported = true;
            found_cipher = crate::data::find_cipher(cipher[0], cipher[1])
                .map(|c| c.ossl_name)
                .unwrap_or("CBC cipher");
            break;
        }
    }

    if cbc_supported {
        Ok(VulnResult::vulnerable(
            "LUCKY13",
            cve,
            format!(
                "CBC cipher suites supported (e.g., {}). LUCKY13 is a theoretical timing attack.",
                found_cipher
            ),
        ))
    } else {
        Ok(VulnResult::not_vulnerable("LUCKY13"))
    }
}
