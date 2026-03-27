//! RC4 cipher check

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// RC4 cipher suites
const RC4_CIPHERS: &[[u8; 2]] = &[
    [0x00, 0x05], // RC4-SHA
    [0x00, 0x04], // RC4-MD5
    [0xC0, 0x11], // ECDHE-RSA-RC4-SHA
    [0xC0, 0x07], // ECDHE-ECDSA-RC4-SHA
    [0x00, 0x18], // ADH-RC4-MD5
    [0x00, 0x03], // EXP-RC4-MD5
];

/// Check for RC4 cipher support
pub async fn check_rc4(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for RC4 cipher support on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2013-2566".to_string(), "CVE-2015-2808".to_string()];

    for cipher in RC4_CIPHERS {
        for version in &[
            crate::tls::client_hello::TlsVersion::Tls12,
            crate::tls::client_hello::TlsVersion::Tls10,
            crate::tls::client_hello::TlsVersion::Ssl30,
        ] {
            if let Ok(true) =
                crate::checks::ciphers::test_cipher_direct(target, *version, *cipher).await
            {
                let cipher_name = crate::data::find_cipher(cipher[0], cipher[1])
                    .map(|c| c.ossl_name)
                    .unwrap_or("RC4 cipher");

                return Ok(VulnResult::vulnerable(
                    "RC4",
                    cve,
                    format!(
                        "RC4 cipher suite is supported: {} (RC4 is cryptographically broken)",
                        cipher_name
                    ),
                ));
            }
        }
    }

    Ok(VulnResult::not_vulnerable("RC4"))
}
