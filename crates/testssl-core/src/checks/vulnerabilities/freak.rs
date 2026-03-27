//! FREAK vulnerability check (CVE-2015-0204)
//! Factoring RSA Export Keys

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// RSA export cipher suites
const EXPORT_RSA_CIPHERS: &[[u8; 2]] = &[
    [0x00, 0x03], // EXP-RC4-MD5
    [0x00, 0x06], // EXP-RC2-CBC-MD5
    [0x00, 0x08], // EXP-DES-CBC-SHA
    [0x00, 0x14], // EXP-RC4-SHA (non-standard)
    [0x00, 0x62], // EXP1024-DES-CBC-SHA
    [0x00, 0x64], // EXP1024-RC4-SHA
    [0x00, 0x60], // EXP1024-RC4-MD5
    [0x00, 0x61], // EXP1024-RC2-CBC-MD5
];

/// Check for FREAK vulnerability (export RSA cipher support)
pub async fn check_freak(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for FREAK (CVE-2015-0204) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2015-0204".to_string()];

    for cipher in EXPORT_RSA_CIPHERS {
        for version in &[
            crate::tls::client_hello::TlsVersion::Tls12,
            crate::tls::client_hello::TlsVersion::Tls10,
        ] {
            if let Ok(true) =
                crate::checks::ciphers::test_cipher_direct(target, *version, *cipher).await
            {
                let cipher_name = crate::data::find_cipher(cipher[0], cipher[1])
                    .map(|c| c.ossl_name)
                    .unwrap_or("export RSA cipher");

                return Ok(VulnResult::vulnerable(
                    "FREAK",
                    cve,
                    format!("Export RSA cipher suite supported: {}", cipher_name),
                ));
            }
        }
    }

    Ok(VulnResult::not_vulnerable("FREAK"))
}
