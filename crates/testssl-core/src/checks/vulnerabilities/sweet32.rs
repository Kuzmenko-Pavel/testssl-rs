//! SWEET32 vulnerability check (CVE-2016-2183, CVE-2016-6329)
//! Birthday attacks on 64-bit block ciphers (3DES, Blowfish)

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// 3DES cipher suites
const TRIPLE_DES_CIPHERS: &[[u8; 2]] = &[
    [0x00, 0x0A], // DES-CBC3-SHA
    [0x00, 0x16], // DHE-RSA-DES-CBC3-SHA
    [0x00, 0x13], // DHE-DSS-DES-CBC3-SHA
    [0xC0, 0x12], // ECDHE-RSA-DES-CBC3-SHA
    [0xC0, 0x08], // ECDHE-ECDSA-DES-CBC3-SHA
    [0xC0, 0x1C], // SRP-DSS-3DES-EDE-CBC-SHA
    [0xC0, 0x1B], // SRP-RSA-3DES-EDE-CBC-SHA
    [0xC0, 0x1A], // SRP-3DES-EDE-CBC-SHA
    [0x00, 0x1F], // DHE-RSA-DES-CBC3-SHA (export)
    [0x00, 0x0D], // DH-DSS-DES-CBC3-SHA
];

/// Check for SWEET32 vulnerability (3DES support)
pub async fn check_sweet32(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for SWEET32 (CVE-2016-2183) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2016-2183".to_string(), "CVE-2016-6329".to_string()];

    // Check if any 3DES ciphers are supported
    for cipher in TRIPLE_DES_CIPHERS {
        if let Ok(true) = crate::checks::ciphers::test_cipher_direct(
            target,
            crate::tls::client_hello::TlsVersion::Tls12,
            *cipher,
        )
        .await
        {
            let cipher_name = crate::data::find_cipher(cipher[0], cipher[1])
                .map(|c| c.ossl_name)
                .unwrap_or("3DES cipher");

            return Ok(VulnResult::vulnerable(
                "SWEET32",
                cve,
                format!("3DES cipher suite supported: {} (64-bit block cipher vulnerable to birthday attacks)", cipher_name),
            ));
        }
    }

    Ok(VulnResult::not_vulnerable("SWEET32"))
}
