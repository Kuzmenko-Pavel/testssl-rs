//! Logjam vulnerability check (CVE-2015-4000)
//! Weak Diffie-Hellman / export DH cipher suites

use anyhow::Result;
use tracing::info;

use super::VulnResult;
use crate::ScanTarget;

/// DHE export cipher suites (512-bit DH)
const EXPORT_DHE_CIPHERS: &[[u8; 2]] = &[
    [0x00, 0x11], // EXP-EDH-RSA-DES-CBC-SHA
    [0x00, 0x14], // EXP-EDH-DSS-DES-CBC-SHA
    [0x00, 0x65], // EXP1024-DHE-DSS-DES-CBC-SHA
    [0x00, 0x63], // EXP1024-DHE-DSS-RC4-SHA (non-standard)
];

/// Check for Logjam vulnerability (export DHE support)
pub async fn check_logjam(target: &ScanTarget) -> Result<VulnResult> {
    info!(
        "Checking for Logjam (CVE-2015-4000) on {}:{}",
        target.host, target.port
    );

    let cve = vec!["CVE-2015-4000".to_string()];

    for cipher in EXPORT_DHE_CIPHERS {
        for version in &[
            crate::tls::client_hello::TlsVersion::Tls12,
            crate::tls::client_hello::TlsVersion::Tls10,
        ] {
            if let Ok(true) =
                crate::checks::ciphers::test_cipher_direct(target, *version, *cipher).await
            {
                let cipher_name = crate::data::find_cipher(cipher[0], cipher[1])
                    .map(|c| c.ossl_name)
                    .unwrap_or("export DHE cipher");

                return Ok(VulnResult::vulnerable(
                    "Logjam",
                    cve,
                    format!(
                        "Export DHE cipher supported: {} (512-bit DH susceptible to factoring)",
                        cipher_name
                    ),
                ));
            }
        }
    }

    // Also check if common DH primes < 1024 are used
    // (This would require completing a handshake and checking DH parameters)
    Ok(VulnResult::not_vulnerable("Logjam"))
}
