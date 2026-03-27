//! Forward secrecy check

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::checks::ciphers::SupportedCipher;
use crate::tls::client_hello::TlsVersion;
use crate::ScanTarget;

/// Forward secrecy check result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForwardSecrecyResult {
    pub has_fs: bool,
    pub ecdhe_ciphers: Vec<SupportedCipher>,
    pub dhe_ciphers: Vec<SupportedCipher>,
    pub num_ecdhe: usize,
    pub num_dhe: usize,
    pub best_dhe_bits: Option<u16>,
    pub curves_supported: Vec<String>,
}

/// Check forward secrecy support
pub async fn check_forward_secrecy(target: &ScanTarget) -> Result<ForwardSecrecyResult> {
    let mut result = ForwardSecrecyResult::default();

    info!(
        "Checking forward secrecy for {}:{}",
        target.host, target.port
    );

    // Enumerate ciphers with forward secrecy
    let fs_ciphers: Vec<[u8; 2]> = vec![
        // ECDHE ciphers
        [0xC0, 0x30], // ECDHE-RSA-AES256-GCM-SHA384
        [0xC0, 0x2C], // ECDHE-ECDSA-AES256-GCM-SHA384
        [0xC0, 0x28], // ECDHE-RSA-AES256-SHA384
        [0xC0, 0x24], // ECDHE-ECDSA-AES256-SHA384
        [0xC0, 0x14], // ECDHE-RSA-AES256-SHA
        [0xC0, 0x0A], // ECDHE-ECDSA-AES256-SHA
        [0xC0, 0x2F], // ECDHE-RSA-AES128-GCM-SHA256
        [0xC0, 0x2B], // ECDHE-ECDSA-AES128-GCM-SHA256
        [0xC0, 0x27], // ECDHE-RSA-AES128-SHA256
        [0xC0, 0x23], // ECDHE-ECDSA-AES128-SHA256
        [0xC0, 0x13], // ECDHE-RSA-AES128-SHA
        [0xC0, 0x09], // ECDHE-ECDSA-AES128-SHA
        [0xCC, 0xA9], // ECDHE-ECDSA-CHACHA20-POLY1305
        [0xCC, 0xA8], // ECDHE-RSA-CHACHA20-POLY1305
        // DHE ciphers
        [0x00, 0x9F], // DHE-RSA-AES256-GCM-SHA384
        [0x00, 0x6B], // DHE-RSA-AES256-SHA256
        [0x00, 0x39], // DHE-RSA-AES256-SHA
        [0x00, 0x9E], // DHE-RSA-AES128-GCM-SHA256
        [0x00, 0x67], // DHE-RSA-AES128-SHA256
        [0x00, 0x33], // DHE-RSA-AES128-SHA
        [0xCC, 0xAA], // DHE-RSA-CHACHA20-POLY1305
        // TLS 1.3
        [0x13, 0x01], // TLS_AES_128_GCM_SHA256
        [0x13, 0x02], // TLS_AES_256_GCM_SHA384
        [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
    ];

    for cipher_code in &fs_ciphers {
        if let Ok(true) =
            crate::checks::ciphers::test_cipher_direct(target, TlsVersion::Tls12, *cipher_code)
                .await
        {
            if let Some(cs) = crate::data::find_cipher(cipher_code[0], cipher_code[1]) {
                let sc = SupportedCipher::from(cs);

                if sc.ossl_name.contains("ECDHE") || sc.rfc_name.contains("ECDHE") {
                    result.ecdhe_ciphers.push(sc);
                } else if sc.ossl_name.contains("DHE") || sc.rfc_name.contains("DHE") {
                    result.dhe_ciphers.push(sc);
                }
            }
        }
    }

    result.num_ecdhe = result.ecdhe_ciphers.len();
    result.num_dhe = result.dhe_ciphers.len();
    result.has_fs = result.num_ecdhe > 0 || result.num_dhe > 0;

    Ok(result)
}
