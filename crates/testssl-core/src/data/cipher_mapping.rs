//! Cipher suite mapping from hex codes to names.
//!
//! Generated at build time via `build.rs` from `etc/cipher-mapping.txt`.
//! All 372 cipher entries are available in both `CIPHER_MAP` (new-style `CipherInfo`)
//! and `CIPHER_SUITES` (legacy `CipherSuite` with old field names for backward compatibility).

/// New-style cipher info struct — generated from build.rs / cipher-mapping.txt.
#[derive(Debug, Clone)]
pub struct CipherInfo {
    pub hex_high: u8,
    pub hex_low: u8,
    pub openssl_name: &'static str,
    pub iana_name: &'static str,
    pub protocol: &'static str,
    pub key_exchange: &'static str,
    pub auth: &'static str,
    pub encryption: &'static str,
    pub key_bits: u16,
    pub mac: &'static str,
    pub is_export: bool,
    pub pfs: bool,
}

/// Legacy cipher suite struct with old field names kept for backward compatibility.
#[derive(Debug, Clone)]
pub struct CipherSuite {
    pub hex_high: u8,
    pub hex_low: u8,
    pub ossl_name: &'static str,
    pub rfc_name: &'static str,
    pub tls_version: &'static str,
    pub kx: &'static str,
    pub auth: &'static str,
    pub enc: &'static str,
    pub bits: u16,
    pub mac: &'static str,
}

impl CipherSuite {
    pub fn hex_code(&self) -> String {
        format!("0x{:02X},0x{:02X}", self.hex_high, self.hex_low)
    }

    pub fn is_export(&self) -> bool {
        self.ossl_name.starts_with("EXP")
    }

    pub fn is_null_cipher(&self) -> bool {
        self.ossl_name.contains("NULL") || self.enc == "None"
    }

    pub fn is_anon(&self) -> bool {
        self.auth == "None"
            || self.ossl_name.contains("anon")
            || self.ossl_name.contains("ADH")
            || self.ossl_name.contains("AECDH")
    }

    pub fn is_weak(&self) -> bool {
        self.bits < 128 || self.ossl_name.contains("RC4") || self.ossl_name.contains("DES-CBC-")
    }

    pub fn supports_forward_secrecy(&self) -> bool {
        self.kx == "ECDH" && (self.ossl_name.contains("ECDHE") || self.ossl_name.contains("DHE"))
            || self.kx == "DH" && self.ossl_name.contains("DHE")
    }
}

// Include the auto-generated statics:
//   - CIPHER_MAP:    &[CipherInfo]   (new-style, all 372 entries)
//   - CIPHER_SUITES: &[CipherSuite]  (legacy, same entries with old field names)
//   - find_cipher(hex_high, hex_low) -> Option<&'static CipherInfo>
include!(concat!(env!("OUT_DIR"), "/cipher_mapping_generated.rs"));
