//! Data modules for cipher suites, TLS data, client profiles, and CA stores

pub mod ca_stores;
pub mod cipher_mapping;
pub mod client_profiles;
pub mod tls_data;

pub use ca_stores::{parse_pem_bundle, CA_APPLE, CA_JAVA, CA_LINUX, CA_MICROSOFT, CA_MOZILLA};
pub use cipher_mapping::{CipherInfo, CipherSuite, CIPHER_MAP, CIPHER_SUITES};
pub use client_profiles::{ClientProfile, CLIENT_PROFILES};
pub use tls_data::TLS_DATA;

/// Find a cipher suite (legacy CipherSuite) by its hex code.
///
/// Returns the legacy `CipherSuite` struct so existing callers don't need to change.
pub fn find_cipher(high: u8, low: u8) -> Option<&'static CipherSuite> {
    CIPHER_SUITES
        .iter()
        .find(|c| c.hex_high == high && c.hex_low == low)
}

/// Find a cipher (new-style CipherInfo) by its hex code.
pub fn find_cipher_info(high: u8, low: u8) -> Option<&'static CipherInfo> {
    cipher_mapping::find_cipher(high, low)
}

/// Find a cipher by its OpenSSL name
pub fn find_cipher_by_ossl_name(name: &str) -> Option<&'static CipherSuite> {
    CIPHER_SUITES.iter().find(|c| c.ossl_name == name)
}
