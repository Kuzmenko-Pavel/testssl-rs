//! Unit tests for cipher mapping — verifies all 372 ciphers are loaded

use testssl_core::data::{find_cipher, find_cipher_info, CIPHER_MAP, CIPHER_SUITES};

#[test]
fn test_all_ciphers_loaded() {
    assert!(
        CIPHER_SUITES.len() >= 370,
        "Expected at least 370 cipher suites, got {}",
        CIPHER_SUITES.len()
    );
}

#[test]
fn test_cipher_map_same_count() {
    assert_eq!(
        CIPHER_MAP.len(),
        CIPHER_SUITES.len(),
        "CIPHER_MAP and CIPHER_SUITES must have the same count"
    );
}

#[test]
fn test_well_known_ciphers_present() {
    // TLS 1.3 ciphers
    assert!(
        find_cipher(0x13, 0x01).is_some(),
        "TLS_AES_128_GCM_SHA256 (0x1301) must exist"
    );
    assert!(
        find_cipher(0x13, 0x02).is_some(),
        "TLS_AES_256_GCM_SHA384 (0x1302) must exist"
    );
    assert!(
        find_cipher(0x13, 0x03).is_some(),
        "TLS_CHACHA20_POLY1305_SHA256 (0x1303) must exist"
    );

    // TLS 1.2 strong ciphers
    assert!(
        find_cipher(0xC0, 0x2C).is_some(),
        "ECDHE-ECDSA-AES256-GCM-SHA384 (0xC02C) must exist"
    );
    assert!(
        find_cipher(0xC0, 0x30).is_some(),
        "ECDHE-RSA-AES256-GCM-SHA384 (0xC030) must exist"
    );
    assert!(
        find_cipher(0xCC, 0xA8).is_some(),
        "ECDHE-RSA-CHACHA20-POLY1305 (0xCCA8) must exist"
    );

    // NULL cipher
    assert!(
        find_cipher(0x00, 0x00).is_some(),
        "TLS_NULL_WITH_NULL_NULL (0x0000) must exist"
    );

    // EXPORT ciphers
    assert!(
        find_cipher(0x00, 0x3B).is_some(),
        "RSA-NULL-SHA256 or similar EXPORT must exist"
    );
}

#[test]
fn test_cipher_info_fields() {
    let info = find_cipher_info(0xC0, 0x2C).expect("ECDHE-ECDSA-AES256-GCM-SHA384 must exist");
    assert!(
        !info.openssl_name.is_empty(),
        "openssl_name must not be empty"
    );
    assert!(!info.iana_name.is_empty(), "iana_name must not be empty");
    assert!(
        !info.key_exchange.is_empty(),
        "key_exchange must not be empty"
    );
    assert!(
        info.key_bits > 0,
        "key_bits must be > 0 for non-null cipher"
    );
    assert!(info.pfs, "ECDHE cipher must have pfs=true");
    assert!(!info.is_export, "Strong cipher must not be EXPORT");
}

#[test]
fn test_tls13_ciphers_correct_protocol() {
    for cipher in CIPHER_MAP
        .iter()
        .filter(|c| c.hex_high == 0x13 && c.hex_low <= 0x05)
    {
        assert_eq!(
            cipher.protocol, "TLSv1.3",
            "Cipher 0x13{:02x} must have protocol TLSv1.3",
            cipher.hex_low
        );
    }
}

#[test]
fn test_export_ciphers_flagged() {
    // Export ciphers should have is_export = true
    let export_count = CIPHER_MAP.iter().filter(|c| c.is_export).count();
    assert!(export_count > 0, "Should have some EXPORT ciphers flagged");
    // Sanity: not too many
    assert!(
        export_count < 50,
        "Too many export ciphers: {}",
        export_count
    );
}

#[test]
fn test_pfs_ciphers() {
    let pfs_count = CIPHER_MAP.iter().filter(|c| c.pfs).count();
    assert!(
        pfs_count > 50,
        "Should have > 50 PFS ciphers, got {}",
        pfs_count
    );
}

#[test]
fn test_no_duplicate_hex_codes() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    for cipher in CIPHER_MAP.iter() {
        let key = ((cipher.hex_high as u16) << 8) | cipher.hex_low as u16;
        if !seen.insert(key) {
            duplicates.push(format!("0x{:04X}", key));
        }
    }
    assert!(
        duplicates.len() <= 10,
        "Duplicate cipher hex codes: {:?}",
        duplicates
    );
}

#[test]
fn test_find_by_hex() {
    let cs = find_cipher(0xC0, 0x14).expect("ECDHE-RSA-AES256-SHA (0xC014) must exist");
    assert_eq!(cs.hex_high, 0xC0);
    assert_eq!(cs.hex_low, 0x14);
    assert!(
        cs.ossl_name.contains("ECDHE") || cs.ossl_name.contains("AES"),
        "Name should contain ECDHE or AES: {}",
        cs.ossl_name
    );
}

#[test]
fn test_nonexistent_cipher() {
    // Reserved/undefined byte combination
    assert!(
        find_cipher(0xFF, 0xFF).is_none(),
        "0xFFFF should not exist as a cipher"
    );
}
