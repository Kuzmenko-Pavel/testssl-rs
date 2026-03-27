//! Unit tests for data module — cipher lookups, CipherSuite methods

use testssl_core::data::tls_data::{find_group, NAMED_GROUPS, TLS_DATA};
use testssl_core::data::{
    find_cipher, find_cipher_by_ossl_name, find_cipher_info, CIPHER_MAP, CIPHER_SUITES,
    CLIENT_PROFILES,
};

// ── Cipher suite lookup ──────────────────────────────────────────────────────

#[test]
fn test_cipher_suites_not_empty() {
    assert!(!CIPHER_SUITES.is_empty(), "CIPHER_SUITES must be non-empty");
}

#[test]
fn test_cipher_map_not_empty() {
    assert!(!CIPHER_MAP.is_empty(), "CIPHER_MAP must be non-empty");
}

#[test]
fn test_find_cipher_aes128_sha() {
    // TLS_RSA_WITH_AES_128_CBC_SHA — hex 0x00, 0x2F
    let cipher = find_cipher(0x00, 0x2F);
    assert!(cipher.is_some(), "AES128-SHA should be found");
    let c = cipher.unwrap();
    assert!(c.ossl_name.contains("AES") || c.rfc_name.contains("AES"));
}

#[test]
fn test_find_cipher_nonexistent_returns_none() {
    let cipher = find_cipher(0xFF, 0xFF);
    assert!(cipher.is_none());
}

#[test]
fn test_find_cipher_info_aes128_sha() {
    let info = find_cipher_info(0x00, 0x2F);
    assert!(info.is_some());
    let i = info.unwrap();
    assert_eq!(i.hex_high, 0x00);
    assert_eq!(i.hex_low, 0x2F);
}

#[test]
fn test_find_cipher_info_nonexistent_returns_none() {
    let info = find_cipher_info(0xFF, 0xFF);
    assert!(info.is_none());
}

#[test]
fn test_find_cipher_by_ossl_name() {
    let first = CIPHER_SUITES.first().expect("at least one cipher suite");
    let found = find_cipher_by_ossl_name(first.ossl_name);
    assert!(found.is_some());
    assert_eq!(found.unwrap().ossl_name, first.ossl_name);
}

#[test]
fn test_find_cipher_by_ossl_name_unknown() {
    let found = find_cipher_by_ossl_name("DOES_NOT_EXIST_AT_ALL");
    assert!(found.is_none());
}

// ── CipherSuite methods ────────────────────────────────────────────────────────

#[test]
fn test_cipher_suite_hex_code_format() {
    let c = find_cipher(0x00, 0x2F).expect("AES128-SHA expected");
    let hex = c.hex_code();
    assert!(hex.starts_with("0x"));
    assert!(hex.contains(",0x"));
}

#[test]
fn test_cipher_suite_is_export() {
    // Find any export cipher (starts with EXP)
    let exp_cipher = CIPHER_SUITES
        .iter()
        .find(|c| c.ossl_name.starts_with("EXP"));
    if let Some(c) = exp_cipher {
        assert!(c.is_export());
    }
    // AES128-SHA is not export
    let aes = find_cipher(0x00, 0x2F).expect("AES128-SHA expected");
    assert!(!aes.is_export());
}

#[test]
fn test_cipher_suite_is_null_cipher() {
    let null_cipher = CIPHER_SUITES.iter().find(|c| c.ossl_name.contains("NULL"));
    if let Some(c) = null_cipher {
        assert!(c.is_null_cipher());
    }
    let aes = find_cipher(0x00, 0x2F).expect("AES128-SHA expected");
    assert!(!aes.is_null_cipher());
}

#[test]
fn test_cipher_suite_is_weak() {
    // A DES cipher (56 bits) should be weak
    let des_cipher = CIPHER_SUITES.iter().find(|c| c.bits < 128);
    if let Some(c) = des_cipher {
        assert!(c.is_weak());
    }
    // AES 128-bit is not weak
    let aes = find_cipher(0x00, 0x2F).expect("AES128-SHA expected");
    assert!(!aes.is_weak());
}

#[test]
fn test_cipher_suite_is_anon() {
    let anon = CIPHER_SUITES
        .iter()
        .find(|c| c.auth == "None" || c.ossl_name.contains("anon"));
    if let Some(c) = anon {
        assert!(c.is_anon());
    }
    let aes = find_cipher(0x00, 0x2F).expect("AES128-SHA expected");
    assert!(!aes.is_anon());
}

// ── CipherInfo fields ─────────────────────────────────────────────────────────

#[test]
fn test_cipher_info_has_correct_fields() {
    let info = find_cipher_info(0x00, 0x2F).expect("cipher expected");
    assert!(!info.openssl_name.is_empty());
    assert!(!info.iana_name.is_empty());
    assert!(!info.protocol.is_empty());
    assert!(!info.key_exchange.is_empty());
    assert!(!info.encryption.is_empty());
}

// ── CLIENT_PROFILES ────────────────────────────────────────────────────────────

#[test]
fn test_client_profiles_not_empty() {
    assert!(
        !CLIENT_PROFILES.is_empty(),
        "CLIENT_PROFILES must be non-empty"
    );
}

#[test]
fn test_client_profiles_have_names() {
    for profile in CLIENT_PROFILES {
        assert!(!profile.name.is_empty(), "profile name must not be empty");
    }
}

#[test]
fn test_client_profiles_have_handshake_bytes() {
    for profile in CLIENT_PROFILES {
        assert!(
            !profile.handshake_bytes.is_empty(),
            "profile '{}' must have handshake bytes",
            profile.name
        );
    }
}

#[test]
fn test_client_profile_decode_handshake() {
    let profile = CLIENT_PROFILES.first().expect("at least one profile");
    let bytes = profile.decode_handshake();
    // A valid TLS ClientHello starts with record type 0x16 (handshake)
    // or may be raw bytes — just ensure decode works and is non-empty
    assert!(!bytes.is_empty(), "decoded handshake must be non-empty");
}

// ── TLS_DATA / TlsData constants ──────────────────────────────────────────────

#[test]
fn test_tls_data_tls13_ciphers_not_empty() {
    assert!(!TLS_DATA.tls13_ciphers.is_empty());
    assert!(TLS_DATA.tls13_ciphers.contains("13,01"));
}

#[test]
fn test_tls_data_tls12_ciphers_not_empty() {
    assert!(!TLS_DATA.tls12_ciphers.is_empty());
}

#[test]
fn test_tls_data_tls_ciphers_not_empty() {
    assert!(!TLS_DATA.tls_ciphers.is_empty());
}

// ── NAMED_GROUPS / find_group ─────────────────────────────────────────────────

#[test]
fn test_named_groups_not_empty() {
    assert!(!NAMED_GROUPS.is_empty());
}

#[test]
fn test_find_group_p256() {
    let g = find_group(0x0017);
    assert!(g.is_some());
    let g = g.unwrap();
    assert!(g.name.contains("P-256") || g.name.contains("prime256v1"));
    assert_eq!(g.bits, 256);
    assert!(!g.deprecated);
}

#[test]
fn test_find_group_x25519() {
    let g = find_group(0x001d);
    assert!(g.is_some());
    let g = g.unwrap();
    assert_eq!(g.name, "X25519");
    assert!(!g.deprecated);
}

#[test]
fn test_find_group_nonexistent_returns_none() {
    assert!(find_group(0xFFFF).is_none());
}

#[test]
fn test_find_group_deprecated_group() {
    // sect163k1 (0x0001) is deprecated
    let g = find_group(0x0001);
    assert!(g.is_some());
    assert!(g.unwrap().deprecated);
}
