//! Unit tests for ClientHello builder — verifies wire-format correctness

use testssl_core::tls::client_hello::{ClientHelloBuilder, TlsVersion};

/// Parse a TLS Record header from raw bytes
fn parse_tls_record_header(data: &[u8]) -> (u8, u8, u8, usize) {
    assert!(data.len() >= 5, "Too short for TLS record header");
    let content_type = data[0];
    let ver_major = data[1];
    let ver_minor = data[2];
    let length = ((data[3] as usize) << 8) | data[4] as usize;
    (content_type, ver_major, ver_minor, length)
}

/// Parse a Handshake header from bytes starting after TLS record header
fn parse_handshake_header(data: &[u8]) -> (u8, usize) {
    assert!(data.len() >= 4, "Too short for Handshake header");
    let handshake_type = data[0];
    let length = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    (handshake_type, length)
}

#[test]
fn test_tls12_record_header() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12).build();
    assert!(hello.len() >= 5, "Hello too short");

    let (ct, maj, min, len) = parse_tls_record_header(&hello);
    assert_eq!(ct, 0x16, "Content type must be 0x16 (handshake)");
    // TLS 1.2 record layer uses 0x03,0x01 for compatibility
    assert_eq!(maj, 0x03);
    assert!(min <= 0x03, "Version minor must be <= 3");
    assert_eq!(
        len,
        hello.len() - 5,
        "Record length must match actual payload"
    );
}

#[test]
fn test_tls12_handshake_header() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12).build();
    let (hs_type, hs_len) = parse_handshake_header(&hello[5..]);
    assert_eq!(hs_type, 0x01, "Handshake type must be 0x01 (ClientHello)");
    assert_eq!(hs_len, hello.len() - 5 - 4, "Handshake length mismatch");
}

#[test]
fn test_tls12_client_version() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12).build();
    // ClientVersion is at offset 5 (record header) + 4 (handshake header) = 9
    let cv_maj = hello[9];
    let cv_min = hello[10];
    assert_eq!(cv_maj, 0x03);
    assert_eq!(cv_min, 0x03, "TLS 1.2 client_version must be 0x0303");
}

#[test]
fn test_tls10_client_version() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls10).build();
    let cv_maj = hello[9];
    let cv_min = hello[10];
    assert_eq!(cv_maj, 0x03);
    assert_eq!(cv_min, 0x01, "TLS 1.0 client_version must be 0x0301");
}

#[test]
fn test_ssl30_client_version() {
    let hello = ClientHelloBuilder::new(TlsVersion::Ssl30).build();
    let cv_maj = hello[9];
    let cv_min = hello[10];
    assert_eq!(cv_maj, 0x03);
    assert_eq!(cv_min, 0x00, "SSLv3 client_version must be 0x0300");
}

#[test]
fn test_random_is_32_bytes() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12).build();
    // Random starts at offset 11 (5 record + 4 handshake + 2 version)
    // Just verify the hello is long enough to contain 32 bytes of random
    assert!(
        hello.len() >= 11 + 32,
        "Hello must have 32 bytes of Random field"
    );
}

#[test]
fn test_cipher_suites_present() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12).build();
    // After TLS record (5) + handshake (4) + version (2) + random (32) + session_id_len (1) = 44
    // Cipher suites length at offset >= 44
    assert!(hello.len() > 44 + 2, "Hello must have cipher suites");

    // Find cipher suites length (variable due to session ID)
    let session_id_len = hello[9 + 2 + 32] as usize; // offset: 5+4+2+32
    let cipher_offset = 9 + 2 + 32 + 1 + session_id_len;
    let cipher_len = ((hello[cipher_offset] as usize) << 8) | hello[cipher_offset + 1] as usize;
    assert!(cipher_len > 0, "Must have at least one cipher suite");
    assert_eq!(cipher_len % 2, 0, "Cipher suite list must have even length");
}

#[test]
fn test_single_cipher_suite() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12)
        .with_cipher_suites(vec![[0xC0, 0x2C]])
        .without_extensions()
        .build();

    // Find cipher suites (after session_id)
    let session_id_len = hello[9 + 2 + 32] as usize;
    let cipher_offset = 9 + 2 + 32 + 1 + session_id_len;
    let cipher_len = ((hello[cipher_offset] as usize) << 8) | hello[cipher_offset + 1] as usize;
    // One cipher = 2 bytes, plus possibly SCSV
    assert!(cipher_len >= 2, "Must have at least 2 bytes (one cipher)");

    // The cipher bytes should contain 0xC0, 0x2C somewhere
    let cipher_bytes = &hello[cipher_offset + 2..cipher_offset + 2 + cipher_len];
    let has_target = cipher_bytes
        .windows(2)
        .any(|w| w[0] == 0xC0 && w[1] == 0x2C);
    assert!(has_target, "Specified cipher 0xC02C must be in cipher list");
}

#[test]
fn test_tls13_has_supported_versions_extension() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls13).build();
    // TLS 1.3 ClientHello must have supported_versions extension (0x002b)
    // Search for 0x00, 0x2b in the extensions area
    let has_sv = hello.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x2b);
    assert!(
        has_sv,
        "TLS 1.3 ClientHello must have supported_versions extension (0x002b)"
    );
}

#[test]
fn test_sni_extension_present() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12)
        .with_sni("example.com")
        .build();
    // SNI extension type is 0x0000
    let has_sni = hello.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x00);
    assert!(
        has_sni,
        "ClientHello with SNI must contain SNI extension (0x0000)"
    );
}

#[test]
fn test_without_extensions() {
    let with_ext = ClientHelloBuilder::new(TlsVersion::Tls12).build();
    let without_ext = ClientHelloBuilder::new(TlsVersion::Tls12)
        .without_extensions()
        .build();
    // Without extensions must be shorter
    assert!(
        without_ext.len() < with_ext.len(),
        "ClientHello without extensions must be shorter than one with"
    );
}

#[test]
fn test_heartbeat_extension() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12)
        .with_heartbeat()
        .build();
    // Heartbeat extension type is 0x000f
    let has_hb = hello.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x0f);
    assert!(
        has_hb,
        "ClientHello with heartbeat must have extension 0x000f"
    );
}

#[test]
fn test_minimum_length() {
    let hello = ClientHelloBuilder::new(TlsVersion::Tls12)
        .without_extensions()
        .with_cipher_suites(vec![[0x00, 0x2F]])
        .build();
    // Minimum: 5 (record) + 4 (hs) + 2 (version) + 32 (random) + 1 (session_id_len)
    //        + 2 (cipher_len) + 2 (cipher) + 1 (compression_len) + 1 (compression) = 50
    assert!(
        hello.len() >= 50,
        "ClientHello minimum size must be at least 50 bytes"
    );
}

#[test]
fn test_total_length_consistency() {
    for version in [
        TlsVersion::Ssl30,
        TlsVersion::Tls10,
        TlsVersion::Tls12,
        TlsVersion::Tls13,
    ] {
        let hello = ClientHelloBuilder::new(version).build();
        let (_, _, _, record_len) = parse_tls_record_header(&hello);
        assert_eq!(
            record_len,
            hello.len() - 5,
            "Record length field must equal total length minus 5-byte header for {:?}",
            version
        );
        let (_, hs_len) = parse_handshake_header(&hello[5..]);
        assert_eq!(
            hs_len,
            hello.len() - 9,
            "Handshake length field must be consistent for {:?}",
            version
        );
    }
}
