//! Unit tests for SSLv2 handshake builder

use testssl_core::tls::sslv2::{
    build_sslv2_client_hello, build_sslv2_client_hello_with_challenge, parse_sslv2_server_hello,
    sslv2_cipher_to_name, MSG_CLIENT_HELLO, MSG_ERROR, MSG_SERVER_HELLO, SSLV2_CIPHERS,
};

/// Build a minimal SSLv2 SERVER-HELLO response with given cipher specs.
fn make_sslv2_server_hello(ciphers: &[[u8; 3]], cert: &[u8]) -> Vec<u8> {
    let cert_len = cert.len() as u16;
    let cipher_specs_len = (ciphers.len() * 3) as u16;
    let conn_id_len: u16 = 8;
    let conn_id = [0xBBu8; 8];

    // Body: type(1) + session_hit(1) + cert_type(1) + version(2) + cert_len(2)
    //       + cipher_specs_len(2) + conn_id_len(2) + cert + ciphers + conn_id
    let mut body: Vec<u8> = vec![
        MSG_SERVER_HELLO, // type
        0x00,             // session_id_hit = false
        0x01,             // cert_type = X.509
        0x00,
        0x02, // server_version = SSLv2
        (cert_len >> 8) as u8,
        cert_len as u8,
        (cipher_specs_len >> 8) as u8,
        cipher_specs_len as u8,
        (conn_id_len >> 8) as u8,
        conn_id_len as u8,
    ];
    body.extend_from_slice(cert);
    for c in ciphers {
        body.extend_from_slice(c);
    }
    body.extend_from_slice(&conn_id);

    // Short header: bit 15 set, 15 bits = body_len
    let body_len = body.len() as u16;
    let mut record = vec![
        0x80 | ((body_len >> 8) as u8 & 0x7f),
        (body_len & 0xff) as u8,
    ];
    record.extend(body);
    record
}

/// Build an SSLv2 MSG-ERROR response
fn make_sslv2_error(code: u16) -> Vec<u8> {
    let body = vec![MSG_ERROR, (code >> 8) as u8, (code & 0xff) as u8];
    let body_len = body.len() as u16;
    let mut record = vec![
        0x80 | ((body_len >> 8) as u8 & 0x7f),
        (body_len & 0xff) as u8,
    ];
    record.extend(body);
    record
}

#[test]
fn test_sslv2_ciphers_not_empty() {
    assert!(!SSLV2_CIPHERS.is_empty());
    // Each cipher spec is 3 bytes
    for cipher in SSLV2_CIPHERS {
        assert_eq!(cipher.len(), 3);
    }
}

#[test]
fn test_build_sslv2_client_hello_default_ciphers() {
    let hello = build_sslv2_client_hello(None);
    assert!(!hello.is_empty());

    // SSLv2 record header: 2 bytes
    // Header byte 0: bit 15 set (0x80 or higher)
    assert!(hello[0] & 0x80 != 0, "SSLv2 short header bit must be set");

    // Body length encoded in header
    let body_len = ((hello[0] as u16 & 0x7f) << 8) | hello[1] as u16;
    assert_eq!(body_len as usize, hello.len() - 2);
}

#[test]
fn test_build_sslv2_client_hello_message_type() {
    let hello = build_sslv2_client_hello(None);
    // First byte of body (after 2-byte header) is message type
    assert_eq!(
        hello[2], MSG_CLIENT_HELLO,
        "message type must be CLIENT_HELLO"
    );
}

#[test]
fn test_build_sslv2_client_hello_version() {
    let hello = build_sslv2_client_hello(None);
    // Version: major=0x00, minor=0x02 (SSLv2)
    assert_eq!(hello[3], 0x00);
    assert_eq!(hello[4], 0x02);
}

#[test]
fn test_build_sslv2_client_hello_cipher_spec_length() {
    let hello = build_sslv2_client_hello(None);
    // cipher_spec_length at bytes 5-6
    let cs_len = ((hello[5] as u16) << 8) | hello[6] as u16;
    let expected = (SSLV2_CIPHERS.len() * 3) as u16;
    assert_eq!(cs_len, expected);
}

#[test]
fn test_build_sslv2_client_hello_session_id_zero() {
    let hello = build_sslv2_client_hello(None);
    // session_id_length at bytes 7-8 must be 0
    assert_eq!(hello[7], 0x00);
    assert_eq!(hello[8], 0x00);
}

#[test]
fn test_build_sslv2_client_hello_challenge_length() {
    let hello = build_sslv2_client_hello(None);
    // challenge_length at bytes 9-10 must be 16
    let ch_len = ((hello[9] as u16) << 8) | hello[10] as u16;
    assert_eq!(ch_len, 16);
}

#[test]
fn test_build_sslv2_client_hello_custom_ciphers() {
    // Single cipher
    let custom: &[[u8; 3]] = &[[0x07, 0x00, 0xc0]];
    let hello = build_sslv2_client_hello(Some(custom));

    let cs_len = ((hello[5] as u16) << 8) | hello[6] as u16;
    assert_eq!(cs_len, 3); // 1 cipher × 3 bytes
}

#[test]
fn test_build_sslv2_client_hello_empty_ciphers() {
    let custom: &[[u8; 3]] = &[];
    let hello = build_sslv2_client_hello(Some(custom));

    let cs_len = ((hello[5] as u16) << 8) | hello[6] as u16;
    assert_eq!(cs_len, 0);
}

#[test]
fn test_build_sslv2_client_hello_total_size() {
    let hello = build_sslv2_client_hello(None);
    // Expected total size:
    // 2 (header) + 1 (type) + 2 (version) + 2 (cs_len) + 2 (sid_len) + 2 (ch_len)
    // + n*3 (ciphers) + 16 (challenge)
    let expected = 2 + 1 + 2 + 2 + 2 + 2 + SSLV2_CIPHERS.len() * 3 + 16;
    assert_eq!(hello.len(), expected);
}

#[test]
fn test_build_sslv2_client_hello_with_challenge() {
    let challenge = [0x11u8; 16];
    let hello = build_sslv2_client_hello_with_challenge(None, &challenge);
    assert!(!hello.is_empty());
    // Message type check
    assert_eq!(hello[2], MSG_CLIENT_HELLO);
}

#[test]
fn test_build_sslv2_client_hello_with_challenge_custom_ciphers() {
    let ciphers: &[[u8; 3]] = &[[0x07, 0x00, 0xc0]];
    let challenge = [0xAAu8; 16];
    let hello = build_sslv2_client_hello_with_challenge(Some(ciphers), &challenge);
    let cs_len = ((hello[5] as u16) << 8) | hello[6] as u16;
    assert_eq!(cs_len, 3);
}

#[test]
fn test_msg_constants() {
    assert_eq!(MSG_CLIENT_HELLO, 0x01);
    assert_eq!(MSG_SERVER_HELLO, 0x04);
    assert_eq!(MSG_ERROR, 0x00);
}

// ── parse_sslv2_server_hello ──────────────────────────────────────────────────

#[test]
fn test_parse_sslv2_server_hello_empty() {
    let result = parse_sslv2_server_hello(&[]).expect("should not error");
    assert!(!result.supported);
}

#[test]
fn test_parse_sslv2_server_hello_too_short() {
    let result = parse_sslv2_server_hello(&[0x80]).expect("should not error");
    assert!(!result.supported);
}

#[test]
fn test_parse_sslv2_server_hello_valid() {
    let cert = [0xCCu8; 10]; // 10-byte dummy cert
    let ciphers = &[[0x07u8, 0x00, 0xc0], [0x01, 0x00, 0x80]];
    let bytes = make_sslv2_server_hello(ciphers, &cert);
    let result = parse_sslv2_server_hello(&bytes).expect("parse failed");
    assert!(result.supported);
    assert_eq!(result.server_version, Some((0x00, 0x02)));
    assert_eq!(result.ciphers.len(), 2);
    assert_eq!(result.ciphers[0], [0x07, 0x00, 0xc0]);
    assert_eq!(result.cert_type, 0x01);
    assert!(!result.session_id_hit);
    assert_eq!(result.certificate, Some(cert.to_vec()));
    assert_eq!(result.connection_id.len(), 8);
}

#[test]
fn test_parse_sslv2_server_hello_no_cert() {
    let bytes = make_sslv2_server_hello(&[[0x07, 0x00, 0xc0]], &[]);
    let result = parse_sslv2_server_hello(&bytes).expect("parse failed");
    assert!(result.supported);
    assert!(result.certificate.is_none());
}

#[test]
fn test_parse_sslv2_error_message() {
    let bytes = make_sslv2_error(0x0001); // error code 1
    let result = parse_sslv2_server_hello(&bytes).expect("should handle error message");
    // MSG_ERROR does not set supported = true
    assert!(!result.supported);
}

#[test]
fn test_parse_sslv2_truncated_body() {
    // Short header claiming large body but only 5 bytes provided
    let bytes = vec![0x80 | 0x10, 0x00, MSG_SERVER_HELLO, 0x00, 0x01]; // claims 16*256 bytes
    let result = parse_sslv2_server_hello(&bytes).expect("should handle truncation");
    assert!(!result.supported);
}

#[test]
fn test_parse_sslv2_long_header() {
    // Long header (bit 15 = 0): 3-byte header
    // Build a valid SERVER-HELLO with a 3-byte header
    let cert = [0xAAu8; 4];
    let ciphers: &[[u8; 3]] = &[[0x07, 0x00, 0xc0]];
    let mut body: Vec<u8> = vec![
        MSG_SERVER_HELLO, // type
        0x00,             // session_id_hit
        0x01,             // cert_type
        0x00,
        0x02, // version
        0x00,
        cert.len() as u8, // cert_len
        0x00,
        (ciphers.len() * 3) as u8, // cipher_specs_len
        0x00,
        0x00, // conn_id_len = 0
    ];
    body.extend_from_slice(&cert);
    for c in ciphers {
        body.extend_from_slice(c);
    }
    // Long 3-byte header: bit 15 = 0, bit 14 = padding flag
    let body_len = body.len() as u16;
    let mut record = vec![
        ((body_len >> 8) as u8) & 0x3f, // bit 15=0, bit 14=0 (no padding), bits 13-8
        (body_len & 0xff) as u8,
        0x00, // padding length (only present if bit 14 was set, but we include it)
    ];
    record.extend(body);
    let result = parse_sslv2_server_hello(&record).expect("should parse long header");
    assert!(result.supported);
}

// ── sslv2_cipher_to_name ──────────────────────────────────────────────────────

#[test]
fn test_sslv2_cipher_to_name_known() {
    assert_eq!(
        sslv2_cipher_to_name(&[0x07, 0x00, 0xc0]),
        "SSL_CK_DES_192_EDE3_CBC_WITH_MD5"
    );
    assert_eq!(
        sslv2_cipher_to_name(&[0x01, 0x00, 0x80]),
        "SSL_CK_RC4_128_WITH_MD5"
    );
    assert_eq!(
        sslv2_cipher_to_name(&[0x02, 0x00, 0x80]),
        "SSL_CK_RC4_128_EXPORT40_WITH_MD5"
    );
}

#[test]
fn test_sslv2_cipher_to_name_all_known_ciphers() {
    for cipher in SSLV2_CIPHERS {
        let name = sslv2_cipher_to_name(cipher);
        assert_ne!(
            name, "UNKNOWN",
            "cipher {:?} should have a known name",
            cipher
        );
    }
}

#[test]
fn test_sslv2_cipher_to_name_unknown() {
    assert_eq!(sslv2_cipher_to_name(&[0xFF, 0xFF, 0xFF]), "UNKNOWN");
}
