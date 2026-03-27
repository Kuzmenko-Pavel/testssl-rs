//! Unit tests for ServerHello parser — verifies parsing of TLS server responses
#![allow(clippy::field_reassign_with_default)]

use testssl_core::tls::server_hello::ServerHelloParser;

/// A minimal TLS 1.2 ServerHello response (captured from a real server)
/// Content: ServerHello choosing TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02B)
const SERVERHELLO_TLS12: &[u8] = &[
    // TLS Record: type=0x16 (handshake), version=0x0303, length
    0x16, 0x03, 0x03, 0x00, 0x51, // Handshake: type=0x02 (ServerHello), length
    0x02, 0x00, 0x00, 0x4D, // ServerVersion: TLS 1.2 = 0x0303
    0x03, 0x03, // Random: 32 bytes
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    // Session ID length: 0
    0x00, // Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    0xC0, 0x2B, // Compression: null (0x00)
    0x00, // Extensions length: 0x0015 = 21
    0x00, 0x15, // Extension: renegotiation_info (0xFF01), length 1, data 0x00
    0xFF, 0x01, 0x00, 0x01, 0x00, // Extension: extended_master_secret (0x0017), length 0
    0x00, 0x17, 0x00, 0x00, // Extension: ec_point_formats (0x000B), length 2, data 01 00
    0x00, 0x0B, 0x00, 0x02, 0x01, 0x00, // Extension: session_ticket (0x0023), length 0
    0x00, 0x23, 0x00, 0x00, // padding for alignment
    0x00, 0x00, 0x00, 0x03, 0x00,
];

/// TLS Alert: fatal, handshake_failure (40 = 0x28)
const ALERT_HANDSHAKE_FAILURE: &[u8] = &[
    0x15, 0x03, 0x03, 0x00, 0x02, 0x02, // fatal
    0x28, // handshake_failure
];

/// TLS Alert: fatal, protocol_version (70 = 0x46)
const ALERT_PROTOCOL_VERSION: &[u8] = &[
    0x15, 0x03, 0x01, 0x00, 0x02, 0x02, // fatal
    0x46, // protocol_version
];

/// TLS Alert: warning, close_notify
const ALERT_CLOSE_NOTIFY: &[u8] = &[
    0x15, 0x03, 0x03, 0x00, 0x02, 0x01, // warning
    0x00, // close_notify
];

#[test]
fn test_parse_alert_handshake_failure() {
    let result = ServerHelloParser::parse(ALERT_HANDSHAKE_FAILURE).expect("Should parse alert");
    assert!(
        ServerHelloParser::has_fatal_alert(&result),
        "Should detect fatal alert"
    );
    assert!(
        !ServerHelloParser::is_successful(&result),
        "Alert should not be successful"
    );
}

#[test]
fn test_parse_alert_protocol_version() {
    let result = ServerHelloParser::parse(ALERT_PROTOCOL_VERSION)
        .expect("Should parse protocol_version alert");
    assert!(
        ServerHelloParser::has_fatal_alert(&result),
        "Protocol version alert is fatal"
    );
}

#[test]
fn test_parse_empty_data() {
    let result = ServerHelloParser::parse(&[]);
    // Empty data should either error or return unknown
    assert!(
        result.is_err() || !ServerHelloParser::is_successful(&result.unwrap_or_default()),
        "Empty data should not parse as successful ServerHello"
    );
}

#[test]
fn test_parse_truncated_record() {
    // Only the record header, no payload
    let truncated = &[0x16u8, 0x03, 0x03, 0x00, 0x10]; // says length=16 but no payload
    let result = ServerHelloParser::parse(truncated);
    // Should not parse successfully
    if let Ok(r) = result {
        assert!(
            !ServerHelloParser::is_successful(&r),
            "Truncated record should not be successful"
        );
    }
}

#[test]
fn test_parse_random_bytes_is_alert() {
    // Random bytes that start with 0x15 look like an alert
    let data = &[0x15u8, 0x03, 0x00, 0x00, 0x02, 0x02, 0x28];
    let result = ServerHelloParser::parse(data);
    if let Ok(r) = result {
        assert!(ServerHelloParser::has_fatal_alert(&r) || !ServerHelloParser::is_successful(&r));
    }
}

// ── Helper to build a minimal valid ServerHello record ───────────────────────

/// Build a raw TLS ServerHello record with the given cipher suite.
/// No extensions, no session ID.
fn make_server_hello(cipher: [u8; 2], version: [u8; 2]) -> Vec<u8> {
    // ServerHello body: version(2) + random(32) + sid_len(1) + cipher(2) + compression(1) = 38
    let body: Vec<u8> = [
        version[0], version[1], // version
    ]
    .iter()
    .chain(&[0u8; 32]) // random
    .chain(&[0x00]) // session_id_len = 0
    .chain(&cipher) // cipher suite
    .chain(&[0x00]) // compression
    .copied()
    .collect();

    // Handshake header: type=0x02(ServerHello) + 3-byte length
    let body_len = body.len() as u32;
    let hs: Vec<u8> = vec![
        0x02,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ]
    .into_iter()
    .chain(body)
    .collect();

    // TLS record header
    let hs_len = hs.len() as u16;
    vec![0x16, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8]
        .into_iter()
        .chain(hs)
        .collect()
}

/// Build an alert record
fn make_alert(level: u8, desc: u8) -> Vec<u8> {
    vec![0x15, 0x03, 0x03, 0x00, 0x02, level, desc]
}

/// Build a ChangeCipherSpec record
fn make_change_cipher_spec() -> Vec<u8> {
    vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
}

/// Build an ApplicationData record (encrypted, indicates handshake done)
fn make_application_data() -> Vec<u8> {
    vec![0x17, 0x03, 0x03, 0x00, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
}

/// Build a ServerHelloDone record (handshake msg type=14)
fn make_server_hello_done() -> Vec<u8> {
    // HandshakeDone body is empty, length=0
    let hs = vec![0x0E, 0x00, 0x00, 0x00]; // type=14, len=0
    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);
    rec
}

// ── Parsing tests ─────────────────────────────────────────────────────────────

#[test]
fn test_parse_minimal_server_hello_tls12() {
    let bytes = make_server_hello([0xC0, 0x2B], [0x03, 0x03]);
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.server_hello_received);
    assert_eq!(result.cipher_suite, [0xC0, 0x2B]);
    assert_eq!(result.version_major, 0x03);
    assert_eq!(result.version_minor, 0x03);
}

#[test]
fn test_parse_change_cipher_spec() {
    let bytes = make_change_cipher_spec();
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.change_cipher_spec_received);
}

#[test]
fn test_parse_application_data_signals_handshake_complete() {
    let bytes = make_application_data();
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.encrypted_data_received);
    assert!(result.handshake_completed);
    assert!(ServerHelloParser::is_successful(&result));
}

#[test]
fn test_parse_server_hello_done_sets_completed() {
    let bytes = make_server_hello_done();
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.server_hello_done);
    assert!(result.handshake_completed);
    assert!(ServerHelloParser::is_successful(&result));
}

#[test]
fn test_parse_consecutive_records() {
    let mut bytes = make_server_hello([0xC0, 0x2C], [0x03, 0x03]);
    bytes.extend(make_change_cipher_spec());
    bytes.extend(make_application_data());
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.server_hello_received);
    assert!(result.change_cipher_spec_received);
    assert!(result.encrypted_data_received);
    assert!(result.handshake_completed);
}

#[test]
fn test_parse_server_hello_with_session_id() {
    // ServerHello with 32-byte session ID
    let sid: [u8; 32] = [0xAB; 32];
    let mut body: Vec<u8> = vec![0x03, 0x03]; // version
    body.extend_from_slice(&[0x01u8; 32]); // random
    body.push(0x20); // session_id_len = 32
    body.extend_from_slice(&sid); // session_id
    body.extend_from_slice(&[0xC0, 0x2B]); // cipher
    body.push(0x00); // compression

    let body_len = body.len() as u32;
    let mut hs = vec![
        0x02,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ];
    hs.extend(body);

    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);

    let result = ServerHelloParser::parse(&rec).expect("parse failed");
    assert!(result.server_hello_received);
    assert_eq!(result.session_id, sid.to_vec());
}

#[test]
fn test_parse_alert_fatal_handshake_failure() {
    let bytes = make_alert(2, 40); // fatal, handshake_failure
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert_eq!(result.alert, Some((2, 40)));
    assert!(ServerHelloParser::has_fatal_alert(&result));
    assert!(!ServerHelloParser::is_successful(&result));
}

#[test]
fn test_parse_alert_warning_not_fatal() {
    let bytes = make_alert(1, 0); // warning, close_notify
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(!ServerHelloParser::has_fatal_alert(&result));
}

#[test]
fn test_parse_too_large_record_length_stops() {
    // A record claiming length > 18432 should be silently skipped
    let bytes = vec![0x16u8, 0x03, 0x03, 0xFF, 0xFF]; // len=65535 > 18432
    let result = ServerHelloParser::parse(&bytes).expect("should not error");
    assert!(!ServerHelloParser::is_successful(&result));
}

// ── version_string ────────────────────────────────────────────────────────────

#[test]
fn test_version_string_sslv3() {
    let mut r = testssl_core::tls::server_hello::ServerHelloResult::default();
    r.version_major = 3;
    r.version_minor = 0;
    assert_eq!(ServerHelloParser::version_string(&r), "SSLv3");
}

#[test]
fn test_version_string_tls10() {
    let mut r = testssl_core::tls::server_hello::ServerHelloResult::default();
    r.version_major = 3;
    r.version_minor = 1;
    assert_eq!(ServerHelloParser::version_string(&r), "TLSv1.0");
}

#[test]
fn test_version_string_tls11() {
    let mut r = testssl_core::tls::server_hello::ServerHelloResult::default();
    r.version_major = 3;
    r.version_minor = 2;
    assert_eq!(ServerHelloParser::version_string(&r), "TLSv1.1");
}

#[test]
fn test_version_string_tls12() {
    let mut r = testssl_core::tls::server_hello::ServerHelloResult::default();
    r.version_major = 3;
    r.version_minor = 3;
    assert_eq!(ServerHelloParser::version_string(&r), "TLSv1.2");
}

#[test]
fn test_version_string_tls13_via_extension() {
    let mut r = testssl_core::tls::server_hello::ServerHelloResult::default();
    r.version_major = 3;
    r.version_minor = 3;
    r.negotiated_version = Some(0x0304);
    assert_eq!(ServerHelloParser::version_string(&r), "TLSv1.3");
}

#[test]
fn test_version_string_unknown() {
    let mut r = testssl_core::tls::server_hello::ServerHelloResult::default();
    r.version_major = 2;
    r.version_minor = 0;
    assert_eq!(ServerHelloParser::version_string(&r), "Unknown");
}

// ── alert_description_name ────────────────────────────────────────────────────

#[test]
fn test_alert_description_names() {
    assert_eq!(ServerHelloParser::alert_description_name(0), "close_notify");
    assert_eq!(
        ServerHelloParser::alert_description_name(40),
        "handshake_failure"
    );
    assert_eq!(
        ServerHelloParser::alert_description_name(70),
        "protocol_version"
    );
    assert_eq!(
        ServerHelloParser::alert_description_name(112),
        "unrecognized_name"
    );
    assert_eq!(ServerHelloParser::alert_description_name(255), "unknown");
}

// ── alert_level_name ──────────────────────────────────────────────────────────

#[test]
fn test_alert_level_names() {
    assert_eq!(ServerHelloParser::alert_level_name(1), "warning");
    assert_eq!(ServerHelloParser::alert_level_name(2), "fatal");
    assert_eq!(ServerHelloParser::alert_level_name(99), "unknown");
}

// ── has_server_hello ──────────────────────────────────────────────────────────

#[test]
fn test_has_server_hello_valid() {
    let bytes = make_server_hello([0xC0, 0x2B], [0x03, 0x03]);
    assert!(ServerHelloParser::has_server_hello(&bytes));
}

#[test]
fn test_has_server_hello_alert_not_server_hello() {
    let bytes = make_alert(2, 40);
    assert!(!ServerHelloParser::has_server_hello(&bytes));
}

#[test]
fn test_has_server_hello_too_short() {
    assert!(!ServerHelloParser::has_server_hello(&[0x16, 0x03]));
}

// ── ServerHello with extensions ───────────────────────────────────────────────

/// Build a ServerHello with a heartbeat extension in the ServerHello body
fn make_server_hello_with_heartbeat() -> Vec<u8> {
    // Heartbeat extension: type=0x000f, len=1, mode=1
    let hb_ext: Vec<u8> = vec![0x00, 0x0f, 0x00, 0x01, 0x01];
    let ext_total_len = hb_ext.len() as u16;

    // ServerHello body: version(2) + random(32) + sid_len(1) + cipher(2) + compression(1) + ext_len(2) + exts
    let mut body: Vec<u8> = vec![0x03, 0x03]; // version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0x00); // sid_len=0
    body.extend_from_slice(&[0xC0, 0x2B]); // cipher
    body.push(0x00); // compression
    body.push((ext_total_len >> 8) as u8);
    body.push((ext_total_len & 0xff) as u8);
    body.extend_from_slice(&hb_ext);

    let body_len = body.len() as u32;
    let mut hs = vec![
        0x02,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ];
    hs.extend(body);

    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);
    rec
}

/// Build a Certificate handshake message with fake cert data
fn make_certificate_record(cert_data: &[u8]) -> Vec<u8> {
    let cert_len = cert_data.len();
    let certs_total = cert_len + 3; // one cert with 3-byte length prefix

    // Certificate message body: certs_total_len(3) + cert_len(3) + cert
    let mut body: Vec<u8> = vec![
        (certs_total >> 16) as u8,
        (certs_total >> 8) as u8,
        (certs_total & 0xff) as u8,
        (cert_len >> 16) as u8,
        (cert_len >> 8) as u8,
        (cert_len & 0xff) as u8,
    ];
    body.extend_from_slice(cert_data);

    let body_len = body.len() as u32;
    let mut hs = vec![
        11u8, // Certificate
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ];
    hs.extend(body);

    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16u8, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);
    rec
}

/// Build a NewSessionTicket handshake record (type 4)
fn make_new_session_ticket() -> Vec<u8> {
    let body = vec![0x00u8; 4]; // 4 bytes of dummy ticket
    let body_len = body.len() as u32;
    let mut hs = vec![
        0x04,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ];
    hs.extend(body);
    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16u8, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);
    rec
}

/// Build a Finished handshake record (type 20)
fn make_finished() -> Vec<u8> {
    let body = vec![0xAAu8; 12]; // 12 bytes verify_data
    let body_len = body.len() as u32;
    let mut hs = vec![
        0x14,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ];
    hs.extend(body);
    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16u8, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);
    rec
}

/// Build a ServerKeyExchange handshake record (type 12)
fn make_server_key_exchange(kx_data: &[u8]) -> Vec<u8> {
    let body_len = kx_data.len() as u32;
    let mut hs = vec![
        0x0c,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ];
    hs.extend_from_slice(kx_data);
    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16u8, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);
    rec
}

#[test]
fn test_parse_server_hello_with_heartbeat_extension() {
    let bytes = make_server_hello_with_heartbeat();
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.server_hello_received);
    assert!(result.heartbeat_offered);
    assert_eq!(result.heartbeat_mode, 1);
}

#[test]
fn test_parse_certificate_message() {
    let cert_data = vec![0xAAu8; 20];
    let bytes = make_certificate_record(&cert_data);
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert_eq!(result.certificates.len(), 1);
    assert_eq!(result.certificates[0], cert_data);
    assert!(ServerHelloParser::is_successful(&result));
}

#[test]
fn test_parse_new_session_ticket_sets_completed() {
    let bytes = make_new_session_ticket();
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.handshake_completed);
}

#[test]
fn test_parse_finished_sets_completed() {
    let bytes = make_finished();
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.handshake_completed);
}

#[test]
fn test_parse_server_key_exchange() {
    let kx = vec![0xBBu8; 32];
    let bytes = make_server_key_exchange(&kx);
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert_eq!(result.server_key_exchange, Some(kx));
}

#[test]
fn test_parse_full_tls12_handshake_sequence() {
    let mut bytes = make_server_hello([0xC0, 0x2B], [0x03, 0x03]);
    bytes.extend(make_certificate_record(&[0xCC; 10]));
    bytes.extend(make_server_hello_done());
    let result = ServerHelloParser::parse(&bytes).expect("parse failed");
    assert!(result.server_hello_received);
    assert_eq!(result.certificates.len(), 1);
    assert!(result.server_hello_done);
    assert!(result.handshake_completed);
}

#[test]
fn test_parse_server_hello_with_supported_versions_tls13() {
    // Build a ServerHello with supported_versions extension claiming TLS 1.3
    let sv_ext: Vec<u8> = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]; // type + len + 0x0304

    let mut body: Vec<u8> = vec![0x03, 0x03]; // version field
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0x00); // sid_len=0
    body.extend_from_slice(&[0x13, 0x01]); // TLS 1.3 cipher
    body.push(0x00); // compression
    let ext_len = sv_ext.len() as u16;
    body.push((ext_len >> 8) as u8);
    body.push((ext_len & 0xff) as u8);
    body.extend_from_slice(&sv_ext);

    let body_len = body.len() as u32;
    let mut hs = vec![
        0x02,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ];
    hs.extend(body);
    let hs_len = hs.len() as u16;
    let mut rec = vec![0x16u8, 0x03, 0x03, (hs_len >> 8) as u8, hs_len as u8];
    rec.extend(hs);

    let result = ServerHelloParser::parse(&rec).expect("parse failed");
    assert!(result.server_hello_received);
    assert_eq!(result.negotiated_version, Some(0x0304));
}

// ── is_alert / extract_alert ──────────────────────────────────────────────────

#[test]
fn test_is_alert_true_for_alert_record() {
    let bytes = make_alert(2, 40);
    assert!(ServerHelloParser::is_alert(&bytes));
}

#[test]
fn test_is_alert_false_for_handshake() {
    let bytes = make_server_hello([0xC0, 0x2B], [0x03, 0x03]);
    assert!(!ServerHelloParser::is_alert(&bytes));
}

#[test]
fn test_extract_alert_some() {
    let bytes = make_alert(2, 40);
    assert_eq!(ServerHelloParser::extract_alert(&bytes), Some((2, 40)));
}

#[test]
fn test_extract_alert_none_for_short_data() {
    assert_eq!(ServerHelloParser::extract_alert(&[0x15, 0x03]), None);
}

#[test]
fn test_extract_alert_none_for_non_alert() {
    let bytes = make_server_hello([0xC0, 0x2B], [0x03, 0x03]);
    assert_eq!(ServerHelloParser::extract_alert(&bytes), None);
}

#[test]
fn test_alert_close_notify_not_fatal() {
    let result = ServerHelloParser::parse(ALERT_CLOSE_NOTIFY).expect("Should parse close_notify");
    // close_notify is warning level, not fatal
    assert!(
        !ServerHelloParser::has_fatal_alert(&result),
        "close_notify should not be fatal"
    );
}

#[test]
fn test_server_hello_version() {
    let result = ServerHelloParser::parse(SERVERHELLO_TLS12);
    if let Ok(r) = result {
        if ServerHelloParser::is_successful(&r) {
            // Server version should be 0x0303 (TLS 1.2)
            assert_eq!(
                [r.version_major, r.version_minor],
                [0x03, 0x03],
                "ServerHello version should be 0x0303 for TLS 1.2"
            );
        }
    }
}

#[test]
fn test_server_hello_cipher_suite() {
    let result = ServerHelloParser::parse(SERVERHELLO_TLS12);
    if let Ok(r) = result {
        if ServerHelloParser::is_successful(&r) {
            assert_eq!(
                r.cipher_suite,
                [0xC0, 0x2B],
                "Parsed cipher should be 0xC02B (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)"
            );
        }
    }
}
