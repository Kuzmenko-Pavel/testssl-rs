//! Unit tests for TLS extension builders and parsers

use testssl_core::tls::extensions::{
    build_alpn_extension, build_ec_point_formats_extension, build_encrypt_then_mac_extension,
    build_extended_master_secret_extension, build_extension, build_heartbeat_extension,
    build_key_share_extension, build_padding_extension, build_psk_key_exchange_modes_extension,
    build_renegotiation_info_extension, build_session_ticket_extension,
    build_signature_algorithms_extension, build_sni_extension, build_supported_groups_extension,
    build_supported_versions_extension, calculate_padding, parse_alpn_extension, parse_extensions,
    parse_supported_versions_server, ParsedExtension,
};

// ── build_extension ───────────────────────────────────────────────────────────

#[test]
fn test_build_extension_header_format() {
    let ext = build_extension(0x0000, b"hello");
    assert_eq!(&ext[0..2], &[0x00, 0x00]); // type
    assert_eq!(&ext[2..4], &[0x00, 0x05]); // length = 5
    assert_eq!(&ext[4..], b"hello");
}

#[test]
fn test_build_extension_empty_data() {
    let ext = build_extension(0x0017, &[]);
    assert_eq!(ext.len(), 4); // type(2) + length(2)
    assert_eq!(&ext[2..4], &[0x00, 0x00]);
}

#[test]
fn test_build_extension_type_high_byte() {
    let ext = build_extension(0xff01, &[0x00]);
    assert_eq!(ext[0], 0xff);
    assert_eq!(ext[1], 0x01);
}

// ── build_sni_extension ───────────────────────────────────────────────────────

#[test]
fn test_build_sni_extension_type() {
    let ext = build_sni_extension("example.com");
    assert_eq!(&ext[0..2], &[0x00, 0x00]); // SNI type
}

#[test]
fn test_build_sni_extension_contains_hostname() {
    let ext = build_sni_extension("example.com");
    let hostname = "example.com".as_bytes();
    let found = ext.windows(hostname.len()).any(|w| w == hostname);
    assert!(found, "SNI extension must contain the hostname");
}

#[test]
fn test_build_sni_extension_length_consistency() {
    let name = "test.example.org";
    let ext = build_sni_extension(name);
    let total_len = ((ext[2] as usize) << 8) | ext[3] as usize;
    assert_eq!(total_len, ext.len() - 4);
}

// ── build_supported_groups_extension ─────────────────────────────────────────

#[test]
fn test_build_supported_groups_extension_type() {
    let ext = build_supported_groups_extension(&[0x001d, 0x0017]);
    assert_eq!(&ext[0..2], &[0x00, 0x0a]); // type 0x000a
}

#[test]
fn test_build_supported_groups_extension_encodes_groups() {
    let ext = build_supported_groups_extension(&[0x001d]);
    // ext: type(2) + len(2) + list_len(2) + group(2)
    assert_eq!(ext.len(), 8);
    // list_len = 2 (one group)
    assert_eq!(&ext[4..6], &[0x00, 0x02]);
    // group = 0x001d
    assert_eq!(&ext[6..8], &[0x00, 0x1d]);
}

#[test]
fn test_build_supported_groups_extension_empty() {
    let ext = build_supported_groups_extension(&[]);
    assert_eq!(ext.len(), 6); // type(2) + len(2) + list_len(2)
}

// ── build_ec_point_formats_extension ─────────────────────────────────────────

#[test]
fn test_build_ec_point_formats_extension_type() {
    let ext = build_ec_point_formats_extension();
    assert_eq!(&ext[0..2], &[0x00, 0x0b]); // type 0x000b
}

#[test]
fn test_build_ec_point_formats_extension_length() {
    let ext = build_ec_point_formats_extension();
    // data = [0x03, 0x00, 0x01, 0x02] = 4 bytes
    assert_eq!(ext.len(), 8); // type(2) + len(2) + data(4)
}

// ── build_signature_algorithms_extension ─────────────────────────────────────

#[test]
fn test_build_signature_algorithms_extension_type() {
    let ext = build_signature_algorithms_extension(&[0x0401]);
    assert_eq!(&ext[0..2], &[0x00, 0x0d]); // type 0x000d
}

#[test]
fn test_build_signature_algorithms_extension_encodes() {
    let ext = build_signature_algorithms_extension(&[0x0401, 0x0501]);
    // type(2) + len(2) + list_len(2) + 2 sigalgs * 2
    assert_eq!(ext.len(), 10);
}

// ── build_heartbeat_extension ─────────────────────────────────────────────────

#[test]
fn test_build_heartbeat_extension_type() {
    let ext = build_heartbeat_extension();
    assert_eq!(&ext[0..2], &[0x00, 0x0f]); // type 0x000f
}

#[test]
fn test_build_heartbeat_extension_mode() {
    let ext = build_heartbeat_extension();
    assert_eq!(ext[4], 0x01); // peer_allowed_to_send
}

// ── build_alpn_extension ──────────────────────────────────────────────────────

#[test]
fn test_build_alpn_extension_type() {
    let ext = build_alpn_extension(&["h2"]);
    assert_eq!(&ext[0..2], &[0x00, 0x10]); // type 0x0010
}

#[test]
fn test_build_alpn_extension_contains_protocol() {
    let ext = build_alpn_extension(&["h2"]);
    let proto = b"h2";
    let found = ext.windows(proto.len()).any(|w| w == proto);
    assert!(found, "ALPN extension must contain the protocol name");
}

#[test]
fn test_build_alpn_extension_multiple_protocols() {
    let ext = build_alpn_extension(&["h2", "http/1.1"]);
    let h2 = b"h2";
    let http1 = b"http/1.1";
    assert!(ext.windows(h2.len()).any(|w| w == h2));
    assert!(ext.windows(http1.len()).any(|w| w == http1));
}

// ── simple empty extensions ───────────────────────────────────────────────────

#[test]
fn test_build_encrypt_then_mac_extension() {
    let ext = build_encrypt_then_mac_extension();
    assert_eq!(&ext[0..2], &[0x00, 0x16]); // type 0x0016
    assert_eq!(ext.len(), 4); // empty data
}

#[test]
fn test_build_extended_master_secret_extension() {
    let ext = build_extended_master_secret_extension();
    assert_eq!(&ext[0..2], &[0x00, 0x17]); // type 0x0017
    assert_eq!(ext.len(), 4);
}

#[test]
fn test_build_session_ticket_extension() {
    let ext = build_session_ticket_extension();
    assert_eq!(&ext[0..2], &[0x00, 0x23]); // type 0x0023
    assert_eq!(ext.len(), 4);
}

// ── build_supported_versions_extension ───────────────────────────────────────

#[test]
fn test_build_supported_versions_extension_type() {
    let ext = build_supported_versions_extension(&[0x0304]);
    assert_eq!(&ext[0..2], &[0x00, 0x2b]); // type 0x002b
}

#[test]
fn test_build_supported_versions_extension_encodes_tls13() {
    let ext = build_supported_versions_extension(&[0x0304]);
    // type(2) + len(2) + list_len(1) + version(2) = 7
    assert_eq!(ext.len(), 7);
    assert_eq!(ext[4], 0x02); // list_len = 2
    assert_eq!(&ext[5..7], &[0x03, 0x04]); // TLS 1.3
}

// ── build_psk_key_exchange_modes_extension ────────────────────────────────────

#[test]
fn test_build_psk_key_exchange_modes_extension_type() {
    let ext = build_psk_key_exchange_modes_extension();
    assert_eq!(&ext[0..2], &[0x00, 0x2d]); // type 0x002d
}

#[test]
fn test_build_psk_key_exchange_modes_extension_data() {
    let ext = build_psk_key_exchange_modes_extension();
    // [0x01, 0x01] = list_len(1) + mode psk_dhe_ke(1)
    assert_eq!(&ext[4..], &[0x01, 0x01]);
}

// ── build_key_share_extension ─────────────────────────────────────────────────

#[test]
fn test_build_key_share_extension_type() {
    let ext = build_key_share_extension();
    assert_eq!(&ext[0..2], &[0x00, 0x33]); // type 0x0033
}

#[test]
fn test_build_key_share_extension_x25519_group() {
    let ext = build_key_share_extension();
    // Should contain group id 0x001d (x25519)
    let found = ext.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x1d);
    assert!(
        found,
        "key_share extension must contain x25519 group (0x001d)"
    );
}

// ── build_renegotiation_info_extension ────────────────────────────────────────

#[test]
fn test_build_renegotiation_info_extension_type() {
    let ext = build_renegotiation_info_extension();
    assert_eq!(&ext[0..2], &[0xff, 0x01]); // type 0xff01
}

#[test]
fn test_build_renegotiation_info_extension_data() {
    let ext = build_renegotiation_info_extension();
    // data = [0x00] (empty renegotiated_connection)
    assert_eq!(ext[4], 0x00);
}

// ── build_padding_extension ───────────────────────────────────────────────────

#[test]
fn test_build_padding_extension_type() {
    let ext = build_padding_extension(10);
    assert_eq!(&ext[0..2], &[0x00, 0x15]); // type 0x0015
}

#[test]
fn test_build_padding_extension_correct_length() {
    let ext = build_padding_extension(20);
    assert_eq!(ext.len(), 24); // type(2) + len(2) + 20 bytes
    let data_len = ((ext[2] as usize) << 8) | ext[3] as usize;
    assert_eq!(data_len, 20);
}

#[test]
fn test_build_padding_extension_zeros() {
    let ext = build_padding_extension(5);
    assert!(
        ext[4..].iter().all(|&b| b == 0),
        "padding must be all zeros"
    );
}

// ── calculate_padding ─────────────────────────────────────────────────────────

#[test]
fn test_calculate_padding_in_range_256_511() {
    // 256 is in the problematic range
    let p = calculate_padding(256);
    assert!(p.is_some(), "padding needed for length 256");
    // Result: 512 - 256 = 256, subtract 4 for ext header = 252
    assert_eq!(p.unwrap(), 252);
}

#[test]
fn test_calculate_padding_511() {
    let p = calculate_padding(511);
    assert!(p.is_some());
    // 512 - 511 = 1, which is <= 4, so Some(1)
    assert_eq!(p.unwrap(), 1);
}

#[test]
fn test_calculate_padding_not_needed_below_256() {
    let p = calculate_padding(255);
    // 255 % 256 = 255, not 10 or 14, and not in 256..=511
    assert!(p.is_none());
}

#[test]
fn test_calculate_padding_not_needed_above_511() {
    let p = calculate_padding(600);
    assert!(p.is_none());
}

#[test]
fn test_calculate_padding_mod_256_eq_10() {
    // 522 % 256 == 10, and 522 > 511 so not in first range
    let p = calculate_padding(522);
    assert_eq!(p, Some(1));
}

#[test]
fn test_calculate_padding_mod_256_eq_14() {
    // 526 % 256 == 14, and 526 > 511 so not in first range
    let p = calculate_padding(526);
    assert_eq!(p, Some(1));
}

// ── parse_extensions ──────────────────────────────────────────────────────────

#[test]
fn test_parse_extensions_empty() {
    let (exts, consumed) = parse_extensions(&[]);
    assert!(exts.is_empty());
    assert_eq!(consumed, 0);
}

#[test]
fn test_parse_extensions_single() {
    let data = vec![0x00, 0x17, 0x00, 0x00]; // type=0x0017, len=0
    let (exts, _) = parse_extensions(&data);
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].ext_type, 0x0017);
    assert!(exts[0].data.is_empty());
}

#[test]
fn test_parse_extensions_with_data() {
    let data = vec![0x00, 0x0f, 0x00, 0x01, 0x01]; // heartbeat, len=1, mode=1
    let (exts, _) = parse_extensions(&data);
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].ext_type, 0x000f);
    assert_eq!(exts[0].data, vec![0x01]);
}

#[test]
fn test_parse_extensions_multiple() {
    let ext1 = vec![0x00, 0x17, 0x00, 0x00]; // extended_master_secret
    let ext2 = vec![0x00, 0x23, 0x00, 0x00]; // session_ticket
    let mut data = ext1;
    data.extend(ext2);
    let (exts, _) = parse_extensions(&data);
    assert_eq!(exts.len(), 2);
    assert_eq!(exts[0].ext_type, 0x0017);
    assert_eq!(exts[1].ext_type, 0x0023);
}

#[test]
fn test_parse_extensions_truncated_stops_gracefully() {
    // Claims length of 10 but only 3 bytes of data follow
    let data = vec![0x00, 0x17, 0x00, 0x0a, 0x01, 0x02, 0x03];
    let (exts, _) = parse_extensions(&data);
    assert!(exts.is_empty()); // truncated, nothing parsed
}

// ── ParsedExtension::ext_type_name ────────────────────────────────────────────

#[test]
fn test_ext_type_name_known() {
    let ext = ParsedExtension {
        ext_type: 0x0000,
        data: vec![],
    };
    assert_eq!(ext.ext_type_name(), "server_name");
}

#[test]
fn test_ext_type_name_heartbeat() {
    let ext = ParsedExtension {
        ext_type: 0x000f,
        data: vec![],
    };
    assert_eq!(ext.ext_type_name(), "heartbeat");
}

#[test]
fn test_ext_type_name_unknown() {
    let ext = ParsedExtension {
        ext_type: 0x1234,
        data: vec![],
    };
    assert_eq!(ext.ext_type_name(), "unknown");
}

// ── parse_alpn_extension ──────────────────────────────────────────────────────

#[test]
fn test_parse_alpn_extension_h2() {
    // Build an ALPN extension data (without the outer type/len header)
    // protocol_name_list_length(2) + proto_len(1) + proto
    let proto = b"h2";
    let proto_len = proto.len() as u8;
    let list_len = (1 + proto.len()) as u16; // proto_len(1) + proto
    let mut data = vec![(list_len >> 8) as u8, (list_len & 0xff) as u8, proto_len];
    data.extend_from_slice(proto);
    let result = parse_alpn_extension(&data);
    assert_eq!(result, Some("h2".to_string()));
}

#[test]
fn test_parse_alpn_extension_too_short() {
    assert_eq!(parse_alpn_extension(&[0x00, 0x02, 0x68]), None);
}

#[test]
fn test_parse_alpn_extension_empty_data() {
    assert_eq!(parse_alpn_extension(&[]), None);
}

// ── parse_supported_versions_server ──────────────────────────────────────────

#[test]
fn test_parse_supported_versions_server_tls13() {
    let data = vec![0x03, 0x04]; // TLS 1.3
    assert_eq!(parse_supported_versions_server(&data), Some(0x0304));
}

#[test]
fn test_parse_supported_versions_server_tls12() {
    let data = vec![0x03, 0x03]; // TLS 1.2
    assert_eq!(parse_supported_versions_server(&data), Some(0x0303));
}

#[test]
fn test_parse_supported_versions_server_too_short() {
    assert_eq!(parse_supported_versions_server(&[0x03]), None);
}

#[test]
fn test_parse_supported_versions_server_empty() {
    assert_eq!(parse_supported_versions_server(&[]), None);
}
