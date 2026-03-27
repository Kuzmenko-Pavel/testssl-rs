//! TLS extensions encoding/decoding

/// TLS extension type codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExtensionType {
    ServerName = 0x0000,
    MaxFragmentLength = 0x0001,
    ClientCertificateUrl = 0x0002,
    TrustedCaKeys = 0x0003,
    TruncatedHmac = 0x0004,
    StatusRequest = 0x0005,
    UserMapping = 0x0006,
    ClientAuthz = 0x0007,
    ServerAuthz = 0x0008,
    CertType = 0x0009,
    SupportedGroups = 0x000a, // also "elliptic_curves"
    EcPointFormats = 0x000b,
    Srp = 0x000c,
    SignatureAlgorithms = 0x000d,
    UseSrtp = 0x000e,
    Heartbeat = 0x000f,
    ApplicationLayerProtocolNegotiation = 0x0010,
    StatusRequestV2 = 0x0011,
    SignedCertificateTimestamp = 0x0012,
    ClientCertificateType = 0x0013,
    ServerCertificateType = 0x0014,
    Padding = 0x0015,
    EncryptThenMac = 0x0016,
    ExtendedMasterSecret = 0x0017,
    CompressCertificate = 0x001b,
    SessionTicket = 0x0023,
    PreSharedKey = 0x0029,
    EarlyData = 0x002a,
    SupportedVersions = 0x002b,
    Cookie = 0x002c,
    PskKeyExchangeModes = 0x002d,
    CertificateAuthorities = 0x002f,
    OidFilters = 0x0030,
    PostHandshakeAuth = 0x0031,
    SignatureAlgorithmsCert = 0x0032,
    KeyShare = 0x0033,
    // GREASE values
    Grease0a0a = 0x0a0a,
    Grease1a1a = 0x1a1a,
    Grease2a2a = 0x2a2a,
    TlsFallbackScsv = 0x5600,
    RenegotiationInfo = 0xff01,
}

/// Generic extension builder: wraps data with type(u16) + length(u16) header
pub fn build_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut ext = Vec::with_capacity(4 + data.len());
    ext.push((ext_type >> 8) as u8);
    ext.push((ext_type & 0xff) as u8);
    let len = data.len() as u16;
    ext.push((len >> 8) as u8);
    ext.push((len & 0xff) as u8);
    ext.extend_from_slice(data);
    ext
}

/// Build the SNI extension (type 0x0000)
///
/// Structure:
///   extension_type:   2 bytes (0x00, 0x00)
///   extension_length: 2 bytes
///   server_name_list_length: 2 bytes
///   server_name_type: 1 byte (0x00 = host_name)
///   server_name_length: 2 bytes
///   server_name: N bytes
pub fn build_sni_extension(hostname: &str) -> Vec<u8> {
    let name_bytes = hostname.as_bytes();
    let name_len = name_bytes.len() as u16;
    // server_name_type(1) + server_name_length(2) + server_name(N)
    let list_len = 1u16 + 2 + name_len;
    // server_name_list_length(2) + list_len
    let ext_data_len = 2u16 + list_len;

    let mut data = Vec::with_capacity(ext_data_len as usize);
    // ServerNameList length
    data.push((list_len >> 8) as u8);
    data.push((list_len & 0xff) as u8);
    // Name type: host_name (0)
    data.push(0x00);
    // Name length
    data.push((name_len >> 8) as u8);
    data.push((name_len & 0xff) as u8);
    // Name
    data.extend_from_slice(name_bytes);

    build_extension(0x0000, &data)
}

/// Build the supported groups (elliptic curves) extension (type 0x000a)
pub fn build_supported_groups_extension(groups: &[u16]) -> Vec<u8> {
    let list_len = (groups.len() * 2) as u16;
    let mut data = Vec::with_capacity(2 + list_len as usize);
    data.push((list_len >> 8) as u8);
    data.push((list_len & 0xff) as u8);
    for g in groups {
        data.push((*g >> 8) as u8);
        data.push((*g & 0xff) as u8);
    }
    build_extension(0x000a, &data)
}

/// Build the EC point formats extension (type 0x000b)
pub fn build_ec_point_formats_extension() -> Vec<u8> {
    // list_length(1) + uncompressed(1) + ansiX962_compressed_prime(1) + ansiX962_compressed_char2(1)
    let data = vec![0x03, 0x00, 0x01, 0x02];
    build_extension(0x000b, &data)
}

/// Build the signature algorithms extension (type 0x000d)
pub fn build_signature_algorithms_extension(sigalgs: &[u16]) -> Vec<u8> {
    let list_len = (sigalgs.len() * 2) as u16;
    let mut data = Vec::with_capacity(2 + list_len as usize);
    data.push((list_len >> 8) as u8);
    data.push((list_len & 0xff) as u8);
    for s in sigalgs {
        data.push((*s >> 8) as u8);
        data.push((*s & 0xff) as u8);
    }
    build_extension(0x000d, &data)
}

/// Build the heartbeat extension (type 0x000f)
/// mode 0x01 = peer_allowed_to_send
pub fn build_heartbeat_extension() -> Vec<u8> {
    build_extension(0x000f, &[0x01])
}

/// Build the ALPN extension (type 0x0010)
pub fn build_alpn_extension(protocols: &[&str]) -> Vec<u8> {
    let mut proto_list = Vec::new();
    for proto in protocols {
        let bytes = proto.as_bytes();
        proto_list.push(bytes.len() as u8);
        proto_list.extend_from_slice(bytes);
    }
    let list_len = proto_list.len() as u16;
    let mut data = Vec::with_capacity(2 + proto_list.len());
    data.push((list_len >> 8) as u8);
    data.push((list_len & 0xff) as u8);
    data.extend_from_slice(&proto_list);
    build_extension(0x0010, &data)
}

/// Build encrypt-then-MAC extension (type 0x0016, empty)
pub fn build_encrypt_then_mac_extension() -> Vec<u8> {
    build_extension(0x0016, &[])
}

/// Build extended master secret extension (type 0x0017, empty)
pub fn build_extended_master_secret_extension() -> Vec<u8> {
    build_extension(0x0017, &[])
}

/// Build the session ticket extension (type 0x0023, empty = request new ticket)
pub fn build_session_ticket_extension() -> Vec<u8> {
    build_extension(0x0023, &[])
}

/// Build the supported versions extension (type 0x002b) for ClientHello
/// In ClientHello this is a list of versions (1-byte length prefix)
pub fn build_supported_versions_extension(versions: &[u16]) -> Vec<u8> {
    let list_len = (versions.len() * 2) as u8;
    let mut data = Vec::with_capacity(1 + versions.len() * 2);
    data.push(list_len);
    for v in versions {
        data.push((*v >> 8) as u8);
        data.push((*v & 0xff) as u8);
    }
    build_extension(0x002b, &data)
}

/// Build the PSK key exchange modes extension (type 0x002d)
/// mode 0x01 = psk_dhe_ke
pub fn build_psk_key_exchange_modes_extension() -> Vec<u8> {
    // list_length(1) + mode(1)
    let data = vec![0x01, 0x01];
    build_extension(0x002d, &data)
}

/// Build the key_share extension (type 0x0033) with x25519 group
///
/// For x25519 (group 0x001d), key exchange is a 32-byte public key.
/// We generate a static but plausible public key for testing.
/// In production this would be a real ephemeral key pair.
pub fn build_key_share_extension() -> Vec<u8> {
    // Use x25519 group (0x001d) - the public key is 32 bytes
    let group_id: u16 = 0x001d; // x25519

    // Static x25519 public key (32 bytes) - valid-looking but not cryptographically meaningful
    // A real implementation would generate an ephemeral key pair using ring or similar
    let key_exchange: [u8; 32] = [
        0x2f, 0xe5, 0x7d, 0xa3, 0x47, 0xcd, 0x62, 0x43, 0x15, 0x28, 0xda, 0xac, 0x5f, 0xbb, 0x29,
        0x07, 0x30, 0xff, 0xf6, 0x84, 0xaf, 0xc4, 0xcf, 0xc2, 0xed, 0x90, 0x99, 0x5f, 0x58, 0xcb,
        0x3b, 0x74,
    ];

    let key_exchange_len = key_exchange.len() as u16;
    // One entry: group(2) + key_exchange_len(2) + key_exchange
    let entry_len = 2u16 + 2 + key_exchange_len;
    // key_share_list_length(2) + entries
    let mut data = Vec::with_capacity(2 + entry_len as usize);
    // client_shares list length
    data.push((entry_len >> 8) as u8);
    data.push((entry_len & 0xff) as u8);
    // group
    data.push((group_id >> 8) as u8);
    data.push((group_id & 0xff) as u8);
    // key_exchange length
    data.push((key_exchange_len >> 8) as u8);
    data.push((key_exchange_len & 0xff) as u8);
    data.extend_from_slice(&key_exchange);

    build_extension(0x0033, &data)
}

/// Build the renegotiation info extension (type 0xff01)
/// Empty renegotiated_connection means initial handshake
pub fn build_renegotiation_info_extension() -> Vec<u8> {
    // renegotiated_connection length (1 byte = 0x00 for empty)
    build_extension(0xff01, &[0x00])
}

/// Build a padding extension (type 0x0015) of the given length
/// Used to avoid TLS ClientHello sizes known to cause issues (256-511 bytes)
pub fn build_padding_extension(padding_len: usize) -> Vec<u8> {
    let data = vec![0u8; padding_len];
    build_extension(0x0015, &data)
}

/// Calculate padding needed to avoid problematic ClientHello lengths
/// Returns Some(padding_bytes) if padding is needed, None otherwise
pub fn calculate_padding(current_hello_len: usize) -> Option<usize> {
    // RFC 7685: pad to avoid 256-511 byte range which causes issues with some servers
    // Also avoid specific lengths that cause problems (mod 256 == 10 or 14)
    if (256..=511).contains(&current_hello_len) {
        // Add padding to reach 512 bytes
        // Extension overhead is 4 bytes (type + length), content must be at least 1 for non-empty
        let needed = 512 - current_hello_len;
        // The extension header is 4 bytes, so we need at least 4 bytes to add
        if needed <= 4 {
            // Can't fit a proper extension, add minimal padding
            Some(1)
        } else {
            Some(needed - 4) // subtract 4 for the extension header
        }
    } else if current_hello_len % 256 == 10 || current_hello_len % 256 == 14 {
        // Some servers fail on these specific lengths
        Some(1) // Add minimal padding (5 bytes total extension: 4 header + 1 data)
    } else {
        None
    }
}

/// Build the TLS fallback SCSV as a cipher suite value (not an extension)
/// This is added to the cipher suite list, not the extensions
pub const TLS_FALLBACK_SCSV: [u8; 2] = [0x56, 0x00];

/// Standard cipher suites used in ClientHello for TLS 1.3
pub const TLS13_CIPHERS: &[[u8; 2]] = &[
    [0x13, 0x01], // TLS_AES_128_GCM_SHA256
    [0x13, 0x02], // TLS_AES_256_GCM_SHA384
    [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
    [0x13, 0x04], // TLS_AES_128_CCM_SHA256
    [0x13, 0x05], // TLS_AES_128_CCM_8_SHA256
];

/// Default signature algorithms for TLS 1.2/1.3
/// Order matters: stronger/more modern algorithms first
pub const DEFAULT_SIG_ALGS: &[u16] = &[
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
    0x0807, // ed25519
    0x0808, // ed448
    0x0809, // rsa_pss_pss_sha256
    0x080a, // rsa_pss_pss_sha384
    0x080b, // rsa_pss_pss_sha512
    0x0201, // rsa_pkcs1_sha1
    0x0203, // ecdsa_sha1
];

/// Default supported groups for ClientHello
/// x25519 first as it's most widely supported and efficient
pub const DEFAULT_GROUPS: &[u16] = &[
    0x001d, // x25519
    0x0017, // secp256r1 (P-256)
    0x001e, // x448
    0x0018, // secp384r1 (P-384)
    0x0019, // secp521r1 (P-521)
    0x0100, // ffdhe2048
    0x0101, // ffdhe3072
];

/// A parsed TLS extension from a ServerHello
#[derive(Debug, Clone)]
pub struct ParsedExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl ParsedExtension {
    pub fn ext_type_name(&self) -> &'static str {
        match self.ext_type {
            0x0000 => "server_name",
            0x0001 => "max_fragment_length",
            0x0005 => "status_request",
            0x000a => "supported_groups",
            0x000b => "ec_point_formats",
            0x000d => "signature_algorithms",
            0x000f => "heartbeat",
            0x0010 => "application_layer_protocol_negotiation",
            0x0016 => "encrypt_then_mac",
            0x0017 => "extended_master_secret",
            0x0023 => "session_ticket",
            0x0029 => "pre_shared_key",
            0x002b => "supported_versions",
            0x002d => "psk_key_exchange_modes",
            0x0033 => "key_share",
            0xff01 => "renegotiation_info",
            _ => "unknown",
        }
    }
}

/// Parse all extensions from a byte slice.
/// Returns a vector of parsed extensions and any remaining unparsed bytes.
pub fn parse_extensions(data: &[u8]) -> (Vec<ParsedExtension>, usize) {
    let mut extensions = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
        let ext_len = ((data[offset + 2] as usize) << 8) | data[offset + 3] as usize;
        offset += 4;

        if data.len() < offset + ext_len {
            break;
        }

        let ext_data = data[offset..offset + ext_len].to_vec();
        offset += ext_len;

        extensions.push(ParsedExtension {
            ext_type,
            data: ext_data,
        });
    }

    (extensions, offset)
}

/// Extract ALPN protocol name from a parsed ALPN extension data
pub fn parse_alpn_extension(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    // protocol_name_list_length (2 bytes)
    let list_len = ((data[0] as usize) << 8) | data[1] as usize;
    if data.len() < 2 + list_len || list_len < 2 {
        return None;
    }
    // First protocol name: length(1) + name
    let proto_len = data[2] as usize;
    if data.len() < 3 + proto_len {
        return None;
    }
    Some(String::from_utf8_lossy(&data[3..3 + proto_len]).to_string())
}

/// Extract negotiated TLS version from supported_versions extension data (ServerHello)
pub fn parse_supported_versions_server(data: &[u8]) -> Option<u16> {
    if data.len() < 2 {
        return None;
    }
    // In ServerHello, supported_versions is exactly 2 bytes (the selected version)
    Some(((data[0] as u16) << 8) | data[1] as u16)
}
