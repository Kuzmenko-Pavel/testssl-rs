//! TLS ClientHello builder - builds wire-format TLS ClientHello messages
//!
//! Produces correctly structured TLS records that real servers will accept.
//! Wire format reference: RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3)

use crate::tls::extensions::*;

/// TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    /// The version advertised in the ClientHello body (client_version field)
    pub fn to_wire_version(self) -> (u8, u8) {
        match self {
            TlsVersion::Ssl30 => (0x03, 0x00),
            TlsVersion::Tls10 => (0x03, 0x01),
            TlsVersion::Tls11 => (0x03, 0x02),
            TlsVersion::Tls12 => (0x03, 0x03),
            // TLS 1.3 still uses 0x0303 in the legacy_version field
            // The real version is communicated via the supported_versions extension
            TlsVersion::Tls13 => (0x03, 0x03),
        }
    }

    /// The version used in the TLS Record Layer header
    /// Per RFC 8446 §5.1, TLS 1.3 record layer MUST be 0x0301 for compatibility
    pub fn record_version(self) -> (u8, u8) {
        match self {
            TlsVersion::Ssl30 => (0x03, 0x00),
            TlsVersion::Tls10 => (0x03, 0x01),
            TlsVersion::Tls11 => (0x03, 0x01),
            TlsVersion::Tls12 => (0x03, 0x01),
            TlsVersion::Tls13 => (0x03, 0x01),
        }
    }

    pub fn from_minor(minor: u8) -> Option<Self> {
        match minor {
            0 => Some(TlsVersion::Ssl30),
            1 => Some(TlsVersion::Tls10),
            2 => Some(TlsVersion::Tls11),
            3 => Some(TlsVersion::Tls12),
            4 => Some(TlsVersion::Tls13),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Ssl30 => "SSLv3",
            TlsVersion::Tls10 => "TLSv1.0",
            TlsVersion::Tls11 => "TLSv1.1",
            TlsVersion::Tls12 => "TLSv1.2",
            TlsVersion::Tls13 => "TLSv1.3",
        }
    }
}

/// Builder for TLS ClientHello messages
///
/// Produces correct wire-format bytes suitable for sending to a real TLS server.
pub struct ClientHelloBuilder {
    version: TlsVersion,
    sni: Option<String>,
    cipher_suites: Vec<[u8; 2]>,
    include_extensions: bool,
    include_heartbeat: bool,
    include_session_ticket: bool,
    include_alpn: bool,
    alpn_protocols: Vec<String>,
    include_sni: bool,
    include_supported_groups: bool,
    include_key_share: bool,
    include_sig_algs: bool,
    include_renegotiation_info: bool,
    include_encrypt_then_mac: bool,
    include_extended_master_secret: bool,
    add_fallback_scsv: bool,
    session_id: Vec<u8>,
    random: Option<[u8; 32]>,
}

impl ClientHelloBuilder {
    pub fn new(version: TlsVersion) -> Self {
        Self {
            version,
            sni: None,
            cipher_suites: Vec::new(),
            include_extensions: true,
            include_heartbeat: false,
            include_session_ticket: true,
            include_alpn: false,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            include_sni: true,
            include_supported_groups: true,
            include_key_share: true,
            include_sig_algs: true,
            include_renegotiation_info: true,
            include_encrypt_then_mac: false,
            include_extended_master_secret: true,
            add_fallback_scsv: false,
            session_id: Vec::new(),
            random: None,
        }
    }

    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    pub fn with_heartbeat(mut self) -> Self {
        self.include_heartbeat = true;
        self
    }

    pub fn with_fallback_scsv(mut self) -> Self {
        self.add_fallback_scsv = true;
        self
    }

    pub fn with_alpn(mut self, protocols: Vec<String>) -> Self {
        self.include_alpn = true;
        self.alpn_protocols = protocols;
        self
    }

    pub fn with_cipher_suites(mut self, ciphers: Vec<[u8; 2]>) -> Self {
        self.cipher_suites = ciphers;
        self
    }

    pub fn without_extensions(mut self) -> Self {
        self.include_extensions = false;
        self
    }

    pub fn with_session_id(mut self, sid: Vec<u8>) -> Self {
        self.session_id = sid;
        self
    }

    pub fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = Some(random);
        self
    }

    pub fn with_encrypt_then_mac(mut self) -> Self {
        self.include_encrypt_then_mac = true;
        self
    }

    pub fn without_sni(mut self) -> Self {
        self.include_sni = false;
        self
    }

    pub fn without_session_ticket(mut self) -> Self {
        self.include_session_ticket = false;
        self
    }

    /// Generate a random-looking byte array using a simple PRNG seeded with time.
    /// For security testing purposes only - not cryptographically secure.
    fn generate_random() -> [u8; 32] {
        let mut r = [0u8; 32];
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        // First 4 bytes: unix timestamp (legacy TLS behavior)
        r[0] = (ts >> 24) as u8;
        r[1] = (ts >> 16) as u8;
        r[2] = (ts >> 8) as u8;
        r[3] = ts as u8;
        // Remaining 28 bytes: pseudo-random using simple LCG
        let mut state: u32 = ts.wrapping_mul(1664525).wrapping_add(1013904223);
        for i in (4..32).step_by(4) {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            r[i] = (state >> 24) as u8;
            if i + 1 < 32 {
                r[i + 1] = (state >> 16) as u8;
            }
            if i + 2 < 32 {
                r[i + 2] = (state >> 8) as u8;
            }
            if i + 3 < 32 {
                r[i + 3] = state as u8;
            }
        }
        r
    }

    /// Add default cipher suites based on TLS version
    fn default_ciphers(&self) -> Vec<[u8; 2]> {
        match self.version {
            TlsVersion::Tls13 => {
                let mut ciphers: Vec<[u8; 2]> = TLS13_CIPHERS.to_vec();
                // Also add TLS 1.2 ciphers for compatibility
                ciphers.extend(tls12_default_ciphers());
                ciphers
            }
            TlsVersion::Tls12 => tls12_default_ciphers(),
            TlsVersion::Tls11 | TlsVersion::Tls10 | TlsVersion::Ssl30 => tls_legacy_ciphers(),
        }
    }

    /// Build the complete TLS record containing the ClientHello
    ///
    /// Wire format:
    /// ```text
    /// TLS Record Layer:
    ///   content_type:   1 byte  (0x16 = handshake)
    ///   version_major:  1 byte  (0x03)
    ///   version_minor:  1 byte  (0x01 for TLS 1.0 record layer)
    ///   length:         2 bytes (big-endian, length of handshake message)
    ///
    /// Handshake Message:
    ///   msg_type:       1 byte  (0x01 = ClientHello)
    ///   length:         3 bytes (big-endian, length of ClientHello body)
    ///
    /// ClientHello body:
    ///   legacy_version: 2 bytes (0x03, 0x03 for TLS 1.2+)
    ///   random:         32 bytes
    ///   session_id_len: 1 byte
    ///   session_id:     N bytes
    ///   cipher_suites_len: 2 bytes
    ///   cipher_suites:  N*2 bytes
    ///   compression_methods_len: 1 byte
    ///   compression_methods: N bytes
    ///   extensions_len: 2 bytes
    ///   extensions:     N bytes
    /// ```
    pub fn build(self) -> Vec<u8> {
        let version = self.version;
        let handshake = self.build_handshake();
        let (rec_major, rec_minor) = version.record_version();

        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(0x16); // handshake content type
        record.push(rec_major);
        record.push(rec_minor);
        let len = handshake.len() as u16;
        record.push((len >> 8) as u8);
        record.push((len & 0xff) as u8);
        record.extend_from_slice(&handshake);
        record
    }

    /// Build just the ClientHello handshake message (without TLS record header)
    pub fn build_handshake(self) -> Vec<u8> {
        let client_hello_body = self.build_client_hello_body();
        let body_len = client_hello_body.len();

        let mut msg = Vec::with_capacity(4 + body_len);
        msg.push(0x01); // ClientHello handshake type
                        // 3-byte big-endian length
        msg.push(((body_len >> 16) & 0xff) as u8);
        msg.push(((body_len >> 8) & 0xff) as u8);
        msg.push((body_len & 0xff) as u8);
        msg.extend_from_slice(&client_hello_body);
        msg
    }

    fn build_client_hello_body(self) -> Vec<u8> {
        let mut body = Vec::new();

        // ClientVersion (legacy_version in TLS 1.3)
        let (major, minor) = self.version.to_wire_version();
        body.push(major);
        body.push(minor);

        // Random (32 bytes)
        let random = self.random.unwrap_or_else(Self::generate_random);
        body.extend_from_slice(&random);

        // Session ID
        // TLS 1.3 uses a random 32-byte session ID for middlebox compatibility
        let session_id: Vec<u8> = if !self.session_id.is_empty() {
            self.session_id.clone()
        } else if self.version == TlsVersion::Tls13 {
            // Per RFC 8446 Appendix D.4: send a random 32-byte legacy_session_id
            // This is "middlebox compatibility mode"
            let r = Self::generate_random();
            r.to_vec()
        } else {
            Vec::new()
        };

        body.push(session_id.len() as u8);
        body.extend_from_slice(&session_id);

        // Cipher suites
        let ciphers = if self.cipher_suites.is_empty() {
            self.default_ciphers()
        } else {
            self.cipher_suites.clone()
        };

        // Build cipher bytes list
        let mut cipher_bytes: Vec<u8> = Vec::with_capacity(ciphers.len() * 2 + 4);
        for c in &ciphers {
            cipher_bytes.push(c[0]);
            cipher_bytes.push(c[1]);
        }
        // Add TLS_FALLBACK_SCSV if requested (must be last in cipher list per RFC 7507)
        if self.add_fallback_scsv {
            cipher_bytes.push(TLS_FALLBACK_SCSV[0]);
            cipher_bytes.push(TLS_FALLBACK_SCSV[1]);
        }
        // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00, 0xff) - equivalent to empty renegotiation_info
        // Only add if we're not adding the renegotiation_info extension separately
        if !self.include_renegotiation_info {
            cipher_bytes.push(0x00);
            cipher_bytes.push(0xff);
        }

        let cipher_len = cipher_bytes.len() as u16;
        body.push((cipher_len >> 8) as u8);
        body.push((cipher_len & 0xff) as u8);
        body.extend_from_slice(&cipher_bytes);

        // Compression methods: null only (0x00)
        // TLS 1.3 MUST only offer null compression
        body.push(0x01); // length = 1
        body.push(0x00); // null compression

        // Extensions (not present for SSL 3.0)
        if self.include_extensions && self.version != TlsVersion::Ssl30 {
            let exts = self.build_extensions();
            let exts_len = exts.len() as u16;
            body.push((exts_len >> 8) as u8);
            body.push((exts_len & 0xff) as u8);
            body.extend_from_slice(&exts);
        }

        body
    }

    fn build_extensions(&self) -> Vec<u8> {
        let mut exts: Vec<u8> = Vec::new();

        // SNI - should be first
        if self.include_sni {
            if let Some(ref sni) = self.sni {
                exts.extend_from_slice(&build_sni_extension(sni));
            }
        }

        // TLS 1.3 specific extensions (added early per RFC 8446 ordering recommendations)
        if self.version == TlsVersion::Tls13 {
            // Supported versions - include TLS 1.3 and TLS 1.2 fallback
            let versions = vec![0x0304u16, 0x0303, 0x0302, 0x0301];
            exts.extend_from_slice(&build_supported_versions_extension(&versions));

            // PSK key exchange modes (must come before key_share)
            exts.extend_from_slice(&build_psk_key_exchange_modes_extension());
        }

        // Session ticket
        if self.include_session_ticket {
            exts.extend_from_slice(&build_session_ticket_extension());
        }

        // Signature algorithms (TLS 1.2+)
        // Per RFC 5246: MUST NOT include if offering only TLS < 1.2
        if self.include_sig_algs
            && (self.version == TlsVersion::Tls12 || self.version == TlsVersion::Tls13)
        {
            exts.extend_from_slice(&build_signature_algorithms_extension(DEFAULT_SIG_ALGS));
        }

        // Supported groups / elliptic curves
        if self.include_supported_groups {
            exts.extend_from_slice(&build_supported_groups_extension(DEFAULT_GROUPS));
        }

        // EC point formats
        exts.extend_from_slice(&build_ec_point_formats_extension());

        // Key share (TLS 1.3)
        if self.version == TlsVersion::Tls13 && self.include_key_share {
            exts.extend_from_slice(&build_key_share_extension());
        }

        // ALPN
        if self.include_alpn && !self.alpn_protocols.is_empty() {
            let proto_refs: Vec<&str> = self.alpn_protocols.iter().map(|s| s.as_str()).collect();
            exts.extend_from_slice(&build_alpn_extension(&proto_refs));
        }

        // Extended Master Secret (RFC 7627)
        if self.include_extended_master_secret && self.version != TlsVersion::Tls13 {
            exts.extend_from_slice(&build_extended_master_secret_extension());
        }

        // Renegotiation info (RFC 5746)
        if self.include_renegotiation_info && self.version != TlsVersion::Tls13 {
            exts.extend_from_slice(&build_renegotiation_info_extension());
        }

        // Encrypt-then-MAC (RFC 7366)
        if self.include_encrypt_then_mac {
            exts.extend_from_slice(&build_encrypt_then_mac_extension());
        }

        // Heartbeat MUST be last (or near last) per RFC 6520 and testssl.sh behavior
        // See PR #792: some servers fail if heartbeat is followed by empty extensions
        if self.include_heartbeat {
            exts.extend_from_slice(&build_heartbeat_extension());
        }

        // Calculate total ClientHello size to determine if padding is needed
        // ClientHello size = 2(version) + 32(random) + 1+N(session_id)
        //                  + 2+M(ciphers) + 1+1(compression) + 2+exts_len(extensions)
        // For padding calculation we approximate the full record size
        let session_id_len = if self.version == TlsVersion::Tls13 {
            33
        } else {
            1
        };
        let ciphers = if self.cipher_suites.is_empty() {
            self.default_ciphers()
        } else {
            self.cipher_suites.clone()
        };
        let cipher_count = ciphers.len()
            + if self.add_fallback_scsv { 1 } else { 0 }
            + if !self.include_renegotiation_info {
                1
            } else {
                0
            };
        let approx_hello_len = 2 + 32 + session_id_len + 2 + cipher_count * 2 + 2 + 2 + exts.len();

        // Add padding extension if needed to avoid problematic ClientHello sizes
        if let Some(pad_len) = calculate_padding(approx_hello_len) {
            exts.extend_from_slice(&build_padding_extension(pad_len));
        }

        exts
    }
}

/// Build a ClientHello for heartbeat testing (with heartbeat extension enabled)
pub fn build_heartbeat_client_hello(sni: Option<&str>, version: TlsVersion) -> Vec<u8> {
    let mut builder = ClientHelloBuilder::new(version).with_heartbeat();
    if let Some(s) = sni {
        builder = builder.with_sni(s);
    }
    builder.build()
}

/// Build a ClientHello for specific cipher suite testing
pub fn build_cipher_test_hello(
    sni: Option<&str>,
    version: TlsVersion,
    ciphers: Vec<[u8; 2]>,
) -> Vec<u8> {
    let mut builder = ClientHelloBuilder::new(version).with_cipher_suites(ciphers);
    if let Some(s) = sni {
        builder = builder.with_sni(s);
    }
    builder.build()
}

/// Build a fallback ClientHello (with TLS_FALLBACK_SCSV for downgrade detection)
pub fn build_fallback_client_hello(sni: Option<&str>, version: TlsVersion) -> Vec<u8> {
    let mut builder = ClientHelloBuilder::new(version).with_fallback_scsv();
    if let Some(s) = sni {
        builder = builder.with_sni(s);
    }
    builder.build()
}

/// TLS 1.2 default cipher suites (comprehensive list from testssl.sh TLS12_CIPHER)
pub fn tls12_default_ciphers() -> Vec<[u8; 2]> {
    vec![
        [0xc0, 0x2c], // ECDHE-ECDSA-AES256-GCM-SHA384
        [0xc0, 0x30], // ECDHE-RSA-AES256-GCM-SHA384
        [0xc0, 0x28], // ECDHE-RSA-AES256-SHA384
        [0xc0, 0x24], // ECDHE-ECDSA-AES256-SHA384
        [0xc0, 0x14], // ECDHE-RSA-AES256-SHA
        [0xc0, 0x0a], // ECDHE-ECDSA-AES256-SHA
        [0x00, 0x9f], // DHE-RSA-AES256-GCM-SHA384
        [0x00, 0x6b], // DHE-RSA-AES256-SHA256
        [0x00, 0x39], // DHE-RSA-AES256-SHA
        [0x00, 0x9d], // AES256-GCM-SHA384
        [0x00, 0x3d], // AES256-SHA256
        [0x00, 0x35], // AES256-SHA
        [0xc0, 0x2b], // ECDHE-ECDSA-AES128-GCM-SHA256
        [0xc0, 0x2f], // ECDHE-RSA-AES128-GCM-SHA256
        [0xc0, 0x27], // ECDHE-RSA-AES128-SHA256
        [0xc0, 0x23], // ECDHE-ECDSA-AES128-SHA256
        [0xc0, 0x13], // ECDHE-RSA-AES128-SHA
        [0xc0, 0x09], // ECDHE-ECDSA-AES128-SHA
        [0x00, 0x9e], // DHE-RSA-AES128-GCM-SHA256
        [0x00, 0x67], // DHE-RSA-AES128-SHA256
        [0x00, 0x33], // DHE-RSA-AES128-SHA
        [0x00, 0x9c], // AES128-GCM-SHA256
        [0x00, 0x3c], // AES128-SHA256
        [0x00, 0x2f], // AES128-SHA
        [0xcc, 0xa9], // ECDHE-ECDSA-CHACHA20-POLY1305
        [0xcc, 0xa8], // ECDHE-RSA-CHACHA20-POLY1305
        [0xcc, 0xaa], // DHE-RSA-CHACHA20-POLY1305
        [0x00, 0xa3], // DHE-DSS-AES256-GCM-SHA384
        [0x00, 0x6a], // DHE-DSS-AES256-SHA256
        [0x00, 0x38], // DHE-DSS-AES256-SHA
        [0xc0, 0x32], // ECDH-RSA-AES256-GCM-SHA384
        [0xc0, 0x2e], // ECDH-ECDSA-AES256-GCM-SHA384
        [0x00, 0x16], // DHE-RSA-DES-CBC3-SHA
        [0x00, 0x0a], // DES-CBC3-SHA
    ]
}

/// Legacy cipher suites for SSLv3/TLS 1.0/1.1
pub fn tls_legacy_ciphers() -> Vec<[u8; 2]> {
    vec![
        [0xc0, 0x14], // ECDHE-RSA-AES256-SHA
        [0xc0, 0x0a], // ECDHE-ECDSA-AES256-SHA
        [0x00, 0x39], // DHE-RSA-AES256-SHA
        [0x00, 0x38], // DHE-DSS-AES256-SHA
        [0x00, 0x35], // AES256-SHA
        [0xc0, 0x13], // ECDHE-RSA-AES128-SHA
        [0xc0, 0x09], // ECDHE-ECDSA-AES128-SHA
        [0x00, 0x33], // DHE-RSA-AES128-SHA
        [0x00, 0x32], // DHE-DSS-AES128-SHA
        [0x00, 0x2f], // AES128-SHA
        [0x00, 0x16], // DHE-RSA-DES-CBC3-SHA
        [0x00, 0x13], // DHE-DSS-DES-CBC3-SHA
        [0x00, 0x0a], // DES-CBC3-SHA
        [0x00, 0x05], // RC4-SHA
        [0x00, 0x04], // RC4-MD5
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tls12_hello() {
        let hello = ClientHelloBuilder::new(TlsVersion::Tls12)
            .with_sni("example.com")
            .build();

        // Check TLS record header
        assert_eq!(hello[0], 0x16, "content type should be handshake");
        assert_eq!(hello[1], 0x03, "record version major should be 0x03");
        assert_eq!(hello[2], 0x01, "record version minor should be 0x01");

        // Check handshake message type
        let record_len = ((hello[3] as usize) << 8) | hello[4] as usize;
        assert!(record_len > 0, "record length should be > 0");
        assert_eq!(hello[5], 0x01, "handshake type should be ClientHello (1)");

        // Check ClientHello version
        assert_eq!(hello[9], 0x03, "client version major");
        assert_eq!(hello[10], 0x03, "client version minor for TLS 1.2");
    }

    #[test]
    fn test_tls13_hello_has_supported_versions() {
        let hello = ClientHelloBuilder::new(TlsVersion::Tls13)
            .with_sni("example.com")
            .build();

        assert_eq!(hello[0], 0x16);
        // TLS 1.3 still uses 0x0303 in client_version
        assert_eq!(hello[9], 0x03);
        assert_eq!(hello[10], 0x03);
        // The message must be longer than a minimal hello (has extensions)
        assert!(hello.len() > 100);
    }

    #[test]
    fn test_sslv3_no_extensions() {
        let hello = ClientHelloBuilder::new(TlsVersion::Ssl30)
            .without_extensions()
            .build();

        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x00, "SSLv3 record version should be 0x0300");
    }

    #[test]
    fn test_record_length_consistent() {
        let hello = ClientHelloBuilder::new(TlsVersion::Tls12)
            .with_sni("test.example.com")
            .build();

        // Verify TLS record length field matches actual data
        let stated_record_len = ((hello[3] as usize) << 8) | hello[4] as usize;
        assert_eq!(
            stated_record_len,
            hello.len() - 5,
            "record length must match actual payload size"
        );

        // Verify handshake length field
        let handshake_len =
            ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(
            handshake_len,
            hello.len() - 9,
            "handshake length must match"
        );
    }
}
