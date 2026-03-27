//! TLS ServerHello parser
//!
//! Parses TLS server responses including ServerHello, Certificate messages,
//! alerts, and various TLS handshake messages.

use anyhow::{Context, Result};
use tracing::debug;

use crate::tls::extensions::{parse_alpn_extension, parse_supported_versions_server};

// Re-export ParsedExtension from extensions module for convenience
pub use crate::tls::extensions::ParsedExtension;

/// Result of parsing a ServerHello
#[derive(Debug, Clone, Default)]
pub struct ServerHelloResult {
    /// Negotiated TLS version (from ServerHello legacy_version field)
    pub version_major: u8,
    pub version_minor: u8,
    /// Server random (32 bytes)
    pub random: Vec<u8>,
    /// Session ID
    pub session_id: Vec<u8>,
    /// Negotiated cipher suite
    pub cipher_suite: [u8; 2],
    /// Compression method
    pub compression_method: u8,
    /// Extensions present in ServerHello
    pub extensions: Vec<ParsedExtension>,
    /// Whether heartbeat extension was offered by server
    pub heartbeat_offered: bool,
    /// Heartbeat mode (1 = peer_allowed_to_send, 2 = peer_not_allowed_to_send)
    pub heartbeat_mode: u8,
    /// Negotiated ALPN protocol
    pub alpn_protocol: Option<String>,
    /// Certificate chains received (DER-encoded)
    pub certificates: Vec<Vec<u8>>,
    /// Whether server sent ServerHelloDone (TLS 1.2 and below)
    pub server_hello_done: bool,
    /// TLS alert received (level, description)
    pub alert: Option<(u8, u8)>,
    /// Whether the handshake appears to have succeeded
    pub handshake_completed: bool,
    /// Raw server response bytes
    pub raw_bytes: Vec<u8>,
    /// Detected TLS version (from supported_versions extension for TLS 1.3)
    /// 0x0304 = TLS 1.3, 0x0303 = TLS 1.2, etc.
    pub negotiated_version: Option<u16>,
    /// Whether ChangeCipherSpec was received
    pub change_cipher_spec_received: bool,
    /// Whether encrypted application data was received
    pub encrypted_data_received: bool,
    /// Server key exchange data (for DH/ECDH parameters)
    pub server_key_exchange: Option<Vec<u8>>,
    /// Whether we got a valid ServerHello (negotiation succeeded at TLS level)
    pub server_hello_received: bool,
    /// Renegotiation info received from server
    pub renegotiation_info: Option<Vec<u8>>,
}

/// Parse error types
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Insufficient data: need {needed} bytes, have {available}")]
    InsufficientData { needed: usize, available: usize },

    #[error("Invalid record type: {0}")]
    InvalidRecordType(u8),

    #[error("Invalid handshake type: {0}")]
    InvalidHandshakeType(u8),

    #[error("ServerHello body too short: {0} bytes")]
    ServerHelloTooShort(usize),

    #[error("TLS alert received: level={level}, description={description}")]
    TlsAlert { level: u8, description: u8 },

    #[error("Encrypted data received (cannot parse without keys)")]
    EncryptedData,
}

/// Parser for TLS ServerHello messages
pub struct ServerHelloParser;

impl ServerHelloParser {
    /// Parse raw bytes received from a TLS server.
    ///
    /// This function processes a stream of TLS records and populates
    /// a ServerHelloResult with all discovered information.
    ///
    /// It handles:
    /// - ServerHello handshake messages
    /// - Certificate messages
    /// - ServerHelloDone messages
    /// - ServerKeyExchange messages
    /// - Alert messages
    /// - ChangeCipherSpec messages
    /// - Encrypted ApplicationData (indicates successful handshake)
    pub fn parse(data: &[u8]) -> Result<ServerHelloResult> {
        let mut result = ServerHelloResult {
            raw_bytes: data.to_vec(),
            ..ServerHelloResult::default()
        };

        let mut offset = 0;

        while offset < data.len() {
            // Need at least 5 bytes for TLS record header
            if data.len() < offset + 5 {
                debug!("Incomplete TLS record header at offset {}", offset);
                break;
            }

            let content_type = data[offset];
            let version_major = data[offset + 1];
            let version_minor = data[offset + 2];
            let record_len = ((data[offset + 3] as usize) << 8) | data[offset + 4] as usize;
            offset += 5;

            // Sanity check: TLS records cannot exceed 16384 bytes of plaintext
            // (16KB + potential padding/MAC/overhead = up to ~18KB)
            if record_len > 18432 {
                debug!(
                    "TLS record length {} seems too large, stopping parse",
                    record_len
                );
                break;
            }

            if data.len() < offset + record_len {
                debug!(
                    "Incomplete TLS record: need {} more bytes (have {})",
                    record_len,
                    data.len() - offset
                );
                break;
            }

            let record_data = &data[offset..offset + record_len];
            offset += record_len;

            debug!(
                "TLS record: type={}, version={:02x}{:02x}, len={}",
                content_type, version_major, version_minor, record_len
            );

            match content_type {
                22 => {
                    // Handshake record
                    Self::parse_handshake_record(record_data, &mut result)
                        .unwrap_or_else(|e| debug!("Error parsing handshake: {}", e));
                }
                21 => {
                    // Alert record
                    if record_data.len() >= 2 {
                        let alert_level = record_data[0];
                        let alert_desc = record_data[1];
                        result.alert = Some((alert_level, alert_desc));
                        debug!(
                            "TLS Alert: level={} ({}), description={} ({})",
                            alert_level,
                            Self::alert_level_name(alert_level),
                            alert_desc,
                            Self::alert_description_name(alert_desc)
                        );
                    }
                }
                20 => {
                    // ChangeCipherSpec record
                    debug!("ChangeCipherSpec received");
                    result.change_cipher_spec_received = true;
                }
                23 => {
                    // ApplicationData record - encrypted, indicates successful handshake
                    debug!("ApplicationData (encrypted) received - handshake successful");
                    result.encrypted_data_received = true;
                    result.handshake_completed = true;
                }
                24 => {
                    // Heartbeat record - record that server processed our heartbeat ext
                    debug!("Heartbeat record received");
                }
                _ => {
                    debug!("Unknown TLS content type: {}", content_type);
                }
            }
        }

        Ok(result)
    }

    /// Parse a single TLS handshake record which may contain multiple handshake messages
    fn parse_handshake_record(data: &[u8], result: &mut ServerHelloResult) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            // Need at least 4 bytes for handshake message header
            if data.len() < offset + 4 {
                debug!("Incomplete handshake message header at offset {}", offset);
                break;
            }

            let msg_type = data[offset];
            let msg_len = ((data[offset + 1] as usize) << 16)
                | ((data[offset + 2] as usize) << 8)
                | data[offset + 3] as usize;
            offset += 4;

            if data.len() < offset + msg_len {
                debug!(
                    "Incomplete handshake message: type={}, need {} bytes",
                    msg_type, msg_len
                );
                break;
            }

            let msg_data = &data[offset..offset + msg_len];
            offset += msg_len;

            match msg_type {
                2 => {
                    // ServerHello
                    debug!("Parsing ServerHello ({} bytes)", msg_len);
                    Self::parse_server_hello(msg_data, result)
                        .context("Failed to parse ServerHello")?;
                }
                4 => {
                    // NewSessionTicket
                    debug!("NewSessionTicket received ({} bytes)", msg_len);
                    result.handshake_completed = true;
                }
                8 => {
                    // EncryptedExtensions (TLS 1.3)
                    debug!("EncryptedExtensions received ({} bytes)", msg_len);
                    // This indicates TLS 1.3 handshake is proceeding
                }
                11 => {
                    // Certificate
                    debug!("Parsing Certificate message ({} bytes)", msg_len);
                    Self::parse_certificate(msg_data, result)
                        .context("Failed to parse Certificate")?;
                }
                12 => {
                    // ServerKeyExchange
                    debug!("ServerKeyExchange received ({} bytes)", msg_len);
                    result.server_key_exchange = Some(msg_data.to_vec());
                }
                13 => {
                    // CertificateRequest
                    debug!("CertificateRequest received");
                }
                14 => {
                    // ServerHelloDone
                    debug!("ServerHelloDone received");
                    result.server_hello_done = true;
                    result.handshake_completed = true;
                }
                15 => {
                    // CertificateVerify
                    debug!("CertificateVerify received ({} bytes)", msg_len);
                }
                20 => {
                    // Finished
                    debug!("Finished received ({} bytes)", msg_len);
                    result.handshake_completed = true;
                }
                _ => {
                    debug!(
                        "Unknown handshake message type: {} ({} bytes)",
                        msg_type, msg_len
                    );
                }
            }
        }

        Ok(())
    }

    /// Parse the ServerHello body (after handshake header)
    fn parse_server_hello(data: &[u8], result: &mut ServerHelloResult) -> Result<()> {
        // Minimum: version(2) + random(32) + session_id_len(1) = 35 bytes
        if data.len() < 35 {
            return Err(anyhow::anyhow!(ParseError::ServerHelloTooShort(data.len())));
        }

        // Legacy version field (always 0x0303 for TLS 1.3, real version in extensions)
        result.version_major = data[0];
        result.version_minor = data[1];

        // Random (32 bytes)
        result.random = data[2..34].to_vec();

        // Session ID (variable length)
        let sid_len = data[34] as usize;

        // Ensure we have enough bytes for session ID + cipher(2) + compression(1)
        let min_needed = 35 + sid_len + 3;
        if data.len() < min_needed {
            return Err(anyhow::anyhow!(
                "ServerHello truncated at session ID: need {} bytes, have {}",
                min_needed,
                data.len()
            ));
        }

        if sid_len > 0 {
            result.session_id = data[35..35 + sid_len].to_vec();
        }

        let pos = 35 + sid_len;

        // Cipher suite (2 bytes)
        result.cipher_suite = [data[pos], data[pos + 1]];

        // Compression method (1 byte)
        result.compression_method = data[pos + 2];

        result.server_hello_received = true;

        debug!(
            "ServerHello: version={:02x}{:02x}, cipher={:02x}{:02x}, compression={:02x}",
            result.version_major,
            result.version_minor,
            result.cipher_suite[0],
            result.cipher_suite[1],
            result.compression_method
        );

        // Parse extensions if present
        let ext_start = pos + 3;
        if data.len() > ext_start + 1 {
            let ext_total_len = ((data[ext_start] as usize) << 8) | data[ext_start + 1] as usize;
            let ext_data_start = ext_start + 2;

            if data.len() >= ext_data_start + ext_total_len {
                let ext_bytes = &data[ext_data_start..ext_data_start + ext_total_len];
                let (raw_extensions, _) = crate::tls::extensions::parse_extensions(ext_bytes);

                for raw_ext in raw_extensions {
                    let ext_type = raw_ext.ext_type;
                    let ext_data = raw_ext.data.clone();

                    match ext_type {
                        0x000f => {
                            // Heartbeat extension
                            if !ext_data.is_empty() {
                                result.heartbeat_mode = ext_data[0];
                                result.heartbeat_offered = true;
                                debug!(
                                    "Server heartbeat: mode={}",
                                    if ext_data[0] == 1 {
                                        "peer_allowed_to_send"
                                    } else {
                                        "peer_not_allowed_to_send"
                                    }
                                );
                            }
                        }
                        0x0010 => {
                            // ALPN extension
                            if let Some(proto) = parse_alpn_extension(&ext_data) {
                                debug!("ALPN protocol negotiated: {}", proto);
                                result.alpn_protocol = Some(proto);
                            }
                        }
                        0x002b => {
                            // Supported versions (TLS 1.3)
                            if let Some(ver) = parse_supported_versions_server(&ext_data) {
                                debug!(
                                    "Negotiated TLS version from supported_versions: 0x{:04x}",
                                    ver
                                );
                                result.negotiated_version = Some(ver);
                                // If server selected TLS 1.3, mark handshake as proceeding
                                if ver == 0x0304 {
                                    result.handshake_completed = false; // Will be set when Finished received
                                }
                            }
                        }
                        0xff01 => {
                            // Renegotiation info
                            result.renegotiation_info = Some(ext_data.clone());
                            debug!("Renegotiation info received ({} bytes)", ext_data.len());
                        }
                        0x0017 => {
                            // Extended master secret
                            debug!("Extended master secret extension received");
                        }
                        0x0023 => {
                            // Session ticket
                            debug!(
                                "Session ticket extension received ({} bytes)",
                                ext_data.len()
                            );
                        }
                        _ => {
                            debug!(
                                "Extension 0x{:04x} received ({} bytes)",
                                ext_type,
                                ext_data.len()
                            );
                        }
                    }

                    result.extensions.push(ParsedExtension {
                        ext_type,
                        data: ext_data,
                    });
                }
            } else {
                debug!(
                    "Extensions length {} exceeds available data {}",
                    ext_total_len,
                    data.len() - ext_data_start
                );
            }
        }

        Ok(())
    }

    /// Parse a Certificate handshake message
    fn parse_certificate(data: &[u8], result: &mut ServerHelloResult) -> Result<()> {
        if data.len() < 3 {
            return Ok(());
        }

        // TLS 1.2 and below: certificate_list (3-byte length prefix)
        let certs_total_len =
            ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;

        if data.len() < 3 + certs_total_len {
            debug!(
                "Certificate message truncated: expected {} bytes, have {}",
                3 + certs_total_len,
                data.len()
            );
            return Ok(());
        }

        let mut offset = 3;
        while offset + 3 <= data.len() && offset < 3 + certs_total_len {
            let cert_len = ((data[offset] as usize) << 16)
                | ((data[offset + 1] as usize) << 8)
                | data[offset + 2] as usize;
            offset += 3;

            if data.len() < offset + cert_len {
                debug!(
                    "Certificate truncated at cert {}",
                    result.certificates.len()
                );
                break;
            }

            if cert_len > 0 {
                let cert_der = data[offset..offset + cert_len].to_vec();
                debug!(
                    "Certificate {} parsed: {} bytes",
                    result.certificates.len(),
                    cert_len
                );
                result.certificates.push(cert_der);
            }
            offset += cert_len;
        }

        debug!("Parsed {} certificate(s)", result.certificates.len());
        Ok(())
    }

    /// Check if the response indicates a successful TLS handshake beginning
    pub fn is_successful(result: &ServerHelloResult) -> bool {
        result.server_hello_received
            || result.handshake_completed
            || !result.certificates.is_empty()
            || result.encrypted_data_received
    }

    /// Check if the server sent a fatal alert
    pub fn has_fatal_alert(result: &ServerHelloResult) -> bool {
        if let Some((level, _desc)) = result.alert {
            level == 2 // fatal
        } else {
            false
        }
    }

    /// Get the negotiated TLS version as a human-readable string
    pub fn version_string(result: &ServerHelloResult) -> &'static str {
        // Check TLS 1.3 via supported_versions extension first
        if result.negotiated_version == Some(0x0304) {
            return "TLSv1.3";
        }
        match (result.version_major, result.version_minor) {
            (3, 0) => "SSLv3",
            (3, 1) => "TLSv1.0",
            (3, 2) => "TLSv1.1",
            (3, 3) => "TLSv1.2",
            _ => "Unknown",
        }
    }

    /// Get a human-readable description of a TLS alert description code
    pub fn alert_description_name(desc: u8) -> &'static str {
        match desc {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            21 => "decryption_failed",
            22 => "record_overflow",
            30 => "decompression_failure",
            40 => "handshake_failure",
            41 => "no_certificate",
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            47 => "illegal_parameter",
            48 => "unknown_ca",
            49 => "access_denied",
            50 => "decode_error",
            51 => "decrypt_error",
            60 => "export_restriction",
            70 => "protocol_version",
            71 => "insufficient_security",
            80 => "internal_error",
            86 => "inappropriate_fallback",
            90 => "user_canceled",
            100 => "no_renegotiation",
            109 => "missing_extension",
            110 => "unsupported_extension",
            112 => "unrecognized_name",
            113 => "bad_certificate_status_response",
            115 => "unknown_psk_identity",
            116 => "certificate_required",
            120 => "no_application_protocol",
            _ => "unknown",
        }
    }

    /// Get a human-readable name for an alert level
    pub fn alert_level_name(level: u8) -> &'static str {
        match level {
            1 => "warning",
            2 => "fatal",
            _ => "unknown",
        }
    }

    /// Quick parse to check if data starts with a valid TLS ServerHello
    pub fn has_server_hello(data: &[u8]) -> bool {
        if data.len() < 10 {
            return false;
        }
        // content_type == 22 (handshake)
        if data[0] != 22 {
            return false;
        }
        // version major == 3
        if data[1] != 3 {
            return false;
        }
        // handshake type == 2 (ServerHello)
        if data[5] != 2 {
            return false;
        }
        true
    }

    /// Quick parse to check if data is a TLS alert
    pub fn is_alert(data: &[u8]) -> bool {
        data.len() >= 5 && data[0] == 21 && data[1] == 3
    }

    /// Extract the alert code if data is a TLS alert record
    pub fn extract_alert(data: &[u8]) -> Option<(u8, u8)> {
        if data.len() < 7 {
            return None;
        }
        if data[0] != 21 {
            return None;
        }
        // content_type(1) + version(2) + length(2) + level(1) + description(1)
        Some((data[5], data[6]))
    }
}
