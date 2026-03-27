//! SSLv2 handshake implementation
//!
//! Implements the SSLv2 CLIENT-HELLO message and SERVER-HELLO parser.
//! Used for the DROWN vulnerability check (CVE-2016-0800) and general
//! SSLv2 protocol support detection.
//!
//! Reference: SSL 2.0 specification (draft-hickman-netscape-ssl-00)

use anyhow::Result;
use tracing::debug;

/// SSLv2 cipher specs (3 bytes each: kind[1] + code[2])
/// Each cipher spec is 3 bytes in SSLv2, unlike 2 bytes in TLS
pub const SSLV2_CIPHERS: &[[u8; 3]] = &[
    [0x07, 0x00, 0xc0], // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
    [0x05, 0x00, 0x80], // SSL_CK_IDEA_128_CBC_WITH_MD5
    [0x03, 0x00, 0x80], // SSL_CK_RC2_128_CBC_WITH_MD5
    [0x01, 0x00, 0x80], // SSL_CK_RC4_128_WITH_MD5
    [0x08, 0x00, 0x80], // SSL_CK_RC4_64_WITH_MD5
    [0x06, 0x00, 0x40], // SSL_CK_DES_64_CBC_WITH_MD5
    [0x04, 0x00, 0x80], // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
    [0x02, 0x00, 0x80], // SSL_CK_RC4_128_EXPORT40_WITH_MD5
];

/// SSLv2 message types
pub const MSG_CLIENT_HELLO: u8 = 0x01;
pub const MSG_SERVER_HELLO: u8 = 0x04;
pub const MSG_ERROR: u8 = 0x00;

/// Build an SSLv2 ClientHello message.
///
/// SSLv2 CLIENT-HELLO wire format:
/// ```text
/// Record Header (2 bytes, short form):
///   bit 15: 1 (indicates 2-byte header)
///   bits 14-0: length of remaining message data
///
/// Message Body:
///   message_type:     1 byte  (0x01 = CLIENT-HELLO)
///   client_version:   2 bytes (0x00, 0x02 = SSLv2)
///   cipher_spec_length: 2 bytes (big-endian, must be multiple of 3)
///   session_id_length:  2 bytes (0 for new session)
///   challenge_length:   2 bytes (16 bytes recommended)
///   cipher_specs:     N*3 bytes (3 bytes per cipher spec)
///   session_id:       S bytes (0 bytes if new session)
///   challenge:        C bytes (random challenge data, 16 bytes)
/// ```
pub fn build_sslv2_client_hello(ciphers: Option<&[[u8; 3]]>) -> Vec<u8> {
    let ciphers = ciphers.unwrap_or(SSLV2_CIPHERS);

    // Challenge data (16 bytes) - pseudo-random for testing
    let challenge: [u8; 16] = [
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c,
    ];

    let cipher_specs_len = (ciphers.len() * 3) as u16;
    let session_id_len: u16 = 0;
    let challenge_len: u16 = challenge.len() as u16;

    // Build the message body
    let mut body: Vec<u8> = vec![
        MSG_CLIENT_HELLO, // message type
        0x00,             // version major (SSLv2 = 0x0002)
        0x02,             // version minor
        (cipher_specs_len >> 8) as u8,
        (cipher_specs_len & 0xff) as u8,
        (session_id_len >> 8) as u8,
        (session_id_len & 0xff) as u8,
        (challenge_len >> 8) as u8,
        (challenge_len & 0xff) as u8,
    ];

    for cipher in ciphers {
        body.extend_from_slice(cipher);
    }

    // session_id (empty)
    // challenge
    body.extend_from_slice(&challenge);

    // SSLv2 record header: 2-byte short form
    // Bit 15 set = short (2-byte) header
    // Bits 14-0 = length of body
    let body_len = body.len() as u16;
    let header_byte0 = 0x80 | ((body_len >> 8) as u8 & 0x7f);
    let header_byte1 = (body_len & 0xff) as u8;

    let mut record = Vec::with_capacity(2 + body.len());
    record.push(header_byte0);
    record.push(header_byte1);
    record.extend_from_slice(&body);

    record
}

/// Build an SSLv2 ClientHello with custom challenge data for DROWN testing
pub fn build_sslv2_client_hello_with_challenge(
    ciphers: Option<&[[u8; 3]]>,
    challenge: &[u8; 16],
) -> Vec<u8> {
    let ciphers = ciphers.unwrap_or(SSLV2_CIPHERS);

    let cipher_specs_len = (ciphers.len() * 3) as u16;
    let session_id_len: u16 = 0;
    let challenge_len: u16 = 16;

    let mut body: Vec<u8> = vec![
        MSG_CLIENT_HELLO,
        0x00,
        0x02,
        (cipher_specs_len >> 8) as u8,
        (cipher_specs_len & 0xff) as u8,
        (session_id_len >> 8) as u8,
        (session_id_len & 0xff) as u8,
        (challenge_len >> 8) as u8,
        (challenge_len & 0xff) as u8,
    ];

    for cipher in ciphers {
        body.extend_from_slice(cipher);
    }

    body.extend_from_slice(challenge);

    let body_len = body.len() as u16;
    let mut record = Vec::with_capacity(2 + body.len());
    record.push(0x80 | ((body_len >> 8) as u8 & 0x7f));
    record.push((body_len & 0xff) as u8);
    record.extend_from_slice(&body);
    record
}

/// Result of an SSLv2 handshake attempt
#[derive(Debug, Default)]
pub struct Sslv2Result {
    /// Whether SSLv2 is supported by the server
    pub supported: bool,
    /// Cipher specs offered by server (3 bytes each)
    pub ciphers: Vec<[u8; 3]>,
    /// Server certificate (DER format)
    pub certificate: Option<Vec<u8>>,
    /// Connection ID from server
    pub connection_id: Vec<u8>,
    /// Server version (major, minor)
    pub server_version: Option<(u8, u8)>,
    /// Whether the session ID was resumed (session_id_hit)
    pub session_id_hit: bool,
    /// Certificate type
    pub cert_type: u8,
}

/// Parse an SSLv2 SERVER-HELLO response.
///
/// SSLv2 SERVER-HELLO wire format:
/// ```text
/// Record Header (2 or 3 bytes):
///   Short (2-byte): bit 15 = 1, bits 14-0 = length
///   Long (3-byte):  bit 15 = 0, bit 14 = pad_present, bits 13-0 = length
///
/// Message Body:
///   message_type:       1 byte (0x04 = SERVER-HELLO)
///   session_id_hit:     1 byte (0 = no, 1 = yes)
///   certificate_type:   1 byte (1 = X.509)
///   server_version:     2 bytes
///   certificate_length: 2 bytes
///   cipher_specs_length: 2 bytes (must be multiple of 3)
///   connection_id_length: 2 bytes
///   certificate:        cert_len bytes (DER-encoded X.509)
///   cipher_specs:       cipher_len bytes (3 bytes each)
///   connection_id:      conn_id_len bytes
/// ```
pub fn parse_sslv2_server_hello(data: &[u8]) -> Result<Sslv2Result> {
    let mut result = Sslv2Result::default();

    if data.len() < 2 {
        return Ok(result);
    }

    // Parse SSLv2 record header
    let (record_len, header_len) = if (data[0] & 0x80) != 0 {
        // Short header (2 bytes): bit 15 = 1
        let len = (((data[0] & 0x7f) as usize) << 8) | data[1] as usize;
        (len, 2usize)
    } else {
        // Long header (3 bytes): bit 15 = 0
        // bit 14 = is_escape (padding present)
        if data.len() < 3 {
            return Ok(result);
        }
        let len = (((data[0] & 0x3f) as usize) << 8) | data[1] as usize;
        (len, 3usize)
    };

    if data.len() < header_len + record_len {
        debug!(
            "SSLv2 response truncated: have {} bytes, need {}",
            data.len(),
            header_len + record_len
        );
        return Ok(result);
    }

    let body = &data[header_len..header_len + record_len];

    if body.is_empty() {
        return Ok(result);
    }

    let msg_type = body[0];
    debug!("SSLv2 message type: 0x{:02x}", msg_type);

    match msg_type {
        MSG_SERVER_HELLO => {
            // SERVER-HELLO
            if body.len() < 11 {
                debug!("SSLv2 SERVER-HELLO too short: {} bytes", body.len());
                return Ok(result);
            }

            let session_id_hit = body[1] != 0;
            let cert_type = body[2];
            let server_version = (body[3], body[4]);
            let cert_len = ((body[5] as usize) << 8) | body[6] as usize;
            let cipher_specs_len = ((body[7] as usize) << 8) | body[8] as usize;
            let connection_id_len = ((body[9] as usize) << 8) | body[10] as usize;

            debug!(
                "SSLv2 SERVER-HELLO: version={:02x}{:02x}, cert_len={}, ciphers_len={}, conn_id_len={}, session_hit={}",
                server_version.0, server_version.1,
                cert_len, cipher_specs_len, connection_id_len,
                session_id_hit
            );

            result.server_version = Some(server_version);
            result.session_id_hit = session_id_hit;
            result.cert_type = cert_type;
            result.supported = true;

            let mut pos = 11usize;

            // Certificate
            if cert_len > 0 && body.len() >= pos + cert_len {
                result.certificate = Some(body[pos..pos + cert_len].to_vec());
                debug!("SSLv2 server certificate: {} bytes", cert_len);
            } else if cert_len > 0 {
                debug!("SSLv2 certificate truncated");
            }
            pos += cert_len;

            // Cipher specs (3 bytes each)
            if !cipher_specs_len.is_multiple_of(3) {
                debug!(
                    "SSLv2 cipher_specs_length {} not multiple of 3",
                    cipher_specs_len
                );
            } else {
                let num_ciphers = cipher_specs_len / 3;
                for _i in 0..num_ciphers {
                    if body.len() >= pos + 3 {
                        let cipher = [body[pos], body[pos + 1], body[pos + 2]];
                        debug!(
                            "SSLv2 cipher: {:02x} {:02x} {:02x}",
                            cipher[0], cipher[1], cipher[2]
                        );
                        result.ciphers.push(cipher);
                    }
                    pos += 3;
                }
            }

            // Connection ID
            if connection_id_len > 0 && body.len() >= pos + connection_id_len {
                result.connection_id = body[pos..pos + connection_id_len].to_vec();
                debug!("SSLv2 connection_id: {} bytes", connection_id_len);
            }
        }
        MSG_ERROR => {
            // MSG-ERROR (0x00)
            debug!("SSLv2 error received");
            if body.len() >= 3 {
                let error_code = ((body[1] as u16) << 8) | body[2] as u16;
                debug!("SSLv2 error code: 0x{:04x}", error_code);
            }
        }
        _ => {
            debug!("Unknown SSLv2 message type: 0x{:02x}", msg_type);
        }
    }

    Ok(result)
}

/// Convert an SSLv2 3-byte cipher spec to a TLS 2-byte cipher suite code
/// (where applicable - not all SSLv2 ciphers map to TLS ciphers)
pub fn sslv2_cipher_to_name(cipher: &[u8; 3]) -> &'static str {
    match (cipher[0], cipher[1], cipher[2]) {
        (0x07, 0x00, 0xc0) => "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        (0x05, 0x00, 0x80) => "SSL_CK_IDEA_128_CBC_WITH_MD5",
        (0x03, 0x00, 0x80) => "SSL_CK_RC2_128_CBC_WITH_MD5",
        (0x01, 0x00, 0x80) => "SSL_CK_RC4_128_WITH_MD5",
        (0x08, 0x00, 0x80) => "SSL_CK_RC4_64_WITH_MD5",
        (0x06, 0x00, 0x40) => "SSL_CK_DES_64_CBC_WITH_MD5",
        (0x04, 0x00, 0x80) => "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
        (0x02, 0x00, 0x80) => "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
        _ => "UNKNOWN",
    }
}

/// Check if a server supports SSLv2 by sending a CLIENT-HELLO and parsing the response.
///
/// Returns an Sslv2Result with `supported = true` if the server responds
/// with a valid SERVER-HELLO.
pub async fn check_sslv2(socket: &mut crate::tls::socket::TlsSocket) -> Result<Sslv2Result> {
    let hello = build_sslv2_client_hello(None);

    debug!("Sending SSLv2 CLIENT-HELLO ({} bytes)", hello.len());
    socket.send(&hello).await?;

    // Give the server time to respond
    match socket.recv(16384).await {
        Ok(data) if !data.is_empty() => {
            debug!(
                "Received {} bytes in response to SSLv2 CLIENT-HELLO",
                data.len()
            );
            parse_sslv2_server_hello(&data)
        }
        Ok(_) => {
            debug!("Empty response to SSLv2 CLIENT-HELLO (server likely rejected)");
            Ok(Sslv2Result::default())
        }
        Err(e) => {
            debug!("Error receiving SSLv2 response: {}", e);
            Ok(Sslv2Result::default())
        }
    }
}
