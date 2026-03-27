//! TLS protocol implementation modules

pub mod client_hello;
pub mod extensions;
pub mod server_hello;
pub mod socket;
pub mod sslv2;

pub use client_hello::{ClientHelloBuilder, TlsVersion};
pub use extensions::ParsedExtension;
pub use server_hello::{ServerHelloParser, ServerHelloResult};
pub use socket::TlsSocket;

/// TLS record content types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

impl TryFrom<u8> for ContentType {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> anyhow::Result<Self> {
        match v {
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            24 => Ok(Self::Heartbeat),
            _ => Err(anyhow::anyhow!("Unknown content type: {}", v)),
        }
    }
}

/// TLS handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateUrl = 21,
    CertificateStatus = 22,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl TryFrom<u8> for HandshakeType {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> anyhow::Result<Self> {
        match v {
            0 => Ok(Self::HelloRequest),
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::HelloVerifyRequest),
            4 => Ok(Self::NewSessionTicket),
            5 => Ok(Self::EndOfEarlyData),
            8 => Ok(Self::EncryptedExtensions),
            11 => Ok(Self::Certificate),
            12 => Ok(Self::ServerKeyExchange),
            13 => Ok(Self::CertificateRequest),
            14 => Ok(Self::ServerHelloDone),
            15 => Ok(Self::CertificateVerify),
            16 => Ok(Self::ClientKeyExchange),
            20 => Ok(Self::Finished),
            21 => Ok(Self::CertificateUrl),
            22 => Ok(Self::CertificateStatus),
            24 => Ok(Self::KeyUpdate),
            254 => Ok(Self::MessageHash),
            _ => Err(anyhow::anyhow!("Unknown handshake type: {}", v)),
        }
    }
}

/// TLS alert levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// TLS alert descriptions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificate = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestriction = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiation = 100,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

/// A raw TLS record
#[derive(Debug, Clone)]
pub struct TlsRecord {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.payload.len());
        buf.push(self.content_type);
        buf.push(self.version_major);
        buf.push(self.version_minor);
        let len = self.payload.len() as u16;
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> anyhow::Result<(Self, usize)> {
        if data.len() < 5 {
            return Err(anyhow::anyhow!("TLS record too short"));
        }
        let content_type = data[0];
        let version_major = data[1];
        let version_minor = data[2];
        let len = ((data[3] as usize) << 8) | data[4] as usize;
        if data.len() < 5 + len {
            return Err(anyhow::anyhow!("TLS record payload incomplete"));
        }
        let payload = data[5..5 + len].to_vec();
        Ok((
            Self {
                content_type,
                version_major,
                version_minor,
                payload,
            },
            5 + len,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ContentType ──────────────────────────────────────────────────────────

    #[test]
    fn test_content_type_try_from_known_values() {
        assert_eq!(
            ContentType::try_from(20).unwrap(),
            ContentType::ChangeCipherSpec
        );
        assert_eq!(ContentType::try_from(21).unwrap(), ContentType::Alert);
        assert_eq!(ContentType::try_from(22).unwrap(), ContentType::Handshake);
        assert_eq!(
            ContentType::try_from(23).unwrap(),
            ContentType::ApplicationData
        );
        assert_eq!(ContentType::try_from(24).unwrap(), ContentType::Heartbeat);
    }

    #[test]
    fn test_content_type_try_from_unknown_returns_error() {
        assert!(ContentType::try_from(0).is_err());
        assert!(ContentType::try_from(255).is_err());
    }

    // ── HandshakeType ────────────────────────────────────────────────────────

    #[test]
    fn test_handshake_type_try_from_known_values() {
        assert_eq!(
            HandshakeType::try_from(0).unwrap(),
            HandshakeType::HelloRequest
        );
        assert_eq!(
            HandshakeType::try_from(1).unwrap(),
            HandshakeType::ClientHello
        );
        assert_eq!(
            HandshakeType::try_from(2).unwrap(),
            HandshakeType::ServerHello
        );
        assert_eq!(
            HandshakeType::try_from(3).unwrap(),
            HandshakeType::HelloVerifyRequest
        );
        assert_eq!(
            HandshakeType::try_from(4).unwrap(),
            HandshakeType::NewSessionTicket
        );
        assert_eq!(
            HandshakeType::try_from(5).unwrap(),
            HandshakeType::EndOfEarlyData
        );
        assert_eq!(
            HandshakeType::try_from(8).unwrap(),
            HandshakeType::EncryptedExtensions
        );
        assert_eq!(
            HandshakeType::try_from(11).unwrap(),
            HandshakeType::Certificate
        );
        assert_eq!(
            HandshakeType::try_from(12).unwrap(),
            HandshakeType::ServerKeyExchange
        );
        assert_eq!(
            HandshakeType::try_from(13).unwrap(),
            HandshakeType::CertificateRequest
        );
        assert_eq!(
            HandshakeType::try_from(14).unwrap(),
            HandshakeType::ServerHelloDone
        );
        assert_eq!(
            HandshakeType::try_from(15).unwrap(),
            HandshakeType::CertificateVerify
        );
        assert_eq!(
            HandshakeType::try_from(16).unwrap(),
            HandshakeType::ClientKeyExchange
        );
        assert_eq!(
            HandshakeType::try_from(20).unwrap(),
            HandshakeType::Finished
        );
        assert_eq!(
            HandshakeType::try_from(21).unwrap(),
            HandshakeType::CertificateUrl
        );
        assert_eq!(
            HandshakeType::try_from(22).unwrap(),
            HandshakeType::CertificateStatus
        );
        assert_eq!(
            HandshakeType::try_from(24).unwrap(),
            HandshakeType::KeyUpdate
        );
        assert_eq!(
            HandshakeType::try_from(254).unwrap(),
            HandshakeType::MessageHash
        );
    }

    #[test]
    fn test_handshake_type_unknown_returns_error() {
        assert!(HandshakeType::try_from(99).is_err());
        assert!(HandshakeType::try_from(255).is_err());
    }

    // ── TlsRecord ────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_record_to_bytes_handshake() {
        let rec = TlsRecord {
            content_type: 22, // Handshake
            version_major: 3,
            version_minor: 3,
            payload: vec![0x01, 0x02, 0x03],
        };
        let bytes = rec.to_bytes();
        assert_eq!(bytes[0], 22);
        assert_eq!(bytes[1], 3);
        assert_eq!(bytes[2], 3);
        assert_eq!(bytes[3], 0); // length high byte
        assert_eq!(bytes[4], 3); // length low byte
        assert_eq!(&bytes[5..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_tls_record_to_bytes_empty_payload() {
        let rec = TlsRecord {
            content_type: 21,
            version_major: 3,
            version_minor: 1,
            payload: vec![],
        };
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[3], 0);
        assert_eq!(bytes[4], 0);
    }

    #[test]
    fn test_tls_record_from_bytes_valid() {
        let bytes = vec![22u8, 3, 3, 0, 3, 0x01, 0x02, 0x03];
        let (rec, consumed) = TlsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(rec.content_type, 22);
        assert_eq!(rec.version_major, 3);
        assert_eq!(rec.version_minor, 3);
        assert_eq!(rec.payload, vec![0x01, 0x02, 0x03]);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_tls_record_from_bytes_too_short() {
        let bytes = vec![22u8, 3, 3, 0]; // only 4 bytes
        assert!(TlsRecord::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_tls_record_from_bytes_payload_too_short() {
        let bytes = vec![22u8, 3, 3, 0, 10, 0x01, 0x02]; // claims 10 bytes but only 2 present
        assert!(TlsRecord::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_tls_record_roundtrip() {
        let original = TlsRecord {
            content_type: 23,
            version_major: 3,
            version_minor: 4,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = original.to_bytes();
        let (recovered, _) = TlsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.content_type, original.content_type);
        assert_eq!(recovered.payload, original.payload);
    }

    #[test]
    fn test_tls_record_large_payload() {
        let payload = vec![0xAB; 300];
        let rec = TlsRecord {
            content_type: 22,
            version_major: 3,
            version_minor: 3,
            payload: payload.clone(),
        };
        let bytes = rec.to_bytes();
        // Length field: 300 = 0x012C
        assert_eq!(bytes[3], 0x01);
        assert_eq!(bytes[4], 0x2C);
        let (recovered, _) = TlsRecord::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.payload, payload);
    }
}
