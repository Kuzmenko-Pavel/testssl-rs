//! Client simulation profiles
//! Generated from etc/client-simulation.txt (from Qualys SSL Labs)

/// A client simulation profile
#[derive(Debug, Clone)]
pub struct ClientProfile {
    pub name: &'static str,
    pub short: &'static str,
    /// Pre-built ClientHello bytes (hex-encoded)
    pub handshake_bytes: &'static str,
    pub lowest_protocol: u16,
    pub highest_protocol: u16,
    pub requires_sha2: bool,
    pub current: bool,
    pub services: &'static str,
}

impl ClientProfile {
    /// Decode handshake bytes from hex string
    pub fn decode_handshake(&self) -> Vec<u8> {
        let hex = self.handshake_bytes;
        let mut bytes = Vec::new();
        let mut i = 0;
        let chars: Vec<char> = hex.chars().collect();
        while i + 1 < chars.len() {
            if let (Some(h), Some(l)) = (chars[i].to_digit(16), chars[i + 1].to_digit(16)) {
                bytes.push(((h << 4) | l) as u8);
            }
            i += 2;
        }
        bytes
    }
}

include!(concat!(env!("OUT_DIR"), "/client_profiles_generated.rs"));
