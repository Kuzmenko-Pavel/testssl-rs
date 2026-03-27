//! Embedded CA trust stores
//!
//! 5 stores: Mozilla, Microsoft, Apple, Java, Linux
//! The raw PEM bytes are embedded at compile time via build.rs.

include!(concat!(env!("OUT_DIR"), "/ca_stores_generated.rs"));

/// Parse a PEM bundle into a list of DER-encoded certificate bytes.
///
/// Handles multi-certificate PEM files (CA bundles). Returns each certificate
/// as a separate DER-encoded byte vector.
pub fn parse_pem_bundle(pem_data: &[u8]) -> Vec<Vec<u8>> {
    let pem_str = match std::str::from_utf8(pem_data) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64_buf = String::new();

    for line in pem_str.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64_buf.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if in_cert {
                if let Ok(der) = base64_decode(b64_buf.as_bytes()) {
                    certs.push(der);
                }
                in_cert = false;
            }
        } else if in_cert {
            b64_buf.push_str(line);
        }
    }

    certs
}

/// Decode base64-encoded data (standard alphabet, ignoring whitespace).
fn base64_decode(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Standard base64 decode table: value 255 means invalid character
    static TABLE: [u8; 256] = {
        let mut t = [255u8; 256];
        let mut i = 0usize;
        // A-Z = 0..25
        while i < 26 {
            t[b'A' as usize + i] = i as u8;
            i += 1;
        }
        // a-z = 26..51
        i = 0;
        while i < 26 {
            t[b'a' as usize + i] = 26 + i as u8;
            i += 1;
        }
        // 0-9 = 52..61
        i = 0;
        while i < 10 {
            t[b'0' as usize + i] = 52 + i as u8;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t[b'=' as usize] = 0; // padding — treated as zero bits
        t
    };

    // Filter to only valid base64 characters (skip whitespace)
    let clean: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&b| TABLE[b as usize] != 255 || b == b'=')
        .collect();

    if clean.is_empty() {
        return Ok(Vec::new());
    }

    // Pad to multiple of 4
    let pad = (4 - (clean.len() % 4)) % 4;
    let mut padded = clean;
    padded.resize(padded.len() + pad, b'=');

    let mut out = Vec::with_capacity(padded.len() / 4 * 3);
    for chunk in padded.chunks(4) {
        let v0 = TABLE[chunk[0] as usize];
        let v1 = TABLE[chunk[1] as usize];
        let v2 = TABLE[chunk[2] as usize];
        let v3 = TABLE[chunk[3] as usize];

        if v0 == 255 || v1 == 255 || v2 == 255 || v3 == 255 {
            return Err("invalid base64 character");
        }

        out.push((v0 << 2) | (v1 >> 4));
        if chunk[2] != b'=' {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if chunk[3] != b'=' {
            out.push((v2 << 6) | v3);
        }
    }

    Ok(out)
}

/// Names of the available CA stores.
pub const CA_STORE_NAMES: &[&str] = &["mozilla", "microsoft", "apple", "java", "linux"];

/// Get the raw PEM bytes for a named CA store.
///
/// Returns `None` if the name is not recognized.
pub fn ca_store_bytes(name: &str) -> Option<&'static [u8]> {
    match name.to_lowercase().as_str() {
        "mozilla" => Some(CA_MOZILLA),
        "microsoft" => Some(CA_MICROSOFT),
        "apple" => Some(CA_APPLE),
        "java" => Some(CA_JAVA),
        "linux" => Some(CA_LINUX),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mozilla_bundle_loads() {
        assert!(
            !CA_MOZILLA.is_empty(),
            "Mozilla CA bundle should not be empty"
        );
    }

    #[test]
    fn test_parse_pem_bundle_mozilla() {
        let certs = parse_pem_bundle(CA_MOZILLA);
        assert!(
            !certs.is_empty(),
            "Mozilla CA bundle should contain certificates"
        );
    }

    #[test]
    fn test_ca_store_bytes_lookup() {
        assert!(ca_store_bytes("mozilla").is_some());
        assert!(ca_store_bytes("MOZILLA").is_some());
        assert!(ca_store_bytes("unknown").is_none());
    }
}
