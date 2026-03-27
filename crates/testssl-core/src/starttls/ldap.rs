//! LDAP StartTLS extended operation
//!
//! Equivalent to starttls_ldap_dialog() in testssl.sh.
//! RFC 2830: LDAPv3: Extension for Transport Layer Security
//! OID: 1.3.6.1.4.1.1466.20037

use anyhow::{bail, Result};
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// LDAP StartTLS ExtendedRequest (BER-encoded).
///
/// Sequence:
///   messageID: 1
///   protocolOp: extendedReq (tag 0x77)
///     requestName: "1.3.6.1.4.1.1466.20037" (OID for StartTLS)
///
/// Full hex: 30 1d 02 01 01 77 18 80 16
///           31 2e 33 2e 36 2e 31 2e 34 2e 31 2e 31 34 36 36 2e 32 30 30 33 37
const LDAP_STARTTLS_REQUEST: &[u8] = &[
    0x30, 0x1d, // SEQUENCE, length 29
    0x02, 0x01, 0x01, // INTEGER messageID = 1
    0x77, 0x18, // [APPLICATION 23] extendedReq, length 24
    0x80, 0x16, // [0] requestName, length 22
    // "1.3.6.1.4.1.1466.20037" as ASCII
    b'1', b'.', b'3', b'.', b'6', b'.', b'1', b'.', b'4', b'.', b'1', b'.', b'1', b'4', b'6', b'6',
    b'.', b'2', b'0', b'0', b'3', b'7',
];

/// Negotiate StartTLS for LDAP.
///
/// Sends an LDAPv3 ExtendedRequest with the StartTLS OID and waits for
/// an ExtendedResponse with resultCode success (0).
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    debug!("LDAP -> StartTLS ExtendedRequest");
    socket.send(LDAP_STARTTLS_REQUEST).await?;

    // Read response — may be a few hundred bytes
    let response = socket.recv(4096).await?;
    debug!(
        "LDAP StartTLS response: {} bytes {:02x?}",
        response.len(),
        &response[..response.len().min(32)]
    );

    if response.len() < 8 {
        bail!(
            "LDAP: StartTLS response too short ({} bytes)",
            response.len()
        );
    }

    // Parse the LDAP ExtendedResponse (BER):
    // 30 LL               -- SEQUENCE
    //   02 01 01          -- messageID = 1
    //   78 LL             -- [APPLICATION 24] extendedResp
    //     0a 01 RR        -- resultCode (RR=0 is success)
    //     04 00           -- matchedDN (empty)
    //     04 00           -- diagnosticMessage (empty)
    //     ...
    //
    // We look for the extendedResp tag (0x78) and then find the resultCode byte.

    // Find 0x78 (extendedResp application tag)
    let result_code = parse_ldap_result(&response);
    match result_code {
        Some(0) => {
            debug!("LDAP StartTLS: success (resultCode=0)");
            Ok(())
        }
        Some(code) => {
            bail!("LDAP StartTLS failed with resultCode={}", code);
        }
        None => {
            // Fallback heuristic: if response contains 0x78 and is long enough, assume OK
            if response.contains(&0x78) && response.len() > 10 {
                debug!("LDAP StartTLS: heuristic success");
                Ok(())
            } else {
                bail!("LDAP StartTLS: could not parse response");
            }
        }
    }
}

/// Parse LDAP ExtendedResponse to extract resultCode.
fn parse_ldap_result(data: &[u8]) -> Option<u8> {
    // Find extendedResp tag 0x78
    let pos = data.iter().position(|&b| b == 0x78)?;

    // After 0x78, we have length byte(s), then contents.
    // Content starts with: 0a 01 RR (resultCode)
    // Skip the length byte(s) — BER length is complex but for short responses it's one byte
    let content_start = if pos + 1 < data.len() {
        let len_byte = data[pos + 1];
        if len_byte & 0x80 == 0 {
            pos + 2 // short form: 1 length byte
        } else {
            let num_len_bytes = (len_byte & 0x7f) as usize;
            pos + 2 + num_len_bytes
        }
    } else {
        return None;
    };

    // Now look for 0x0a (ENUMERATED tag for resultCode), 0x01 (length=1), RR (value)
    for i in content_start..data.len().saturating_sub(2) {
        if data[i] == 0x0a && data[i + 1] == 0x01 {
            return Some(data[i + 2]);
        }
    }

    None
}
