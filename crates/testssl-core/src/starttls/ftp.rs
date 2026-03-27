//! FTP STARTTLS negotiation (AUTH TLS)
//!
//! Equivalent to starttls_ftp_dialog() in testssl.sh.
//! RFC 4217: Securing FTP with TLS

use anyhow::{bail, Result};
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// Negotiate AUTH TLS for FTP.
///
/// Dialog:
/// 1. S: "220 ... FTP server ready"
/// 2. C: "FEAT"
/// 3. S: "211-Features:\r\n ... AUTH TLS ...\r\n211 end"
/// 4. C: "AUTH TLS"
/// 5. S: "234 Honored" — socket is ready for TLS
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    // Step 1: Read greeting (may be multi-line: 220- ... 220 )
    let greeting = read_ftp_response(socket).await?;
    debug!("FTP greeting: {:?}", greeting);

    if !greeting.iter().any(|l| l.starts_with("220")) {
        bail!("FTP: unexpected greeting: {:?}", greeting);
    }

    // Step 2: Send FEAT to check AUTH TLS support
    socket.write_line("FEAT").await?;
    debug!("FTP -> FEAT");

    // Step 3: Read FEAT response (211- ... 211 )
    let feat_resp = read_ftp_response(socket).await?;
    debug!("FTP FEAT: {:?}", feat_resp);

    let has_auth_tls = feat_resp.iter().any(|l| {
        let u = l.to_uppercase();
        u.contains("AUTH TLS") || u.contains("AUTH SSL")
    });

    if !has_auth_tls {
        bail!("FTP: AUTH TLS not advertised in FEAT response");
    }

    // Step 4: Send AUTH TLS
    socket.write_line("AUTH TLS").await?;
    debug!("FTP -> AUTH TLS");

    // Step 5: Read ack (234 ...)
    let ack = read_ftp_response(socket).await?;
    debug!("FTP AUTH TLS ack: {:?}", ack);

    if ack.iter().any(|l| l.starts_with("234")) {
        debug!("FTP AUTH TLS complete");
        return Ok(());
    }

    // Fallback: try AUTH SSL
    socket.write_line("AUTH SSL").await?;
    debug!("FTP -> AUTH SSL");
    let ack2 = read_ftp_response(socket).await?;
    debug!("FTP AUTH SSL ack: {:?}", ack2);

    if !ack2.iter().any(|l| l.starts_with("234")) {
        bail!("FTP: AUTH TLS/SSL failed: {:?}", ack2);
    }

    debug!("FTP AUTH SSL complete");
    Ok(())
}

/// Read a complete FTP response (handles multi-line: "211-...\r\n211 ...\r\n")
async fn read_ftp_response(socket: &mut TlsSocket) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for _ in 0..200 {
        let line = socket.read_line().await?;
        if line.is_empty() {
            break;
        }
        debug!("S: {}", line);
        lines.push(line.clone());
        // Multi-line FTP responses have 'XYZ-' prefix; final line has 'XYZ ' (space)
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            break;
        }
        if line.len() < 4 {
            break;
        }
    }
    Ok(lines)
}
