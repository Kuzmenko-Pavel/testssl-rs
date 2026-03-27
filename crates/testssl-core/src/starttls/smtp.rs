//! SMTP/LMTP STARTTLS negotiation
//!
//! Equivalent to starttls_smtp_dialog() in testssl.sh.
//! RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security

use anyhow::{bail, Result};
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// Negotiate STARTTLS for SMTP.
///
/// Dialog:
/// 1. S: "220 ... ESMTP"
/// 2. C: "EHLO testssl.sh"
/// 3. S: "250-..." (multi-line capabilities with STARTTLS)
/// 4. C: "STARTTLS"
/// 5. S: "220 Go ahead" — socket is now ready for TLS
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    negotiate_inner(socket, "testssl.sh", false).await
}

/// LMTP variant (LHLO instead of EHLO, port 24)
pub async fn negotiate_lmtp(socket: &mut TlsSocket) -> Result<()> {
    negotiate_inner(socket, "testssl.sh", true).await
}

async fn negotiate_inner(socket: &mut TlsSocket, hostname: &str, lmtp: bool) -> Result<()> {
    // Step 1: read server greeting — may be multi-line (220- ... 220 )
    let greeting = read_smtp_response(socket).await?;
    debug!("SMTP greeting: {:?}", greeting);

    for line in &greeting {
        if line.starts_with("421") {
            bail!("SMTP: server is busy (421): {}", line);
        }
    }
    if !greeting.iter().any(|l| l.starts_with("220")) {
        bail!("SMTP: unexpected greeting: {:?}", greeting);
    }

    // Step 2: send EHLO / LHLO
    let hello = if lmtp {
        format!("LHLO {}", hostname)
    } else {
        format!("EHLO {}", hostname)
    };
    socket.write_line(&hello).await?;
    debug!("SMTP -> {}", hello);

    // Step 3: read capabilities (250- ... 250 )
    let caps = read_smtp_response(socket).await?;
    debug!("SMTP capabilities: {:?}", caps);

    if !caps.iter().any(|l| {
        let u = l.to_uppercase();
        u.contains("STARTTLS")
    }) {
        bail!("SMTP: STARTTLS not advertised in capabilities");
    }

    // Step 4: send STARTTLS
    socket.write_line("STARTTLS").await?;
    debug!("SMTP -> STARTTLS");

    // Step 5: read ack (220 ...)
    let ack = read_smtp_response(socket).await?;
    debug!("SMTP STARTTLS ack: {:?}", ack);

    if !ack.iter().any(|l| l.starts_with("220")) {
        bail!("SMTP: STARTTLS rejected: {:?}", ack);
    }

    debug!("SMTP STARTTLS complete");
    Ok(())
}

/// Read a complete SMTP response (handles multi-line: "250-foo\r\n250 bar\r\n")
async fn read_smtp_response(socket: &mut TlsSocket) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for _ in 0..100 {
        let line = socket.read_line().await?;
        if line.is_empty() {
            break;
        }
        debug!("S: {}", line);
        lines.push(line.clone());
        // If the 4th character is a space (not '-'), this is the last line
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            break;
        }
        // Also stop if we have fewer than 4 chars (malformed) or no continuation dash
        if line.len() < 4 {
            break;
        }
    }
    Ok(lines)
}
