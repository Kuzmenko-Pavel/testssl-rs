//! LMTP STARTTLS negotiation (RFC 2033, RFC 3207, RFC 5321)
//!
//! LMTP is nearly identical to SMTP STARTTLS but uses LHLO instead of EHLO.
//!
//! Dialog:
//!   ← 220 greeting
//!   → LHLO <hostname>
//!   ← 250-... (capabilities, must include STARTTLS)
//!   ← 250 ...
//!   → STARTTLS
//!   ← 220 Ready to start TLS

use anyhow::{bail, Result};

use crate::tls::socket::TlsSocket;

pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    // Read server greeting
    let greeting = socket.read_line().await?;
    if !greeting.starts_with("220") {
        bail!("LMTP: unexpected greeting: {}", greeting.trim());
    }

    // Send LHLO (LMTP equivalent of EHLO)
    socket.write_line("LHLO testssl.rs").await?;

    // Read capabilities (multi-line 250)
    let mut has_starttls = false;
    loop {
        let line = socket.read_line().await?;
        let upper = line.to_uppercase();
        if upper.contains("STARTTLS") {
            has_starttls = true;
        }
        // Multi-line 250 uses "250-" prefix; last line uses "250 "
        if line.starts_with("250 ") {
            break;
        }
        if !line.starts_with("250") {
            bail!("LMTP: unexpected capabilities response: {}", line.trim());
        }
    }

    if !has_starttls {
        bail!("LMTP: server does not advertise STARTTLS capability");
    }

    // Initiate STARTTLS
    socket.write_line("STARTTLS").await?;

    // Expect 220 Ready
    let response = socket.read_line().await?;
    if !response.starts_with("220") {
        bail!("LMTP: unexpected response to STARTTLS: {}", response.trim());
    }

    Ok(())
}
