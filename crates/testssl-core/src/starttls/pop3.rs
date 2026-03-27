//! POP3 STARTTLS negotiation (STLS command)
//!
//! Equivalent to starttls_pop3_dialog() in testssl.sh.
//! RFC 2595: Using TLS with IMAP, POP3 and ACAP

use anyhow::{bail, Result};
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// Negotiate STARTTLS for POP3.
///
/// Dialog:
/// 1. S: "+OK ... POP3 server ready"
/// 2. C: "STLS"
/// 3. S: "+OK Begin TLS negotiation" — socket is ready for TLS
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    // Step 1: Read server greeting (+OK ...)
    let greeting = socket.read_line().await?;
    debug!("POP3 greeting: {}", greeting);

    if !greeting.starts_with("+OK") {
        bail!("POP3: unexpected greeting: {}", greeting);
    }

    // Step 2: Send STLS
    socket.write_line("STLS").await?;
    debug!("POP3 -> STLS");

    // Step 3: Read ack (+OK ...)
    let response = socket.read_line().await?;
    debug!("POP3 STLS response: {}", response);

    if !response.starts_with("+OK") {
        bail!("POP3: STLS failed: {}", response);
    }

    debug!("POP3 STARTTLS complete");
    Ok(())
}
