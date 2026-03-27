//! NNTP STARTTLS negotiation (RFC 4642)
//!
//! Dialog from testssl.sh:
//!   ← wait for greeting (200/201)
//!   → STARTTLS
//!   ← 382 Continue with TLS negotiation

use anyhow::{bail, Result};

use crate::tls::socket::TlsSocket;

pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    // Read server greeting (200 or 201)
    let greeting = socket.read_line().await?;
    if !greeting.starts_with("200 ") && !greeting.starts_with("201 ") {
        bail!("NNTP: unexpected greeting: {}", greeting.trim());
    }

    // Send STARTTLS
    socket.write_line("STARTTLS").await?;

    // Expect 382 Continue with TLS negotiation
    let response = socket.read_line().await?;
    if !response.starts_with("382 ") {
        bail!("NNTP: unexpected response to STARTTLS: {}", response.trim());
    }

    Ok(())
}
