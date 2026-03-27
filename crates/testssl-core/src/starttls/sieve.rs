//! ManageSieve STARTTLS negotiation (RFC 5804)
//!
//! Dialog from testssl.sh:
//!   ← server capabilities (quoted strings, one per line, ends with OK)
//!     must include "STARTTLS" capability
//!   → STARTTLS
//!   ← OK (Begin TLS negotiation now)

use anyhow::{bail, Result};

use crate::tls::socket::TlsSocket;

pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    // Read capability lines until "OK"
    // Capability lines start with quoted strings like "IMPLEMENTATION ..."
    // We must see "STARTTLS" among them
    let mut has_starttls = false;
    loop {
        let line = socket.read_line().await?;
        let trimmed = line.trim();

        if trimmed.starts_with("OK") {
            break;
        }
        if trimmed.eq_ignore_ascii_case("\"STARTTLS\"")
            || trimmed.to_uppercase().contains("STARTTLS")
        {
            has_starttls = true;
        }
        // Also handle capability lines like: "SASL" "PLAIN LOGIN"
    }

    if !has_starttls {
        bail!("Sieve: server does not advertise STARTTLS capability");
    }

    // Send STARTTLS
    socket.write_line("STARTTLS").await?;

    // Expect OK
    let response = socket.read_line().await?;
    if !response.trim_start().starts_with("OK") {
        bail!(
            "Sieve: unexpected response to STARTTLS: {}",
            response.trim()
        );
    }

    Ok(())
}
