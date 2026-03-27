//! IRC STARTTLS negotiation (IRCv3 TLS extension)
//!
//! References:
//!   https://ircv3.net/specs/extensions/tls-3.1.html
//!   https://ircv3.net/specs/core/capability-negotiation.html
//!
//! Note: testssl.sh marks IRC STARTTLS as "FIXME: not yet supported".
//! We implement the IRCv3 capability negotiation approach.
//!
//! Dialog:
//!   → CAP LS 302
//!   ← :server CAP * LS :... tls ...
//!   → CAP REQ :tls
//!   ← :server CAP * ACK :tls
//!   → STARTTLS
//!   ← :server 670 * :STARTTLS successful, go ahead with TLS handshake

use anyhow::{bail, Result};

use crate::tls::socket::TlsSocket;

pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    // Request capability list
    socket.write_line("CAP LS 302").await?;

    // Read until we get the CAP LS response
    let mut has_tls = false;
    let mut attempts = 0;
    loop {
        let line = socket.read_line().await?;
        let upper = line.to_uppercase();
        // CAP * LS response contains available capabilities
        if upper.contains("CAP") && upper.contains(" LS ") {
            if upper.contains(" TLS") || line.contains(":tls") || line.contains(" tls") {
                has_tls = true;
            }
            // Multi-line CAP LS ends with line not having "*" before capability list
            if !line.contains('*') || line.contains(":tls") || line.ends_with("LS :") {
                break;
            }
        }
        // Skip server-sent PING, NOTICE, etc.
        attempts += 1;
        if attempts > 20 {
            break;
        }
    }

    if !has_tls {
        bail!("IRC: server does not advertise TLS capability");
    }

    // Request TLS capability
    socket.write_line("CAP REQ :tls").await?;

    // Expect ACK
    let mut acked = false;
    for _ in 0..10 {
        let line = socket.read_line().await?;
        let upper = line.to_uppercase();
        if upper.contains("CAP") && upper.contains("ACK") {
            acked = true;
            break;
        }
        if upper.contains("CAP") && upper.contains("NAK") {
            bail!("IRC: server rejected TLS capability request");
        }
    }
    if !acked {
        bail!("IRC: did not receive CAP ACK for TLS");
    }

    // Send STARTTLS
    socket.write_line("STARTTLS").await?;

    // Expect 670 (STARTTLS successful)
    for _ in 0..10 {
        let line = socket.read_line().await?;
        if line.contains("670") {
            return Ok(());
        }
        if line.contains("691") {
            bail!("IRC: server rejected STARTTLS (691 error)");
        }
    }

    bail!("IRC: did not receive STARTTLS confirmation (670)")
}
