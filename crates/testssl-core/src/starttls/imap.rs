//! IMAP STARTTLS negotiation
//!
//! Equivalent to starttls_imap_dialog() in testssl.sh.
//! RFC 2595: Using TLS with IMAP, POP3 and ACAP

use anyhow::{bail, Result};
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// Negotiate STARTTLS for IMAP.
///
/// Dialog:
/// 1. S: "* OK ... IMAP4rev1 ..."  (server greeting)
/// 2. C: "a001 CAPABILITY"
/// 3. S: "* CAPABILITY ... STARTTLS ..." then "a001 OK ..."
/// 4. C: "a002 STARTTLS"
/// 5. S: "a002 OK ..." — socket is now ready for TLS
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    // Step 1: Read server greeting (* OK ...)
    let greeting = read_until_tagged(socket, "* ", None).await?;
    debug!("IMAP greeting: {:?}", greeting);

    if !greeting
        .iter()
        .any(|l| l.starts_with("* OK") || l.starts_with("* PREAUTH"))
    {
        bail!("IMAP: unexpected greeting: {:?}", greeting);
    }

    // Step 2: Send CAPABILITY
    socket.write_line("a001 CAPABILITY").await?;
    debug!("IMAP -> a001 CAPABILITY");

    // Step 3: Read capability response (* CAPABILITY ... a001 OK)
    let caps = read_until_tagged(socket, "a001", None).await?;
    debug!("IMAP capabilities: {:?}", caps);

    // Check if STARTTLS is in capabilities
    let has_starttls = caps.iter().any(|l| l.to_uppercase().contains("STARTTLS"));

    if !has_starttls {
        bail!("IMAP: STARTTLS not supported by server");
    }

    // Step 4: Send STARTTLS
    socket.write_line("a002 STARTTLS").await?;
    debug!("IMAP -> a002 STARTTLS");

    // Step 5: Read acknowledgement (a002 OK ...)
    let ack = read_until_tagged(socket, "a002", None).await?;
    debug!("IMAP STARTTLS ack: {:?}", ack);

    if !ack.iter().any(|l| l.starts_with("a002 OK")) {
        bail!("IMAP: STARTTLS failed: {:?}", ack);
    }

    debug!("IMAP STARTTLS complete");
    Ok(())
}

/// Read lines until a line starts with the given tag (e.g. "a001 OK" or "a001 BAD")
async fn read_until_tagged(
    socket: &mut TlsSocket,
    end_tag: &str,
    error_tag: Option<&str>,
) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for _ in 0..100 {
        let line = socket.read_line().await?;
        if line.is_empty() {
            break;
        }
        debug!("S: {}", line);

        if let Some(etag) = error_tag {
            if line.starts_with(etag) {
                lines.push(line);
                break;
            }
        }

        lines.push(line.clone());
        if line.starts_with(end_tag) {
            break;
        }
    }
    Ok(lines)
}
