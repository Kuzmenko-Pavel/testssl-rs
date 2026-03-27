//! XMPP STARTTLS negotiation
//!
//! Equivalent to starttls_xmpp_dialog() in testssl.sh.
//! RFC 6120: Extensible Messaging and Presence Protocol (XMPP): Core

use anyhow::{bail, Result};
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// Negotiate STARTTLS for XMPP (client-to-server, port 5222).
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    negotiate_inner(socket, false).await
}

/// Negotiate STARTTLS for XMPP server-to-server (port 5269).
pub async fn negotiate_server(socket: &mut TlsSocket, xmpp_host: &str) -> Result<()> {
    negotiate_inner_with_host(socket, xmpp_host, true).await
}

async fn negotiate_inner(socket: &mut TlsSocket, server_to_server: bool) -> Result<()> {
    // Use socket's peer address as the XMPP host
    let host = socket
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "localhost".to_string());
    negotiate_inner_with_host(socket, &host, server_to_server).await
}

async fn negotiate_inner_with_host(
    socket: &mut TlsSocket,
    xmpp_host: &str,
    server_to_server: bool,
) -> Result<()> {
    let namespace = if server_to_server {
        "jabber:server"
    } else {
        "jabber:client"
    };

    // Step 1: Send stream opening
    let stream_open = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' \
         xmlns='{}' to='{}' version='1.0'>",
        namespace, xmpp_host
    );
    socket.send(stream_open.as_bytes()).await?;
    debug!(
        "XMPP -> stream open (namespace={}, host={})",
        namespace, xmpp_host
    );

    // Step 2: Read server response — wait for features containing starttls
    let response = read_xmpp_until(socket, "starttls", 5000).await?;
    debug!(
        "XMPP stream features: {}",
        &response[..response.len().min(500)]
    );

    if !response.to_lowercase().contains("starttls") {
        bail!("XMPP: server does not offer STARTTLS in stream features");
    }

    // Step 3: Send STARTTLS request
    let starttls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
    socket.send(starttls.as_bytes()).await?;
    debug!("XMPP -> STARTTLS request");

    // Step 4: Read <proceed> response
    let proceed = read_xmpp_until(socket, "proceed", 5000).await?;
    debug!(
        "XMPP STARTTLS response: {}",
        &proceed[..proceed.len().min(200)]
    );

    if !proceed.to_lowercase().contains("proceed") {
        bail!("XMPP: STARTTLS failed — no <proceed>: {}", proceed);
    }

    debug!("XMPP STARTTLS complete");
    Ok(())
}

/// Read raw bytes from socket until pattern is found or timeout, return as UTF-8 string.
async fn read_xmpp_until(
    socket: &mut TlsSocket,
    _pattern: &str,
    timeout_ms: u64,
) -> Result<String> {
    let data = socket.recv_multiple_records(timeout_ms).await?;
    let s = String::from_utf8_lossy(&data).into_owned();
    if s.is_empty() {
        bail!("XMPP: no data received (timeout or connection closed)");
    }
    Ok(s)
}
