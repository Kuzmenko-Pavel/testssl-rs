//! MySQL SSL negotiation

use anyhow::Result;
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// MySQL capabilities flags for SSL
const CLIENT_SSL: u32 = 0x0800;
const CLIENT_PROTOCOL_41: u32 = 0x0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x8000;

/// Negotiate SSL for MySQL
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    debug!("Waiting for MySQL server greeting");

    // Read initial handshake packet
    let response =
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), socket.recv(4096)).await {
            Ok(Ok(data)) if !data.is_empty() => data,
            _ => return Err(anyhow::anyhow!("MySQL: failed to read greeting")),
        };

    debug!("MySQL greeting: {} bytes", response.len());

    if response.len() < 4 {
        return Err(anyhow::anyhow!("MySQL: greeting too short"));
    }

    // Parse MySQL packet header
    let _pkt_len = ((response[0] as u32)
        | ((response[1] as u32) << 8)
        | ((response[2] as u32) << 16)) as usize;
    let _seq_id = response[3];

    // Packet type should be 10 (protocol version 10)
    if response.len() > 4 && response[4] == 10 {
        debug!("MySQL: protocol version 10");
    } else if response.len() > 4 && response[4] == 0xff {
        return Err(anyhow::anyhow!("MySQL: server sent error packet"));
    }

    // Send SSL request packet
    // Minimal SSL request with CLIENT_SSL capability flag
    let capabilities: u32 = CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
    let max_packet_size: u32 = 16777216;
    let charset: u8 = 0x21; // utf8

    let mut ssl_request_body = Vec::new();
    ssl_request_body.extend_from_slice(&capabilities.to_le_bytes());
    ssl_request_body.extend_from_slice(&max_packet_size.to_le_bytes());
    ssl_request_body.push(charset);
    ssl_request_body.extend_from_slice(&[0u8; 23]); // reserved

    let body_len = ssl_request_body.len();
    let mut packet = vec![
        (body_len & 0xff) as u8,
        ((body_len >> 8) & 0xff) as u8,
        ((body_len >> 16) & 0xff) as u8,
        0x01, // sequence ID = 1
    ];
    packet.extend_from_slice(&ssl_request_body);

    socket.send(&packet).await?;
    debug!("MySQL: SSL request sent");

    Ok(())
}
