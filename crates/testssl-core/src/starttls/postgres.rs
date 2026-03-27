//! PostgreSQL SSL negotiation

use anyhow::Result;
use tracing::debug;

use crate::tls::socket::TlsSocket;

/// PostgreSQL SSL request message
/// This is a special startup message requesting SSL
const POSTGRES_SSL_REQUEST: &[u8] = &[
    0x00, 0x00, 0x00, 0x08, // message length (8 bytes)
    0x04, 0xd2, 0x16, 0x2f, // SSLRequest code: 80877103
];

/// Negotiate SSL for PostgreSQL
pub async fn negotiate(socket: &mut TlsSocket) -> Result<()> {
    debug!("Sending PostgreSQL SSL request");

    socket.send(POSTGRES_SSL_REQUEST).await?;

    // Read single byte response
    let response = socket.recv(1).await?;
    debug!("PostgreSQL SSL response: {:?}", response);

    if response.is_empty() {
        return Err(anyhow::anyhow!("PostgreSQL: no response to SSL request"));
    }

    match response[0] {
        b'S' => {
            // 'S' = SSL is supported
            debug!("PostgreSQL: SSL supported");
            Ok(())
        }
        b'N' => {
            // 'N' = SSL not supported
            Err(anyhow::anyhow!("PostgreSQL server does not support SSL"))
        }
        b'E' => {
            // 'E' = Error
            Err(anyhow::anyhow!("PostgreSQL SSL negotiation error"))
        }
        other => Err(anyhow::anyhow!(
            "PostgreSQL: unexpected response byte: 0x{:02x}",
            other
        )),
    }
}
