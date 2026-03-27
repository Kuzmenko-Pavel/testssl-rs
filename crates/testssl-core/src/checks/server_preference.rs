//! Server cipher preference check
//!
//! Detects whether the server enforces its own cipher order or follows
//! the client's preference, and identifies the preferred cipher(s).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::tls::client_hello::{tls12_default_ciphers, ClientHelloBuilder, TlsVersion};
use crate::tls::server_hello::ServerHelloParser;
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Server cipher preference result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerPreferenceResult {
    /// Whether the server enforces its own cipher order
    pub cipher_order_enforced: Option<bool>,
    /// Alias for backward compatibility
    pub has_order: Option<bool>,

    /// Preferred cipher for TLS 1.2 (hex bytes)
    pub preferred_cipher_tls12: Option<[u8; 2]>,
    /// Preferred cipher for TLS 1.3 (hex bytes)
    pub preferred_cipher_tls13: Option<[u8; 2]>,
    /// OpenSSL name of the preferred TLS 1.2 cipher
    pub preferred_cipher_ossl_name: Option<String>,

    /// Server-preferred cipher ordering (as OpenSSL names)
    pub cipher_order: Vec<String>,

    /// Whether the server enforces protocol order
    pub protocol_order_enforced: Option<bool>,
}

/// Connect and send a ClientHello with the specified cipher list.
/// Returns the cipher suite chosen by the server, or None if handshake failed.
async fn get_server_preferred_cipher(
    target: &ScanTarget,
    version: TlsVersion,
    ciphers: Vec<[u8; 2]>,
) -> Result<Option<[u8; 2]>> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = TlsSocket::connect(&host, target.port, target.timeout_secs).await?;

    if let Some(ref starttls) = target.starttls {
        starttls.negotiate(&mut socket).await?;
    }

    let mut builder = ClientHelloBuilder::new(version).with_cipher_suites(ciphers);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello_bytes = builder.build();
    socket.send(&hello_bytes).await?;

    let response = socket.recv_multiple_records(3000).await?;
    if response.is_empty() {
        return Ok(None);
    }

    let result = ServerHelloParser::parse(&response)?;
    if ServerHelloParser::is_successful(&result) {
        Ok(Some(result.cipher_suite))
    } else {
        Ok(None)
    }
}

/// Build the server's preferred cipher order by probing with progressively
/// smaller cipher lists (removing the previously selected cipher each round).
///
/// This mirrors testssl.sh's approach: each iteration removes the cipher the
/// server just selected, forcing it to reveal the next preference.
async fn probe_cipher_order(
    target: &ScanTarget,
    version: TlsVersion,
    initial_ciphers: Vec<[u8; 2]>,
    max_rounds: usize,
) -> Vec<[u8; 2]> {
    let mut order: Vec<[u8; 2]> = Vec::new();
    let mut remaining = initial_ciphers;

    for _ in 0..max_rounds {
        if remaining.len() < 2 {
            // Only one cipher left — add it if server accepts
            if let Ok(Some(chosen)) =
                get_server_preferred_cipher(target, version, remaining.clone()).await
            {
                if !order.contains(&chosen) {
                    order.push(chosen);
                }
            }
            break;
        }

        match get_server_preferred_cipher(target, version, remaining.clone()).await {
            Ok(Some(chosen)) => {
                if order.contains(&chosen) {
                    // Server repeating itself — stop
                    break;
                }
                order.push(chosen);
                // Remove chosen cipher from the list for next round
                remaining.retain(|c| c != &chosen);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    order
}

/// Check server cipher preference
pub async fn check_server_preference(target: &ScanTarget) -> Result<ServerPreferenceResult> {
    let mut result = ServerPreferenceResult::default();

    info!(
        "Checking server cipher preference for {}:{}",
        target.host, target.port
    );

    let ciphers = tls12_default_ciphers();
    let reversed: Vec<[u8; 2]> = ciphers.iter().rev().cloned().collect();

    // Round 1: cipher list in normal order
    let cipher1 = get_server_preferred_cipher(target, TlsVersion::Tls12, ciphers.clone()).await?;

    // Round 2: cipher list reversed — if server picks the same cipher, it enforces order
    let cipher2 = get_server_preferred_cipher(target, TlsVersion::Tls12, reversed).await?;

    result.preferred_cipher_tls12 = cipher1;

    let enforces_order = match (cipher1, cipher2) {
        (Some(c1), Some(c2)) => Some(c1 == c2),
        _ => None,
    };
    result.cipher_order_enforced = enforces_order;
    result.has_order = enforces_order;

    // Look up cipher name
    if let Some(cipher) = result.preferred_cipher_tls12 {
        if let Some(cs) = crate::data::find_cipher(cipher[0], cipher[1]) {
            result.preferred_cipher_ossl_name = Some(cs.ossl_name.to_string());
        }
    }

    // Only probe full order when the server enforces one (avoid excessive connections)
    if enforces_order == Some(true) {
        let ordered_ciphers =
            probe_cipher_order(target, TlsVersion::Tls12, ciphers.clone(), 10).await;

        for cipher in &ordered_ciphers {
            if let Some(cs) = crate::data::find_cipher(cipher[0], cipher[1]) {
                result.cipher_order.push(cs.ossl_name.to_string());
            } else {
                result
                    .cipher_order
                    .push(format!("0x{:02X}{:02X}", cipher[0], cipher[1]));
            }
        }
    }

    Ok(result)
}
