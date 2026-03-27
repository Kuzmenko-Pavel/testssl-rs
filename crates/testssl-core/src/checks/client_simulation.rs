//! Client simulation check

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::data::client_profiles::{ClientProfile, CLIENT_PROFILES};
use crate::tls::server_hello::ServerHelloParser;
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Result of simulating a specific client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSimResult {
    pub client_name: String,
    pub client_short: String,
    pub handshake_succeeded: bool,
    pub negotiated_version: Option<String>,
    pub negotiated_cipher: Option<String>,
    pub negotiated_cipher_hex: Option<String>,
}

/// Simulate a specific client connecting to the server
async fn simulate_client(target: &ScanTarget, profile: &ClientProfile) -> Result<ClientSimResult> {
    let mut result = ClientSimResult {
        client_name: profile.name.to_string(),
        client_short: profile.short.to_string(),
        handshake_succeeded: false,
        negotiated_version: None,
        negotiated_cipher: None,
        negotiated_cipher_hex: None,
    };

    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(_) => return Ok(result),
    };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(result);
        }
    }

    // Decode and send the pre-built handshake bytes
    let handshake_bytes = profile.decode_handshake();
    if handshake_bytes.is_empty() {
        return Ok(result);
    }

    // Optionally update SNI in the handshake bytes if we have a target SNI
    // For simplicity, we send as-is
    if socket.send(&handshake_bytes).await.is_err() {
        return Ok(result);
    }

    let response = match socket.recv_multiple_records(3000).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(result),
    };

    let sh_result = match ServerHelloParser::parse(&response) {
        Ok(r) => r,
        Err(_) => return Ok(result),
    };

    if ServerHelloParser::is_successful(&sh_result)
        && !ServerHelloParser::has_fatal_alert(&sh_result)
    {
        result.handshake_succeeded = true;
        result.negotiated_version = Some(ServerHelloParser::version_string(&sh_result).to_string());

        let cipher = sh_result.cipher_suite;
        result.negotiated_cipher_hex = Some(format!("{:02X}{:02X}", cipher[0], cipher[1]));

        if let Some(cs) = crate::data::find_cipher(cipher[0], cipher[1]) {
            result.negotiated_cipher = Some(cs.ossl_name.to_string());
        }
    }

    Ok(result)
}

/// Run client simulation for all profiles
pub async fn run_client_simulation(target: &ScanTarget) -> Result<Vec<ClientSimResult>> {
    let mut results = Vec::new();

    info!(
        "Running client simulation for {}:{}",
        target.host, target.port
    );

    for profile in CLIENT_PROFILES {
        match simulate_client(target, profile).await {
            Ok(r) => results.push(r),
            Err(e) => {
                tracing::warn!("Client simulation failed for {}: {}", profile.name, e);
            }
        }
    }

    Ok(results)
}
