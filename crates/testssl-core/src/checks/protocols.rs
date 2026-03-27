//! Check TLS/SSL protocol support

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::tls::client_hello::{ClientHelloBuilder, TlsVersion};
use crate::tls::server_hello::ServerHelloParser;
use crate::tls::socket::TlsSocket;
use crate::ScanTarget;

/// Protocol support results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolSupport {
    pub ssl2: Option<bool>,
    pub ssl3: Option<bool>,
    pub tls10: Option<bool>,
    pub tls11: Option<bool>,
    pub tls12: Option<bool>,
    pub tls13: Option<bool>,
}

impl ProtocolSupport {
    pub fn any_supported(&self) -> bool {
        self.ssl2 == Some(true)
            || self.ssl3 == Some(true)
            || self.tls10 == Some(true)
            || self.tls11 == Some(true)
            || self.tls12 == Some(true)
            || self.tls13 == Some(true)
    }

    pub fn best_protocol(&self) -> Option<TlsVersion> {
        if self.tls13 == Some(true) {
            Some(TlsVersion::Tls13)
        } else if self.tls12 == Some(true) {
            Some(TlsVersion::Tls12)
        } else if self.tls11 == Some(true) {
            Some(TlsVersion::Tls11)
        } else if self.tls10 == Some(true) {
            Some(TlsVersion::Tls10)
        } else if self.ssl3 == Some(true) {
            Some(TlsVersion::Ssl30)
        } else {
            None
        }
    }

    pub fn supported_versions(&self) -> Vec<&'static str> {
        let mut versions = Vec::new();
        if self.ssl2 == Some(true) {
            versions.push("SSLv2");
        }
        if self.ssl3 == Some(true) {
            versions.push("SSLv3");
        }
        if self.tls10 == Some(true) {
            versions.push("TLSv1.0");
        }
        if self.tls11 == Some(true) {
            versions.push("TLSv1.1");
        }
        if self.tls12 == Some(true) {
            versions.push("TLSv1.2");
        }
        if self.tls13 == Some(true) {
            versions.push("TLSv1.3");
        }
        versions
    }
}

/// Test if a specific TLS version is supported
async fn test_protocol_version(target: &ScanTarget, version: TlsVersion) -> Result<bool> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(e) => {
            debug!("Connection failed for {:?}: {}", version, e);
            return Ok(false);
        }
    };

    // Handle STARTTLS if needed
    if let Some(ref starttls) = target.starttls {
        if let Err(e) = starttls.negotiate(&mut socket).await {
            debug!("STARTTLS failed: {}", e);
            return Ok(false);
        }
    }

    let mut builder = ClientHelloBuilder::new(version);
    if let Some(ref sni) = target.sni {
        builder = builder.with_sni(sni.as_str());
    }
    let hello_bytes = builder.build();

    if let Err(e) = socket.send(&hello_bytes).await {
        debug!("Send failed: {}", e);
        return Ok(false);
    }

    let response = match socket.recv_multiple_records(3000).await {
        Ok(data) => data,
        Err(_) => return Ok(false),
    };

    if response.is_empty() {
        return Ok(false);
    }

    let result = ServerHelloParser::parse(&response)?;

    // First, basic check: did we get a ServerHello without a fatal alert?
    if !ServerHelloParser::is_successful(&result) || ServerHelloParser::has_fatal_alert(&result) {
        return Ok(false);
    }

    // Verify the server actually negotiated the version we requested.
    // Some servers accept old ClientHellos but respond with a newer version.
    let negotiated_version = [result.version_major, result.version_minor];
    let (exp_major, exp_minor) = version.to_wire_version();
    let expected = [exp_major, exp_minor];

    let actually_negotiated = match version {
        TlsVersion::Tls13 => {
            // TLS 1.3 ServerHello uses legacy_version = 0x0303.
            // The real negotiated version is in the supported_versions extension (0x0304).
            result.negotiated_version == Some(0x0304) || negotiated_version == [0x03, 0x04]
        }
        _ => negotiated_version == expected,
    };

    if actually_negotiated {
        debug!(
            "Protocol {:?} is supported (negotiated version confirmed)",
            version
        );
    } else {
        debug!(
            "Protocol {:?} rejected: server responded with version {:02x}{:02x} instead of {:02x}{:02x}",
            version,
            negotiated_version[0], negotiated_version[1],
            expected[0], expected[1],
        );
    }

    Ok(actually_negotiated)
}

/// Test SSLv2 support specifically
async fn test_sslv2(target: &ScanTarget) -> Result<bool> {
    let host = target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| target.host.clone());

    let mut socket = match TlsSocket::connect(&host, target.port, target.timeout_secs).await {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    if let Some(ref starttls) = target.starttls {
        if starttls.negotiate(&mut socket).await.is_err() {
            return Ok(false);
        }
    }

    let hello = crate::tls::sslv2::build_sslv2_client_hello(None);
    if socket.send(&hello).await.is_err() {
        return Ok(false);
    }

    let response = match socket.recv(16384).await {
        Ok(data) if !data.is_empty() => data,
        _ => return Ok(false),
    };

    let result = crate::tls::sslv2::parse_sslv2_server_hello(&response)?;
    Ok(result.supported)
}

/// Public helper for protocol version testing
pub async fn test_protocol_version_direct(
    target: &ScanTarget,
    version: TlsVersion,
) -> Result<bool> {
    test_protocol_version(target, version).await
}

/// Run all protocol checks
pub async fn check_protocols(target: &ScanTarget) -> Result<ProtocolSupport> {
    let mut support = ProtocolSupport::default();

    info!(
        "Checking protocol support for {}:{}",
        target.host, target.port
    );

    // Check SSLv2
    support.ssl2 = Some(test_sslv2(target).await.unwrap_or(false));

    // Check SSLv3
    support.ssl3 = Some(
        test_protocol_version(target, TlsVersion::Ssl30)
            .await
            .unwrap_or(false),
    );

    // Check TLS 1.0
    support.tls10 = Some(
        test_protocol_version(target, TlsVersion::Tls10)
            .await
            .unwrap_or(false),
    );

    // Check TLS 1.1
    support.tls11 = Some(
        test_protocol_version(target, TlsVersion::Tls11)
            .await
            .unwrap_or(false),
    );

    // Check TLS 1.2
    support.tls12 = Some(
        test_protocol_version(target, TlsVersion::Tls12)
            .await
            .unwrap_or(false),
    );

    // Check TLS 1.3
    support.tls13 = Some(
        test_protocol_version(target, TlsVersion::Tls13)
            .await
            .unwrap_or(false),
    );

    Ok(support)
}
