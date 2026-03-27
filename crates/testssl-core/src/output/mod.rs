//! Output formatting modules

pub mod csv;
pub mod html;
pub mod json;
pub mod terminal;

use serde::{Deserialize, Serialize};

/// Complete scan results for output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub port: u16,
    pub ip: Option<String>,
    pub scan_time: String,
    pub protocols: Option<crate::checks::protocols::ProtocolSupport>,
    pub ciphers: Option<crate::checks::ciphers::CipherEnumResult>,
    pub certificate: Option<crate::checks::certificate::CertCheckResult>,
    pub http_headers: Option<crate::checks::http_headers::HttpHeadersResult>,
    pub vulnerabilities: Vec<crate::checks::vulnerabilities::VulnResult>,
    pub rating: Option<crate::checks::rating::RatingResult>,
    pub server_defaults: Option<crate::checks::server_defaults::ServerDefaults>,
    pub forward_secrecy: Option<crate::checks::forward_secrecy::ForwardSecrecyResult>,
    pub client_simulation: Vec<crate::checks::client_simulation::ClientSimResult>,
}

impl ScanResults {
    pub fn new(target: String, port: u16) -> Self {
        Self {
            target,
            port,
            ip: None,
            scan_time: chrono_now(),
            protocols: None,
            ciphers: None,
            certificate: None,
            http_headers: None,
            vulnerabilities: Vec::new(),
            rating: None,
            server_defaults: None,
            forward_secrecy: None,
            client_simulation: Vec::new(),
        }
    }
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}
