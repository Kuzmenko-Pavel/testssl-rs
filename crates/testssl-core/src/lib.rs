//! testssl-core: Core library for TLS/SSL scanning
//!
//! This crate provides the core functionality for testing TLS/SSL servers,
//! including protocol support detection, cipher enumeration, vulnerability
//! checks, and certificate analysis.

pub mod checks;
pub mod data;
pub mod dns;
pub mod output;
pub mod scanner;
pub mod starttls;
pub mod tls;

pub use anyhow::{Context, Error, Result};

/// Version of the testssl-rs library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default connection timeout in seconds
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Default port for HTTPS
pub const DEFAULT_PORT: u16 = 443;

/// Configuration for a scan target
#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub host: String,
    pub ip: Option<std::net::IpAddr>,
    pub port: u16,
    pub starttls: Option<crate::starttls::StarttlsProtocol>,
    pub sni: Option<String>,
    pub timeout_secs: u64,
}

impl ScanTarget {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        let sni = Some(host.clone());
        Self {
            host,
            ip: None,
            port,
            starttls: None,
            sni,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }

    pub fn with_starttls(mut self, proto: crate::starttls::StarttlsProtocol) -> Self {
        self.starttls = Some(proto);
        self
    }

    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}
