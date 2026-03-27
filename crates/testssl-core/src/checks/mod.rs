//! TLS/SSL security check modules

pub mod certificate;
pub mod ciphers;
pub mod client_simulation;
pub mod forward_secrecy;
pub mod grease;
pub mod http_headers;
pub mod protocols;
pub mod rating;
pub mod server_defaults;
pub mod server_preference;
pub mod vulnerabilities;

use serde::{Deserialize, Serialize};

/// Severity level for a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Ok,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Ok => write!(f, "OK"),
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub finding: String,
    pub cve: Vec<String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        finding: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            severity,
            finding: finding.into(),
            cve: Vec::new(),
        }
    }

    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve.push(cve.into());
        self
    }
}

/// Result of a check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub findings: Vec<Finding>,
}

impl CheckResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn is_vulnerable(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= Severity::Medium)
    }
}

impl Default for CheckResult {
    fn default() -> Self {
        Self::new()
    }
}
