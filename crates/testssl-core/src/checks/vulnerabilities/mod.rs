//! Vulnerability check modules

pub mod beast;
pub mod breach;
pub mod ccs_injection;
pub mod crime;
pub mod drown;
pub mod freak;
pub mod heartbleed;
pub mod logjam;
pub mod lucky13;
pub mod poodle;
pub mod rc4;
pub mod robot;
pub mod secure_renegotiation;
pub mod sweet32;
pub mod ticketbleed;
pub mod tls_fallback;
pub mod winshock;

use serde::{Deserialize, Serialize};

/// Vulnerability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnStatus {
    /// Server is vulnerable
    Vulnerable,
    /// Server is not vulnerable
    NotVulnerable,
    /// Could not determine
    Unknown,
    /// Not applicable
    NotApplicable,
}

impl std::fmt::Display for VulnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnStatus::Vulnerable => write!(f, "VULNERABLE"),
            VulnStatus::NotVulnerable => write!(f, "not vulnerable"),
            VulnStatus::Unknown => write!(f, "unknown"),
            VulnStatus::NotApplicable => write!(f, "N/A"),
        }
    }
}

/// Common vulnerability check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    pub name: String,
    pub cve: Vec<String>,
    pub status: VulnStatus,
    pub details: String,
}

impl VulnResult {
    pub fn vulnerable(
        name: impl Into<String>,
        cve: Vec<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            cve,
            status: VulnStatus::Vulnerable,
            details: details.into(),
        }
    }

    pub fn not_vulnerable(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cve: Vec::new(),
            status: VulnStatus::NotVulnerable,
            details: String::new(),
        }
    }

    pub fn unknown(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cve: Vec::new(),
            status: VulnStatus::Unknown,
            details: reason.into(),
        }
    }

    pub fn not_applicable(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cve: Vec::new(),
            status: VulnStatus::NotApplicable,
            details: reason.into(),
        }
    }
}
