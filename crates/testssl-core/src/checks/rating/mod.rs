//! SSL Labs-compatible TLS/SSL rating subsystem.
//!
//! Four-layer architecture:
//!   1. Fact collection   — `model::collect_rating_facts`
//!   2. Numeric scoring   — `scoring::{calc_*_score, calc_numeric_score}`
//!   3. Base grade        — `scoring::score_to_base_grade`
//!   4. Rule engine       — `rules::apply_rules` (fatal → cap → warning → bonus)

pub mod model;
pub mod rules;
pub mod scoring;

use serde::{Deserialize, Serialize};

use crate::checks::certificate::CertCheckResult;
use crate::checks::ciphers::CipherEnumResult;
use crate::checks::forward_secrecy::ForwardSecrecyResult;
use crate::checks::http_headers::HttpHeadersResult;
use crate::checks::protocols::ProtocolSupport;
use crate::checks::server_defaults::ServerDefaults;
use crate::checks::vulnerabilities::VulnResult;

use model::collect_rating_facts;
use rules::apply_rules;
use scoring::{
    calc_cipher_score, calc_kx_score, calc_numeric_score, calc_protocol_score, score_to_base_grade,
};

// ── Grade enum ────────────────────────────────────────────────────────────────

/// SSL Labs-compatible letter grade.
///
/// Implements `Ord` so that higher ordinal = worse quality:
/// `APlus(0) < A(1) < AMinus(2) < B(3) < C(4) < D(5) < E(6) < F(7) < T(8) < M(9) < Unknown(10)`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum Grade {
    APlus,
    A,
    AMinus,
    B,
    C,
    D,
    E,
    F,
    T, // Untrusted certificate
    M, // Hostname mismatch
    #[default]
    Unknown,
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Grade::APlus => write!(f, "A+"),
            Grade::A => write!(f, "A"),
            Grade::AMinus => write!(f, "A-"),
            Grade::B => write!(f, "B"),
            Grade::C => write!(f, "C"),
            Grade::D => write!(f, "D"),
            Grade::E => write!(f, "E"),
            Grade::F => write!(f, "F"),
            Grade::T => write!(f, "T"),
            Grade::M => write!(f, "M"),
            Grade::Unknown => write!(f, "?"),
        }
    }
}

// ── RatingResult ──────────────────────────────────────────────────────────────

/// Complete rating result with explanation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingResult {
    /// Policy identifier, e.g. `"ssl_labs_2025"`.
    pub policy_id: String,
    /// Grade derived from the numeric score (before caps and bonuses).
    pub base_grade: Grade,
    /// Worst cap applied across all rule phases (None = no cap).
    pub grade_cap: Option<Grade>,
    /// Protocol support sub-score (0–100).
    pub protocol_score: u32,
    /// Key-exchange sub-score (0–100).
    pub key_exchange_score: u32,
    /// Cipher strength sub-score (0–100).
    pub cipher_strength_score: u32,
    /// Weighted numeric score: protocol×30% + KX×30% + cipher×40%.
    pub overall_score: u32,
    /// Human-readable reasons for applied caps (backward-compatible field).
    pub grade_reasons: Vec<String>,
    /// Non-fatal warnings (e.g. "No TLS 1.3 support").
    pub warnings: Vec<String>,
    /// Machine-readable rule codes applied (e.g. `["SSL3_ENABLED", "WARN_NO_TLS13"]`).
    pub applied_rules: Vec<String>,
}

impl RatingResult {
    pub fn new() -> Self {
        Self {
            policy_id: "ssl_labs_2025".to_string(),
            base_grade: Grade::Unknown,
            grade_cap: None,
            protocol_score: 0,
            key_exchange_score: 0,
            cipher_strength_score: 0,
            overall_score: 0,
            grade_reasons: Vec::new(),
            warnings: Vec::new(),
            applied_rules: Vec::new(),
        }
    }

    /// Effective grade after applying the grade cap.
    ///
    /// The cap is a *ceiling* that can only make the grade worse:
    /// `effective = max(base_grade, grade_cap)` in terms of Ord (higher = worse).
    pub fn effective_grade(&self) -> Grade {
        match self.grade_cap {
            Some(cap) if cap > self.base_grade => cap,
            _ => self.base_grade,
        }
    }
}

impl Default for RatingResult {
    fn default() -> Self {
        Self::new()
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Rate a server's TLS configuration using SSL Labs-compatible scoring.
///
/// Pass `None` for any check result that was not performed; absent facts are
/// handled conservatively (they do not penalise the grade).
#[allow(clippy::too_many_arguments)]
pub fn rate_server(
    proto: &ProtocolSupport,
    cipher_result: Option<&CipherEnumResult>,
    cert_result: Option<&CertCheckResult>,
    fs_result: Option<&ForwardSecrecyResult>,
    headers_result: Option<&HttpHeadersResult>,
    server_defaults: Option<&ServerDefaults>,
    vulnerabilities: Option<&[VulnResult]>,
    target_hostname: Option<&str>,
) -> RatingResult {
    let facts = collect_rating_facts(
        proto,
        cipher_result,
        cert_result,
        fs_result,
        headers_result,
        server_defaults,
        vulnerabilities,
        target_hostname,
    );

    let p = calc_protocol_score(&facts);
    let kx = calc_kx_score(&facts);
    let c = calc_cipher_score(&facts);
    let numeric = calc_numeric_score(p, kx, c);

    let mut result = RatingResult::new();
    result.base_grade = score_to_base_grade(numeric);
    result.protocol_score = p;
    result.key_exchange_score = kx;
    result.cipher_strength_score = c;
    result.overall_score = numeric;

    apply_rules(&facts, &mut result);

    result
}
