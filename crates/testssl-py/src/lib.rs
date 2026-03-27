//! PyO3 bindings for testssl-core
//!
//! Exposes testssl-rs functionality to Python via maturin.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::time::Duration;

use testssl_core::scanner::{ScanConfig, Scanner};
use testssl_core::starttls::StarttlsProtocol;

// ─── Option types ─────────────────────────────────────────────────────────────

/// Scan options passed from Python.
#[pyclass(get_all, set_all)]
#[derive(Default, Clone)]
pub struct ScanOptions {
    pub check_protocols: Option<bool>,
    pub check_ciphers: Option<bool>,
    pub check_vulnerabilities: Option<bool>,
    pub check_certificate: Option<bool>,
    pub check_http_headers: Option<bool>,
    pub check_forward_secrecy: Option<bool>,
    pub check_server_defaults: Option<bool>,
    pub check_server_preference: Option<bool>,
    pub check_client_simulation: Option<bool>,
    pub check_grease: Option<bool>,
    pub check_rating: Option<bool>,
    /// Timeout in seconds.
    pub timeout: Option<u32>,
    /// Connection timeout in seconds.
    pub connect_timeout: Option<u32>,
    pub sni: Option<String>,
    /// "smtp"|"imap"|"pop3"|"ftp"|"ldap"|"xmpp"|"postgres"|"mysql"
    pub starttls: Option<String>,
    pub ipv6: Option<bool>,
    pub parallel: Option<u32>,
}

#[pymethods]
impl ScanOptions {
    #[new]
    pub fn new() -> Self {
        ScanOptions::default()
    }
}

// ─── Result types ─────────────────────────────────────────────────────────────

#[pyclass(get_all)]
#[derive(Clone)]
pub struct ProtocolResults {
    pub ssl2: Option<bool>,
    pub ssl3: Option<bool>,
    pub tls10: Option<bool>,
    pub tls11: Option<bool>,
    pub tls12: Option<bool>,
    pub tls13: Option<bool>,
}

#[pymethods]
impl ProtocolResults {
    fn __repr__(&self) -> String {
        format!(
            "ProtocolResults(ssl2={:?}, ssl3={:?}, tls10={:?}, tls11={:?}, tls12={:?}, tls13={:?})",
            self.ssl2, self.ssl3, self.tls10, self.tls11, self.tls12, self.tls13
        )
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct VulnResult {
    /// "VULNERABLE" | "not_vulnerable" | "unknown" | "N/A"
    pub status: String,
    /// CVE identifiers (may be empty).
    pub cve: Vec<String>,
    pub details: String,
}

#[pymethods]
impl VulnResult {
    fn __repr__(&self) -> String {
        format!(
            "VulnResult(status={:?}, cve={:?}, details={:?})",
            self.status, self.cve, self.details
        )
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct VulnerabilityReport {
    pub heartbleed: Option<VulnResult>,
    pub ccs_injection: Option<VulnResult>,
    pub robot: Option<VulnResult>,
    pub poodle: Option<VulnResult>,
    pub tls_fallback: Option<VulnResult>,
    pub sweet32: Option<VulnResult>,
    pub freak: Option<VulnResult>,
    pub drown: Option<VulnResult>,
    pub logjam: Option<VulnResult>,
    pub beast: Option<VulnResult>,
    pub lucky13: Option<VulnResult>,
    pub crime: Option<VulnResult>,
    pub breach: Option<VulnResult>,
    pub rc4: Option<VulnResult>,
    pub ticketbleed: Option<VulnResult>,
    pub secure_renegotiation: Option<VulnResult>,
    pub winshock: Option<VulnResult>,
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct CipherResult {
    /// e.g. "0xC0,0x2C"
    pub hex_code: String,
    pub openssl_name: String,
    pub iana_name: String,
    pub protocol: String,
    pub key_exchange: String,
    pub bits: u32,
    pub pfs: bool,
    pub is_export: bool,
}

#[pymethods]
impl CipherResult {
    fn __repr__(&self) -> String {
        format!(
            "CipherResult(hex_code={:?}, openssl_name={:?}, bits={})",
            self.hex_code, self.openssl_name, self.bits
        )
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct CertificateReport {
    pub subject: String,
    pub issuer: String,
    pub san: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i32,
    pub expired: bool,
    pub self_signed: bool,
    pub fingerprint_sha256: String,
    pub key_type: String,
    pub key_bits: u32,
    pub signature_algorithm: String,
    pub must_staple: bool,
}

#[pymethods]
impl CertificateReport {
    fn __repr__(&self) -> String {
        format!(
            "CertificateReport(subject={:?}, issuer={:?}, days_left={})",
            self.subject, self.issuer, self.days_left
        )
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct HttpHeaderReport {
    pub hsts: Option<String>,
    pub hsts_max_age: Option<u32>,
    pub hpkp: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub csp: Option<String>,
    pub server: Option<String>,
    pub cookie_flags: Vec<String>,
}

/// Structured rating details (SSL Labs-compatible scoring).
#[pyclass(get_all)]
#[derive(Clone)]
pub struct RatingDetails {
    pub numeric_score: u32,
    pub base_grade: String,
    pub protocol_score: u32,
    pub key_exchange_score: u32,
    pub cipher_strength_score: u32,
    pub warnings: Vec<String>,
    pub applied_rules: Vec<String>,
}

#[pymethods]
impl RatingDetails {
    fn __repr__(&self) -> String {
        format!(
            "RatingDetails(base_grade={:?}, numeric_score={}, warnings={})",
            self.base_grade,
            self.numeric_score,
            self.warnings.len()
        )
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct ScanResult {
    pub target: String,
    pub ip: String,
    pub rdns: Option<String>,
    pub protocols: Option<ProtocolResults>,
    pub vulnerabilities: Option<VulnerabilityReport>,
    pub certificate: Option<CertificateReport>,
    pub ciphers: Option<Vec<CipherResult>>,
    pub http_headers: Option<HttpHeaderReport>,
    /// "A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M", "?"
    pub rating: Option<String>,
    /// Structured rating details (SSL Labs-compatible scoring).
    pub rating_details: Option<RatingDetails>,
    pub scan_duration_ms: u32,
    pub errors: Vec<String>,
}

#[pymethods]
impl ScanResult {
    fn __repr__(&self) -> String {
        format!(
            "ScanResult(target={:?}, ip={:?}, rating={:?}, errors={})",
            self.target,
            self.ip,
            self.rating,
            self.errors.len()
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_starttls(s: &str) -> Option<StarttlsProtocol> {
    match s.to_lowercase().as_str() {
        "smtp" => Some(StarttlsProtocol::Smtp),
        "imap" => Some(StarttlsProtocol::Imap),
        "pop3" => Some(StarttlsProtocol::Pop3),
        "ftp" => Some(StarttlsProtocol::Ftp),
        "ldap" => Some(StarttlsProtocol::Ldap),
        "xmpp" => Some(StarttlsProtocol::Xmpp),
        "postgres" | "postgresql" => Some(StarttlsProtocol::Postgres),
        "mysql" => Some(StarttlsProtocol::Mysql),
        _ => None,
    }
}

fn build_scan_config(options: Option<&ScanOptions>) -> ScanConfig {
    let Some(opts) = options else {
        return ScanConfig::default();
    };

    let mut config = ScanConfig::default();

    if let Some(v) = opts.check_protocols {
        config.check_protocols = v;
    }
    if let Some(v) = opts.check_ciphers {
        config.check_ciphers = v;
    }
    if let Some(v) = opts.check_vulnerabilities {
        config.check_vulnerabilities = v;
    }
    if let Some(v) = opts.check_certificate {
        config.check_certificate = v;
    }
    if let Some(v) = opts.check_http_headers {
        config.check_http_headers = v;
    }
    if let Some(v) = opts.check_forward_secrecy {
        config.check_forward_secrecy = v;
    }
    if let Some(v) = opts.check_server_defaults {
        config.check_server_defaults = v;
    }
    if let Some(v) = opts.check_server_preference {
        config.check_server_preference = v;
    }
    if let Some(v) = opts.check_client_simulation {
        config.check_client_simulation = v;
    }
    if let Some(v) = opts.check_grease {
        config.check_grease = v;
    }
    if let Some(v) = opts.check_rating {
        config.check_rating = v;
    }
    if let Some(secs) = opts.timeout {
        config.timeout = Duration::from_secs(secs as u64);
    }
    if let Some(secs) = opts.connect_timeout {
        config.connect_timeout = Duration::from_secs(secs as u64);
    }
    if let Some(ref sni) = opts.sni {
        config.sni = Some(sni.clone());
    }
    if let Some(ref st) = opts.starttls {
        config.starttls = parse_starttls(st);
    }
    if let Some(v) = opts.ipv6 {
        config.ipv6 = v;
    }
    if let Some(v) = opts.parallel {
        config.parallel = v as usize;
    }

    config
}

fn convert_protocols(p: testssl_core::checks::protocols::ProtocolSupport) -> ProtocolResults {
    ProtocolResults {
        ssl2: p.ssl2,
        ssl3: p.ssl3,
        tls10: p.tls10,
        tls11: p.tls11,
        tls12: p.tls12,
        tls13: p.tls13,
    }
}

fn convert_vuln(v: &testssl_core::checks::vulnerabilities::VulnResult) -> VulnResult {
    VulnResult {
        status: v.status.to_string(),
        cve: v.cve.clone(),
        details: v.details.clone(),
    }
}

fn find_vuln(
    vulns: &[testssl_core::checks::vulnerabilities::VulnResult],
    name: &str,
) -> Option<VulnResult> {
    let name_lower = name.to_lowercase();
    vulns
        .iter()
        .find(|v| v.name.to_lowercase().contains(&name_lower))
        .map(convert_vuln)
}

fn convert_vulnerabilities(
    vulns: Vec<testssl_core::checks::vulnerabilities::VulnResult>,
) -> VulnerabilityReport {
    VulnerabilityReport {
        heartbleed: find_vuln(&vulns, "heartbleed"),
        ccs_injection: find_vuln(&vulns, "ccs"),
        robot: find_vuln(&vulns, "robot"),
        poodle: find_vuln(&vulns, "poodle"),
        tls_fallback: find_vuln(&vulns, "fallback"),
        sweet32: find_vuln(&vulns, "sweet32"),
        freak: find_vuln(&vulns, "freak"),
        drown: find_vuln(&vulns, "drown"),
        logjam: find_vuln(&vulns, "logjam"),
        beast: find_vuln(&vulns, "beast"),
        lucky13: find_vuln(&vulns, "lucky13"),
        crime: find_vuln(&vulns, "crime"),
        breach: find_vuln(&vulns, "breach"),
        rc4: find_vuln(&vulns, "rc4"),
        ticketbleed: find_vuln(&vulns, "ticketbleed"),
        secure_renegotiation: find_vuln(&vulns, "renegotiation"),
        winshock: find_vuln(&vulns, "winshock"),
    }
}

fn convert_certificate(
    cert_check: testssl_core::checks::certificate::CertCheckResult,
) -> Option<CertificateReport> {
    let cert = cert_check.certs.into_iter().next()?;
    Some(CertificateReport {
        subject: cert.subject,
        issuer: cert.issuer,
        san: cert.subject_alt_names,
        not_before: cert.not_before,
        not_after: cert.not_after,
        days_left: cert.days_until_expiry as i32,
        expired: cert.is_expired,
        self_signed: cert.is_self_signed,
        fingerprint_sha256: cert.fingerprint_sha256,
        key_type: cert.key_type,
        key_bits: cert.key_bits,
        signature_algorithm: cert.signature_algorithm,
        must_staple: cert_check.ocsp_must_staple,
    })
}

fn convert_ciphers(
    cipher_result: testssl_core::checks::ciphers::CipherEnumResult,
) -> Vec<CipherResult> {
    cipher_result
        .supported
        .into_iter()
        .map(|c| CipherResult {
            hex_code: format!("0x{:02X},0x{:02X}", c.hex_high, c.hex_low),
            openssl_name: c.ossl_name,
            iana_name: c.rfc_name,
            protocol: c.tls_version,
            key_exchange: c.kx,
            bits: c.bits as u32,
            pfs: c.pfs,
            is_export: c.is_export,
        })
        .collect()
}

fn convert_http_headers(
    h: testssl_core::checks::http_headers::HttpHeadersResult,
) -> HttpHeaderReport {
    let (hsts_str, hsts_max_age) = match h.hsts {
        Some(ref info) => (Some(info.raw_value.clone()), Some(info.max_age as u32)),
        None => (None, None),
    };

    let cookie_flags: Vec<String> = h
        .cookie_flags
        .iter()
        .map(|c| {
            let mut flags = Vec::new();
            if c.secure {
                flags.push("Secure");
            }
            if c.http_only {
                flags.push("HttpOnly");
            }
            format!("{}:{}", c.name, flags.join(","))
        })
        .collect();

    HttpHeaderReport {
        hsts: hsts_str,
        hsts_max_age,
        hpkp: h.hpkp,
        x_frame_options: h.x_frame_options,
        x_content_type_options: h.x_content_type_options,
        csp: h.content_security_policy,
        server: h.server,
        cookie_flags,
    }
}

fn convert_scan_result(r: testssl_core::scanner::ScanResult) -> ScanResult {
    let protocols = r.protocols.map(convert_protocols);
    let vulnerabilities = r.vulnerabilities.map(convert_vulnerabilities);
    let certificate = r.certificate.and_then(convert_certificate);
    let ciphers = r.ciphers.map(convert_ciphers);
    let http_headers = r.http_headers.map(convert_http_headers);
    let (rating, rating_details) = match r.rating {
        Some(rat) => {
            let grade_str = rat.effective_grade().to_string();
            let details = RatingDetails {
                numeric_score: rat.overall_score,
                base_grade: rat.base_grade.to_string(),
                protocol_score: rat.protocol_score,
                key_exchange_score: rat.key_exchange_score,
                cipher_strength_score: rat.cipher_strength_score,
                warnings: rat.warnings,
                applied_rules: rat.applied_rules,
            };
            (Some(grade_str), Some(details))
        }
        None => (None, None),
    };

    ScanResult {
        target: r.target,
        ip: r.ip,
        rdns: r.rdns,
        protocols,
        vulnerabilities,
        certificate,
        ciphers,
        http_headers,
        rating,
        rating_details,
        scan_duration_ms: r.scan_duration_ms as u32,
        errors: r.errors,
    }
}

fn py_runtime_err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

// ─── TlsScanner class ─────────────────────────────────────────────────────────

/// Main scanner class. All async methods return Python awaitables.
///
/// Usage::
///
///     import asyncio
///     from testssl_py import TlsScanner
///
///     async def main():
///         scanner = TlsScanner()
///         result = await scanner.scan("example.com")
///         print(result.rating)
///
///     asyncio.run(main())
#[pyclass]
#[derive(Default)]
pub struct TlsScanner {}

#[pymethods]
impl TlsScanner {
    #[new]
    pub fn new() -> Self {
        TlsScanner {}
    }

    /// Scan a target host with the given options.
    ///
    /// `target` may be ``"host"``, ``"host:port"``, or ``"https://host:port/"``.
    /// Returns a coroutine yielding :class:`ScanResult`.
    #[pyo3(signature = (target, options=None))]
    fn scan<'py>(
        &self,
        py: Python<'py>,
        target: String,
        options: Option<ScanOptions>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let config = build_scan_config(options.as_ref());
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let scanner = Scanner::new(config);
            let result = scanner.scan(&target).await.map_err(py_runtime_err)?;
            Ok(convert_scan_result(result))
        })
    }

    /// Quick scan: only protocols + certificate.
    fn quick_scan<'py>(&self, py: Python<'py>, target: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let scanner = Scanner::new(ScanConfig::minimal());
            let result = scanner.scan(&target).await.map_err(py_runtime_err)?;
            Ok(convert_scan_result(result))
        })
    }

    /// Scan multiple targets sequentially.
    /// Returns a coroutine yielding a list of :class:`ScanResult`.
    #[pyo3(signature = (targets, options=None))]
    fn scan_batch<'py>(
        &self,
        py: Python<'py>,
        targets: Vec<String>,
        options: Option<ScanOptions>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let config = build_scan_config(options.as_ref());
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let scanner = Scanner::new(config);
            let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
            let results = scanner.scan_batch(&refs).await;
            let mut out = Vec::with_capacity(results.len());
            for res in results {
                let r = res.map_err(py_runtime_err)?;
                out.push(convert_scan_result(r));
            }
            Ok(out)
        })
    }

    /// Run only vulnerability checks on a target.
    fn check_vulnerabilities<'py>(
        &self,
        py: Python<'py>,
        target: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let config = ScanConfig {
                check_vulnerabilities: true,
                check_protocols: false,
                check_certificate: false,
                check_rating: false,
                ..ScanConfig::default()
            };
            let scanner = Scanner::new(config);
            let result = scanner.scan(&target).await.map_err(py_runtime_err)?;
            let vulns = result.vulnerabilities.unwrap_or_default();
            Ok(convert_vulnerabilities(vulns))
        })
    }

    /// Run only certificate check on a target.
    fn check_certificate<'py>(
        &self,
        py: Python<'py>,
        target: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let config = ScanConfig {
                check_certificate: true,
                check_protocols: false,
                check_rating: false,
                ..ScanConfig::default()
            };
            let scanner = Scanner::new(config);
            let result = scanner.scan(&target).await.map_err(py_runtime_err)?;
            let cert_report = result
                .certificate
                .and_then(convert_certificate)
                .ok_or_else(|| PyRuntimeError::new_err("No certificate found"))?;
            Ok(cert_report)
        })
    }

    /// Enumerate cipher suites supported by a target.
    fn enumerate_ciphers<'py>(
        &self,
        py: Python<'py>,
        target: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let config = ScanConfig {
                check_ciphers: true,
                check_protocols: false,
                check_certificate: false,
                check_rating: false,
                ..ScanConfig::default()
            };
            let scanner = Scanner::new(config);
            let result = scanner.scan(&target).await.map_err(py_runtime_err)?;
            let ciphers: Vec<CipherResult> =
                result.ciphers.map(convert_ciphers).unwrap_or_default();
            Ok(ciphers)
        })
    }

    /// Return the library version string.
    #[staticmethod]
    fn version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    fn __repr__(&self) -> &'static str {
        "TlsScanner()"
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Parse a scan target URI into ``[host, port]`` components.
#[pyfunction]
pub fn parse_target(uri: String) -> PyResult<Vec<String>> {
    let uri = uri.trim();

    let without_scheme = ["https://", "http://", "smtp://", "imap://", "pop3://"]
        .iter()
        .find_map(|scheme| uri.strip_prefix(scheme))
        .unwrap_or(uri);

    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);

    if host_port.contains('[') {
        let end_bracket = host_port
            .find(']')
            .ok_or_else(|| PyRuntimeError::new_err("Invalid IPv6 address"))?;
        let host = &host_port[1..end_bracket];
        let rest = &host_port[end_bracket + 1..];
        let port = if let Some(p) = rest.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| PyRuntimeError::new_err("Invalid port"))?
                .to_string()
        } else {
            "443".to_string()
        };
        return Ok(vec![host.to_string(), port]);
    }

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| PyRuntimeError::new_err("Invalid port"))?;
        return Ok(vec![host.to_string(), port.to_string()]);
    }

    Ok(vec![host_port.to_string(), "443".to_string()])
}

/// Return the library version string.
#[pyfunction]
pub fn version() -> String {
    testssl_core::VERSION.to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use testssl_core::checks::certificate::{CertCheckResult, CertInfo};
    use testssl_core::checks::ciphers::{CipherEnumResult, SupportedCipher};
    use testssl_core::checks::http_headers::{CookieInfo, HstsInfo, HttpHeadersResult};
    use testssl_core::checks::protocols::ProtocolSupport;
    use testssl_core::checks::vulnerabilities::{VulnResult as CoreVulnResult, VulnStatus};

    // ── parse_starttls ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_starttls_smtp() {
        assert_eq!(parse_starttls("smtp"), Some(StarttlsProtocol::Smtp));
    }

    #[test]
    fn test_parse_starttls_imap() {
        assert_eq!(parse_starttls("imap"), Some(StarttlsProtocol::Imap));
    }

    #[test]
    fn test_parse_starttls_pop3() {
        assert_eq!(parse_starttls("pop3"), Some(StarttlsProtocol::Pop3));
    }

    #[test]
    fn test_parse_starttls_ftp() {
        assert_eq!(parse_starttls("ftp"), Some(StarttlsProtocol::Ftp));
    }

    #[test]
    fn test_parse_starttls_ldap() {
        assert_eq!(parse_starttls("ldap"), Some(StarttlsProtocol::Ldap));
    }

    #[test]
    fn test_parse_starttls_xmpp() {
        assert_eq!(parse_starttls("xmpp"), Some(StarttlsProtocol::Xmpp));
    }

    #[test]
    fn test_parse_starttls_postgres() {
        assert_eq!(parse_starttls("postgres"), Some(StarttlsProtocol::Postgres));
        assert_eq!(
            parse_starttls("postgresql"),
            Some(StarttlsProtocol::Postgres)
        );
    }

    #[test]
    fn test_parse_starttls_mysql() {
        assert_eq!(parse_starttls("mysql"), Some(StarttlsProtocol::Mysql));
    }

    #[test]
    fn test_parse_starttls_case_insensitive() {
        assert_eq!(parse_starttls("SMTP"), Some(StarttlsProtocol::Smtp));
        assert_eq!(parse_starttls("IMAP"), Some(StarttlsProtocol::Imap));
    }

    #[test]
    fn test_parse_starttls_unknown_returns_none() {
        assert_eq!(parse_starttls("http"), None);
        assert_eq!(parse_starttls(""), None);
        assert_eq!(parse_starttls("rdp"), None);
    }

    // ── build_scan_config ─────────────────────────────────────────────────────

    #[test]
    fn test_build_scan_config_none_returns_default() {
        let config = build_scan_config(None);
        let default = ScanConfig::default();
        assert_eq!(config.check_protocols, default.check_protocols);
        assert_eq!(config.check_ciphers, default.check_ciphers);
    }

    #[test]
    fn test_build_scan_config_overrides_fields() {
        let opts = ScanOptions {
            check_protocols: Some(false),
            check_ciphers: Some(true),
            check_vulnerabilities: Some(false),
            ..ScanOptions::default()
        };
        let config = build_scan_config(Some(&opts));
        assert!(!config.check_protocols);
        assert!(config.check_ciphers);
        assert!(!config.check_vulnerabilities);
    }

    #[test]
    fn test_build_scan_config_timeout() {
        let opts = ScanOptions {
            timeout: Some(30),
            connect_timeout: Some(5),
            ..ScanOptions::default()
        };
        let config = build_scan_config(Some(&opts));
        assert_eq!(config.timeout, std::time::Duration::from_secs(30));
        assert_eq!(config.connect_timeout, std::time::Duration::from_secs(5));
    }

    #[test]
    fn test_build_scan_config_sni() {
        let opts = ScanOptions {
            sni: Some("example.com".to_string()),
            ..ScanOptions::default()
        };
        let config = build_scan_config(Some(&opts));
        assert_eq!(config.sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_build_scan_config_starttls() {
        let opts = ScanOptions {
            starttls: Some("smtp".to_string()),
            ..ScanOptions::default()
        };
        let config = build_scan_config(Some(&opts));
        assert_eq!(config.starttls, Some(StarttlsProtocol::Smtp));
    }

    #[test]
    fn test_build_scan_config_parallel() {
        let opts = ScanOptions {
            parallel: Some(4),
            ..ScanOptions::default()
        };
        let config = build_scan_config(Some(&opts));
        assert_eq!(config.parallel, 4);
    }

    // ── convert_protocols ─────────────────────────────────────────────────────

    #[test]
    fn test_convert_protocols_maps_all_fields() {
        let ps = ProtocolSupport {
            ssl2: Some(false),
            ssl3: Some(false),
            tls10: Some(true),
            tls11: Some(true),
            tls12: Some(true),
            tls13: Some(true),
        };
        let result = convert_protocols(ps);
        assert_eq!(result.ssl2, Some(false));
        assert_eq!(result.ssl3, Some(false));
        assert_eq!(result.tls10, Some(true));
        assert_eq!(result.tls12, Some(true));
        assert_eq!(result.tls13, Some(true));
    }

    #[test]
    fn test_convert_protocols_none_fields() {
        let ps = ProtocolSupport {
            ssl2: None,
            ssl3: None,
            tls10: None,
            tls11: None,
            tls12: None,
            tls13: None,
        };
        let result = convert_protocols(ps);
        assert!(result.ssl2.is_none());
        assert!(result.tls13.is_none());
    }

    // ── convert_vuln ──────────────────────────────────────────────────────────

    #[test]
    fn test_convert_vuln_vulnerable() {
        let v = CoreVulnResult {
            name: "heartbleed".to_string(),
            status: VulnStatus::Vulnerable,
            cve: vec!["CVE-2014-0160".to_string()],
            details: "heartbleed detail".to_string(),
        };
        let result = convert_vuln(&v);
        assert_eq!(result.status, "VULNERABLE");
        assert_eq!(result.cve, vec!["CVE-2014-0160"]);
        assert_eq!(result.details, "heartbleed detail");
    }

    #[test]
    fn test_convert_vuln_not_vulnerable() {
        let v = CoreVulnResult {
            name: "poodle".to_string(),
            status: VulnStatus::NotVulnerable,
            cve: vec![],
            details: String::new(),
        };
        let result = convert_vuln(&v);
        assert_eq!(result.status, "not vulnerable");
        assert!(result.cve.is_empty());
    }

    // ── find_vuln ─────────────────────────────────────────────────────────────

    #[test]
    fn test_find_vuln_found_by_name() {
        let vulns = vec![CoreVulnResult {
            name: "heartbleed".to_string(),
            status: VulnStatus::Vulnerable,
            cve: vec!["CVE-2014-0160".to_string()],
            details: "detail".to_string(),
        }];
        let result = find_vuln(&vulns, "heartbleed");
        assert!(result.is_some());
        assert_eq!(result.unwrap().status, "VULNERABLE");
    }

    #[test]
    fn test_find_vuln_not_found() {
        let vulns = vec![CoreVulnResult {
            name: "heartbleed".to_string(),
            status: VulnStatus::NotVulnerable,
            cve: vec![],
            details: String::new(),
        }];
        assert!(find_vuln(&vulns, "poodle").is_none());
    }

    #[test]
    fn test_find_vuln_case_insensitive() {
        let vulns = vec![CoreVulnResult {
            name: "BEAST".to_string(),
            status: VulnStatus::NotVulnerable,
            cve: vec![],
            details: String::new(),
        }];
        let result = find_vuln(&vulns, "beast");
        assert!(result.is_some());
    }

    // ── convert_vulnerabilities ───────────────────────────────────────────────

    #[test]
    fn test_convert_vulnerabilities_heartbleed_found() {
        let vulns = vec![CoreVulnResult {
            name: "Heartbleed".to_string(),
            status: VulnStatus::Vulnerable,
            cve: vec!["CVE-2014-0160".to_string()],
            details: "detail".to_string(),
        }];
        let report = convert_vulnerabilities(vulns);
        assert!(report.heartbleed.is_some());
        assert!(report.poodle.is_none());
    }

    #[test]
    fn test_convert_vulnerabilities_empty_list() {
        let report = convert_vulnerabilities(vec![]);
        assert!(report.heartbleed.is_none());
        assert!(report.ccs_injection.is_none());
        assert!(report.robot.is_none());
        assert!(report.winshock.is_none());
    }

    // ── convert_http_headers ──────────────────────────────────────────────────

    #[test]
    fn test_convert_http_headers_with_hsts() {
        let h = HttpHeadersResult {
            hsts: Some(HstsInfo {
                raw_value: "max-age=31536000; includeSubDomains".to_string(),
                max_age: 31536000,
                include_subdomains: true,
                preload: false,
            }),
            ..HttpHeadersResult::default()
        };
        let report = convert_http_headers(h);
        assert_eq!(
            report.hsts,
            Some("max-age=31536000; includeSubDomains".to_string())
        );
        assert_eq!(report.hsts_max_age, Some(31536000));
    }

    #[test]
    fn test_convert_http_headers_no_hsts() {
        let h = HttpHeadersResult::default();
        let report = convert_http_headers(h);
        assert!(report.hsts.is_none());
        assert!(report.hsts_max_age.is_none());
    }

    #[test]
    fn test_convert_http_headers_cookie_flags() {
        let h = HttpHeadersResult {
            cookie_flags: vec![
                CookieInfo {
                    name: "session".to_string(),
                    secure: true,
                    http_only: true,
                    same_site: None,
                    path: None,
                    domain: None,
                },
                CookieInfo {
                    name: "tracking".to_string(),
                    secure: false,
                    http_only: false,
                    same_site: None,
                    path: None,
                    domain: None,
                },
            ],
            ..HttpHeadersResult::default()
        };
        let report = convert_http_headers(h);
        assert_eq!(report.cookie_flags.len(), 2);
        assert!(report.cookie_flags[0].contains("session"));
        assert!(report.cookie_flags[0].contains("Secure"));
        assert!(report.cookie_flags[0].contains("HttpOnly"));
        assert!(report.cookie_flags[1].contains("tracking"));
    }

    // ── convert_ciphers ───────────────────────────────────────────────────────

    #[test]
    fn test_convert_ciphers_hex_format() {
        let cipher_result = CipherEnumResult {
            supported: vec![SupportedCipher {
                hex_high: 0xC0,
                hex_low: 0x2C,
                ossl_name: "ECDHE-ECDSA-AES256-GCM-SHA384".to_string(),
                rfc_name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                tls_version: "TLSv1.2".to_string(),
                kx: "ECDH".to_string(),
                enc: "AESGCM".to_string(),
                bits: 256,
                mac: "AEAD".to_string(),
                pfs: true,
                is_export: false,
            }],
            total_tested: 1,
        };
        let results = convert_ciphers(cipher_result);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hex_code, "0xC0,0x2C");
        assert_eq!(results[0].openssl_name, "ECDHE-ECDSA-AES256-GCM-SHA384");
        assert_eq!(results[0].bits, 256);
        assert!(results[0].pfs);
        assert!(!results[0].is_export);
    }

    #[test]
    fn test_convert_ciphers_empty() {
        let cipher_result = CipherEnumResult::default();
        let results = convert_ciphers(cipher_result);
        assert!(results.is_empty());
    }

    // ── convert_certificate ───────────────────────────────────────────────────

    #[test]
    fn test_convert_certificate_with_cert() {
        let cert_check = CertCheckResult {
            certs: vec![CertInfo {
                subject: "CN=example.com".to_string(),
                issuer: "CN=Let's Encrypt".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2025-01-01".to_string(),
                days_until_expiry: 100,
                is_expired: false,
                is_self_signed: false,
                fingerprint_sha256: "AA:BB".to_string(),
                key_type: "RSA".to_string(),
                key_bits: 2048,
                signature_algorithm: "sha256WithRSAEncryption".to_string(),
                subject_alt_names: vec!["example.com".to_string()],
                ..CertInfo::default()
            }],
            ocsp_must_staple: true,
            ..CertCheckResult::default()
        };
        let report = convert_certificate(cert_check);
        assert!(report.is_some());
        let r = report.unwrap();
        assert_eq!(r.subject, "CN=example.com");
        assert_eq!(r.issuer, "CN=Let's Encrypt");
        assert_eq!(r.days_left, 100);
        assert!(!r.expired);
        assert!(r.must_staple);
    }

    #[test]
    fn test_convert_certificate_empty_certs_returns_none() {
        let cert_check = CertCheckResult::default();
        let report = convert_certificate(cert_check);
        assert!(report.is_none());
    }
}

// ─── Module ───────────────────────────────────────────────────────────────────

#[pymodule]
fn testssl_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TlsScanner>()?;
    m.add_class::<ScanOptions>()?;
    m.add_class::<ScanResult>()?;
    m.add_class::<ProtocolResults>()?;
    m.add_class::<VulnResult>()?;
    m.add_class::<VulnerabilityReport>()?;
    m.add_class::<CipherResult>()?;
    m.add_class::<CertificateReport>()?;
    m.add_class::<HttpHeaderReport>()?;
    m.add_function(wrap_pyfunction!(parse_target, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
