//! Main scanner orchestrator

use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::{info, warn};

use crate::checks::certificate::CertCheckResult;
use crate::checks::ciphers::CipherEnumResult;
use crate::checks::client_simulation::ClientSimResult;
use crate::checks::forward_secrecy::ForwardSecrecyResult;
use crate::checks::grease::GreaseResult;
use crate::checks::http_headers::HttpHeadersResult;
use crate::checks::protocols::ProtocolSupport;
use crate::checks::rating::RatingResult;
use crate::checks::server_defaults::ServerDefaults;
use crate::checks::server_preference::ServerPreferenceResult;
use crate::checks::vulnerabilities::VulnResult;
use crate::starttls::StarttlsProtocol;
use crate::ScanTarget;

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub sni: Option<String>,
    pub starttls: Option<StarttlsProtocol>,
    pub check_protocols: bool,
    pub check_ciphers: bool,
    pub check_vulnerabilities: bool,
    pub check_certificate: bool,
    pub check_http_headers: bool,
    pub check_forward_secrecy: bool,
    pub check_server_defaults: bool,
    pub check_server_preference: bool,
    pub check_client_simulation: bool,
    pub check_grease: bool,
    pub check_rating: bool,
    pub ipv6: bool,
    pub parallel: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            sni: None,
            starttls: None,
            check_protocols: true,
            check_ciphers: false,
            check_vulnerabilities: false,
            check_certificate: true,
            check_http_headers: false,
            check_forward_secrecy: false,
            check_server_defaults: false,
            check_server_preference: false,
            check_client_simulation: false,
            check_grease: false,
            check_rating: false,
            ipv6: false,
            parallel: 4,
        }
    }
}

impl ScanConfig {
    /// Create a config that runs all checks
    pub fn all() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            sni: None,
            starttls: None,
            check_protocols: true,
            check_ciphers: true,
            check_vulnerabilities: true,
            check_certificate: true,
            check_http_headers: true,
            check_forward_secrecy: true,
            check_server_defaults: true,
            check_server_preference: true,
            check_client_simulation: true,
            check_grease: true,
            check_rating: true,
            ipv6: false,
            parallel: 4,
        }
    }

    /// Create a minimal config (protocols + certificate only, no rating)
    pub fn minimal() -> Self {
        Self {
            check_protocols: true,
            check_certificate: true,
            ..Default::default()
        }
    }

    pub fn with_protocols(mut self) -> Self {
        self.check_protocols = true;
        self
    }
    pub fn with_ciphers(mut self) -> Self {
        self.check_ciphers = true;
        self
    }
    pub fn with_certificate(mut self) -> Self {
        self.check_certificate = true;
        self
    }
    pub fn with_http_headers(mut self) -> Self {
        self.check_http_headers = true;
        self
    }
    pub fn with_vulnerabilities(mut self) -> Self {
        self.check_vulnerabilities = true;
        self
    }
    pub fn with_forward_secrecy(mut self) -> Self {
        self.check_forward_secrecy = true;
        self
    }
    pub fn with_server_defaults(mut self) -> Self {
        self.check_server_defaults = true;
        self
    }
    pub fn with_server_preference(mut self) -> Self {
        self.check_server_preference = true;
        self
    }
    pub fn with_client_simulation(mut self) -> Self {
        self.check_client_simulation = true;
        self
    }
    pub fn with_grease(mut self) -> Self {
        self.check_grease = true;
        self
    }
}

/// Complete scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub target: String,
    pub ip: String,
    pub rdns: Option<String>,
    pub protocols: Option<ProtocolSupport>,
    pub ciphers: Option<CipherEnumResult>,
    pub vulnerabilities: Option<Vec<VulnResult>>,
    pub certificate: Option<CertCheckResult>,
    pub http_headers: Option<HttpHeadersResult>,
    pub forward_secrecy: Option<ForwardSecrecyResult>,
    pub server_defaults: Option<ServerDefaults>,
    pub server_preference: Option<ServerPreferenceResult>,
    pub client_simulation: Option<Vec<ClientSimResult>>,
    pub grease: Option<GreaseResult>,
    pub rating: Option<RatingResult>,
    pub scan_duration_ms: u64,
    pub errors: Vec<String>,
}

impl ScanResult {
    fn new(target: String) -> Self {
        Self {
            target,
            ip: String::new(),
            rdns: None,
            protocols: None,
            ciphers: None,
            vulnerabilities: None,
            certificate: None,
            http_headers: None,
            forward_secrecy: None,
            server_defaults: None,
            server_preference: None,
            client_simulation: None,
            grease: None,
            rating: None,
            scan_duration_ms: 0,
            errors: Vec::new(),
        }
    }
}

/// The main scanner orchestrator
pub struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Scan a single target (host:port or URI)
    pub async fn scan(&self, target: &str) -> Result<ScanResult> {
        let start = Instant::now();
        let mut result = ScanResult::new(target.to_string());

        // Parse host and port from target string
        let (host, port) = parse_target(target)?;

        info!("Starting scan of {}:{}", host, port);

        // Build ScanTarget
        let mut scan_target = ScanTarget::new(host.clone(), port);
        if let Some(ref sni) = self.config.sni {
            scan_target = scan_target.with_sni(sni.clone());
        }
        if let Some(starttls) = self.config.starttls {
            scan_target = scan_target.with_starttls(starttls);
        }
        scan_target = scan_target.with_timeout(self.config.timeout.as_secs());

        // DNS lookup
        match crate::dns::resolve_first_ipv4(&host).await {
            Ok(Some(ip)) => {
                result.ip = ip.to_string();
                scan_target.ip = Some(ip);
            }
            Ok(None) => {
                let msg = format!("Could not resolve {} to IPv4", host);
                warn!("{}", msg);
                result.errors.push(msg);
            }
            Err(e) => {
                let msg = format!("DNS resolution failed for {}: {}", host, e);
                warn!("{}", msg);
                result.errors.push(msg);
            }
        }

        // Run checks
        if self.config.check_protocols {
            info!("Checking protocol support");
            match crate::checks::protocols::check_protocols(&scan_target).await {
                Ok(proto) => result.protocols = Some(proto),
                Err(e) => {
                    let msg = format!("Protocol check failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_certificate {
            info!("Checking certificate");
            match crate::checks::certificate::check_certificate(&scan_target).await {
                Ok(cert) => result.certificate = Some(cert),
                Err(e) => {
                    let msg = format!("Certificate check failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_server_defaults {
            info!("Checking server defaults");
            match crate::checks::server_defaults::check_server_defaults(&scan_target).await {
                Ok(defaults) => result.server_defaults = Some(defaults),
                Err(e) => {
                    let msg = format!("Server defaults check failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_server_preference {
            info!("Checking server preference");
            match crate::checks::server_preference::check_server_preference(&scan_target).await {
                Ok(pref) => result.server_preference = Some(pref),
                Err(e) => {
                    let msg = format!("Server preference check failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_ciphers {
            info!("Enumerating cipher suites");
            match crate::checks::ciphers::enumerate_ciphers(
                &scan_target,
                crate::tls::client_hello::TlsVersion::Tls12,
            )
            .await
            {
                Ok(ciphers) => result.ciphers = Some(ciphers),
                Err(e) => {
                    let msg = format!("Cipher enumeration failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_forward_secrecy {
            info!("Checking forward secrecy");
            match crate::checks::forward_secrecy::check_forward_secrecy(&scan_target).await {
                Ok(fs) => result.forward_secrecy = Some(fs),
                Err(e) => {
                    let msg = format!("Forward secrecy check failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_http_headers {
            info!("Checking HTTP headers");
            match crate::checks::http_headers::check_http_headers(&scan_target).await {
                Ok(headers) => result.http_headers = Some(headers),
                Err(e) => {
                    let msg = format!("HTTP headers check failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_vulnerabilities {
            info!("Checking vulnerabilities");
            let mut vulns: Vec<VulnResult> = Vec::new();
            run_vulnerability_checks(&scan_target, &mut vulns).await;
            result.vulnerabilities = Some(vulns);
        }

        if self.config.check_client_simulation {
            info!("Running client simulation");
            match crate::checks::client_simulation::run_client_simulation(&scan_target).await {
                Ok(sim) => result.client_simulation = Some(sim),
                Err(e) => {
                    let msg = format!("Client simulation failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        if self.config.check_grease {
            info!("Checking GREASE tolerance");
            match crate::checks::grease::check_grease(&scan_target).await {
                Ok(grease) => result.grease = Some(grease),
                Err(e) => {
                    let msg = format!("GREASE check failed: {}", e);
                    warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
        }

        // Calculate rating if protocols were checked
        if self.config.check_rating {
            if let Some(ref proto) = result.protocols {
                let vulns_slice = result.vulnerabilities.as_deref();
                let rating = crate::checks::rating::rate_server(
                    proto,
                    result.ciphers.as_ref(),
                    result.certificate.as_ref(),
                    result.forward_secrecy.as_ref(),
                    result.http_headers.as_ref(),
                    result.server_defaults.as_ref(),
                    vulns_slice,
                    Some(host.as_str()),
                );
                result.rating = Some(rating);
            }
        }

        result.scan_duration_ms = start.elapsed().as_millis() as u64;
        info!(
            "Scan completed for {} in {}ms",
            target, result.scan_duration_ms
        );
        Ok(result)
    }

    /// Scan multiple targets, returning one result per target
    pub async fn scan_batch(&self, targets: &[&str]) -> Vec<Result<ScanResult>> {
        let mut results = Vec::with_capacity(targets.len());
        // Simple sequential approach; for parallel use tokio::spawn
        for &target in targets {
            results.push(self.scan(target).await);
        }
        results
    }
}

/// Parse "host:port", "https://host:port/", or plain "host" into (host, port).
fn parse_target(target: &str) -> Result<(String, u16)> {
    // Strip URI scheme
    let stripped = if let Some(rest) = target.strip_prefix("https://") {
        rest
    } else if let Some(rest) = target.strip_prefix("http://") {
        rest
    } else {
        target
    };

    // Strip path component
    let host_port = stripped.split('/').next().unwrap_or(stripped);

    if let Some(colon_pos) = host_port.rfind(':') {
        let host = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((host.to_string(), port));
        }
    }

    // No port specified — default to 443
    Ok((host_port.to_string(), crate::DEFAULT_PORT))
}

/// Run all vulnerability checks, appending results to the provided Vec.
async fn run_vulnerability_checks(target: &ScanTarget, vulns: &mut Vec<VulnResult>) {
    use crate::checks::vulnerabilities::*;

    macro_rules! run_check {
        ($check:expr, $name:literal) => {
            match $check.await {
                Ok(r) => vulns.push(r),
                Err(e) => warn!("{} check failed: {}", $name, e),
            }
        };
    }

    run_check!(heartbleed::check_heartbleed(target), "Heartbleed");
    run_check!(ccs_injection::check_ccs_injection(target), "CCS Injection");
    run_check!(ticketbleed::check_ticketbleed(target), "Ticketbleed");
    run_check!(robot::check_robot(target), "ROBOT");
    run_check!(
        secure_renegotiation::check_secure_renegotiation(target),
        "Secure Renegotiation"
    );
    run_check!(crime::check_crime(target), "CRIME");
    run_check!(breach::check_breach(target), "BREACH");
    run_check!(poodle::check_poodle(target), "POODLE");
    run_check!(tls_fallback::check_tls_fallback(target), "TLS Fallback");
    run_check!(sweet32::check_sweet32(target), "SWEET32");
    run_check!(freak::check_freak(target), "FREAK");
    run_check!(drown::check_drown(target), "DROWN");
    run_check!(logjam::check_logjam(target), "Logjam");
    run_check!(beast::check_beast(target), "BEAST");
    run_check!(lucky13::check_lucky13(target), "LUCKY13");
    run_check!(rc4::check_rc4(target), "RC4");
}

/// Legacy run_scan function for backward compatibility
pub async fn run_scan(
    target: ScanTarget,
    config: ScanConfig,
) -> Result<crate::output::ScanResults> {
    let mut results = crate::output::ScanResults::new(target.host.clone(), target.port);

    info!("Starting scan of {}:{}", target.host, target.port);

    // Resolve IP if needed
    if target.ip.is_none() {
        match crate::dns::resolve_first_ipv4(&target.host).await {
            Ok(Some(ip)) => {
                results.ip = Some(ip.to_string());
            }
            Ok(None) => {
                warn!("Could not resolve {} to IPv4", target.host);
            }
            Err(e) => {
                warn!("DNS resolution failed: {}", e);
            }
        }
    } else {
        results.ip = target.ip.map(|ip| ip.to_string());
    }

    if config.check_protocols {
        info!("Checking protocol support");
        match crate::checks::protocols::check_protocols(&target).await {
            Ok(proto) => results.protocols = Some(proto),
            Err(e) => warn!("Protocol check failed: {}", e),
        }
    }

    if config.check_server_defaults {
        info!("Checking server defaults");
        match crate::checks::server_defaults::check_server_defaults(&target).await {
            Ok(defaults) => results.server_defaults = Some(defaults),
            Err(e) => warn!("Server defaults check failed: {}", e),
        }
    }

    if config.check_certificate {
        info!("Checking certificate");
        match crate::checks::certificate::check_certificate(&target).await {
            Ok(cert) => results.certificate = Some(cert),
            Err(e) => warn!("Certificate check failed: {}", e),
        }
    }

    if config.check_http_headers {
        info!("Checking HTTP headers");
        match crate::checks::http_headers::check_http_headers(&target).await {
            Ok(headers) => results.http_headers = Some(headers),
            Err(e) => warn!("HTTP headers check failed: {}", e),
        }
    }

    if config.check_forward_secrecy {
        info!("Checking forward secrecy");
        match crate::checks::forward_secrecy::check_forward_secrecy(&target).await {
            Ok(fs) => results.forward_secrecy = Some(fs),
            Err(e) => warn!("Forward secrecy check failed: {}", e),
        }
    }

    if config.check_vulnerabilities {
        use crate::checks::vulnerabilities::*;
        info!("Checking vulnerabilities");

        macro_rules! run_vuln {
            ($check:expr, $name:literal) => {
                match $check.await {
                    Ok(r) => results.vulnerabilities.push(r),
                    Err(e) => warn!("{} check failed: {}", $name, e),
                }
            };
        }

        run_vuln!(heartbleed::check_heartbleed(&target), "Heartbleed");
        run_vuln!(ccs_injection::check_ccs_injection(&target), "CCS Injection");
        run_vuln!(ticketbleed::check_ticketbleed(&target), "Ticketbleed");
        run_vuln!(robot::check_robot(&target), "ROBOT");
        run_vuln!(
            secure_renegotiation::check_secure_renegotiation(&target),
            "Secure Renegotiation"
        );
        run_vuln!(crime::check_crime(&target), "CRIME");
        run_vuln!(breach::check_breach(&target), "BREACH");
        run_vuln!(poodle::check_poodle(&target), "POODLE");
        run_vuln!(tls_fallback::check_tls_fallback(&target), "TLS Fallback");
        run_vuln!(sweet32::check_sweet32(&target), "SWEET32");
        run_vuln!(freak::check_freak(&target), "FREAK");
        run_vuln!(drown::check_drown(&target), "DROWN");
        run_vuln!(logjam::check_logjam(&target), "Logjam");
        run_vuln!(beast::check_beast(&target), "BEAST");
        run_vuln!(lucky13::check_lucky13(&target), "LUCKY13");
        run_vuln!(rc4::check_rc4(&target), "RC4");
    }

    if config.check_client_simulation {
        info!("Running client simulation");
        match crate::checks::client_simulation::run_client_simulation(&target).await {
            Ok(sim) => results.client_simulation = sim,
            Err(e) => warn!("Client simulation failed: {}", e),
        }
    }

    // Calculate rating
    if let Some(ref proto) = results.protocols {
        let rating = crate::checks::rating::rate_server(
            proto,
            results.ciphers.as_ref(),
            results.certificate.as_ref(),
            results.forward_secrecy.as_ref(),
            results.http_headers.as_ref(),
            results.server_defaults.as_ref(),
            Some(results.vulnerabilities.as_slice()),
            Some(&target.host),
        );
        results.rating = Some(rating);
    }

    info!("Scan completed for {}:{}", target.host, target.port);
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_host_only() {
        let (host, port) = parse_target("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, crate::DEFAULT_PORT);
    }

    #[test]
    fn test_parse_target_host_port() {
        let (host, port) = parse_target("example.com:8443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_target_https_url() {
        let (host, port) = parse_target("https://example.com/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, crate::DEFAULT_PORT);
    }

    #[test]
    fn test_parse_target_https_url_with_port() {
        let (host, port) = parse_target("https://example.com:8443/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_target_http_url() {
        let (host, port) = parse_target("http://example.com/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, crate::DEFAULT_PORT);
    }

    #[test]
    fn test_parse_target_http_url_with_port() {
        let (host, port) = parse_target("http://example.com:80/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_target_ip_with_port() {
        let (host, port) = parse_target("192.168.1.1:443").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_target_default_port_443() {
        let (_, port) = parse_target("example.com").unwrap();
        assert_eq!(port, 443);
    }

    #[test]
    fn test_scan_config_default() {
        let cfg = ScanConfig::default();
        assert!(cfg.check_protocols);
        assert!(cfg.check_certificate);
        assert!(!cfg.check_ciphers);
        assert!(!cfg.check_vulnerabilities);
        assert!(!cfg.check_rating);
    }

    #[test]
    fn test_scan_config_all() {
        let cfg = ScanConfig::all();
        assert!(cfg.check_protocols);
        assert!(cfg.check_certificate);
        assert!(cfg.check_ciphers);
        assert!(cfg.check_vulnerabilities);
        assert!(cfg.check_rating);
    }

    #[test]
    fn test_scan_config_minimal() {
        let cfg = ScanConfig::minimal();
        assert!(cfg.check_protocols);
        assert!(cfg.check_certificate);
        assert!(!cfg.check_ciphers);
    }

    #[test]
    fn test_scan_config_builders() {
        let cfg = ScanConfig::default()
            .with_ciphers()
            .with_vulnerabilities()
            .with_forward_secrecy()
            .with_server_defaults()
            .with_server_preference()
            .with_client_simulation()
            .with_grease()
            .with_http_headers();
        assert!(cfg.check_ciphers);
        assert!(cfg.check_vulnerabilities);
        assert!(cfg.check_forward_secrecy);
        assert!(cfg.check_server_defaults);
        assert!(cfg.check_server_preference);
        assert!(cfg.check_client_simulation);
        assert!(cfg.check_grease);
        assert!(cfg.check_http_headers);
    }
}
