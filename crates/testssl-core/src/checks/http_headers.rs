//! HTTP security headers check
//!
//! For HTTPS targets (port 443): uses reqwest with rustls to make a real
//! TLS-tunnelled HTTP request and inspect the response headers directly.
//!
//! For plain HTTP targets (port 80): connects via raw TCP and sends HTTP/1.1 GET.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::info;

use crate::ScanTarget;

/// HTTP security headers result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpHeadersResult {
    pub status_code: Option<u16>,
    pub hsts: Option<HstsInfo>,
    pub hpkp: Option<String>,
    pub server: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub content_security_policy: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub cache_control: Option<String>,
    pub x_powered_by: Option<String>,
    pub via: Option<String>,
    pub cookie_flags: Vec<CookieInfo>,
    pub compressed: Option<bool>,
    /// True when the HTTP response was successfully retrieved
    pub http_available: bool,
    /// True when the connection was over TLS
    pub over_tls: bool,
}

/// HSTS header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsInfo {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
    pub raw_value: String,
}

/// Cookie security info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub path: Option<String>,
    pub domain: Option<String>,
}

// ─── Header parsers ──────────────────────────────────────────────────────────

/// Parse Strict-Transport-Security header value
fn parse_hsts(value: &str) -> Option<HstsInfo> {
    let mut max_age = None;
    let mut include_subdomains = false;
    let mut preload = false;

    for part in value.split(';') {
        let part = part.trim();
        if let Some(age_str) = part.strip_prefix("max-age=") {
            if let Ok(age) = age_str.trim().parse::<u64>() {
                max_age = Some(age);
            }
        } else if part.eq_ignore_ascii_case("includeSubDomains") {
            include_subdomains = true;
        } else if part.eq_ignore_ascii_case("preload") {
            preload = true;
        }
    }

    max_age.map(|max_age| HstsInfo {
        max_age,
        include_subdomains,
        preload,
        raw_value: value.to_string(),
    })
}

/// Parse Set-Cookie header value
fn parse_cookie(value: &str) -> CookieInfo {
    let parts: Vec<&str> = value.split(';').collect();
    let name = parts[0].split('=').next().unwrap_or("").trim().to_string();

    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;
    let mut path = None;
    let mut domain = None;

    for part in parts[1..].iter() {
        let part = part.trim();
        if part.eq_ignore_ascii_case("secure") {
            secure = true;
        } else if part.eq_ignore_ascii_case("httponly") {
            http_only = true;
        } else if let Some(ss) = part
            .strip_prefix("SameSite=")
            .or_else(|| part.strip_prefix("samesite="))
        {
            same_site = Some(ss.trim().to_string());
        } else if let Some(p) = part
            .strip_prefix("Path=")
            .or_else(|| part.strip_prefix("path="))
        {
            path = Some(p.trim().to_string());
        } else if let Some(d) = part
            .strip_prefix("Domain=")
            .or_else(|| part.strip_prefix("domain="))
        {
            domain = Some(d.trim().to_string());
        }
    }

    CookieInfo {
        name,
        secure,
        http_only,
        same_site,
        path,
        domain,
    }
}

// ─── HTTP response parsing ────────────────────────────────────────────────────

/// Extract the numeric HTTP status code from the first status line.
fn parse_status_code(status_line: &str) -> Option<u16> {
    // "HTTP/1.1 200 OK"
    let mut parts = status_line.splitn(3, ' ');
    parts.next()?; // skip "HTTP/1.x"
    parts.next()?.trim().parse::<u16>().ok()
}

/// Parse a raw HTTP response byte slice into a result struct.
fn parse_http_response(raw: &[u8]) -> HttpHeadersResult {
    let mut result = HttpHeadersResult {
        http_available: true,
        ..HttpHeadersResult::default()
    };

    // Split headers from body at the first blank line
    let separator = b"\r\n\r\n";
    let header_end = raw
        .windows(separator.len())
        .position(|w| w == separator)
        .unwrap_or(raw.len());

    let header_bytes = &raw[..header_end];
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.lines();

    // Status line
    if let Some(status_line) = lines.next() {
        result.status_code = parse_status_code(status_line);
    }

    // Header lines
    for line in lines {
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_lowercase();
            let value = line[colon + 1..].trim();

            match name.as_str() {
                "strict-transport-security" => {
                    result.hsts = parse_hsts(value);
                }
                "public-key-pins" => {
                    result.hpkp = Some(value.to_string());
                }
                "server" => {
                    result.server = Some(value.to_string());
                }
                "x-frame-options" => {
                    result.x_frame_options = Some(value.to_string());
                }
                "x-content-type-options" => {
                    result.x_content_type_options = Some(value.to_string());
                }
                "x-xss-protection" => {
                    result.x_xss_protection = Some(value.to_string());
                }
                "content-security-policy" => {
                    result.content_security_policy = Some(value.to_string());
                }
                "referrer-policy" => {
                    result.referrer_policy = Some(value.to_string());
                }
                "permissions-policy" | "feature-policy" => {
                    result.permissions_policy = Some(value.to_string());
                }
                "cache-control" => {
                    result.cache_control = Some(value.to_string());
                }
                "x-powered-by" => {
                    result.x_powered_by = Some(value.to_string());
                }
                "via" => {
                    result.via = Some(value.to_string());
                }
                "set-cookie" => {
                    result.cookie_flags.push(parse_cookie(value));
                }
                "content-encoding" => {
                    let lower = value.to_lowercase();
                    result.compressed = Some(
                        lower.contains("gzip")
                            || lower.contains("deflate")
                            || lower.contains("br")
                            || lower.contains("zstd"),
                    );
                }
                _ => {}
            }
        }
    }

    result
}

// ─── HTTP request builder ─────────────────────────────────────────────────────

/// Build an HTTP/1.1 GET request
fn build_http_get(hostname: &str, path: &str) -> Vec<u8> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: testssl/3.3dev\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, hostname
    );
    req.into_bytes()
}

// ─── Main check function ──────────────────────────────────────────────────────

/// Fetch HTTP security headers from the target.
///
/// - HTTPS (port 443 or non-80 without explicit plain signal): uses reqwest
///   with rustls to make a real TLS-tunnelled GET request — this is the only
///   way to correctly see headers like HSTS that servers only send over HTTPS.
/// - Plain HTTP (port 80): connects raw TCP and sends HTTP/1.1 GET.
pub async fn check_http_headers(target: &ScanTarget) -> Result<HttpHeadersResult> {
    info!("Checking HTTP headers for {}:{}", target.host, target.port);

    let hostname = target.sni.as_deref().unwrap_or(target.host.as_str());

    // For port 80: use reqwest with redirect following (a 308 → https:// redirect
    // must be followed to see the real HTTPS security headers).
    // For port 443 / HTTPS: reqwest without redirect — check the actual HTTPS response.
    if target.port == 80 {
        let url = format!("http://{}/", hostname);
        let mut result = try_reqwest(&url, true, target.timeout_secs).await?;
        result.over_tls = false;
        return Ok(result);
    }

    if target.starttls.is_some() && target.port != 443 {
        // Plain-text protocol on non-standard port — raw TCP
        let host_for_connect = target
            .ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| target.host.clone());
        return try_plain_http(
            &host_for_connect,
            hostname,
            target.port,
            target.timeout_secs,
        )
        .await;
    }

    // HTTPS — real TLS via reqwest, no redirects (we want the HTTPS response itself)
    let url = if target.port == 443 {
        format!("https://{}/", hostname)
    } else {
        format!("https://{}:{}/", hostname, target.port)
    };
    let mut result = try_reqwest(&url, false, target.timeout_secs).await?;
    result.over_tls = true;
    Ok(result)
}

/// Fetch HTTP(S) headers using reqwest.
///
/// `follow_redirects`: if true, follows up to 5 redirects (used for port 80
/// where servers typically 301/308 to HTTPS — we want the final HTTPS headers).
/// If false, returns the first response as-is (used for direct HTTPS checks).
async fn try_reqwest(
    url: &str,
    follow_redirects: bool,
    timeout_secs: u64,
) -> Result<HttpHeadersResult> {
    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(5)
    } else {
        reqwest::redirect::Policy::none()
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true) // we want headers even for bad certs
        .redirect(redirect_policy)
        .user_agent("testssl/3.3dev")
        .build()?;

    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(HttpHeadersResult::default()),
    };

    let mut result = HttpHeadersResult {
        http_available: true,
        status_code: Some(response.status().as_u16()),
        ..Default::default()
    };

    // Serialize headers to raw bytes and reuse existing parse_http_response
    let raw_headers: Vec<u8> = response
        .headers()
        .iter()
        .flat_map(|(k, v)| {
            let mut line = format!("{}: ", k.as_str()).into_bytes();
            line.extend_from_slice(v.as_bytes());
            line.extend_from_slice(b"\r\n");
            line
        })
        .collect();

    let parsed = parse_http_response(&raw_headers);
    result.hsts = parsed.hsts;
    result.hpkp = parsed.hpkp;
    result.x_frame_options = parsed.x_frame_options;
    result.x_content_type_options = parsed.x_content_type_options;
    result.x_xss_protection = parsed.x_xss_protection;
    result.content_security_policy = parsed.content_security_policy;
    result.referrer_policy = parsed.referrer_policy;
    result.permissions_policy = parsed.permissions_policy;
    result.server = parsed.server;
    result.x_powered_by = parsed.x_powered_by;
    result.cookie_flags = parsed.cookie_flags;

    Ok(result)
}

/// Attempt to fetch HTTP headers over a plain (unencrypted) TCP connection.
async fn try_plain_http(
    connect_host: &str,
    request_hostname: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<HttpHeadersResult> {
    let addr = format!("{}:{}", connect_host, port);
    let dur = Duration::from_secs(timeout_secs);

    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_e)) => {
            // Connection refused or other OS error — return empty result
            return Ok(HttpHeadersResult::default());
        }
        Err(_) => {
            // Timeout
            return Ok(HttpHeadersResult::default());
        }
    };

    let request = build_http_get(request_hostname, "/");
    if timeout(dur, stream.write_all(&request)).await.is_err() {
        return Ok(HttpHeadersResult::default());
    }

    // Read the response (up to 128 KB)
    let mut response = Vec::with_capacity(8192);
    let mut buf = [0u8; 4096];
    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > 131_072 {
                    break; // stop reading after 128 KB
                }
                // Stop after headers section is complete
                if response.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            _ => break,
        }
    }

    if response.is_empty() {
        return Ok(HttpHeadersResult::default());
    }

    Ok(parse_http_response(&response))
}

// ─── Analysis helpers ─────────────────────────────────────────────────────────

/// Severity of the HSTS configuration
pub fn analyze_hsts(hsts: &Option<HstsInfo>) -> crate::checks::Severity {
    match hsts {
        None => crate::checks::Severity::Medium,
        Some(h) => {
            if h.max_age < 180 * 86400 {
                // Less than 6 months
                crate::checks::Severity::Low
            } else if !h.include_subdomains {
                crate::checks::Severity::Info
            } else {
                crate::checks::Severity::Ok
            }
        }
    }
}

/// Severity of missing X-Frame-Options
pub fn analyze_x_frame_options(xfo: &Option<String>) -> crate::checks::Severity {
    match xfo {
        None => crate::checks::Severity::Medium,
        Some(v) => {
            let upper = v.to_uppercase();
            if upper == "DENY" || upper == "SAMEORIGIN" {
                crate::checks::Severity::Ok
            } else {
                crate::checks::Severity::Low
            }
        }
    }
}

/// Severity of missing X-Content-Type-Options
pub fn analyze_x_content_type_options(xcto: &Option<String>) -> crate::checks::Severity {
    match xcto {
        None => crate::checks::Severity::Low,
        Some(v) if v.to_lowercase() == "nosniff" => crate::checks::Severity::Ok,
        Some(_) => crate::checks::Severity::Low,
    }
}

/// Analyse cookie security flags
pub fn analyze_cookies(
    cookies: &[CookieInfo],
    over_tls: bool,
) -> Vec<(String, crate::checks::Severity)> {
    let mut findings = Vec::new();

    for cookie in cookies {
        if over_tls && !cookie.secure {
            findings.push((
                format!("Cookie '{}' missing Secure flag", cookie.name),
                crate::checks::Severity::Medium,
            ));
        }
        if !cookie.http_only {
            findings.push((
                format!("Cookie '{}' missing HttpOnly flag", cookie.name),
                crate::checks::Severity::Low,
            ));
        }
        if cookie.same_site.is_none() {
            findings.push((
                format!("Cookie '{}' missing SameSite attribute", cookie.name),
                crate::checks::Severity::Low,
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_hsts ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_hsts_max_age_only() {
        let hsts = parse_hsts("max-age=31536000").unwrap();
        assert_eq!(hsts.max_age, 31536000);
        assert!(!hsts.include_subdomains);
        assert!(!hsts.preload);
    }

    #[test]
    fn test_parse_hsts_with_subdomains() {
        let hsts = parse_hsts("max-age=31536000; includeSubDomains").unwrap();
        assert_eq!(hsts.max_age, 31536000);
        assert!(hsts.include_subdomains);
        assert!(!hsts.preload);
    }

    #[test]
    fn test_parse_hsts_with_preload() {
        let hsts = parse_hsts("max-age=31536000; includeSubDomains; preload").unwrap();
        assert_eq!(hsts.max_age, 31536000);
        assert!(hsts.include_subdomains);
        assert!(hsts.preload);
    }

    #[test]
    fn test_parse_hsts_no_max_age_returns_none() {
        let hsts = parse_hsts("includeSubDomains");
        assert!(hsts.is_none());
    }

    #[test]
    fn test_parse_hsts_raw_value_preserved() {
        let raw = "max-age=60; includeSubDomains";
        let hsts = parse_hsts(raw).unwrap();
        assert_eq!(hsts.raw_value, raw);
    }

    #[test]
    fn test_parse_hsts_case_insensitive_preload() {
        let hsts = parse_hsts("max-age=86400; PRELOAD").unwrap();
        assert!(hsts.preload);
    }

    // ── parse_cookie ──────────────────────────────────────────────────────────

    #[test]
    fn test_parse_cookie_basic() {
        let cookie = parse_cookie("sessionid=abc123");
        assert_eq!(cookie.name, "sessionid");
        assert!(!cookie.secure);
        assert!(!cookie.http_only);
        assert!(cookie.same_site.is_none());
    }

    #[test]
    fn test_parse_cookie_with_flags() {
        let cookie = parse_cookie(
            "session=xyz; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com",
        );
        assert_eq!(cookie.name, "session");
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site.as_deref(), Some("Strict"));
        assert_eq!(cookie.path.as_deref(), Some("/"));
        assert_eq!(cookie.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_cookie_samesite_lax() {
        let cookie = parse_cookie("id=1; samesite=Lax");
        assert_eq!(cookie.same_site.as_deref(), Some("Lax"));
    }

    // ── parse_status_code ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_status_code_200() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
    }

    #[test]
    fn test_parse_status_code_301() {
        assert_eq!(
            parse_status_code("HTTP/1.1 301 Moved Permanently"),
            Some(301)
        );
    }

    #[test]
    fn test_parse_status_code_404() {
        assert_eq!(parse_status_code("HTTP/1.1 404 Not Found"), Some(404));
    }

    #[test]
    fn test_parse_status_code_invalid_returns_none() {
        assert_eq!(parse_status_code("bad"), None);
    }

    // ── parse_http_response ───────────────────────────────────────────────────

    #[test]
    fn test_parse_http_response_status_code() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html/>";
        let result = parse_http_response(raw);
        assert!(result.http_available);
        assert_eq!(result.status_code, Some(200));
    }

    #[test]
    fn test_parse_http_response_hsts_header() {
        let raw = b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n\r\n";
        let result = parse_http_response(raw);
        let hsts = result.hsts.unwrap();
        assert_eq!(hsts.max_age, 31536000);
        assert!(hsts.include_subdomains);
    }

    #[test]
    fn test_parse_http_response_server_header() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.server.as_deref(), Some("nginx/1.24.0"));
    }

    #[test]
    fn test_parse_http_response_x_frame_options() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.x_frame_options.as_deref(), Some("DENY"));
    }

    #[test]
    fn test_parse_http_response_x_content_type_options() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.x_content_type_options.as_deref(), Some("nosniff"));
    }

    #[test]
    fn test_parse_http_response_csp() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\r\n";
        let result = parse_http_response(raw);
        assert!(result.content_security_policy.is_some());
    }

    #[test]
    fn test_parse_http_response_referrer_policy() {
        let raw = b"HTTP/1.1 200 OK\r\nReferrer-Policy: no-referrer\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.referrer_policy.as_deref(), Some("no-referrer"));
    }

    #[test]
    fn test_parse_http_response_cache_control() {
        let raw = b"HTTP/1.1 200 OK\r\nCache-Control: no-cache\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.cache_control.as_deref(), Some("no-cache"));
    }

    #[test]
    fn test_parse_http_response_x_powered_by() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.x_powered_by.as_deref(), Some("PHP/8.1"));
    }

    #[test]
    fn test_parse_http_response_via_header() {
        let raw = b"HTTP/1.1 200 OK\r\nVia: 1.1 proxy\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.via.as_deref(), Some("1.1 proxy"));
    }

    #[test]
    fn test_parse_http_response_cookie() {
        let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Secure; HttpOnly\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.cookie_flags.len(), 1);
        assert!(result.cookie_flags[0].secure);
        assert!(result.cookie_flags[0].http_only);
    }

    #[test]
    fn test_parse_http_response_compressed_gzip() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.compressed, Some(true));
    }

    #[test]
    fn test_parse_http_response_compressed_br() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.compressed, Some(true));
    }

    #[test]
    fn test_parse_http_response_not_compressed() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.compressed, Some(false));
    }

    #[test]
    fn test_parse_http_response_permissions_policy() {
        let raw = b"HTTP/1.1 200 OK\r\nPermissions-Policy: geolocation=()\r\n\r\n";
        let result = parse_http_response(raw);
        assert!(result.permissions_policy.is_some());
    }

    #[test]
    fn test_parse_http_response_hpkp() {
        let raw =
            b"HTTP/1.1 200 OK\r\nPublic-Key-Pins: pin-sha256=\"abc\"; max-age=5184000\r\n\r\n";
        let result = parse_http_response(raw);
        assert!(result.hpkp.is_some());
    }

    #[test]
    fn test_parse_http_response_xss_protection() {
        let raw = b"HTTP/1.1 200 OK\r\nX-XSS-Protection: 1; mode=block\r\n\r\n";
        let result = parse_http_response(raw);
        assert_eq!(result.x_xss_protection.as_deref(), Some("1; mode=block"));
    }

    // ── build_http_get ────────────────────────────────────────────────────────

    #[test]
    fn test_build_http_get_contains_host() {
        let req = build_http_get("example.com", "/");
        let req_str = String::from_utf8(req).unwrap();
        assert!(req_str.contains("GET / HTTP/1.1"));
        assert!(req_str.contains("Host: example.com"));
        assert!(req_str.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_build_http_get_custom_path() {
        let req = build_http_get("api.example.com", "/api/v1/status");
        let req_str = String::from_utf8(req).unwrap();
        assert!(req_str.contains("GET /api/v1/status HTTP/1.1"));
    }
}
