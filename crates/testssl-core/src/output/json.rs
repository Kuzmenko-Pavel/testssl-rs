//! JSON output — compatible with testssl.sh JSON schema
//!
//! Output format matches the original testssl.sh JSON output so that
//! existing parsers/dashboards built for testssl.sh work without changes.
//!
//! Schema: https://github.com/testssl/testssl.sh/blob/3.3dev/doc/testssl.1.md#json-file-output

use anyhow::Result;
use serde_json::{json, Value};

use crate::checks::vulnerabilities::VulnStatus;
use crate::output::ScanResults;

/// Build the full testssl.sh-compatible JSON document
pub fn write_json(results: &ScanResults, pretty: bool) -> Result<String> {
    let doc = build_testssl_json(results);
    if pretty {
        serde_json::to_string_pretty(&doc).map_err(Into::into)
    } else {
        serde_json::to_string(&doc).map_err(Into::into)
    }
}

/// Write scan results to a JSON file
pub fn write_json_file(results: &ScanResults, path: &std::path::Path, pretty: bool) -> Result<()> {
    let json = write_json(results, pretty)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Build the full testssl.sh-compatible JSON document
fn build_testssl_json(results: &ScanResults) -> Value {
    let findings = build_json_findings(results);

    json!({
        "Invocation": format!("testssl-rs {}", env!("CARGO_PKG_VERSION")),
        "at": results.scan_time,
        "version": env!("CARGO_PKG_VERSION"),
        "openssl": "n/a (native Rust TLS)",
        "startTime": unix_now(),
        "scanResult": [{
            "targetHost": results.target,
            "ip": results.ip.as_deref().unwrap_or(""),
            "port": results.port.to_string(),
            "rdns": "",
            "service": "HTTP",
            "findings": findings,
        }],
        "scanTime": 0,
    })
}

/// Build a JSON array of findings in testssl.sh format
pub fn build_json_findings(results: &ScanResults) -> Vec<Value> {
    let mut findings: Vec<Value> = Vec::new();
    let ip = results.ip.as_deref().unwrap_or("");
    let port = results.port.to_string();

    // ── Protocols ──────────────────────────────────────────────────────────
    if let Some(ref proto) = results.protocols {
        let proto_findings = [
            (
                "SSLv2",
                proto.ssl2,
                "CRITICAL",
                "not offered (OK)",
                "offered",
            ),
            ("SSLv3", proto.ssl3, "HIGH", "not offered (OK)", "offered"),
            ("TLS1", proto.tls10, "LOW", "not offered", "offered"),
            ("TLS1_1", proto.tls11, "LOW", "not offered", "offered"),
            ("TLS1_2", proto.tls12, "OK", "offered (OK)", "not offered"),
            ("TLS1_3", proto.tls13, "OK", "offered (OK)", "not offered"),
        ];
        for (id, supported, sev_bad, ok_text, bad_text) in &proto_findings {
            match supported {
                Some(true) => {
                    let sev = if *id == "TLS1_2" || *id == "TLS1_3" {
                        "OK"
                    } else {
                        *sev_bad
                    };
                    findings.push(json!({
                        "id": id, "ip": ip, "port": port,
                        "severity": sev, "finding": bad_text,
                    }));
                }
                Some(false) => {
                    findings.push(json!({
                        "id": id, "ip": ip, "port": port,
                        "severity": "OK", "finding": ok_text,
                    }));
                }
                None => {}
            }
        }
    }

    // ── Vulnerabilities ───────────────────────────────────────────────────
    // Map vuln name → (testssl_id, CVE, CWE)
    let vuln_meta: &[(&str, &str, &str, &str)] = &[
        ("heartbleed", "heartbleed", "CVE-2014-0160", "CWE-119"),
        ("ccs_injection", "CCS", "CVE-2014-0224", "CWE-310"),
        ("ticketbleed", "ticketbleed", "CVE-2016-9244", "CWE-200"),
        ("robot", "ROBOT", "", ""),
        (
            "secure_renegotiation",
            "secure_renego",
            "CVE-2009-3555",
            "CWE-310",
        ),
        ("crime", "CRIME_TLS", "CVE-2012-4929", "CWE-310"),
        ("breach", "BREACH", "CVE-2013-3587", "CWE-310"),
        ("poodle", "POODLE_SSL", "CVE-2014-3566", "CWE-310"),
        ("tls_fallback", "fallback_SCSV", "", ""),
        ("sweet32", "SWEET32", "CVE-2016-2183", "CWE-327"),
        ("freak", "FREAK", "CVE-2015-0204", "CWE-310"),
        ("drown", "DROWN", "CVE-2016-0800", "CWE-310"),
        ("logjam", "LOGJAM", "CVE-2015-4000", "CWE-310"),
        ("beast", "BEAST_CBC_TLS1", "CVE-2011-3389", "CWE-20"),
        ("lucky13", "LUCKY13", "CVE-2013-0169", "CWE-310"),
        ("rc4", "RC4", "CVE-2013-2566", "CWE-326"),
        ("winshock", "winshock", "CVE-2014-6321", "CWE-119"),
    ];

    for vuln in &results.vulnerabilities {
        let name_lower = vuln.name.to_lowercase();
        let meta = vuln_meta.iter().find(|(k, _, _, _)| name_lower.contains(k));
        let (ts_id, cve, cwe) =
            meta.map(|(_, id, cve, cwe)| (*id, *cve, *cwe))
                .unwrap_or((&*vuln.name, "", ""));

        let (severity, finding) = match vuln.status {
            VulnStatus::Vulnerable => ("VULNERABLE", format!("VULNERABLE: {}", vuln.details)),
            VulnStatus::NotVulnerable => (
                "OK",
                format!(
                    "not vulnerable (OK){}",
                    if vuln.details.is_empty() {
                        String::new()
                    } else {
                        format!(", {}", vuln.details)
                    }
                ),
            ),
            VulnStatus::Unknown => ("WARN", format!("check skipped: {}", vuln.details)),
            VulnStatus::NotApplicable => ("INFO", format!("not applicable: {}", vuln.details)),
        };

        let mut f = json!({
            "id": ts_id,
            "ip": ip,
            "port": port,
            "severity": severity,
            "finding": finding,
        });
        if !cve.is_empty() {
            f["cve"] = json!(cve);
        }
        if !cwe.is_empty() {
            f["cwe"] = json!(cwe);
        }
        findings.push(f);
    }

    // ── Certificate ───────────────────────────────────────────────────────
    if let Some(ref cert_result) = results.certificate {
        if let Some(cert) = cert_result.certs.first() {
            findings.push(json!({ "id": "cert_commonName",         "ip": ip, "port": port, "severity": "INFO", "finding": cert.subject }));
            findings.push(json!({ "id": "cert_subjectAltName",     "ip": ip, "port": port, "severity": "INFO", "finding": cert.subject_alt_names.join(" ") }));
            findings.push(json!({ "id": "cert_caIssuers",          "ip": ip, "port": port, "severity": "INFO", "finding": cert.issuer }));
            findings.push(json!({ "id": "cert_signatureAlgorithm", "ip": ip, "port": port, "severity": "INFO", "finding": cert.signature_algorithm }));
            findings.push(json!({ "id": "cert_keySize",            "ip": ip, "port": port, "severity": "INFO", "finding": format!("{} {}", cert.key_type, cert.key_bits) }));
            findings.push(json!({ "id": "cert_fingerprintSHA256",  "ip": ip, "port": port, "severity": "INFO", "finding": cert.fingerprint_sha256 }));
            findings.push(json!({ "id": "cert_notBefore",          "ip": ip, "port": port, "severity": "INFO", "finding": cert.not_before }));
            findings.push(json!({ "id": "cert_notAfter",           "ip": ip, "port": port, "severity": "INFO", "finding": cert.not_after }));

            let (exp_sev, exp_finding) = if cert.is_expired {
                (
                    "CRITICAL",
                    format!(
                        "expired ({} days ago)",
                        cert.days_until_expiry.unsigned_abs()
                    ),
                )
            } else if cert.days_until_expiry < 30 {
                (
                    "HIGH",
                    format!("expires in {} days", cert.days_until_expiry),
                )
            } else if cert.days_until_expiry < 60 {
                (
                    "MEDIUM",
                    format!("expires in {} days", cert.days_until_expiry),
                )
            } else {
                (
                    "OK",
                    format!("{} days ({} left)", cert.days_until_expiry, cert.not_after),
                )
            };
            findings.push(json!({ "id": "cert_expirationStatus", "ip": ip, "port": port, "severity": exp_sev, "finding": exp_finding }));

            if cert.is_self_signed {
                findings.push(json!({ "id": "cert_chain_of_trust", "ip": ip, "port": port, "severity": "CRITICAL", "finding": "self-signed (NOT ok)" }));
            }
            if cert_result.ocsp_must_staple {
                findings.push(json!({ "id": "cert_mustStapleExtension", "ip": ip, "port": port, "severity": "INFO", "finding": "supported" }));
            }
        }
    }

    // ── HTTP headers ──────────────────────────────────────────────────────
    if let Some(ref hdrs) = results.http_headers {
        if let Some(ref hsts) = hdrs.hsts {
            findings.push(
                json!({ "id": "HSTS", "ip": ip, "port": port, "severity": "OK",
                "finding": format!("{} seconds", hsts.max_age) }),
            );
            if hsts.include_subdomains {
                findings.push(json!({ "id": "HSTS_subdomains", "ip": ip, "port": port, "severity": "OK", "finding": "yes" }));
            }
            if hsts.preload {
                findings.push(json!({ "id": "HSTS_preload", "ip": ip, "port": port, "severity": "OK", "finding": "yes" }));
            }
        } else {
            findings.push(json!({ "id": "HSTS", "ip": ip, "port": port, "severity": "LOW", "finding": "not set" }));
        }
        if let Some(ref srv) = hdrs.server {
            findings.push(json!({ "id": "banner_server", "ip": ip, "port": port,
                "severity": "INFO", "finding": srv }));
        }
        if let Some(ref xfo) = hdrs.x_frame_options {
            findings.push(json!({ "id": "X-Frame-Options", "ip": ip, "port": port,
                "severity": "OK", "finding": xfo }));
        }
        if let Some(ref xcto) = hdrs.x_content_type_options {
            findings.push(
                json!({ "id": "X-Content-Type-Options", "ip": ip, "port": port,
                "severity": "OK", "finding": xcto }),
            );
        }
        if let Some(ref csp) = hdrs.content_security_policy {
            findings.push(
                json!({ "id": "Content-Security-Policy", "ip": ip, "port": port,
                "severity": "OK", "finding": &csp[..csp.len().min(80)] }),
            );
        }
    }

    // ── Rating ────────────────────────────────────────────────────────────
    if let Some(ref rating) = results.rating {
        let grade = rating.effective_grade().to_string();
        let sev = match grade.as_str() {
            "A+" | "A" | "A-" => "OK",
            "B" => "LOW",
            "C" => "MEDIUM",
            _ => "HIGH",
        };
        findings.push(json!({
            "id": "rating",
            "ip": ip,
            "port": port,
            "severity": sev,
            "finding": grade,
            "rating_details": {
                "policy": rating.policy_id,
                "numeric_score": rating.overall_score,
                "base_grade": rating.base_grade.to_string(),
                "effective_grade": grade,
                "protocol_score": rating.protocol_score,
                "key_exchange_score": rating.key_exchange_score,
                "cipher_strength_score": rating.cipher_strength_score,
                "warnings": rating.warnings,
                "applied_rules": rating.applied_rules,
            }
        }));
    }

    findings
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
