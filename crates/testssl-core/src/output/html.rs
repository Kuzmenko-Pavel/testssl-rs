//! HTML output formatter

use anyhow::Result;

use crate::checks::vulnerabilities::VulnStatus;
use crate::output::ScanResults;

/// Write scan results as HTML
pub fn write_html(results: &ScanResults) -> Result<String> {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html lang=\"en\">\n");
    html.push_str("<head>\n");
    html.push_str("  <meta charset=\"UTF-8\">\n");
    html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!(
        "  <title>testssl-rs Report - {}:{}</title>\n",
        results.target, results.port
    ));
    html.push_str("  <style>\n");
    html.push_str("    body { font-family: monospace; background: #1a1a1a; color: #e0e0e0; }\n");
    html.push_str("    h1, h2 { color: #00ff88; }\n");
    html.push_str("    .ok { color: #00ff88; }\n");
    html.push_str("    .info { color: #00ccff; }\n");
    html.push_str("    .low { color: #ffff00; }\n");
    html.push_str("    .medium { color: #ffaa00; }\n");
    html.push_str("    .high, .critical { color: #ff4444; font-weight: bold; }\n");
    html.push_str("    table { border-collapse: collapse; width: 100%; }\n");
    html.push_str("    td, th { border: 1px solid #444; padding: 4px 8px; text-align: left; }\n");
    html.push_str("    th { background: #333; color: #00ff88; }\n");
    html.push_str("  </style>\n");
    html.push_str("</head>\n");
    html.push_str("<body>\n");

    html.push_str(&format!(
        "<h1>testssl-rs Scan Report: {}:{}</h1>\n",
        escape_html(&results.target),
        results.port
    ));

    if let Some(ref ip) = results.ip {
        html.push_str(&format!("<p>IP: {}</p>\n", escape_html(ip)));
    }

    // Protocols section
    if let Some(ref proto) = results.protocols {
        html.push_str("<h2>Protocol Support</h2>\n");
        html.push_str("<table>\n");
        html.push_str("<tr><th>Protocol</th><th>Status</th></tr>\n");

        let protocols = [
            ("SSLv2", proto.ssl2, true),
            ("SSLv3", proto.ssl3, true),
            ("TLS 1.0", proto.tls10, false),
            ("TLS 1.1", proto.tls11, false),
            ("TLS 1.2", proto.tls12, false),
            ("TLS 1.3", proto.tls13, false),
        ];

        for (name, supported, is_bad) in &protocols {
            let (class, text) = match supported {
                Some(true) if *is_bad => ("high", "offered (NOT ok)"),
                Some(true) => ("ok", "offered"),
                Some(false) => ("info", "not offered"),
                None => ("info", "not tested"),
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"{}\">{}</td></tr>\n",
                name, class, text
            ));
        }

        html.push_str("</table>\n");
    }

    // Vulnerabilities section
    if !results.vulnerabilities.is_empty() {
        html.push_str("<h2>Vulnerabilities</h2>\n");
        html.push_str("<table>\n");
        html.push_str("<tr><th>Name</th><th>CVE</th><th>Status</th><th>Details</th></tr>\n");

        for vuln in &results.vulnerabilities {
            let (class, status) = match vuln.status {
                VulnStatus::Vulnerable => ("high", "VULNERABLE"),
                VulnStatus::NotVulnerable => ("ok", "not vulnerable"),
                VulnStatus::Unknown => ("low", "unknown"),
                VulnStatus::NotApplicable => ("info", "N/A"),
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>\n",
                escape_html(&vuln.name),
                escape_html(&vuln.cve.join(", ")),
                class,
                status,
                escape_html(&vuln.details),
            ));
        }

        html.push_str("</table>\n");
    }

    // Rating section
    if let Some(ref rating) = results.rating {
        use crate::checks::rating::Grade;
        let eff = rating.effective_grade();
        let grade_class = match eff {
            Grade::APlus | Grade::A | Grade::AMinus => "ok",
            Grade::B => "info",
            Grade::C | Grade::D => "low",
            _ => "high",
        };
        html.push_str("<h2>Overall Grade</h2>\n");
        html.push_str(&format!(
            "<p class=\"{}\">Grade: <strong>{}</strong> (Score: {})</p>\n",
            grade_class,
            escape_html(&eff.to_string()),
            rating.overall_score,
        ));
        if eff != rating.base_grade {
            html.push_str(&format!(
                "<p>Base grade: {} | Protocol: {} | Key exchange: {} | Cipher: {}</p>\n",
                escape_html(&rating.base_grade.to_string()),
                rating.protocol_score,
                rating.key_exchange_score,
                rating.cipher_strength_score,
            ));
        }
        if !rating.warnings.is_empty() {
            html.push_str("<ul>\n");
            for w in &rating.warnings {
                html.push_str(&format!("<li class=\"low\">⚠ {}</li>\n", escape_html(w)));
            }
            html.push_str("</ul>\n");
        }
    }

    html.push_str("</body>\n</html>\n");

    Ok(html)
}

/// Write HTML to file
pub fn write_html_file(results: &ScanResults, path: &std::path::Path) -> Result<()> {
    let html = write_html(results)?;
    std::fs::write(path, html)?;
    Ok(())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
