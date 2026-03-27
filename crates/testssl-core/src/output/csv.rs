//! CSV output formatter

use anyhow::Result;

use crate::output::ScanResults;

/// Write scan results as CSV
pub fn write_csv(results: &ScanResults) -> Result<String> {
    let mut buf = Vec::new();
    let mut writer = csv::Writer::from_writer(&mut buf);

    // CSV header
    writer.write_record(["target", "port", "id", "severity", "finding"])?;

    // Protocol rows
    if let Some(ref proto) = results.protocols {
        let target = &results.target;
        let port = results.port.to_string();

        let protocols = [
            ("SSLv2", proto.ssl2),
            ("SSLv3", proto.ssl3),
            ("TLS1", proto.tls10),
            ("TLS1_1", proto.tls11),
            ("TLS1_2", proto.tls12),
            ("TLS1_3", proto.tls13),
        ];

        for (id, supported) in &protocols {
            let (severity, finding) = match supported {
                Some(true) if id.starts_with("SSL") => ("CRITICAL", "offered"),
                Some(true) => ("OK", "offered"),
                Some(false) => ("INFO", "not offered"),
                None => ("INFO", "not tested"),
            };
            writer.write_record([target.as_str(), &port, id, severity, finding])?;
        }
    }

    // Vulnerability rows
    for vuln in &results.vulnerabilities {
        let severity = match vuln.status {
            crate::checks::vulnerabilities::VulnStatus::Vulnerable => "VULNERABLE",
            crate::checks::vulnerabilities::VulnStatus::NotVulnerable => "OK",
            crate::checks::vulnerabilities::VulnStatus::Unknown => "WARN",
            crate::checks::vulnerabilities::VulnStatus::NotApplicable => "INFO",
        };
        let finding = if vuln.details.is_empty() {
            vuln.status.to_string()
        } else {
            format!("{}: {}", vuln.status, vuln.details)
        };
        writer.write_record([
            &results.target,
            &results.port.to_string(),
            &vuln.name,
            severity,
            &finding,
        ])?;
    }

    writer.flush()?;
    drop(writer);

    Ok(String::from_utf8(buf)?)
}

/// Write scan results to a CSV file
pub fn write_csv_file(results: &ScanResults, path: &std::path::Path) -> Result<()> {
    let csv = write_csv(results)?;
    std::fs::write(path, csv)?;
    Ok(())
}
