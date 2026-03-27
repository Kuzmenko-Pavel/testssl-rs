//! Terminal/console output with color support
//!
//! Output style matches testssl.sh terminal output for familiar UX.

use colored::Colorize;

use crate::checks::vulnerabilities::VulnStatus;
use crate::checks::Severity;
use crate::output::ScanResults;

const COL_WIDTH: usize = 36;

/// Print scan results to terminal in testssl.sh style
pub fn print_results(results: &ScanResults) {
    print_banner(results);

    if let Some(ref proto) = results.protocols {
        section(" Testing protocols via sockets");
        print_protocol(" SSLv2", proto.ssl2, true);
        print_protocol(" SSLv3", proto.ssl3, true);
        print_protocol(" TLS 1", proto.tls10, false);
        print_protocol(" TLS 1.1", proto.tls11, false);
        print_protocol(" TLS 1.2", proto.tls12, false);
        print_protocol(" TLS 1.3", proto.tls13, false);
        println!();
    }

    if let Some(ref defaults) = results.server_defaults {
        section(" Testing server defaults (RFC-compliant)");
        if let Some(hb) = defaults.heartbeat {
            let v = if hb {
                "offered".yellow().to_string()
            } else {
                "not offered".normal().to_string()
            };
            row("Heartbeat (extension)", &v);
        }
        if !defaults.tls_extensions.is_empty() {
            row(
                "TLS extensions (standard)",
                &defaults.tls_extensions.join(" "),
            );
        }
        if let Some(st) = defaults.session_ticket {
            let v = if st {
                "offered".normal().to_string()
            } else {
                "not offered".normal().to_string()
            };
            row("Session Ticket", &v);
        }
        println!();
    }

    if let Some(ref fs) = results.forward_secrecy {
        section(" Testing robust forward secrecy (FS) -- omitting Null Authentication/Encryption, 3DES, RC4");
        if fs.has_fs {
            let details = format!(
                "{} (offered{}{})",
                "Forward Secrecy".green().bold(),
                if fs.num_ecdhe > 0 {
                    format!(", {} ECDHE", fs.num_ecdhe)
                } else {
                    String::new()
                },
                if fs.num_dhe > 0 {
                    format!(", {} DHE", fs.num_dhe)
                } else {
                    String::new()
                },
            );
            println!(" {:<COL_WIDTH$} {}", "", details);
        } else {
            row("Forward Secrecy", &"not offered".red().to_string());
        }
        println!();
    }

    if let Some(ref cert) = results.certificate {
        section(" Testing server certificate(s)");
        for (i, c) in cert.certs.iter().enumerate() {
            if i > 0 {
                println!("  --- Certificate #{} ---", i + 1);
            }
            row("Common Name (CN)", &c.subject);
            if !c.subject_alt_names.is_empty() {
                row("subjectAltName (SAN)", &c.subject_alt_names.join(" "));
            }
            row("Issuer", &c.issuer);
            row("Signature Algorithm", &c.signature_algorithm);
            row("Key", &format!("{} {} bits", c.key_type, c.key_bits));
            row("Fingerprint / Serial", &c.fingerprint_sha256);
            row("Not valid before", &c.not_before);

            let expiry_str = if c.is_expired {
                format!(
                    "{} (EXPIRED {}d ago)",
                    c.not_after,
                    c.days_until_expiry.unsigned_abs()
                )
                .red()
                .bold()
                .to_string()
            } else if c.days_until_expiry < 30 {
                format!("{} ({} days left)", c.not_after, c.days_until_expiry)
                    .red()
                    .to_string()
            } else if c.days_until_expiry < 60 {
                format!("{} ({} days left)", c.not_after, c.days_until_expiry)
                    .yellow()
                    .to_string()
            } else {
                format!("{} ({} days left)", c.not_after, c.days_until_expiry)
                    .green()
                    .to_string()
            };
            row("Not valid after", &expiry_str);

            if c.is_self_signed && !c.is_root_ca {
                row(
                    "Trust (hostname)",
                    &"SELF-SIGNED (NOT ok)".red().bold().to_string(),
                );
            }
        }
        if cert.ocsp_must_staple {
            row("OCSP Must-Staple", &"supported".green().to_string());
        }
        println!();
    }

    if let Some(ref headers) = results.http_headers {
        section(" Testing HTTP security headers");
        if let Some(ref hsts) = headers.hsts {
            let max_age = hsts.max_age;
            let subs = if hsts.include_subdomains {
                ", includeSubDomains"
            } else {
                ""
            };
            let pre = if hsts.preload { ", preload" } else { "" };
            let s = format!("max-age={}{}{}", max_age, subs, pre);
            let colored = if max_age >= 180 * 86400 {
                s.green().to_string()
            } else {
                format!("{} (too short!)", s).yellow().to_string()
            };
            row("Strict Transport Security", &colored);
        } else {
            row(
                "Strict Transport Security",
                &"not set (NOT ok)".red().to_string(),
            );
        }
        if let Some(ref xfo) = headers.x_frame_options {
            row("X-Frame-Options", &xfo.green().to_string());
        } else {
            row("X-Frame-Options", &"not set".yellow().to_string());
        }
        if let Some(ref xcto) = headers.x_content_type_options {
            row("X-Content-Type-Options", &xcto.green().to_string());
        } else {
            row("X-Content-Type-Options", &"not set".yellow().to_string());
        }
        if let Some(ref csp) = headers.content_security_policy {
            let short = &csp[..csp.len().min(60)];
            row("Content-Security-Policy", &short.green().to_string());
        } else {
            row("Content-Security-Policy", &"not set".yellow().to_string());
        }
        if let Some(ref srv) = headers.server {
            row("Server banner", &srv.yellow().to_string());
        }
        println!();
    }

    if !results.vulnerabilities.is_empty() {
        section(" Testing vulnerabilities");
        for vuln in &results.vulnerabilities {
            let label = vuln_label(&vuln.name);
            let finding = match vuln.status {
                VulnStatus::Vulnerable => {
                    let cve = if !vuln.cve.is_empty() {
                        format!(" ({})", vuln.cve.join(", "))
                    } else {
                        String::new()
                    };
                    format!("{}{}", format!("VULNERABLE{}", cve).red().bold(), {
                        if vuln.details.is_empty() {
                            String::new()
                        } else {
                            format!(", {}", vuln.details)
                        }
                    })
                }
                VulnStatus::NotVulnerable => {
                    format!(
                        "{}{}",
                        "not vulnerable (OK)".green(),
                        if vuln.details.is_empty() {
                            String::new()
                        } else {
                            format!(", {}", vuln.details)
                        }
                    )
                }
                VulnStatus::Unknown => {
                    format!(
                        "{}{}",
                        "check skipped".yellow(),
                        if vuln.details.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", vuln.details)
                        }
                    )
                }
                VulnStatus::NotApplicable => "not applicable".normal().to_string(),
            };
            println!(" {:<COL_WIDTH$} {}", label.bold(), finding);
        }
        println!();
    }

    if let Some(ref rating) = results.rating {
        let eff = rating.effective_grade();
        let base = rating.base_grade;
        let eff_str = eff.to_string();
        let colored_grade = match eff_str.as_str() {
            "A+" | "A" | "A-" => eff_str.green().bold().to_string(),
            "B" => eff_str.blue().bold().to_string(),
            "C" => eff_str.yellow().bold().to_string(),
            _ => eff_str.red().bold().to_string(),
        };
        section(" Rating");
        println!(
            " {:<COL_WIDTH$} {} (score: {})",
            "Grade:".bold(),
            colored_grade,
            rating.overall_score
        );
        // Show base grade if it differs from effective (i.e. a cap or bonus was applied)
        if base != eff {
            println!(
                " {:<COL_WIDTH$} {} (protocol: {}, key exchange: {}, cipher: {})",
                "Base:".bold(),
                base.to_string().normal(),
                rating.protocol_score,
                rating.key_exchange_score,
                rating.cipher_strength_score,
            );
        } else {
            println!(
                " {:<COL_WIDTH$} protocol: {}, key exchange: {}, cipher: {}",
                "Scores:".bold(),
                rating.protocol_score,
                rating.key_exchange_score,
                rating.cipher_strength_score,
            );
        }
        if rating.grade_reasons.is_empty() {
            println!(" {:<COL_WIDTH$} [none]", "Caps:".bold());
        } else {
            for reason in &rating.grade_reasons {
                println!("   -- {}", reason.yellow());
            }
        }
        for warning in &rating.warnings {
            println!("   !! {}", warning.yellow());
        }
        println!();
    }

    println!(
        " Done {} scanning {}:{}",
        now_str(),
        results.target,
        results.port
    );
    println!();
}

fn print_banner(results: &ScanResults) {
    let line = "###########################################################";
    println!();
    println!("{}", line.bold());
    println!(
        "{}  testssl-rs {}  ({})",
        " ".repeat(5),
        env!("CARGO_PKG_VERSION"),
        "https://github.com/testssl/testssl-rs".dimmed()
    );
    println!("{}", line.bold());
    println!();
    let ip_part = results
        .ip
        .as_deref()
        .map(|ip| format!(" ({})", ip))
        .unwrap_or_default();
    println!(
        " Start {}        -->> {}:{}{} <<--",
        now_str().dimmed(),
        results.target.bold().yellow(),
        results.port,
        ip_part.dimmed()
    );
    println!();
}

fn section(title: &str) {
    println!("{}", title.bold().underline());
    println!();
}

fn row(label: &str, value: &str) {
    println!(" {:<COL_WIDTH$} {}", format!("{}:", label).bold(), value);
}

fn print_protocol(name: &str, supported: Option<bool>, is_ssl: bool) {
    let label = format!("{}:", name);
    match supported {
        Some(true) if is_ssl => {
            println!(
                " {:<COL_WIDTH$} {}",
                label.bold(),
                "offered (NOT ok)".red().bold()
            );
        }
        Some(true)
            if name.contains("1.1") || name.contains("TLS 1 ") || name.trim_start().eq("TLS 1") =>
        {
            println!(
                " {:<COL_WIDTH$} {}",
                label.bold(),
                "offered (deprecated)".yellow()
            );
        }
        Some(true) => {
            println!(" {:<COL_WIDTH$} {}", label.bold(), "offered (OK)".green());
        }
        Some(false) if is_ssl => {
            println!(
                " {:<COL_WIDTH$} {}",
                label.bold(),
                "not offered (OK)".green()
            );
        }
        Some(false) => {
            println!(" {:<COL_WIDTH$} {}", label.bold(), "not offered".normal());
        }
        None => {
            println!(" {:<COL_WIDTH$} {}", label.bold(), "not tested".dimmed());
        }
    }
}

fn vuln_label(name: &str) -> String {
    // Map internal names → display labels matching testssl.sh
    match name.to_lowercase().as_str() {
        n if n.contains("heartbleed") => "Heartbleed (CVE-2014-0160)".to_string(),
        n if n.contains("ccs") => "CCS (CVE-2014-0224)".to_string(),
        n if n.contains("ticketbleed") => "Ticketbleed (CVE-2016-9244)".to_string(),
        n if n.contains("robot") => "ROBOT".to_string(),
        n if n.contains("secure_rene") => "Secure Renegotiation (RFC 5746)".to_string(),
        n if n.contains("crime") => "CRIME, TLS (CVE-2012-4929)".to_string(),
        n if n.contains("breach") => "BREACH (CVE-2013-3587)".to_string(),
        n if n.contains("poodle") => "POODLE, SSL (CVE-2014-3566)".to_string(),
        n if n.contains("fallback") => "TLS_FALLBACK_SCSV (RFC 7507)".to_string(),
        n if n.contains("sweet32") => "SWEET32 (CVE-2016-2183)".to_string(),
        n if n.contains("freak") => "FREAK (CVE-2015-0204)".to_string(),
        n if n.contains("drown") => "DROWN (CVE-2016-0800)".to_string(),
        n if n.contains("logjam") => "LOGJAM (CVE-2015-4000)".to_string(),
        n if n.contains("beast") => "BEAST (CVE-2011-3389)".to_string(),
        n if n.contains("lucky13") => "LUCKY13 (CVE-2013-0169)".to_string(),
        n if n.contains("rc4") => "RC4 (CVE-2013-2566)".to_string(),
        n if n.contains("winshock") => "WINSHOCK (CVE-2014-6321)".to_string(),
        _ => name.to_string(),
    }
}

fn now_str() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple UTC formatting without chrono
    let s = secs;
    let (y, mo, d, h, mi, sc) = epoch_to_ymd_hms(s);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, mo, d, h, mi, sc
    )
}

fn epoch_to_ymd_hms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let sc = (secs % 60) as u32;
    let mi = ((secs / 60) % 60) as u32;
    let h = ((secs / 3600) % 24) as u32;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    (y, mo, d, h, mi, sc)
}

fn days_to_ymd(mut days: u64) -> (u32, u32, u32) {
    // Days since 1970-01-01
    days += 719468;
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y as u32, mo as u32, d as u32)
}

/// Print a finding with appropriate color (used from scanner)
pub fn print_finding(severity: Severity, title: &str, finding: &str) {
    let colored_title = match severity {
        Severity::Ok => title.green().to_string(),
        Severity::Info => title.cyan().to_string(),
        Severity::Low => title.yellow().to_string(),
        Severity::Medium => title.bright_yellow().to_string(),
        Severity::High => title.red().to_string(),
        Severity::Critical => title.red().bold().to_string(),
    };
    println!(" {:<COL_WIDTH$} {}", colored_title, finding);
}
