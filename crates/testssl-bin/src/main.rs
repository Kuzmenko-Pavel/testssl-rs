//! testssl-rs: TLS/SSL scanner CLI

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use testssl_core::scanner::{run_scan, ScanConfig};
use testssl_core::starttls::StarttlsProtocol;
use testssl_core::ScanTarget;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = build_cli().get_matches();

    // Setup logging
    let log_level = if matches.get_flag("debug") {
        "debug"
    } else if matches.get_flag("quiet") {
        "error"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .with_target(false)
        .init();

    // Parse target
    let uri = matches
        .get_one::<String>("URI")
        .ok_or_else(|| anyhow::anyhow!("No target URI provided"))?;

    let (host, port, starttls) = parse_uri(uri, &matches)?;

    // Build scan target
    let timeout = matches.get_one::<u64>("timeout").copied().unwrap_or(10);
    let mut target = ScanTarget::new(host, port).with_timeout(timeout);

    // Set SNI
    if let Some(sni) = matches.get_one::<String>("sni") {
        target = target.with_sni(sni.clone());
    } else if uri.parse::<std::net::IpAddr>().is_err() {
        // Use hostname as SNI by default
        let host_for_sni = target.host.clone();
        target = target.with_sni(host_for_sni);
    }

    // Set IP if specified
    if let Some(ip_str) = matches.get_one::<String>("ip") {
        if let Ok(ip) = ip_str.parse() {
            target.ip = Some(ip);
        }
    }

    // Set STARTTLS
    if let Some(proto) = starttls {
        target = target.with_starttls(proto);
    }

    // Build scan config
    let config = build_scan_config(&matches);

    // Run scan
    let results = run_scan(target, config).await?;

    // Output results
    let quiet = matches.get_flag("quiet");

    if !quiet {
        testssl_core::output::terminal::print_results(&results);
    }

    // Write JSON output if requested
    if let Some(json_path) = matches.get_one::<PathBuf>("jsonfile") {
        let pretty = !matches.get_flag("json-no-pretty");
        testssl_core::output::json::write_json_file(&results, json_path, pretty)?;
        eprintln!("JSON output written to {}", json_path.display());
    }

    // Write CSV output if requested
    if let Some(csv_path) = matches.get_one::<PathBuf>("csvfile") {
        testssl_core::output::csv::write_csv_file(&results, csv_path)?;
        eprintln!("CSV output written to {}", csv_path.display());
    }

    // Write HTML output if requested
    if let Some(html_path) = matches.get_one::<PathBuf>("htmlfile") {
        testssl_core::output::html::write_html_file(&results, html_path)?;
        eprintln!("HTML output written to {}", html_path.display());
    }

    // Write log file if requested
    if let Some(log_path) = matches.get_one::<PathBuf>("logfile") {
        let json = testssl_core::output::json::write_json(&results, true)?;
        std::fs::write(log_path, json)?;
    }

    // Output JSON to stdout if requested
    if matches.get_flag("jsonfile_pretty") {
        let json = testssl_core::output::json::write_json(&results, true)?;
        println!("{}", json);
    }

    // Return exit code based on findings
    if results
        .vulnerabilities
        .iter()
        .any(|v| v.status == testssl_core::checks::vulnerabilities::VulnStatus::Vulnerable)
    {
        std::process::exit(1);
    }

    Ok(())
}

fn build_cli() -> Command {
    Command::new("testssl")
        .version(testssl_core::VERSION)
        .about("testssl-rs: TLS/SSL scanner - Rust implementation")
        .arg(
            Arg::new("URI")
                .help("URI to scan: <hostname>[:port] or https://<hostname>[:port]")
                .index(1)
        )
        // Protocol options
        .arg(
            Arg::new("sslv2")
                .long("sslv2")
                .help("Check for SSLv2")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("sslv3")
                .long("sslv3")
                .help("Check for SSLv3")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("tls1")
                .long("tls1")
                .help("Check for TLS 1.0")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("tls1_1")
                .long("tls1_1")
                .help("Check for TLS 1.1")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("tls1_2")
                .long("tls1_2")
                .help("Check for TLS 1.2")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("tls1_3")
                .long("tls1_3")
                .help("Check for TLS 1.3")
                .action(ArgAction::SetTrue)
        )
        // Scan options
        .arg(
            Arg::new("protocols")
                .short('p')
                .long("protocols")
                .help("Test all TLS/SSL protocols")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("server-defaults")
                .short('S')
                .long("server-defaults")
                .help("Show server defaults")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("server-preference")
                .short('P')
                .long("server-preference")
                .help("Check server cipher preference")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("server-certificate")
                .short('x')
                .long("server-certificate")
                .help("Show server certificate info")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ciphers")
                .short('e')
                .long("each-cipher")
                .help("Check each cipher")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ciphersuites")
                .short('E')
                .long("cipher-per-proto")
                .help("Check ciphers per protocol")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("forward-secrecy")
                .short('f')
                .long("fs")
                .help("Forward secrecy ciphers")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("http-headers")
                .short('h')
                .long("headers")
                .help("HTTP headers (security headers)")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("vulnerabilities")
                .short('U')
                .long("vulnerable")
                .help("Run all vulnerability checks")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("all")
                .short('a')
                .long("all")
                .help("Run all checks")
                .action(ArgAction::SetTrue)
        )
        // Individual vulnerability checks
        .arg(
            Arg::new("heartbleed")
                .long("heartbleed")
                .help("Check for Heartbleed")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ccs")
                .long("ccs-injection")
                .help("Check for CCS Injection")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("ticketbleed")
                .long("ticketbleed")
                .help("Check for Ticketbleed")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("robot")
                .long("robot")
                .help("Check for ROBOT")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("poodle")
                .long("poodle")
                .help("Check for POODLE SSL")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("tls-fallback")
                .long("tls-fallback")
                .help("Check TLS_FALLBACK_SCSV")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("sweet32")
                .long("sweet32")
                .help("Check for SWEET32")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("beast")
                .long("beast")
                .help("Check for BEAST")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("lucky13")
                .long("lucky13")
                .help("Check for LUCKY13")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("freak")
                .long("freak")
                .help("Check for FREAK")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("drown")
                .long("drown")
                .help("Check for DROWN")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("logjam")
                .long("logjam")
                .help("Check for Logjam")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("breach")
                .long("breach")
                .help("Check for BREACH")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("crime")
                .long("crime")
                .help("Check for CRIME")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("rc4")
                .long("rc4")
                .help("Check for RC4 ciphers")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("winshock")
                .long("winshock")
                .help("Check for WINSHOCK")
                .action(ArgAction::SetTrue)
        )
        // Connection options
        .arg(
            Arg::new("starttls")
                .short('t')
                .long("starttls")
                .value_name("PROTOCOL")
                .help("STARTTLS protocol: smtp, lmtp, imap, pop3, ftp, ldap, xmpp, xmpp-server, postgres, mysql, nntp, sieve, irc")
        )
        .arg(
            Arg::new("sni")
                .long("sni-name")
                .value_name("SNI")
                .help("Specify SNI hostname (default: target hostname)")
        )
        .arg(
            Arg::new("ip")
                .long("ip")
                .value_name("IP")
                .help("Specify IP address to test")
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECS")
                .value_parser(clap::value_parser!(u64))
                .default_value("10")
                .help("Connection timeout in seconds")
        )
        // Output options
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Suppress banner and other output")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("wide")
                .short('w')
                .long("wide")
                .help("Wide output (more columns)")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("color")
                .long("color")
                .value_name("LEVEL")
                .help("Color level: 0 (none), 1 (B/W), 2 (full, default)")
                .default_value("2")
        )
        .arg(
            Arg::new("jsonfile")
                .long("jsonfile")
                .value_name("FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Write JSON output to file")
        )
        .arg(
            Arg::new("jsonfile_pretty")
                .long("jsonfile-pretty")
                .help("Print pretty JSON to stdout")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("json-no-pretty")
                .long("json-no-pretty")
                .help("Write compact (non-pretty) JSON")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("csvfile")
                .long("csvfile")
                .value_name("FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Write CSV output to file")
        )
        .arg(
            Arg::new("htmlfile")
                .long("htmlfile")
                .value_name("FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Write HTML output to file")
        )
        .arg(
            Arg::new("logfile")
                .long("logfile")
                .value_name("FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Write log to file")
        )
        .arg(
            Arg::new("outprefix")
                .long("outprefix")
                .value_name("PREFIX")
                .help("Prefix for output files")
        )
        .arg(
            Arg::new("append")
                .long("append")
                .help("Append to output files")
                .action(ArgAction::SetTrue)
        )
        // Misc
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("Enable debug output")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("sneaky")
                .long("sneaky")
                .help("Sneaky mode (use normal browser UA)")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("fast")
                .long("fast")
                .help("Fast mode (fewer tests)")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("parallel")
                .long("parallel")
                .help("Run tests in parallel")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("nodns")
                .long("nodns")
                .help("Skip DNS lookups")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("assume-http")
                .long("assume-http")
                .help("Assume HTTP service")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("rating")
                .long("rating")
                .help("Enable grading")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("grease")
                .long("grease")
                .help("Check GREASE tolerance")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("client-simulation")
                .long("client-simulation")
                .help("Run client simulation")
                .action(ArgAction::SetTrue)
        )
}

fn parse_uri(
    uri: &str,
    matches: &clap::ArgMatches,
) -> anyhow::Result<(String, u16, Option<StarttlsProtocol>)> {
    let mut starttls = matches
        .get_one::<String>("starttls")
        .and_then(|s| StarttlsProtocol::from_name(s));

    // Strip scheme
    let (scheme, rest) = if let Some(rest) = uri.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = uri.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = uri.strip_prefix("smtp://") {
        if starttls.is_none() {
            starttls = Some(StarttlsProtocol::Smtp);
        }
        ("smtp", rest)
    } else if let Some(rest) = uri.strip_prefix("imap://") {
        if starttls.is_none() {
            starttls = Some(StarttlsProtocol::Imap);
        }
        ("imap", rest)
    } else if let Some(rest) = uri.strip_prefix("pop3://") {
        if starttls.is_none() {
            starttls = Some(StarttlsProtocol::Pop3);
        }
        ("pop3", rest)
    } else if let Some(rest) = uri.strip_prefix("ftp://") {
        if starttls.is_none() {
            starttls = Some(StarttlsProtocol::Ftp);
        }
        ("ftp", rest)
    } else if let Some(rest) = uri.strip_prefix("xmpp://") {
        if starttls.is_none() {
            starttls = Some(StarttlsProtocol::Xmpp);
        }
        ("xmpp", rest)
    } else if let Some(rest) = uri.strip_prefix("postgres://") {
        if starttls.is_none() {
            starttls = Some(StarttlsProtocol::Postgres);
        }
        ("postgres", rest)
    } else if let Some(rest) = uri.strip_prefix("mysql://") {
        if starttls.is_none() {
            starttls = Some(StarttlsProtocol::Mysql);
        }
        ("mysql", rest)
    } else {
        ("", uri)
    };

    // Remove trailing path
    let rest = rest.split('/').next().unwrap_or(rest);

    // Parse host:port
    let default_port: u16 = match scheme {
        "https" => 443,
        "http" => 80,
        "smtp" => 25,
        "imap" => 143,
        "pop3" => 110,
        "ftp" => 21,
        "xmpp" => 5222,
        "postgres" => 5432,
        "mysql" => 3306,
        _ => 443,
    };

    let (host, port) = if rest.contains('[') {
        // IPv6 address like [::1]:port
        if let Some(bracket_end) = rest.find(']') {
            let ip = &rest[1..bracket_end];
            let port_str = rest.get(bracket_end + 2..).unwrap_or("");
            let port = port_str.parse().unwrap_or(default_port);
            (ip.to_string(), port)
        } else {
            (rest.to_string(), default_port)
        }
    } else if rest.contains(':') && !rest.starts_with('[') {
        // Could be host:port or IPv6 without brackets
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[1].parse::<u16>() {
                (parts[0].to_string(), port)
            } else {
                (rest.to_string(), default_port)
            }
        } else {
            (rest.to_string(), default_port)
        }
    } else {
        (rest.to_string(), default_port)
    };

    Ok((host, port, starttls))
}

fn build_scan_config(matches: &clap::ArgMatches) -> ScanConfig {
    if matches.get_flag("all") {
        return ScanConfig::all();
    }

    let check_protocols = matches.get_flag("protocols")
        || matches.get_flag("sslv2")
        || matches.get_flag("sslv3")
        || matches.get_flag("tls1")
        || matches.get_flag("tls1_1")
        || matches.get_flag("tls1_2")
        || matches.get_flag("tls1_3");
    let check_ciphers = matches.get_flag("ciphers") || matches.get_flag("ciphersuites");
    let check_certificate = matches.get_flag("server-certificate");
    let check_http_headers = matches.get_flag("http-headers");
    let check_vulnerabilities = matches.get_flag("vulnerabilities")
        || matches.get_flag("heartbleed")
        || matches.get_flag("ccs")
        || matches.get_flag("ticketbleed")
        || matches.get_flag("robot")
        || matches.get_flag("poodle")
        || matches.get_flag("sweet32")
        || matches.get_flag("beast")
        || matches.get_flag("lucky13")
        || matches.get_flag("freak")
        || matches.get_flag("drown")
        || matches.get_flag("logjam")
        || matches.get_flag("breach")
        || matches.get_flag("crime")
        || matches.get_flag("rc4")
        || matches.get_flag("winshock");
    let check_forward_secrecy = matches.get_flag("forward-secrecy");
    let check_server_defaults = matches.get_flag("server-defaults");
    let check_server_preference = matches.get_flag("server-preference");
    let check_client_simulation = matches.get_flag("client-simulation");
    let check_grease = matches.get_flag("grease");
    let check_rating = matches.get_flag("rating");

    // No explicit check flags → use sensible default: protocols + certificate
    let any_check = check_protocols
        || check_ciphers
        || check_certificate
        || check_http_headers
        || check_vulnerabilities
        || check_forward_secrecy
        || check_server_defaults
        || check_server_preference
        || check_client_simulation
        || check_grease
        || check_rating;

    if !any_check {
        return ScanConfig::default(); // protocols + certificate, no rating
    }

    ScanConfig {
        check_protocols,
        check_ciphers,
        check_certificate,
        check_http_headers,
        check_vulnerabilities,
        check_forward_secrecy,
        check_server_defaults,
        check_server_preference,
        check_client_simulation,
        check_grease,
        check_rating,
        ..ScanConfig::default()
    }
}
