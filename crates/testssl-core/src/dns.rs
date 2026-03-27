//! DNS resolution utilities

use anyhow::{Context, Result};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::IpAddr;
use tracing::debug;

/// DNS resolver wrapper
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
}

impl DnsResolver {
    /// Create a new DNS resolver using system defaults
    pub async fn new() -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self { resolver })
    }

    /// Create a DNS resolver with custom config
    pub async fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(config, opts);
        Ok(Self { resolver })
    }

    /// Resolve a hostname to IP addresses
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        debug!("Resolving {}", hostname);

        // Check if it's already an IP address
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let response = self
            .resolver
            .lookup_ip(hostname)
            .await
            .with_context(|| format!("Failed to resolve {}", hostname))?;

        let addrs: Vec<IpAddr> = response.iter().collect();
        debug!("Resolved {} to {} addresses", hostname, addrs.len());

        Ok(addrs)
    }

    /// Resolve only IPv4 addresses
    pub async fn resolve_ipv4(&self, hostname: &str) -> Result<Vec<std::net::Ipv4Addr>> {
        let response = self
            .resolver
            .ipv4_lookup(hostname)
            .await
            .with_context(|| format!("Failed to resolve IPv4 for {}", hostname))?;

        Ok(response.iter().map(|r| r.0).collect())
    }

    /// Resolve only IPv6 addresses
    pub async fn resolve_ipv6(&self, hostname: &str) -> Result<Vec<std::net::Ipv6Addr>> {
        let response = self
            .resolver
            .ipv6_lookup(hostname)
            .await
            .with_context(|| format!("Failed to resolve IPv6 for {}", hostname))?;

        Ok(response.iter().map(|r| r.0).collect())
    }

    /// Reverse DNS lookup
    pub async fn reverse_lookup(&self, ip: IpAddr) -> Result<Vec<String>> {
        let response = self
            .resolver
            .reverse_lookup(ip)
            .await
            .with_context(|| format!("Failed to reverse lookup for {}", ip))?;

        Ok(response.iter().map(|r| r.0.to_string()).collect())
    }

    /// Lookup MX records
    pub async fn mx_lookup(&self, domain: &str) -> Result<Vec<(u16, String)>> {
        let response = self
            .resolver
            .mx_lookup(domain)
            .await
            .with_context(|| format!("Failed to lookup MX for {}", domain))?;

        let mut mx_records: Vec<(u16, String)> = response
            .iter()
            .map(|r| (r.preference(), r.exchange().to_string()))
            .collect();

        mx_records.sort_by_key(|(pref, _)| *pref);
        Ok(mx_records)
    }

    /// Lookup CAA records
    pub async fn caa_lookup(&self, _domain: &str) -> Result<Vec<String>> {
        // CAA records would require additional setup with hickory
        // Return empty for now
        Ok(Vec::new())
    }
}

/// Convenience function to resolve a hostname
pub async fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>> {
    let resolver = DnsResolver::new().await?;
    resolver.resolve(hostname).await
}

/// Get the first IPv4 address for a hostname
pub async fn resolve_first_ipv4(hostname: &str) -> Result<Option<IpAddr>> {
    let resolver = DnsResolver::new().await?;
    let addrs = resolver.resolve(hostname).await?;
    Ok(addrs.into_iter().find(|a| a.is_ipv4()))
}
