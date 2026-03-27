//! Shared helpers for integration tests

/// Returns true if integration tests are enabled via env var.
/// All integration tests must call this guard at the start.
pub fn integration_enabled() -> bool {
    std::env::var("TESTSSL_INTEGRATION")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Skip macro — returns early with a pass if integration is not enabled
#[macro_export]
macro_rules! require_integration {
    () => {
        if !$crate::integration::helpers::integration_enabled() {
            eprintln!("Skipping integration test (set TESTSSL_INTEGRATION=1 to run)");
            return;
        }
    };
}

/// Build a ScanTarget for a host:port
pub fn target(host: &str, port: u16) -> testssl_core::ScanTarget {
    testssl_core::ScanTarget::new(host, port)
}
