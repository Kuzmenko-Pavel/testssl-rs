//! Integration tests for testssl-core
//!
//! These tests require network access and are gated behind:
//!   TESTSSL_INTEGRATION=1
//!
//! Run with:
//!   TESTSSL_INTEGRATION=1 cargo test -p testssl-core --test integration_tests
//!
//! Default test target: badssl.com subdomains (maintained for TLS testing)

mod integration;
