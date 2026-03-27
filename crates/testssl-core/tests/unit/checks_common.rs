//! Unit tests for checks/mod.rs — Severity, Finding, CheckResult

use testssl_core::checks::{CheckResult, Finding, Severity};

// ── Severity ──────────────────────────────────────────────────────────────────

#[test]
fn test_severity_display() {
    assert_eq!(Severity::Ok.to_string(), "OK");
    assert_eq!(Severity::Info.to_string(), "INFO");
    assert_eq!(Severity::Low.to_string(), "LOW");
    assert_eq!(Severity::Medium.to_string(), "MEDIUM");
    assert_eq!(Severity::High.to_string(), "HIGH");
    assert_eq!(Severity::Critical.to_string(), "CRITICAL");
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Ok < Severity::Info);
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn test_severity_equality() {
    assert_eq!(Severity::High, Severity::High);
    assert_ne!(Severity::High, Severity::Critical);
}

// ── Finding ───────────────────────────────────────────────────────────────────

#[test]
fn test_finding_new() {
    let f = Finding::new("heartbleed", "Heartbleed", Severity::Critical, "vulnerable");
    assert_eq!(f.id, "heartbleed");
    assert_eq!(f.title, "Heartbleed");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.finding, "vulnerable");
    assert!(f.cve.is_empty());
}

#[test]
fn test_finding_with_cve() {
    let f = Finding::new("heartbleed", "Heartbleed", Severity::Critical, "vulnerable")
        .with_cve("CVE-2014-0160");
    assert_eq!(f.cve, vec!["CVE-2014-0160"]);
}

#[test]
fn test_finding_multiple_cve() {
    let f = Finding::new("test", "Test", Severity::High, "finding")
        .with_cve("CVE-2020-1234")
        .with_cve("CVE-2021-5678");
    assert_eq!(f.cve.len(), 2);
    assert!(f.cve.contains(&"CVE-2020-1234".to_string()));
    assert!(f.cve.contains(&"CVE-2021-5678".to_string()));
}

// ── CheckResult ───────────────────────────────────────────────────────────────

#[test]
fn test_check_result_new_is_empty() {
    let cr = CheckResult::new();
    assert!(cr.findings.is_empty());
}

#[test]
fn test_check_result_default_is_empty() {
    let cr = CheckResult::default();
    assert!(cr.findings.is_empty());
}

#[test]
fn test_check_result_add_finding() {
    let mut cr = CheckResult::new();
    cr.add(Finding::new("test", "Test", Severity::Info, "finding"));
    assert_eq!(cr.findings.len(), 1);
}

#[test]
fn test_check_result_is_vulnerable_with_medium() {
    let mut cr = CheckResult::new();
    cr.add(Finding::new("test", "Test", Severity::Medium, "finding"));
    assert!(cr.is_vulnerable());
}

#[test]
fn test_check_result_is_vulnerable_with_high() {
    let mut cr = CheckResult::new();
    cr.add(Finding::new("test", "Test", Severity::High, "finding"));
    assert!(cr.is_vulnerable());
}

#[test]
fn test_check_result_is_vulnerable_with_critical() {
    let mut cr = CheckResult::new();
    cr.add(Finding::new("test", "Test", Severity::Critical, "finding"));
    assert!(cr.is_vulnerable());
}

#[test]
fn test_check_result_not_vulnerable_with_ok() {
    let mut cr = CheckResult::new();
    cr.add(Finding::new("test", "Test", Severity::Ok, "finding"));
    assert!(!cr.is_vulnerable());
}

#[test]
fn test_check_result_not_vulnerable_with_info() {
    let mut cr = CheckResult::new();
    cr.add(Finding::new("test", "Test", Severity::Info, "finding"));
    assert!(!cr.is_vulnerable());
}

#[test]
fn test_check_result_not_vulnerable_with_low() {
    let mut cr = CheckResult::new();
    cr.add(Finding::new("test", "Test", Severity::Low, "finding"));
    assert!(!cr.is_vulnerable());
}

#[test]
fn test_check_result_empty_not_vulnerable() {
    let cr = CheckResult::new();
    assert!(!cr.is_vulnerable());
}
