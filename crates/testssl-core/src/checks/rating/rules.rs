//! Rule engine: fatal → cap → warning → bonus phases

use super::model::RatingFacts;
use super::{Grade, RatingResult};

/// Apply all rule phases in order, mutating `result`.
pub fn apply_rules(facts: &RatingFacts, result: &mut RatingResult) {
    apply_fatal_cert_rules(facts, result);
    apply_cap_rules(facts, result);
    apply_warning_rules(facts, result);
    apply_bonus_rule(facts, result);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Apply a grade cap if it is worse than any existing cap.
/// Pushes a human-readable reason and a machine-readable rule code.
fn cap(result: &mut RatingResult, grade: Grade, reason: &str, code: &str) {
    // Only overwrite if the new cap is worse (higher ordinal = worse quality)
    if result.grade_cap.is_none_or(|existing| grade > existing) {
        result.grade_cap = Some(grade);
    }
    result.grade_reasons.push(reason.to_string());
    result.applied_rules.push(code.to_string());
}

/// Add a warning and optionally apply an A- ceiling when the current effective
/// grade is A or better. The A- cap is harmless when the grade is already B or
/// worse because `effective_grade()` always returns the worst of base and cap.
fn warn_and_cap_to_aminus(result: &mut RatingResult, message: &str, code: &str) {
    result.warnings.push(message.to_string());
    result.applied_rules.push(code.to_string());
    // Cap only has effect when current grade is A or APlus
    cap(result, Grade::AMinus, message, &format!("{code}_CAP"));
}

// ── Phase 1: Fatal certificate rules ─────────────────────────────────────────

fn apply_fatal_cert_rules(facts: &RatingFacts, result: &mut RatingResult) {
    if !facts.cert_hostname_match {
        cap(
            result,
            Grade::M,
            "Certificate hostname mismatch",
            "CERT_MISMATCH",
        );
    }
    if !facts.cert_trusted {
        cap(
            result,
            Grade::T,
            "Certificate is not trusted",
            "CERT_UNTRUSTED",
        );
    }
    if facts.cert_expired {
        cap(result, Grade::T, "Certificate is expired", "CERT_EXPIRED");
    }
    if facts.cert_self_signed {
        cap(
            result,
            Grade::T,
            "Certificate is self-signed",
            "CERT_SELF_SIGNED",
        );
    }
    // Insecure signature algorithm (MD2/MD5)
    let sig = facts.cert_sig_algorithm.to_lowercase();
    if sig.contains("md5") || sig.contains("md2") {
        cap(
            result,
            Grade::F,
            "Certificate uses insecure signature algorithm (MD5/MD2)",
            "CERT_INSECURE_SIG",
        );
    }
    // Insecure RSA key
    if (facts.cert_key_type == "RSA" || facts.cert_key_type.is_empty())
        && facts.cert_key_bits > 0
        && facts.cert_key_bits < 512
    {
        cap(
            result,
            Grade::F,
            "Certificate uses insecure RSA key (<512 bits)",
            "CERT_INSECURE_KEY",
        );
    }
}

// ── Phase 2: Cap rules ────────────────────────────────────────────────────────

fn apply_cap_rules(facts: &RatingFacts, result: &mut RatingResult) {
    if facts.has_ssl2 {
        cap(
            result,
            Grade::F,
            "SSLv2 is supported (extremely vulnerable)",
            "SSL2_ENABLED",
        );
    }
    if facts.has_export {
        cap(
            result,
            Grade::F,
            "Export cipher suites are supported (FREAK/LOGJAM)",
            "EXPORT_CIPHER",
        );
    }
    if facts.has_null {
        cap(
            result,
            Grade::F,
            "Null cipher suites are supported (no encryption)",
            "NULL_CIPHER",
        );
    }
    if facts.robot_vulnerable {
        cap(
            result,
            Grade::F,
            "ROBOT vulnerability (Bleichenbacher oracle)",
            "ROBOT_VULN",
        );
    }
    if facts.fs_data_available && !facts.has_forward_secrecy {
        cap(result, Grade::B, "No forward secrecy", "NO_FS");
    }
    if facts.cipher_data_available && !facts.has_aead {
        cap(result, Grade::B, "No AEAD cipher suites", "NO_AEAD");
    }
    if facts.has_ssl3 {
        cap(
            result,
            Grade::B,
            "SSLv3 is supported (POODLE vulnerable)",
            "SSL3_ENABLED",
        );
    }
    // TLS 1.0 cap applies even when TLS 1.2/1.3 are also supported (2020 update)
    if facts.has_tls10 {
        cap(result, Grade::B, "TLS 1.0 is supported", "TLS10_ENABLED");
    }
    if facts.has_tls11 {
        cap(result, Grade::B, "TLS 1.1 is supported", "TLS11_ENABLED");
    }
    if !facts.has_tls12 && !facts.has_tls13 {
        cap(result, Grade::B, "TLS 1.2 is not supported", "NO_TLS12");
    }
    if !facts.chain_complete {
        cap(
            result,
            Grade::B,
            "Certificate chain is incomplete",
            "CHAIN_INCOMPLETE",
        );
    }
    // RC4 with any modern protocol
    if facts.has_rc4 && (facts.has_tls11 || facts.has_tls12 || facts.has_tls13) {
        cap(
            result,
            Grade::C,
            "RC4 cipher suites are supported",
            "RC4_CIPHER",
        );
    }
}

// ── Phase 3: Warning rules ────────────────────────────────────────────────────

fn apply_warning_rules(facts: &RatingFacts, result: &mut RatingResult) {
    if !facts.has_tls13 {
        warn_and_cap_to_aminus(result, "No TLS 1.3 support", "WARN_NO_TLS13");
    }
    if facts.headers_data_available {
        if !facts.hsts_present {
            warn_and_cap_to_aminus(result, "HSTS not configured", "WARN_NO_HSTS");
        } else if !facts.hsts_valid {
            warn_and_cap_to_aminus(
                result,
                "HSTS header is invalid (max-age=0)",
                "WARN_HSTS_INVALID",
            );
        }
    }
    if facts.cert_days_until_expiry > 0 && facts.cert_days_until_expiry < 30 {
        result.warnings.push(format!(
            "Certificate expires in {} days",
            facts.cert_days_until_expiry
        ));
        result.applied_rules.push("WARN_CERT_EXPIRING".to_string());
    }
}

// ── Phase 4: Bonus rule (A+) ──────────────────────────────────────────────────

fn apply_bonus_rule(facts: &RatingFacts, result: &mut RatingResult) {
    // A+ requires: effective grade A, no warnings, valid HSTS with sufficient max-age
    let effective = result.effective_grade();
    if effective == Grade::A
        && result.warnings.is_empty()
        && facts.hsts_valid
        && facts.hsts_max_age >= 15_768_000
        && !facts.cert_expired
        && facts.cert_trusted
        && facts.cert_hostname_match
    {
        result.base_grade = Grade::APlus;
    }
}
