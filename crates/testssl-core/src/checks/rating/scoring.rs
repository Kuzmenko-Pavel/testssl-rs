//! SSL Labs-compatible numeric scoring formulas

use super::model::RatingFacts;
use super::Grade;

/// SSL Labs protocol score table.
fn proto_to_score(proto: &str) -> u32 {
    match proto {
        "SSL2" => 0,
        "SSL3" => 80,
        "TLS1.0" => 90,
        "TLS1.1" => 95,
        "TLS1.2" | "TLS1.3" => 100,
        _ => 0,
    }
}

/// Protocol score: average of best and worst supported protocol scores.
pub fn calc_protocol_score(facts: &RatingFacts) -> u32 {
    let best = proto_to_score(&facts.best_protocol);
    let worst = proto_to_score(&facts.worst_protocol);
    (best + worst) / 2
}

/// SSL Labs key exchange score from RSA-equivalent bits.
pub fn calc_kx_score(facts: &RatingFacts) -> u32 {
    if facts.has_anon {
        return 0;
    }
    match facts.effective_kx_bits {
        0 => 0,
        1..=511 => 20,
        512..=1023 => 40,
        1024..=2047 => 80,
        2048..=4095 => 90,
        _ => 100,
    }
}

/// SSL Labs cipher strength score from key/block bits.
fn cipher_bits_to_score(bits: u16) -> u32 {
    match bits {
        0 => 0,
        1..=127 => 20,
        128..=255 => 80,
        _ => 100,
    }
}

/// Cipher strength score: average of best and worst supported cipher scores.
pub fn calc_cipher_score(facts: &RatingFacts) -> u32 {
    if !facts.cipher_data_available {
        // No cipher data — don't penalize; use a moderate optimistic score
        return 80;
    }
    let best = cipher_bits_to_score(facts.max_cipher_bits);
    let worst = cipher_bits_to_score(facts.min_cipher_bits);
    (best + worst) / 2
}

/// Weighted aggregation: protocol 30%, key exchange 30%, cipher strength 40%.
pub fn calc_numeric_score(protocol: u32, kx: u32, cipher: u32) -> u32 {
    (protocol * 30 + kx * 30 + cipher * 40) / 100
}

/// SSL Labs numeric-to-letter grade translation.
pub fn score_to_base_grade(score: u32) -> Grade {
    match score {
        80..=100 => Grade::A,
        65..=79 => Grade::B,
        50..=64 => Grade::C,
        35..=49 => Grade::D,
        20..=34 => Grade::E,
        _ => Grade::F,
    }
}
