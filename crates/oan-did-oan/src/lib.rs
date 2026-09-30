// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! `did:oan` current did:oan parsing, generation, and validation.

use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;
use thiserror::Error;

pub const DID_PREFIX: &str = "did:oan:";
pub const ROUTING_CODE_LEN: usize = 5;
pub const SUFFIX_CODE_LEN: usize = 32;
pub const DID_LEN: usize = 46;
pub const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn did_regex() -> &'static Regex {
    static DID_RE: OnceLock<Regex> = OnceLock::new();
    DID_RE.get_or_init(|| {
        Regex::new(r"^did:oan:[1-9A-HJ-NP-Za-km-z]{5}:[1-9A-HJ-NP-Za-km-z]{32}$").unwrap()
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidOanError {
    #[error("did must start with did:oan")]
    InvalidPrefix,
    #[error("did must have 4 colon-separated parts")]
    InvalidPartCount,
    #[error("routing-code must be exactly 5 case-sensitive Base58 characters")]
    InvalidRoutingCode,
    #[error("suffix-code must be exactly 32 Base58 characters")]
    InvalidSuffixCode,
    #[error("invalid did:oan current did:oan syntax")]
    InvalidSyntax,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DidOan {
    value: String,
    routing_code: String,
    suffix_code: String,
}

impl DidOan {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, DidOanError> {
        let value = value.as_ref();
        if !value.starts_with(DID_PREFIX) {
            return Err(DidOanError::InvalidPrefix);
        }
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 4 {
            return Err(DidOanError::InvalidPartCount);
        }
        let routing_code = parts[2];
        validate_routing_code(routing_code)?;
        let suffix_code = parts[3];
        validate_suffix_code(suffix_code)?;
        if !did_regex().is_match(value) {
            return Err(DidOanError::InvalidSyntax);
        }
        Ok(Self {
            value: value.to_owned(),
            routing_code: routing_code.to_owned(),
            suffix_code: suffix_code.to_owned(),
        })
    }

    pub fn generate(routing_code: &str) -> Result<Self, DidOanError> {
        validate_routing_code(routing_code)?;
        Self::parse(format!(
            "{DID_PREFIX}{routing_code}:{}",
            random_base58_suffix()
        ))
    }

    pub fn derive(
        routing_code: &str,
        controller_material: &[u8],
        nonce: &[u8],
    ) -> Result<Self, DidOanError> {
        validate_routing_code(routing_code)?;
        let mut hasher = Sha256::new();
        hasher.update(b"OAN-DID-SUFFIX-v2");
        hasher.update(routing_code.as_bytes());
        hasher.update(controller_material);
        hasher.update(nonce);
        Self::parse(format!(
            "{DID_PREFIX}{routing_code}:{}",
            derived_base58_suffix(hasher)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
    pub fn routing_code(&self) -> &str {
        &self.routing_code
    }
    pub fn suffix_code(&self) -> &str {
        &self.suffix_code
    }
    pub fn key_id(&self, fragment: &str) -> String {
        format!("{}#{}", self.value, fragment.trim_start_matches('#'))
    }
}

impl Display for DidOan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl FromStr for DidOan {
    type Err = DidOanError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

pub fn validate(value: &str) -> Result<(), DidOanError> {
    DidOan::parse(value).map(|_| ())
}

pub fn validate_routing_code(value: &str) -> Result<(), DidOanError> {
    if value.len() == ROUTING_CODE_LEN && value.chars().all(|ch| BASE58_ALPHABET.contains(ch)) {
        Ok(())
    } else {
        Err(DidOanError::InvalidRoutingCode)
    }
}

pub fn validate_suffix_code(value: &str) -> Result<(), DidOanError> {
    if value.len() == SUFFIX_CODE_LEN && value.chars().all(|ch| BASE58_ALPHABET.contains(ch)) {
        Ok(())
    } else {
        Err(DidOanError::InvalidSuffixCode)
    }
}

fn random_base58_suffix() -> String {
    let mut suffix = String::with_capacity(SUFFIX_CODE_LEN);
    let mut bytes = [0u8; 64];
    while suffix.len() < SUFFIX_CODE_LEN {
        OsRng.fill_bytes(&mut bytes);
        push_unbiased_base58_chars(&mut suffix, &bytes);
    }
    suffix.truncate(SUFFIX_CODE_LEN);
    suffix
}

fn derived_base58_suffix(seed_hasher: Sha256) -> String {
    let mut suffix = String::with_capacity(SUFFIX_CODE_LEN);
    let mut counter = 0u64;
    while suffix.len() < SUFFIX_CODE_LEN {
        let mut hasher = seed_hasher.clone();
        hasher.update(counter.to_be_bytes());
        push_unbiased_base58_chars(&mut suffix, hasher.finalize().as_slice());
        counter += 1;
    }
    suffix.truncate(SUFFIX_CODE_LEN);
    suffix
}

fn push_unbiased_base58_chars(output: &mut String, bytes: &[u8]) {
    let alphabet = BASE58_ALPHABET.as_bytes();
    let rejection_zone = u8::MAX - (u8::MAX % alphabet.len() as u8);
    for byte in bytes {
        if *byte < rejection_zone {
            output.push(alphabet[(*byte as usize) % alphabet.len()] as char);
            if output.len() == SUFFIX_CODE_LEN {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SUFFIX: &str = "7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz";

    #[test]
    fn parses_oan_did_without_type_inference() {
        let did = DidOan::parse(format!("did:oan:K7mQ9:{SUFFIX}")).unwrap();
        assert_eq!(did.routing_code(), "K7mQ9");
        assert_eq!(did.suffix_code(), SUFFIX);
        assert_eq!(did.as_str().len(), DID_LEN);
    }

    #[test]
    fn preserves_case_and_treats_codes_as_distinct() {
        let upper = DidOan::parse(format!("did:oan:K7mQ9:{SUFFIX}")).unwrap();
        let lower = DidOan::parse(format!("did:oan:k7mQ9:{SUFFIX}")).unwrap();
        assert_ne!(upper, lower);
        assert_eq!(lower.routing_code(), "k7mQ9");
    }

    #[test]
    fn rejects_legacy_and_malformed_identifiers() {
        let cases = [
            (
                format!("did:oan:SKFI:{SUFFIX}"),
                DidOanError::InvalidRoutingCode,
            ),
            (
                format!("did:oan:K7mQ:{SUFFIX}"),
                DidOanError::InvalidRoutingCode,
            ),
            (
                format!("did:oan:K7mQ90:{SUFFIX}"),
                DidOanError::InvalidRoutingCode,
            ),
            (
                format!("did:oan:K7mQ0:{SUFFIX}"),
                DidOanError::InvalidRoutingCode,
            ),
            (
                "did:oan:K7mQ9:short".to_owned(),
                DidOanError::InvalidSuffixCode,
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(DidOan::parse(value).unwrap_err(), expected);
        }
        assert_eq!(
            DidOan::parse(format!("did:ans:K7mQ9:{SUFFIX}")).unwrap_err(),
            DidOanError::InvalidPrefix
        );
        assert_eq!(
            DidOan::parse(format!("did:oan:K7mQ9:{SUFFIX}:extra")).unwrap_err(),
            DidOanError::InvalidPartCount
        );
    }

    #[test]
    fn validates_routing_and_suffix_boundaries() {
        assert_eq!(validate_routing_code("K7mQ9"), Ok(()));
        assert_eq!(
            validate_routing_code("K7mQ"),
            Err(DidOanError::InvalidRoutingCode)
        );
        assert_eq!(
            validate_routing_code("K7mQ90"),
            Err(DidOanError::InvalidRoutingCode)
        );
        assert_eq!(
            validate_routing_code("K7mQ0"),
            Err(DidOanError::InvalidRoutingCode)
        );

        assert_eq!(validate_suffix_code(SUFFIX), Ok(()));
        assert_eq!(
            validate_suffix_code(&SUFFIX[..31]),
            Err(DidOanError::InvalidSuffixCode)
        );
        assert_eq!(
            validate_suffix_code(&format!("{SUFFIX}1")),
            Err(DidOanError::InvalidSuffixCode)
        );
        assert_eq!(
            validate_suffix_code("7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgN0"),
            Err(DidOanError::InvalidSuffixCode)
        );
    }

    #[test]
    fn generates_and_derives_stable_oan_identifiers() {
        let generated = DidOan::generate("K7mQ9").unwrap();
        assert_eq!(generated.as_str().len(), DID_LEN);
        assert_eq!(DidOan::parse(generated.as_str()).unwrap(), generated);
        let a = DidOan::derive("K7mQ9", b"controller", b"nonce").unwrap();
        let b = DidOan::derive("K7mQ9", b"controller", b"nonce").unwrap();
        let c = DidOan::derive("K7mQ9", b"controller", b"other").unwrap();
        let d = DidOan::derive("QwErT", b"controller", b"nonce").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(d.routing_code(), "QwErT");
    }

    #[test]
    fn cross_language_fixture_did_cases_match_parser_behavior() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-fixtures/did-oan-cross-language.json"
        ))
        .unwrap();
        let cases = fixture["didCases"].as_array().unwrap();
        assert!(cases.len() >= 10);

        for case in cases {
            let did = case["did"].as_str().unwrap();
            match case["expected"].as_str().unwrap() {
                "valid" => {
                    let parsed = DidOan::parse(did).unwrap();
                    assert_eq!(parsed.routing_code(), case["routingCode"].as_str().unwrap());
                    assert_eq!(parsed.suffix_code(), case["suffixCode"].as_str().unwrap());
                }
                "invalid" => {
                    let actual = format!("{:?}", DidOan::parse(did).unwrap_err());
                    assert_eq!(actual, case["error"].as_str().unwrap());
                }
                expected => panic!("unexpected fixture expectation: {expected}"),
            }
        }
    }

    #[test]
    fn key_id_normalizes_fragment_marker() {
        let did = DidOan::parse(format!("did:oan:K7mQ9:{SUFFIX}")).unwrap();
        assert_eq!(did.key_id("#key-1"), format!("{}#key-1", did.as_str()));
    }
}
