// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! `did:oan` profile-v2 parsing, generation, and validation.

use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;
use thiserror::Error;

pub const DID_PREFIX: &str = "did:oan:";
pub const REGISTRAR_CODE_LEN: usize = 5;
pub const RESOURCE_SUFFIX_LEN: usize = 32;
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
    #[error("registrar code must be exactly 5 case-sensitive Base58 characters")]
    InvalidRegistrarCode,
    #[error("resource suffix must be exactly 32 Base58 characters")]
    InvalidResourceSuffix,
    #[error("invalid did:oan profile-v2 syntax")]
    InvalidSyntax,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DidOan {
    value: String,
    registrar_code: String,
    resource_suffix: String,
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
        let registrar_code = parts[2];
        validate_registrar_code(registrar_code)?;
        let resource_suffix = parts[3];
        validate_resource_suffix(resource_suffix)?;
        if !did_regex().is_match(value) {
            return Err(DidOanError::InvalidSyntax);
        }
        Ok(Self {
            value: value.to_owned(),
            registrar_code: registrar_code.to_owned(),
            resource_suffix: resource_suffix.to_owned(),
        })
    }

    pub fn generate(registrar_code: &str) -> Result<Self, DidOanError> {
        validate_registrar_code(registrar_code)?;
        Self::parse(format!(
            "{DID_PREFIX}{registrar_code}:{}",
            random_base58_suffix()
        ))
    }

    pub fn derive(
        registrar_code: &str,
        controller_material: &[u8],
        nonce: &[u8],
    ) -> Result<Self, DidOanError> {
        validate_registrar_code(registrar_code)?;
        let mut hasher = Sha256::new();
        hasher.update(b"OAN-DID-SUFFIX-v2");
        hasher.update(registrar_code.as_bytes());
        hasher.update(controller_material);
        hasher.update(nonce);
        Self::parse(format!(
            "{DID_PREFIX}{registrar_code}:{}",
            derived_base58_suffix(hasher)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
    pub fn registrar_code(&self) -> &str {
        &self.registrar_code
    }
    pub fn resource_suffix(&self) -> &str {
        &self.resource_suffix
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

pub fn validate_registrar_code(value: &str) -> Result<(), DidOanError> {
    if value.len() == REGISTRAR_CODE_LEN && value.chars().all(|ch| BASE58_ALPHABET.contains(ch)) {
        Ok(())
    } else {
        Err(DidOanError::InvalidRegistrarCode)
    }
}

pub fn validate_resource_suffix(value: &str) -> Result<(), DidOanError> {
    if value.len() == RESOURCE_SUFFIX_LEN && value.chars().all(|ch| BASE58_ALPHABET.contains(ch)) {
        Ok(())
    } else {
        Err(DidOanError::InvalidResourceSuffix)
    }
}

fn random_base58_suffix() -> String {
    let mut suffix = String::with_capacity(RESOURCE_SUFFIX_LEN);
    let mut bytes = [0u8; 64];
    while suffix.len() < RESOURCE_SUFFIX_LEN {
        OsRng.fill_bytes(&mut bytes);
        push_unbiased_base58_chars(&mut suffix, &bytes);
    }
    suffix.truncate(RESOURCE_SUFFIX_LEN);
    suffix
}

fn derived_base58_suffix(seed_hasher: Sha256) -> String {
    let mut suffix = String::with_capacity(RESOURCE_SUFFIX_LEN);
    let mut counter = 0u64;
    while suffix.len() < RESOURCE_SUFFIX_LEN {
        let mut hasher = seed_hasher.clone();
        hasher.update(counter.to_be_bytes());
        push_unbiased_base58_chars(&mut suffix, hasher.finalize().as_slice());
        counter += 1;
    }
    suffix.truncate(RESOURCE_SUFFIX_LEN);
    suffix
}

fn push_unbiased_base58_chars(output: &mut String, bytes: &[u8]) {
    let alphabet = BASE58_ALPHABET.as_bytes();
    let rejection_zone = u8::MAX - (u8::MAX % alphabet.len() as u8);
    for byte in bytes {
        if *byte < rejection_zone {
            output.push(alphabet[(*byte as usize) % alphabet.len()] as char);
            if output.len() == RESOURCE_SUFFIX_LEN {
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
    fn parses_profile_v2_did_without_type_inference() {
        let did = DidOan::parse(format!("did:oan:K7mQ9:{SUFFIX}")).unwrap();
        assert_eq!(did.registrar_code(), "K7mQ9");
        assert_eq!(did.resource_suffix(), SUFFIX);
        assert_eq!(did.as_str().len(), DID_LEN);
    }

    #[test]
    fn preserves_case_and_treats_codes_as_distinct() {
        let upper = DidOan::parse(format!("did:oan:K7mQ9:{SUFFIX}")).unwrap();
        let lower = DidOan::parse(format!("did:oan:k7mQ9:{SUFFIX}")).unwrap();
        assert_ne!(upper, lower);
        assert_eq!(lower.registrar_code(), "k7mQ9");
    }

    #[test]
    fn rejects_legacy_and_malformed_identifiers() {
        let cases = [
            (
                format!("did:oan:SKFI:{SUFFIX}"),
                DidOanError::InvalidRegistrarCode,
            ),
            (
                format!("did:oan:K7mQ:{SUFFIX}"),
                DidOanError::InvalidRegistrarCode,
            ),
            (
                format!("did:oan:K7mQ90:{SUFFIX}"),
                DidOanError::InvalidRegistrarCode,
            ),
            (
                format!("did:oan:K7mQ0:{SUFFIX}"),
                DidOanError::InvalidRegistrarCode,
            ),
            (
                "did:oan:K7mQ9:short".to_owned(),
                DidOanError::InvalidResourceSuffix,
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
    fn generates_and_derives_stable_profile_v2_identifiers() {
        let generated = DidOan::generate("K7mQ9").unwrap();
        assert_eq!(generated.as_str().len(), DID_LEN);
        assert_eq!(DidOan::parse(generated.as_str()).unwrap(), generated);
        let a = DidOan::derive("K7mQ9", b"controller", b"nonce").unwrap();
        let b = DidOan::derive("K7mQ9", b"controller", b"nonce").unwrap();
        let c = DidOan::derive("K7mQ9", b"controller", b"other").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn key_id_normalizes_fragment_marker() {
        let did = DidOan::parse(format!("did:oan:K7mQ9:{SUFFIX}")).unwrap();
        assert_eq!(did.key_id("#key-1"), format!("{}#key-1", did.as_str()));
    }
}
