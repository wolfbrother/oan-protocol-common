// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! did:oan parsing, generation, and validation.

use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;
use thiserror::Error;

pub const DID_PREFIX: &str = "did:oan:";
pub const SUFFIX_LEN: usize = 32;
pub const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn did_regex() -> &'static Regex {
    static DID_RE: OnceLock<Regex> = OnceLock::new();
    DID_RE.get_or_init(|| Regex::new(r"^did:oan:[A-Z0-9]{4}:[1-9A-HJ-NP-Za-km-z]{32}$").unwrap())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OanSubjectCode {
    AgentService,
    Skill,
    McpServer,
    ToolApi,
    InfrastructureNode,
    Organization,
    Developer,
    ReservedResource,
    Other,
}

impl OanSubjectCode {
    pub fn parse(value: &str) -> Self {
        match value {
            "AG" => Self::AgentService,
            "SK" => Self::Skill,
            "MC" => Self::McpServer,
            "TL" => Self::ToolApi,
            "IN" => Self::InfrastructureNode,
            "OR" => Self::Organization,
            "DV" => Self::Developer,
            "RS" => Self::ReservedResource,
            _ => Self::Other,
        }
    }

    pub fn as_code(self) -> Option<&'static str> {
        match self {
            Self::AgentService => Some("AG"),
            Self::Skill => Some("SK"),
            Self::McpServer => Some("MC"),
            Self::ToolApi => Some("TL"),
            Self::InfrastructureNode => Some("IN"),
            Self::Organization => Some("OR"),
            Self::Developer => Some("DV"),
            Self::ReservedResource => Some("RS"),
            Self::Other => None,
        }
    }

    pub fn expected_resource_type(self) -> Option<&'static str> {
        match self {
            Self::AgentService => Some("agent_service"),
            Self::Skill => Some("skill"),
            Self::McpServer => Some("mcp_server"),
            Self::ToolApi => Some("tool_api"),
            Self::InfrastructureNode => Some("infrastructure_node"),
            Self::Organization => Some("organization"),
            Self::Developer => Some("developer"),
            _ => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidOanError {
    #[error("did must start with did:oan")]
    InvalidPrefix,
    #[error("did must have 4 colon-separated parts")]
    InvalidPartCount,
    #[error("semantic code must be 4 uppercase alphanumeric characters")]
    InvalidSemanticCode,
    #[error("suffix must be exactly 32 Base58 characters")]
    InvalidSuffix,
    #[error("invalid did:oan syntax")]
    InvalidSyntax,
    #[error("resource type does not match did subject code")]
    ResourceTypeMismatch,
    #[error("unsupported subject code")]
    UnsupportedSubjectCode,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DidOan {
    value: String,
    semantic_code: String,
    subject_code: String,
    app_domain_code: String,
    suffix: String,
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

        let semantic_code = parts[2];
        validate_semantic_code(semantic_code)?;

        let suffix = parts[3];
        validate_suffix(suffix)?;

        if !did_regex().is_match(value) {
            return Err(DidOanError::InvalidSyntax);
        }

        Ok(Self {
            value: value.to_owned(),
            semantic_code: semantic_code.to_owned(),
            subject_code: semantic_code[..2].to_owned(),
            app_domain_code: semantic_code[2..].to_owned(),
            suffix: suffix.to_owned(),
        })
    }

    pub fn generate(semantic_code: &str) -> Result<Self, DidOanError> {
        validate_semantic_code(semantic_code)?;
        let suffix = random_base58_suffix();
        Self::parse(format!("{DID_PREFIX}{semantic_code}:{suffix}"))
    }

    pub fn derive(
        semantic_code: &str,
        controller_material: &[u8],
        nonce: &[u8],
    ) -> Result<Self, DidOanError> {
        validate_semantic_code(semantic_code)?;
        let mut hasher = Sha256::new();
        hasher.update(b"OAN-DID-SUFFIX-v1");
        hasher.update(semantic_code.as_bytes());
        hasher.update(controller_material);
        hasher.update(nonce);
        let suffix = derived_base58_suffix(hasher);
        Self::parse(format!("{DID_PREFIX}{semantic_code}:{suffix}"))
    }

    pub fn validate_resource_type(&self, resource_type: &str) -> Result<(), DidOanError> {
        let Some(expected) = self.subject().expected_resource_type() else {
            return Err(DidOanError::UnsupportedSubjectCode);
        };
        if expected == resource_type {
            Ok(())
        } else {
            Err(DidOanError::ResourceTypeMismatch)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn semantic_code(&self) -> &str {
        &self.semantic_code
    }

    pub fn subject_code(&self) -> &str {
        &self.subject_code
    }

    pub fn app_domain_code(&self) -> &str {
        &self.app_domain_code
    }

    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    pub fn subject(&self) -> OanSubjectCode {
        OanSubjectCode::parse(&self.subject_code)
    }

    pub fn key_id(&self, fragment: &str) -> String {
        let fragment = fragment.trim_start_matches('#');
        format!("{}#{fragment}", self.value)
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

pub fn validate_semantic_code(value: &str) -> Result<(), DidOanError> {
    if value.len() == 4
        && value
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(DidOanError::InvalidSemanticCode)
    }
}

pub fn validate_suffix(value: &str) -> Result<(), DidOanError> {
    if value.len() == SUFFIX_LEN && value.chars().all(|ch| BASE58_ALPHABET.contains(ch)) {
        Ok(())
    } else {
        Err(DidOanError::InvalidSuffix)
    }
}

fn random_base58_suffix() -> String {
    let mut suffix = String::with_capacity(SUFFIX_LEN);
    let mut bytes = [0u8; 64];
    while suffix.len() < SUFFIX_LEN {
        OsRng.fill_bytes(&mut bytes);
        push_unbiased_base58_chars(&mut suffix, &bytes);
    }
    suffix.truncate(SUFFIX_LEN);
    suffix
}

fn derived_base58_suffix(seed_hasher: Sha256) -> String {
    let mut suffix = String::with_capacity(SUFFIX_LEN);
    let mut counter = 0u64;
    while suffix.len() < SUFFIX_LEN {
        let mut hasher = seed_hasher.clone();
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        push_unbiased_base58_chars(&mut suffix, digest.as_slice());
        counter += 1;
    }
    suffix.truncate(SUFFIX_LEN);
    suffix
}

fn push_unbiased_base58_chars(output: &mut String, bytes: &[u8]) {
    let alphabet = BASE58_ALPHABET.as_bytes();
    let rejection_zone = u8::MAX - (u8::MAX % alphabet.len() as u8);
    for byte in bytes {
        if *byte < rejection_zone {
            output.push(alphabet[(*byte as usize) % alphabet.len()] as char);
            if output.len() == SUFFIX_LEN {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_did() {
        let did = DidOan::parse("did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz").unwrap();

        assert_eq!(did.semantic_code(), "AGFI");
        assert_eq!(did.subject_code(), "AG");
        assert_eq!(did.app_domain_code(), "FI");
        assert_eq!(did.subject(), OanSubjectCode::AgentService);
        assert_eq!(did.suffix(), "7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz");
    }

    #[test]
    fn rejects_did_ans_prefix() {
        assert_eq!(
            DidOan::parse("did:ans:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz").unwrap_err(),
            DidOanError::InvalidPrefix
        );
    }

    #[test]
    fn rejects_wrong_suffix_length() {
        assert_eq!(
            DidOan::parse("did:oan:AGFI:short").unwrap_err(),
            DidOanError::InvalidSuffix
        );
    }

    #[test]
    fn rejects_lowercase_semantic_code() {
        assert_eq!(
            DidOan::parse("did:oan:agFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz").unwrap_err(),
            DidOanError::InvalidSemanticCode
        );
    }

    #[test]
    fn rejects_non_base58_suffix_characters() {
        assert_eq!(
            DidOan::parse("did:oan:AGFI:0YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz").unwrap_err(),
            DidOanError::InvalidSuffix
        );
        assert_eq!(
            DidOan::parse("did:oan:AGFI:OYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz").unwrap_err(),
            DidOanError::InvalidSuffix
        );
    }

    #[test]
    fn rejects_wrong_part_count() {
        assert_eq!(
            DidOan::parse("did:oan:AGFI").unwrap_err(),
            DidOanError::InvalidPartCount
        );
        assert_eq!(
            DidOan::parse("did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz:extra").unwrap_err(),
            DidOanError::InvalidPartCount
        );
    }

    #[test]
    fn validates_resource_type_mapping() {
        let skill = DidOan::parse("did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu").unwrap();
        assert!(skill.validate_resource_type("skill").is_ok());
        assert_eq!(
            skill.validate_resource_type("mcp_server").unwrap_err(),
            DidOanError::ResourceTypeMismatch
        );
    }

    #[test]
    fn validates_all_standard_product_resource_mappings() {
        let cases = [
            (
                "did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
                "agent_service",
            ),
            ("did:oan:SKFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz", "skill"),
            (
                "did:oan:MCFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
                "mcp_server",
            ),
            ("did:oan:TLFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz", "tool_api"),
        ];

        for (did, resource_type) in cases {
            assert!(DidOan::parse(did)
                .unwrap()
                .validate_resource_type(resource_type)
                .is_ok());
        }
    }

    #[test]
    fn unknown_subject_code_is_parseable_but_not_product_validated() {
        let did = DidOan::parse("did:oan:ZZFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz").unwrap();
        assert_eq!(did.subject(), OanSubjectCode::Other);
        assert_eq!(
            did.validate_resource_type("skill").unwrap_err(),
            DidOanError::UnsupportedSubjectCode
        );
    }

    #[test]
    fn generates_canonical_did() {
        let did = DidOan::generate("TLFI").unwrap();
        assert_eq!(did.as_str().len(), 45);
        assert_eq!(did.as_str().len(), DID_PREFIX.len() + 4 + 1 + SUFFIX_LEN);
        assert_eq!(did.subject(), OanSubjectCode::ToolApi);
        assert!(did.suffix().chars().all(|ch| BASE58_ALPHABET.contains(ch)));
        assert_eq!(DidOan::parse(did.as_str()).unwrap(), did);
    }

    #[test]
    fn deterministic_derivation_is_stable() {
        let a = DidOan::derive("MCFI", b"controller", b"nonce").unwrap();
        let b = DidOan::derive("MCFI", b"controller", b"nonce").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_derivation_changes_with_nonce_or_controller() {
        let a = DidOan::derive("MCFI", b"controller", b"nonce-a").unwrap();
        let b = DidOan::derive("MCFI", b"controller", b"nonce-b").unwrap();
        let c = DidOan::derive("MCFI", b"other-controller", b"nonce-a").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn suffix_first_character_is_plain_identifier_material() {
        for prefix_like in ["e", "z"] {
            let suffix = format!("{prefix_like}YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz");
            assert_eq!(suffix.len(), SUFFIX_LEN);
            let did = DidOan::parse(format!("did:oan:AGFI:{suffix}")).unwrap();
            assert_eq!(did.suffix(), suffix);
            assert_eq!(did.subject(), OanSubjectCode::AgentService);
        }
    }

    #[test]
    fn key_id_normalizes_fragment_marker() {
        let did = DidOan::parse("did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz").unwrap();
        assert_eq!(
            did.key_id("#key-1"),
            "did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1"
        );
        assert_eq!(
            did.key_id("key-1"),
            "did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1"
        );
    }
}
