// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Core domain types shared by OAN services.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

pub const DID_OAN_CONTEXTS: [&str; 3] = [
    "https://www.w3.org/ns/did/v1",
    "https://openagenet.xyz/did-oan-specs/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

impl OanJwk {
    pub fn validate_ed25519(&self, private: bool) -> Result<(), OanProfileError> {
        if self.kty != "OKP"
            || self.crv != "Ed25519"
            || self.x.is_empty()
            || (private && self.d.as_deref().unwrap_or_default().is_empty())
            || (!private && self.d.is_some())
            || self.alg.as_deref() == Some("Ed25519")
        {
            return Err(OanProfileError::InvalidJwk);
        }
        let public_key = URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|_| OanProfileError::InvalidJwk)?;
        if public_key.len() != 32 {
            return Err(OanProfileError::InvalidJwk);
        }
        if private
            && URL_SAFE_NO_PAD
                .decode(self.d.as_deref().unwrap_or_default())
                .map_err(|_| OanProfileError::InvalidJwk)?
                .len()
                != 32
        {
            return Err(OanProfileError::InvalidJwk);
        }
        if let Some(alg) = &self.alg {
            if alg != "EdDSA" {
                return Err(OanProfileError::InvalidJwk);
            }
        }
        Ok(())
    }
}

fn decode_oan_multibase(
    value: &str,
    expected_len: usize,
    error: OanProfileError,
) -> Result<Vec<u8>, OanProfileError> {
    let encoded = value.strip_prefix('z').ok_or(error.clone())?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| error.clone())?;
    if bytes.len() != expected_len || bs58::encode(&bytes).into_string() != encoded {
        return Err(error);
    }
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<OanJwk>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanDataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanCredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
}

impl OanCredentialProof {
    pub fn validate_for(&self, issuer: &str) -> Result<(), OanProfileError> {
        if self.proof_type != "Ed25519Signature2020"
            || self.proof_purpose != "assertionMethod"
            || self.verification_method != format!("{issuer}#key-1")
        {
            return Err(OanProfileError::InvalidProof);
        }
        decode_oan_multibase(&self.proof_value, 64, OanProfileError::InvalidProof)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanVerifiableCredential {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: serde_json::Value,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<serde_json::Value>,
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<serde_json::Value>,
    pub proof: OanCredentialProof,
}

impl OanVerifiableCredential {
    pub fn validate(&self) -> Result<(), OanProfileError> {
        if self.context
            != [
                "https://www.w3.org/2018/credentials/v1".to_owned(),
                "https://openagenet.xyz/did-oan-specs/v1".to_owned(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_owned(),
            ]
        {
            return Err(OanProfileError::InvalidContext);
        }
        if self.credential_type.is_empty()
            || !self
                .credential_type
                .iter()
                .any(|value| value == "VerifiableCredential")
        {
            return Err(OanProfileError::InvalidCredential);
        }
        oan_did_oan::DidOan::parse(&self.issuer).map_err(|_| OanProfileError::InvalidDid)?;
        self.proof.validate_for(&self.issuer)
    }
}

impl OanDataIntegrityProof {
    pub fn validate_for(&self, did: &str) -> Result<(), OanProfileError> {
        if self.proof_type != "Ed25519Signature2020"
            || self.proof_purpose != "assertionMethod"
            || self.verification_method != format!("{did}#key-1")
        {
            return Err(OanProfileError::InvalidProof);
        }
        decode_oan_multibase(&self.proof_value, 64, OanProfileError::InvalidProof)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanDidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<DidController>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<OanVerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<String>,
    #[serde(default)]
    pub service: Vec<serde_json::Value>,
    pub proof: OanDataIntegrityProof,
    #[serde(rename = "oanMetadata", default)]
    pub oan_metadata: Option<serde_json::Value>,
}

impl OanDidDocument {
    pub fn validate(&self) -> Result<(), OanProfileError> {
        if self.context.iter().map(String::as_str).collect::<Vec<_>>() != DID_OAN_CONTEXTS {
            return Err(OanProfileError::InvalidContext);
        }
        oan_did_oan::DidOan::parse(&self.id).map_err(|_| OanProfileError::InvalidDid)?;
        let key_id = format!("{}#key-1", self.id);
        let method = self
            .verification_method
            .iter()
            .find(|method| method.id == key_id)
            .ok_or(OanProfileError::InvalidVerificationMethod)?;
        if method.method_type != "Ed25519VerificationKey2020"
            || method.public_key_multibase.is_none() && method.public_key_jwk.is_none()
            || !self.authentication.iter().any(|value| value == &key_id)
            || !self.assertion_method.iter().any(|value| value == &key_id)
        {
            return Err(OanProfileError::InvalidVerificationMethod);
        }
        if !self
            .controller
            .as_ref()
            .is_some_and(|controller| controller.contains(&method.controller))
            && method.controller != self.id
        {
            return Err(OanProfileError::InvalidVerificationMethod);
        }
        let multibase_key = method
            .public_key_multibase
            .as_deref()
            .map(|value| {
                decode_oan_multibase(value, 34, OanProfileError::InvalidVerificationMethod)
            })
            .transpose()?;
        if let Some(jwk) = &method.public_key_jwk {
            jwk.validate_ed25519(false)?;
            if let Some(multibase_key) = multibase_key {
                let jwk_key = URL_SAFE_NO_PAD
                    .decode(&jwk.x)
                    .map_err(|_| OanProfileError::InvalidVerificationMethod)?;
                if multibase_key[..2] != [0xed, 0x01] || jwk_key != multibase_key[2..] {
                    return Err(OanProfileError::InvalidVerificationMethod);
                }
            }
        }
        self.proof.validate_for(&self.id)
    }
}

pub fn oan_canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_owned(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => serde_json::to_string(value).unwrap(),
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(oan_canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|key| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key).unwrap(),
                            oan_canonical_json(&values[*key])
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

pub fn oan_signature_input(document: &OanDidDocument) -> Result<Vec<u8>, OanProfileError> {
    let mut value = serde_json::to_value(document).map_err(|_| OanProfileError::InvalidProof)?;
    value
        .as_object_mut()
        .ok_or(OanProfileError::InvalidProof)?
        .remove("proof");
    Ok(oan_canonical_json(&value).into_bytes())
}

pub fn oan_did_document_hash(document: &OanDidDocument) -> Result<String, OanProfileError> {
    let value = serde_json::to_value(document).map_err(|_| OanProfileError::InvalidProof)?;
    let canonical = oan_canonical_json(&value);
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanPublicIdentity {
    pub id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub did: String,
    #[serde(rename = "verificationMethodId")]
    pub verification_method_id: String,
    #[serde(rename = "didDocument")]
    pub did_document: OanDidDocument,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: OanJwk,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OanIdentity {
    pub id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub did: String,
    #[serde(rename = "verificationMethodId")]
    pub verification_method_id: String,
    #[serde(rename = "didDocument")]
    pub did_document: OanDidDocument,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: OanJwk,
    #[serde(rename = "privateKeyJwk")]
    pub private_key_jwk: OanJwk,
}

impl OanIdentity {
    pub fn public_projection(&self) -> OanPublicIdentity {
        OanPublicIdentity {
            id: self.id.clone(),
            created_at: self.created_at.clone(),
            did: self.did.clone(),
            verification_method_id: self.verification_method_id.clone(),
            did_document: self.did_document.clone(),
            public_key_jwk: self.public_key_jwk.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), OanProfileError> {
        if self.did != self.did_document.id
            || self.verification_method_id != format!("{}#key-1", self.did)
            || self.did_document.validate().is_err()
        {
            return Err(OanProfileError::InvalidIdentity);
        }
        self.public_key_jwk.validate_ed25519(false)?;
        self.private_key_jwk.validate_ed25519(true)?;
        let method = self
            .did_document
            .verification_method
            .iter()
            .find(|method| method.id == self.verification_method_id)
            .ok_or(OanProfileError::InvalidIdentity)?;
        if let Some(method_jwk) = &method.public_key_jwk {
            if method_jwk != &self.public_key_jwk {
                return Err(OanProfileError::InvalidIdentity);
            }
        } else if let Some(multibase) = &method.public_key_multibase {
            let multibase_key =
                decode_oan_multibase(multibase, 34, OanProfileError::InvalidIdentity)?;
            let public_key = URL_SAFE_NO_PAD
                .decode(&self.public_key_jwk.x)
                .map_err(|_| OanProfileError::InvalidIdentity)?;
            if multibase_key[..2] != [0xed, 0x01] || public_key != multibase_key[2..] {
                return Err(OanProfileError::InvalidIdentity);
            }
        } else {
            return Err(OanProfileError::InvalidIdentity);
        }
        let private_bytes = URL_SAFE_NO_PAD
            .decode(self.private_key_jwk.d.as_deref().unwrap_or_default())
            .map_err(|_| OanProfileError::InvalidIdentity)?;
        let private_bytes: [u8; 32] = private_bytes
            .try_into()
            .map_err(|_| OanProfileError::InvalidIdentity)?;
        let signing_key = SigningKey::from_bytes(&private_bytes);
        if signing_key.verifying_key().to_bytes()
            != URL_SAFE_NO_PAD
                .decode(&self.public_key_jwk.x)
                .map_err(|_| OanProfileError::InvalidIdentity)?
                .as_slice()
        {
            return Err(OanProfileError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OanProfileError {
    #[error("invalid did:oan identifier")]
    InvalidDid,
    #[error("invalid did document context")]
    InvalidContext,
    #[error("invalid verification method")]
    InvalidVerificationMethod,
    #[error("invalid data integrity proof")]
    InvalidProof,
    #[error("invalid Ed25519 JWK")]
    InvalidJwk,
    #[error("invalid OAN Identity")]
    InvalidIdentity,
    #[error("invalid verifiable credential")]
    InvalidCredential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoSuite {
    #[serde(alias = "Ed25519Sha256Legacy")]
    Ed25519Sha256Legacy,
    #[serde(alias = "Ed25519Sha256")]
    Ed25519Sha256,
    #[serde(alias = "Sm2Sm3")]
    Sm2Sm3,
}

impl CryptoSuite {
    pub fn signing_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519",
            Self::Sm2Sm3 => "SM2",
        }
    }

    pub fn hash_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "SHA-256",
            Self::Sm2Sm3 => "SM3",
        }
    }

    /// Canonical current did:oan spelling used in serialized proofs.
    pub fn canonical_hash_algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "sha256",
            Self::Sm2Sm3 => "sm3",
        }
    }

    pub fn verification_method_type(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519VerificationKey2020",
            Self::Sm2Sm3 => "SM2VerificationKey2020",
        }
    }

    pub fn proof_type(&self) -> &'static str {
        match self {
            Self::Ed25519Sha256Legacy | Self::Ed25519Sha256 => "Ed25519Signature2020",
            Self::Sm2Sm3 => "SM2Signature2020",
        }
    }

    pub fn from_verification_method_type(value: &str) -> Option<Self> {
        match value {
            "Ed25519VerificationKey2020" => Some(Self::Ed25519Sha256),
            "SM2VerificationKey2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }

    pub fn from_proof_type(value: &str) -> Option<Self> {
        match value {
            "Ed25519Signature2020" => Some(Self::Ed25519Sha256),
            "SM2Signature2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    AgentInstance,
    AgentProduct,
    RootNode,
    RegistrarNode,
    DiscoveryNode,
    CdnNode,
    VcIssuerNode,
    TrustIndexerNode,
    Unspecified,
    #[serde(skip)]
    Agent,
    AgentService,
    Skill,
    McpServer,
    ToolApi,
    Organization,
    Developer,
    InfrastructureNode,
    Controller,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    AgentInstance,
    AgentProduct,
    AgentService,
    Skill,
    McpServer,
    ToolApi,
    InfrastructureNode,
    Organization,
    Developer,
    RootNode,
    RegistrarNode,
    DiscoveryNode,
    CdnNode,
    VcIssuerNode,
    TrustIndexerNode,
    Unspecified,
    Controller,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentInstance => "agent_instance",
            Self::AgentProduct => "agent_product",
            Self::AgentService => "agent_service",
            Self::Skill => "skill",
            Self::McpServer => "mcp_server",
            Self::ToolApi => "tool_api",
            Self::InfrastructureNode => "infrastructure_node",
            Self::Organization => "organization",
            Self::Developer => "developer",
            Self::RootNode => "root_node",
            Self::RegistrarNode => "registrar_node",
            Self::DiscoveryNode => "discovery_node",
            Self::CdnNode => "cdn_node",
            Self::VcIssuerNode => "vc_issuer_node",
            Self::TrustIndexerNode => "trust_indexer_node",
            Self::Unspecified => "unspecified",
            Self::Controller => "controller",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Root,
    Registrar,
    Discovery,
    ServiceAgent,
    UserAgent,
    TestAgent,
}

impl NodeRole {
    pub fn subject_type(&self) -> SubjectType {
        match self {
            Self::ServiceAgent | Self::UserAgent | Self::TestAgent => SubjectType::Agent,
            Self::Root | Self::Registrar | Self::Discovery => SubjectType::InfrastructureNode,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "publicKeyFormat", skip_serializing_if = "Option::is_none")]
    pub public_key_format: Option<String>,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

impl VerificationMethod {
    pub fn crypto_suite(&self) -> Option<CryptoSuite> {
        self.crypto_suite
            .clone()
            .or_else(|| CryptoSuite::from_verification_method_type(&self.method_type))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub creator: String,
    pub created: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "hashAlgorithm", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

impl DataIntegrityProof {
    pub fn crypto_suite(&self) -> Option<CryptoSuite> {
        self.crypto_suite
            .clone()
            .or_else(|| CryptoSuite::from_proof_type(&self.proof_type))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "serverType", skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBinding {
    pub id: String,
    #[serde(rename = "addressType")]
    pub address_type: String,
    pub network: String,
    pub address: String,
    pub controller: String,
    pub purpose: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AgentDescription {
    #[serde(rename = "capabilityDescription")]
    pub capability_description: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "useCaseExamples", default)]
    pub use_case_examples: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceDescription {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(
        rename = "capabilityDescription",
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_description: Option<String>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "useCaseExamples", default)]
    pub use_case_examples: Vec<String>,
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolBinding {
    pub id: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(rename = "serviceRef", skip_serializing_if = "Option::is_none")]
    pub service_ref: Option<String>,
    #[serde(rename = "schemaRef", skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplementationLink {
    pub relation: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    #[serde(rename = "targetType", skip_serializing_if = "Option::is_none")]
    pub target_type: Option<ResourceType>,
    #[serde(rename = "targetService", skip_serializing_if = "Option::is_none")]
    pub target_service: Option<String>,
    #[serde(rename = "versionConstraint", skip_serializing_if = "Option::is_none")]
    pub version_constraint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialIssuer {
    Did(String),
    Dids(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequirement {
    pub id: String,
    pub purpose: String,
    #[serde(rename = "credentialType")]
    pub credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<CredentialIssuer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,
    #[serde(rename = "presentationMode", skip_serializing_if = "Option::is_none")]
    pub presentation_mode: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInfo {
    #[serde(rename = "manifestUrl", skip_serializing_if = "Option::is_none")]
    pub manifest_url: Option<String>,
    #[serde(rename = "downloadUrl", skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(rename = "packageHash", skip_serializing_if = "Option::is_none")]
    pub package_hash: Option<String>,
    #[serde(rename = "metadataHash", skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    #[serde(rename = "rootProofRef", skip_serializing_if = "Option::is_none")]
    pub root_proof_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionScheme", skip_serializing_if = "Option::is_none")]
    pub version_scheme: Option<String>,
    #[serde(rename = "previousVersion", skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    #[serde(rename = "releaseNotesUrl", skip_serializing_if = "Option::is_none")]
    pub release_notes_url: Option<String>,
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OanMetadata {
    #[serde(rename = "subjectType")]
    pub subject_type: SubjectType,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(
        rename = "externalIdentifiers",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub external_identifiers: Vec<ExternalIdentifier>,
    #[serde(rename = "identityType", skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
    #[serde(rename = "controllerDid", skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,
    #[serde(rename = "publisherDid", skip_serializing_if = "Option::is_none")]
    pub publisher_did: Option<String>,
    #[serde(rename = "issuerDid", skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(
        rename = "resourceDescription",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_description: Option<ResourceDescription>,
    #[serde(rename = "agentDescription", skip_serializing_if = "Option::is_none")]
    pub agent_description: Option<AgentDescription>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(
        rename = "protocolBindings",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub protocol_bindings: Vec<ProtocolBinding>,
    #[serde(
        rename = "implementationLinks",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub implementation_links: Vec<ImplementationLink>,
    #[serde(
        rename = "credentialRequirements",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub credential_requirements: Vec<CredentialRequirement>,
    #[serde(rename = "packageInfo", skip_serializing_if = "Option::is_none")]
    pub package_info: Option<PackageInfo>,
    #[serde(rename = "servicePolicy", skip_serializing_if = "Option::is_none")]
    pub service_policy: Option<String>,
    #[serde(rename = "networkScope", skip_serializing_if = "Option::is_none")]
    pub network_scope: Option<String>,
    #[serde(rename = "lifecycleState", skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<DidController>,
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod", default)]
    pub assertion_method: Vec<String>,
    #[serde(
        rename = "capabilityInvocation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<String>,
    #[serde(default)]
    pub service: Vec<ServiceEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
    #[serde(rename = "oanMetadata", skip_serializing_if = "Option::is_none")]
    pub oan_metadata: Option<OanMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentifier {
    pub id: String,
    #[serde(
        rename = "resolutionServiceEndpoint",
        skip_serializing_if = "Option::is_none"
    )]
    pub resolution_service_endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DidController {
    Did(String),
    Dids(Vec<String>),
}

impl DidController {
    pub fn contains(&self, did: &str) -> bool {
        match self {
            Self::Did(value) => value == did,
            Self::Dids(values) => values.iter().any(|value| value == did),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTag {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTreeNode {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<CapabilityTreeNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTagTree {
    pub version: u64,
    #[serde(default)]
    pub tags: Vec<CapabilityTag>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tree: Vec<CapabilityTreeNode>,
}

impl CapabilityTagTree {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, oan_storage::StorageError> {
        let store = oan_storage::JsonStore::new(".");
        let mut tree: Self = store.read(path)?;
        if tree.tags.is_empty() && !tree.tree.is_empty() {
            tree.flatten_tree();
        }
        Ok(tree)
    }

    pub fn normalize_tag<'a>(&'a self, value: &str) -> Option<&'a str> {
        self.tags.iter().find_map(|tag| {
            if tag.id == value || tag.aliases.iter().any(|alias| alias == value) {
                Some(tag.id.as_str())
            } else {
                None
            }
        })
    }

    pub fn is_descendant_or_same(&self, tag_id: &str, domain_id: &str) -> bool {
        if domain_id == "*" || tag_id == domain_id {
            return true;
        }

        let by_id = self
            .tags
            .iter()
            .map(|tag| (tag.id.as_str(), tag))
            .collect::<BTreeMap<_, _>>();
        let mut current = by_id.get(tag_id).and_then(|tag| tag.parent.as_deref());
        let mut seen = BTreeSet::new();

        while let Some(parent) = current {
            if parent == domain_id {
                return true;
            }
            if !seen.insert(parent) {
                return false;
            }
            current = by_id.get(parent).and_then(|tag| tag.parent.as_deref());
        }

        false
    }

    pub fn matches_authorized_domains(
        &self,
        capability_tags: &[String],
        authorized_domains: &[String],
    ) -> bool {
        if authorized_domains.iter().any(|domain| domain == "*") {
            return true;
        }

        capability_tags.iter().any(|capability| {
            let normalized_capability = self.normalize_tag(capability).unwrap_or(capability);
            authorized_domains.iter().any(|domain| {
                let normalized_domain = self.normalize_tag(domain).unwrap_or(domain);
                self.is_descendant_or_same(normalized_capability, normalized_domain)
            })
        })
    }

    pub fn flatten_tree(&mut self) {
        if !self.tags.is_empty() || self.tree.is_empty() {
            return;
        }

        fn walk(node: &CapabilityTreeNode, parent: Option<&str>, tags: &mut Vec<CapabilityTag>) {
            tags.push(CapabilityTag {
                id: node.id.clone(),
                label: node.label.clone(),
                parent: parent.map(ToOwned::to_owned),
                aliases: vec![],
            });
            for child in &node.children {
                walk(child, Some(node.id.as_str()), tags);
            }
        }

        for node in &self.tree {
            walk(node, None, &mut self.tags);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDomain {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDomainTreeNode {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<AuthorizedDomainTreeNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDomainTaxonomy {
    pub version: u64,
    #[serde(rename = "snapshotHash", skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(default)]
    pub domains: Vec<AuthorizedDomain>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tree: Vec<AuthorizedDomainTreeNode>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizedDomainError {
    #[error("authorized domain list must not mix wildcard with concrete domains")]
    WildcardMixed,
    #[error("authorized domains must be sorted and unique")]
    DuplicateOrUnsorted,
    #[error("authorized domain is empty")]
    EmptyDomain,
    #[error("authorized domain is not canonical")]
    NonCanonicalDomain,
    #[error("authorized domain is unknown")]
    UnknownDomain,
}

impl AuthorizedDomainTaxonomy {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, oan_storage::StorageError> {
        let store = oan_storage::JsonStore::new(".");
        let mut taxonomy: Self = store.read(path)?;
        if taxonomy.domains.is_empty() && !taxonomy.tree.is_empty() {
            taxonomy.flatten_tree();
        }
        Ok(taxonomy)
    }

    pub fn normalize_domain<'a>(&'a self, value: &str) -> Option<&'a str> {
        self.domains.iter().find_map(|domain| {
            if domain.id == value || domain.aliases.iter().any(|alias| alias == value) {
                Some(domain.id.as_str())
            } else {
                None
            }
        })
    }

    pub fn validate_authorized_domains(
        &self,
        domains: &[String],
    ) -> Result<Vec<String>, AuthorizedDomainError> {
        if domains.is_empty() {
            return Ok(Vec::new());
        }
        if domains.iter().any(|domain| domain == "*") {
            return if domains.len() == 1 {
                Ok(vec!["*".to_owned()])
            } else {
                Err(AuthorizedDomainError::WildcardMixed)
            };
        }

        let mut normalized = Vec::with_capacity(domains.len());
        for domain in domains {
            if domain.is_empty() {
                return Err(AuthorizedDomainError::EmptyDomain);
            }
            let canonical = self
                .normalize_domain(domain)
                .ok_or(AuthorizedDomainError::UnknownDomain)?;
            if canonical != domain {
                return Err(AuthorizedDomainError::NonCanonicalDomain);
            }
            if canonical.matches('.').count() > 1 {
                return Err(AuthorizedDomainError::NonCanonicalDomain);
            }
            normalized.push(canonical.to_owned());
        }

        if normalized.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(AuthorizedDomainError::DuplicateOrUnsorted);
        }

        Ok(normalized)
    }

    pub fn covers_authorized_domains(
        &self,
        requested_domains: &[String],
        granted_domains: &[String],
    ) -> bool {
        if requested_domains.is_empty() {
            return true;
        }
        if granted_domains.iter().any(|domain| domain == "*") {
            return true;
        }
        if granted_domains.is_empty() {
            return false;
        }

        requested_domains.iter().all(|requested| {
            let Some(normalized_requested) = self.normalize_domain(requested) else {
                return false;
            };
            granted_domains.iter().any(|granted| {
                self.normalize_domain(granted)
                    .is_some_and(|normalized_granted| {
                        self.is_descendant_or_same(normalized_requested, normalized_granted)
                    })
            })
        })
    }

    pub fn flatten_tree(&mut self) {
        if !self.domains.is_empty() || self.tree.is_empty() {
            return;
        }

        fn walk(
            node: &AuthorizedDomainTreeNode,
            parent: Option<&str>,
            domains: &mut Vec<AuthorizedDomain>,
        ) {
            domains.push(AuthorizedDomain {
                id: node.id.clone(),
                label: node.label.clone(),
                parent: parent.map(ToOwned::to_owned),
                aliases: vec![],
            });
            for child in &node.children {
                walk(child, Some(node.id.as_str()), domains);
            }
        }

        for node in &self.tree {
            walk(node, None, &mut self.domains);
        }
    }

    fn is_descendant_or_same(&self, domain_id: &str, granted_domain_id: &str) -> bool {
        if granted_domain_id == "*" || domain_id == granted_domain_id {
            return true;
        }

        let by_id = self
            .domains
            .iter()
            .map(|domain| (domain.id.as_str(), domain))
            .collect::<BTreeMap<_, _>>();
        let mut current = by_id
            .get(domain_id)
            .and_then(|domain| domain.parent.as_deref());
        let mut seen = BTreeSet::new();

        while let Some(parent) = current {
            if parent == granted_domain_id {
                return true;
            }
            if !seen.insert(parent) {
                return false;
            }
            current = by_id
                .get(parent)
                .and_then(|domain| domain.parent.as_deref());
        }

        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidDocumentError {
    #[error("did document id is empty")]
    EmptyId,
    #[error("did document context must include https://www.w3.org/ns/did/v1")]
    MissingDidCoreContext,
    #[error("did document must include at least one verification method")]
    MissingVerificationMethod,
    #[error("did document must include at least one authentication method")]
    MissingAuthentication,
    #[error("did document must include at least one assertion method")]
    MissingAssertionMethod,
    #[error("oan metadata missing")]
    MissingOanMetadata,
    #[error("oan subject type and resource type must match for discoverable resources")]
    ResourceTypeMismatch,
    #[error("did:oan identifier does not match current did:oan syntax")]
    InvalidDidOanIdentifier,
    #[error("did document controller is required")]
    MissingController,
    #[error("did document top-level proof is required")]
    MissingProof,
    #[error("did document proof is invalid: {0}")]
    InvalidProof(&'static str),
    #[error("external identifier list is invalid: {0}")]
    InvalidExternalIdentifier(&'static str),
    #[error("subject type and resource type combination is invalid")]
    InvalidTypeCombination,
    #[error("oan metadata controllerDid must match the top-level controller")]
    ControllerDidMismatch,
}

impl DidDocument {
    pub fn validate_mvp(&self) -> Result<(), DidDocumentError> {
        if self.id.is_empty() {
            return Err(DidDocumentError::EmptyId);
        }
        if self.context.iter().map(String::as_str).collect::<Vec<_>>() != DID_OAN_CONTEXTS {
            return Err(DidDocumentError::MissingDidCoreContext);
        }
        if self.verification_method.is_empty() {
            return Err(DidDocumentError::MissingVerificationMethod);
        }
        if self.authentication.is_empty() {
            return Err(DidDocumentError::MissingAuthentication);
        }
        if self.assertion_method.is_empty() {
            return Err(DidDocumentError::MissingAssertionMethod);
        }
        Ok(())
    }

    pub fn validate_oan_resource(&self) -> Result<(), DidDocumentError> {
        self.validate_mvp()?;
        let controller = self
            .controller
            .as_ref()
            .ok_or(DidDocumentError::MissingController)?;
        let metadata = self
            .oan_metadata
            .as_ref()
            .ok_or(DidDocumentError::MissingOanMetadata)?;
        if let Some(controller_did) = metadata.controller_did.as_deref() {
            if !controller.contains(controller_did) {
                return Err(DidDocumentError::ControllerDidMismatch);
            }
        }
        if !valid_type_combination(&metadata.subject_type, &metadata.resource_type) {
            return Err(DidDocumentError::InvalidTypeCombination);
        }
        if metadata.subject_type == SubjectType::Controller
            && metadata.resource_type == ResourceType::Controller
            && !controller.contains(&self.id)
        {
            return Err(DidDocumentError::ControllerDidMismatch);
        }
        let did = oan_did_oan::DidOan::parse(&self.id)
            .map_err(|_| DidDocumentError::InvalidDidOanIdentifier)?;
        let _ = did;
        let proof = self.proof.as_ref().ok_or(DidDocumentError::MissingProof)?;
        validate_proof(self, controller, proof)?;
        validate_external_identifiers(&metadata.external_identifiers)?;
        Ok(())
    }

    pub fn validate_infrastructure_profile(
        &self,
        expected_resource_type: ResourceType,
    ) -> Result<(), DidDocumentError> {
        self.validate_mvp()?;
        let metadata = self
            .oan_metadata
            .as_ref()
            .ok_or(DidDocumentError::MissingOanMetadata)?;
        if metadata.subject_type != SubjectType::InfrastructureNode
            || metadata.resource_type != expected_resource_type
        {
            return Err(DidDocumentError::InvalidTypeCombination);
        }
        if metadata.identity_type.is_some()
            || metadata.extra.contains_key("nodeRole")
            || metadata.extra.contains_key("identityType")
        {
            return Err(DidDocumentError::InvalidTypeCombination);
        }
        let controller = self
            .controller
            .as_ref()
            .ok_or(DidDocumentError::MissingController)?;
        let key_id = format!("{}#key-1", self.id);
        let method = self
            .verification_method
            .iter()
            .find(|method| method.id == key_id && method.controller == self.id)
            .ok_or(DidDocumentError::MissingVerificationMethod)?;
        let expected_service_type = match expected_resource_type {
            ResourceType::RootNode => "OANRootService",
            ResourceType::RegistrarNode => "OANRegistrarService",
            ResourceType::DiscoveryNode => "OANDiscoveryService",
            ResourceType::VcIssuerNode => "OANVcIssuerService",
            _ => return Err(DidDocumentError::InvalidTypeCombination),
        };
        if !self.authentication.iter().any(|value| value == &key_id)
            || !self.assertion_method.iter().any(|value| value == &key_id)
            || !controller.contains(&self.id)
            || !self
                .service
                .iter()
                .any(|service| service.service_type == expected_service_type)
        {
            return Err(DidDocumentError::InvalidTypeCombination);
        }
        if self.proof.is_none() || method.crypto_suite().is_none() {
            return Err(DidDocumentError::MissingProof);
        }
        Ok(())
    }
}

fn valid_type_combination(subject: &SubjectType, resource: &ResourceType) -> bool {
    matches!(
        (subject, resource),
        (SubjectType::AgentInstance, ResourceType::AgentInstance)
            | (SubjectType::AgentInstance, ResourceType::AgentService)
            | (SubjectType::AgentProduct, ResourceType::AgentProduct)
            | (SubjectType::Organization, ResourceType::Organization)
            | (SubjectType::Developer, ResourceType::Developer)
            | (SubjectType::AgentService, ResourceType::AgentService)
            | (SubjectType::Skill, ResourceType::Skill)
            | (SubjectType::McpServer, ResourceType::McpServer)
            | (SubjectType::ToolApi, ResourceType::ToolApi)
            | (
                SubjectType::InfrastructureNode,
                ResourceType::InfrastructureNode
            )
            | (SubjectType::InfrastructureNode, ResourceType::RootNode)
            | (SubjectType::InfrastructureNode, ResourceType::RegistrarNode)
            | (SubjectType::InfrastructureNode, ResourceType::DiscoveryNode)
            | (SubjectType::InfrastructureNode, ResourceType::CdnNode)
            | (SubjectType::InfrastructureNode, ResourceType::VcIssuerNode)
            | (
                SubjectType::InfrastructureNode,
                ResourceType::TrustIndexerNode
            )
            | (SubjectType::RootNode, ResourceType::RootNode)
            | (SubjectType::RegistrarNode, ResourceType::RegistrarNode)
            | (SubjectType::DiscoveryNode, ResourceType::DiscoveryNode)
            | (SubjectType::CdnNode, ResourceType::CdnNode)
            | (SubjectType::VcIssuerNode, ResourceType::VcIssuerNode)
            | (
                SubjectType::TrustIndexerNode,
                ResourceType::TrustIndexerNode
            )
            | (SubjectType::Controller, ResourceType::Controller)
            | (SubjectType::Unspecified, ResourceType::Unspecified)
    )
}

fn validate_proof(
    document: &DidDocument,
    _controller: &DidController,
    proof: &DataIntegrityProof,
) -> Result<(), DidDocumentError> {
    let verification_method = proof
        .verification_method
        .as_deref()
        .ok_or(DidDocumentError::InvalidProof("verificationMethod"))?;
    let expected_method = format!("{}#key-1", document.id);
    if !proof.creator.is_empty()
        || proof.crypto_suite.is_some()
        || proof.hash_algorithm.is_some()
        || proof.proof_type != "Ed25519Signature2020"
        || proof.proof_purpose != "assertionMethod"
        || verification_method != expected_method
        || !proof.proof_value.starts_with('z')
        || bs58::decode(&proof.proof_value[1..])
            .into_vec()
            .map_or(true, |signature: Vec<u8>| signature.len() != 64)
        || !document
            .assertion_method
            .iter()
            .any(|method| method == verification_method)
        || !document
            .authentication
            .iter()
            .any(|method| method == verification_method)
    {
        return Err(DidDocumentError::InvalidProof("did:oan"));
    }
    Ok(())
    /*
    let verification_method = proof
        .verification_method
        .as_deref()
        .ok_or(DidDocumentError::InvalidProof("verificationMethod"))?;
    if proof.creator != verification_method {
        return Err(DidDocumentError::InvalidProof("creator"));
    }
    if !document
        .assertion_method
        .iter()
        .any(|method| method == verification_method)
    {
        return Err(DidDocumentError::InvalidProof("assertionMethod"));
    }
    let method = document
        .verification_method
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or(DidDocumentError::InvalidProof(
            "verificationMethodReference",
        ))?;
    if !controller.contains(&method.controller) {
        return Err(DidDocumentError::InvalidProof("controller"));
    }
    if proof.crypto_suite.is_none() {
        return Err(DidDocumentError::InvalidProof("cryptoSuite"));
    }
    if proof.hash_algorithm.is_none() {
        return Err(DidDocumentError::InvalidProof("hashAlgorithm"));
    }
    let suite = proof.crypto_suite.as_ref().expect("checked above");
    if matches!(suite, CryptoSuite::Ed25519Sha256Legacy) {
        return Err(DidDocumentError::InvalidProof("legacyCryptoSuite"));
    }
    let hash_algorithm = suite.canonical_hash_algorithm();
    if proof.proof_type != suite.proof_type()
        || proof.hash_algorithm.as_deref() != Some(hash_algorithm)
        || method.crypto_suite.as_ref() != Some(suite)
        || method.method_type != suite.verification_method_type()
    {
        return Err(DidDocumentError::InvalidProof("algorithmMismatch"));
    }
    Ok(())
    */
}

fn validate_external_identifiers(values: &[ExternalIdentifier]) -> Result<(), DidDocumentError> {
    if values.len() > 8 {
        return Err(DidDocumentError::InvalidExternalIdentifier("maxItems"));
    }
    let mut ids = BTreeSet::new();
    for value in values {
        if value.id.is_empty()
            || value.id.len() > 512
            || value.id.chars().any(|ch| ch.is_control())
            || value.id.starts_with("did:oan:")
        {
            return Err(DidDocumentError::InvalidExternalIdentifier("id"));
        }
        if !ids.insert(&value.id) {
            return Err(DidDocumentError::InvalidExternalIdentifier("duplicate"));
        }
        if let Some(endpoint) = &value.resolution_service_endpoint {
            if endpoint.len() > 1024 {
                return Err(DidDocumentError::InvalidExternalIdentifier(
                    "endpointLength",
                ));
            }
            let parsed = url::Url::parse(endpoint)
                .map_err(|_| DidDocumentError::InvalidExternalIdentifier("endpointUri"))?;
            if matches!(parsed.scheme(), "file" | "data" | "javascript")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(DidDocumentError::InvalidExternalIdentifier(
                    "endpointSafety",
                ));
            }
        }
    }
    let serialized = serde_json::to_vec(values)
        .map_err(|_| DidDocumentError::InvalidExternalIdentifier("serialization"))?;
    if serialized.len() > 8192 {
        return Err(DidDocumentError::InvalidExternalIdentifier("maxBytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn oan_fixture_contract_is_stable() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-fixtures/did-oan-contract.json"))
                .unwrap();
        assert_eq!(fixture["contexts"], serde_json::json!(DID_OAN_CONTEXTS));
        assert_eq!(
            fixture["proof"]["verificationMethod"],
            format!("{}#key-1", fixture["did"].as_str().unwrap())
        );
        assert!(fixture["proof"]["proofValue"]
            .as_str()
            .unwrap()
            .starts_with('z'));
    }

    #[test]
    fn oan_proof_rejects_legacy_fields_on_deserialization() {
        let value = serde_json::json!({
            "type": "Ed25519Signature2020",
            "created": "2026-09-29T00:00:00Z",
            "proofPurpose": "assertionMethod",
            "proofValue": "z111",
            "verificationMethod": "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
            "creator": "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"
        });
        assert!(serde_json::from_value::<OanDataIntegrityProof>(value).is_err());
    }

    #[test]
    fn oan_jwk_rejects_nonstandard_alg() {
        let jwk = OanJwk {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: "AQ".to_owned(),
            d: None,
            alg: Some("Ed25519".to_owned()),
        };
        assert_eq!(
            jwk.validate_ed25519(false),
            Err(OanProfileError::InvalidJwk)
        );
    }

    #[test]
    fn oan_credential_rejects_legacy_proof_fields() {
        let value = serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://openagenet.xyz/did-oan-specs/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "issuer": "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
            "credentialSubject": {"id": "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu"},
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2026-09-29T00:00:00Z",
                "proofPurpose": "assertionMethod",
                "proofValue": "z111",
                "verificationMethod": "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
                "hashAlgorithm": "sha256"
            }
        });
        assert!(serde_json::from_value::<OanVerifiableCredential>(value).is_err());
    }

    #[test]
    fn oan_credential_requires_fixed_context_and_multibase_proof() {
        let credential = OanVerifiableCredential {
            id: None,
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                "OANResourceRegistrationCredential".to_owned(),
            ],
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_owned(),
                "https://openagenet.xyz/did-oan-specs/v1".to_owned(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_owned(),
            ],
            issuer: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: json!({"id": "did:oan:K7mQ9:subject"}),
            credential_status: None,
            credential_schema: None,
            proof: OanCredentialProof {
                proof_type: "Ed25519Signature2020".to_owned(),
                created: Utc::now(),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: format!("z{}", bs58::encode([9u8; 64]).into_string()),
                verification_method: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"
                    .to_owned(),
            },
        };
        assert_eq!(credential.validate(), Ok(()));
    }

    #[test]
    fn oan_hash_excludes_proof_for_signature_input_but_includes_it_for_final_hash() {
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let key_id = format!("{did}#key-1");
        let document = OanDidDocument {
            context: DID_OAN_CONTEXTS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            id: did.to_owned(),
            controller: Some(DidController::Did(did.to_owned())),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            capability_invocation: vec![],
            service: vec![],
            proof: OanDataIntegrityProof {
                proof_type: "Ed25519Signature2020".to_owned(),
                created: Utc::now(),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: format!("z{}", bs58::encode([8u8; 64]).into_string()),
                verification_method: key_id,
            },
            oan_metadata: None,
        };
        let input = oan_signature_input(&document).unwrap();
        let hash = oan_did_document_hash(&document).unwrap();
        assert!(!input.is_empty());
        assert!(hash.starts_with("sha256:"));
    }

    #[test]
    fn oan_jwk_requires_32_byte_public_key() {
        let jwk = OanJwk {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode([1u8; 31]),
            d: None,
            alg: None,
        };
        assert_eq!(
            jwk.validate_ed25519(false),
            Err(OanProfileError::InvalidJwk)
        );
    }

    #[test]
    fn oan_identity_public_projection_excludes_private_key() {
        let public = OanJwk {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode([3u8; 32]),
            d: None,
            alg: Some("EdDSA".to_owned()),
        };
        let private = OanJwk {
            d: Some(URL_SAFE_NO_PAD.encode([4u8; 32])),
            ..public.clone()
        };
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let key_id = format!("{did}#key-1");
        let identity = OanIdentity {
            id: "urn:oan:identity:test".to_owned(),
            created_at: "2026-09-29T00:00:00Z".to_owned(),
            did: did.to_owned(),
            verification_method_id: key_id.clone(),
            did_document: OanDidDocument {
                context: DID_OAN_CONTEXTS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                id: did.to_owned(),
                controller: Some(DidController::Did(did.to_owned())),
                verification_method: vec![OanVerificationMethod {
                    id: key_id.clone(),
                    method_type: "Ed25519VerificationKey2020".to_owned(),
                    controller: did.to_owned(),
                    public_key_multibase: None,
                    public_key_jwk: Some(public.clone()),
                }],
                authentication: vec![key_id.clone()],
                assertion_method: vec![key_id.clone()],
                capability_invocation: vec![],
                service: vec![],
                proof: OanDataIntegrityProof {
                    proof_type: "Ed25519Signature2020".to_owned(),
                    created: Utc::now(),
                    proof_purpose: "assertionMethod".to_owned(),
                    proof_value: format!("z{}", bs58::encode([8u8; 64]).into_string()),
                    verification_method: key_id,
                },
                oan_metadata: None,
            },
            public_key_jwk: public,
            private_key_jwk: private,
        };
        let projection = identity.public_projection();
        let serialized = serde_json::to_value(projection).unwrap();
        assert!(serialized.get("privateKeyJwk").is_none());
    }

    #[test]
    fn oan_did_document_accepts_fixed_context_and_key_1() {
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let key_id = format!("{did}#key-1");
        let document = OanDidDocument {
            context: DID_OAN_CONTEXTS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            id: did.to_owned(),
            controller: Some(DidController::Did(did.to_owned())),
            verification_method: vec![OanVerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_multibase: Some(format!(
                    "z{}",
                    bs58::encode([vec![0xed, 0x01], vec![7u8; 32]].concat()).into_string()
                )),
                public_key_jwk: None,
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id.clone()],
            capability_invocation: vec![],
            service: vec![],
            proof: OanDataIntegrityProof {
                proof_type: "Ed25519Signature2020".to_owned(),
                created: Utc::now(),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: format!("z{}", bs58::encode([8u8; 64]).into_string()),
                verification_method: key_id,
            },
            oan_metadata: None,
        };
        assert_eq!(document.validate(), Ok(()));
    }

    #[test]
    fn oan_did_document_rejects_old_context_and_non_multibase_signature() {
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let key_id = format!("{did}#key-1");
        let mut document = OanDidDocument {
            context: DID_OAN_CONTEXTS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            id: did.to_owned(),
            controller: Some(DidController::Did(did.to_owned())),
            verification_method: vec![OanVerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_multibase: Some(format!(
                    "z{}",
                    bs58::encode([vec![0xed, 0x01], vec![7u8; 32]].concat()).into_string()
                )),
                public_key_jwk: None,
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id.clone()],
            capability_invocation: vec![],
            service: vec![],
            proof: OanDataIntegrityProof {
                proof_type: "Ed25519Signature2020".to_owned(),
                created: Utc::now(),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: format!("z{}", bs58::encode([8u8; 64]).into_string()),
                verification_method: key_id,
            },
            oan_metadata: None,
        };
        document.context[1] = "https://w3id.org/oan/v1".to_owned();
        assert_eq!(document.validate(), Err(OanProfileError::InvalidContext));
        document.context[1] = DID_OAN_CONTEXTS[1].to_owned();
        document.proof.proof_value = "base64url-signature".to_owned();
        assert_eq!(document.validate(), Err(OanProfileError::InvalidProof));
    }

    fn sample_oan_resource_document(
        resource_type: ResourceType,
        subject_type: SubjectType,
    ) -> DidDocument {
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let key_id = format!("{did}#key-1");
        DidDocument {
            context: DID_OAN_CONTEXTS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            id: did.to_owned(),
            controller: Some(DidController::Did(did.to_owned())),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: None,
                public_key_format: None,
                public_key_multibase: Some("zExample".to_owned()),
                public_key_jwk: None,
            }],
            authentication: vec![format!("{did}#key-1")],
            assertion_method: vec![format!("{did}#key-1")],
            capability_invocation: vec![format!("{did}#key-1")],
            service: vec![],
            proof: Some(DataIntegrityProof {
                context: None,
                proof_type: "Ed25519Signature2020".to_owned(),
                creator: String::new(),
                created: Utc::now(),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: format!("z{}", bs58::encode([8u8; 64]).into_string()),
                crypto_suite: None,
                hash_algorithm: None,
                verification_method: Some(key_id),
            }),
            oan_metadata: Some(OanMetadata {
                subject_type,
                resource_type,
                external_identifiers: vec![],
                identity_type: None,
                controller_did: None,
                publisher_did: Some("did:oan:P9aBc:8LcR3Vn5YpQw2Tx7Mb9Zd4Fa6GhKsEuJ".to_owned()),
                issuer_did: None,
                ttl: None,
                resource_description: Some(ResourceDescription {
                    name: Some("Contract Review Skill".to_owned()),
                    description: Some("Review contracts and identify risks.".to_owned()),
                    capability_tags: vec!["legal.contract.review".to_owned()],
                    ..Default::default()
                }),
                agent_description: None,
                capability_tags: vec!["legal.contract.review".to_owned()],
                authorized_domains: vec!["legal".to_owned()],
                protocol_bindings: vec![],
                implementation_links: vec![],
                credential_requirements: vec![],
                package_info: Some(PackageInfo {
                    manifest_url: Some(
                        "https://discovery.example.org/packages/skill.json".to_owned(),
                    ),
                    download_url: Some(
                        "https://discovery.example.org/download/skill.zip".to_owned(),
                    ),
                    package_hash: Some("sha256:pkg".to_owned()),
                    metadata_hash: Some("sha256:meta".to_owned()),
                    root_proof_ref: Some("https://root.example.org/proofs/skill.json".to_owned()),
                    version: Some("1.0.0".to_owned()),
                    version_scheme: Some("semver".to_owned()),
                    previous_version: None,
                    release_notes_url: None,
                    created_at: Some(Utc::now()),
                    updated_at: None,
                    expires_at: None,
                }),
                service_policy: None,
                network_scope: None,
                lifecycle_state: Some("active".to_owned()),
                extra: BTreeMap::new(),
            }),
        }
    }

    #[test]
    fn infrastructure_nodes_are_not_agents() {
        assert_eq!(
            NodeRole::Root.subject_type(),
            SubjectType::InfrastructureNode
        );
        assert_eq!(
            NodeRole::Registrar.subject_type(),
            SubjectType::InfrastructureNode
        );
        assert_eq!(
            NodeRole::Discovery.subject_type(),
            SubjectType::InfrastructureNode
        );
        assert_eq!(NodeRole::ServiceAgent.subject_type(), SubjectType::Agent);
    }

    #[test]
    fn oan_type_values_are_independent_of_did_code() {
        assert_eq!(ResourceType::Skill.as_str(), "skill");
        assert_eq!(ResourceType::RegistrarNode.as_str(), "registrar_node");
        assert_eq!(SubjectType::AgentInstance, SubjectType::AgentInstance);
        assert_eq!(ResourceType::Controller.as_str(), "controller");
    }

    #[test]
    fn controller_profile_allows_only_controller_resource_pair() {
        assert!(valid_type_combination(
            &SubjectType::Controller,
            &ResourceType::Controller
        ));
        assert!(!valid_type_combination(
            &SubjectType::Controller,
            &ResourceType::Skill
        ));
        assert!(!valid_type_combination(
            &SubjectType::Skill,
            &ResourceType::Controller
        ));
    }

    #[test]
    fn oan_serialization_has_no_legacy_node_role() {
        let metadata = OanMetadata {
            subject_type: SubjectType::Skill,
            resource_type: ResourceType::Skill,
            external_identifiers: vec![],
            identity_type: None,
            controller_did: None,
            publisher_did: None,
            issuer_did: None,
            ttl: None,
            resource_description: None,
            agent_description: None,
            capability_tags: vec![],
            authorized_domains: vec![],
            protocol_bindings: vec![],
            implementation_links: vec![],
            credential_requirements: vec![],
            package_info: None,
            service_policy: None,
            network_scope: None,
            lifecycle_state: None,
            extra: BTreeMap::new(),
        };
        let value = serde_json::to_value(&metadata).unwrap();
        assert!(value.get("nodeRole").is_none());
    }

    #[test]
    fn infrastructure_profile_requires_exact_role_resource_and_service() {
        let mut document = sample_oan_resource_document(
            ResourceType::RegistrarNode,
            SubjectType::InfrastructureNode,
        );
        document.service.push(ServiceEndpoint {
            id: format!("{}#registrar-api", document.id),
            service_type: "OANRegistrarService".to_owned(),
            service_endpoint: "https://registrar.example".to_owned(),
            version: None,
            protocol: None,
            server_type: None,
            port: None,
        });
        document
            .validate_infrastructure_profile(ResourceType::RegistrarNode)
            .unwrap();
        document
            .oan_metadata
            .as_mut()
            .unwrap()
            .extra
            .insert("nodeRole".to_owned(), serde_json::json!("registrar"));
        assert!(document
            .validate_infrastructure_profile(ResourceType::RegistrarNode)
            .is_err());
    }

    #[test]
    fn external_identifier_limits_and_safety_are_enforced() {
        let mut values = vec![ExternalIdentifier {
            id: "urn:example:one".to_owned(),
            resolution_service_endpoint: Some("https://example.org/resolve".to_owned()),
        }];
        assert!(validate_external_identifiers(&values).is_ok());
        values[0].resolution_service_endpoint = Some("file:///secret".to_owned());
        assert_eq!(
            validate_external_identifiers(&values).unwrap_err(),
            DidDocumentError::InvalidExternalIdentifier("endpointSafety")
        );
        values[0].resolution_service_endpoint = None;
        values[0].id = "did:oan:K7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned();
        assert_eq!(
            validate_external_identifiers(&values).unwrap_err(),
            DidDocumentError::InvalidExternalIdentifier("id")
        );
    }

    #[test]
    fn external_identifier_count_duplicate_and_size_limits_are_enforced() {
        let values = (0..9)
            .map(|index| ExternalIdentifier {
                id: format!("urn:example:{index}"),
                resolution_service_endpoint: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            validate_external_identifiers(&values).unwrap_err(),
            DidDocumentError::InvalidExternalIdentifier("maxItems")
        );

        let duplicate = vec![
            ExternalIdentifier {
                id: "urn:example:dup".to_owned(),
                resolution_service_endpoint: None,
            },
            ExternalIdentifier {
                id: "urn:example:dup".to_owned(),
                resolution_service_endpoint: None,
            },
        ];
        assert_eq!(
            validate_external_identifiers(&duplicate).unwrap_err(),
            DidDocumentError::InvalidExternalIdentifier("duplicate")
        );

        let oversized = vec![
            ExternalIdentifier {
                id: "urn:example:a".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "a".repeat(1024)
                )),
            },
            ExternalIdentifier {
                id: "urn:example:b".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "b".repeat(1024)
                )),
            },
            ExternalIdentifier {
                id: "urn:example:c".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "c".repeat(1024)
                )),
            },
            ExternalIdentifier {
                id: "urn:example:d".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "d".repeat(1024)
                )),
            },
            ExternalIdentifier {
                id: "urn:example:e".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "e".repeat(1024)
                )),
            },
            ExternalIdentifier {
                id: "urn:example:f".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "f".repeat(1024)
                )),
            },
            ExternalIdentifier {
                id: "urn:example:g".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "g".repeat(1024)
                )),
            },
            ExternalIdentifier {
                id: "urn:example:h".to_owned(),
                resolution_service_endpoint: Some(format!(
                    "https://example.org/{}",
                    "h".repeat(1024)
                )),
            },
        ];
        assert_eq!(
            validate_external_identifiers(&oversized).unwrap_err(),
            DidDocumentError::InvalidExternalIdentifier("endpointLength")
        );
    }

    #[test]
    fn oan_rejects_legacy_crypto_suite() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.proof.as_mut().unwrap().proof_value = "legacy-signature".to_owned();
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::InvalidProof("did:oan")
        );
    }

    #[test]
    fn validates_oan_resource_document_metadata() {
        let document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);

        assert_eq!(document.validate_oan_resource(), Ok(()));
    }

    #[test]
    fn unspecified_type_pair_is_valid_without_did_code_inference() {
        let document =
            sample_oan_resource_document(ResourceType::Unspecified, SubjectType::Unspecified);

        assert_eq!(document.validate_oan_resource(), Ok(()));
    }

    #[test]
    fn oan_requires_top_level_proof() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.proof = None;
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::MissingProof
        );
    }

    #[test]
    fn oan_rejects_proof_relationship_mismatch() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.proof.as_mut().unwrap().verification_method =
            Some(format!("{}#missing", document.id));
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::InvalidProof("did:oan")
        );

        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        let method_id = document
            .proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone()
            .unwrap();
        document.assertion_method = vec![format!("{method_id}-other")];
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::InvalidProof("did:oan")
        );
    }

    #[test]
    fn oan_rejects_legacy_creator_even_when_it_matches_verification_method() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        let method_id = document
            .proof
            .as_ref()
            .and_then(|proof| proof.verification_method.clone())
            .unwrap();
        document.proof.as_mut().unwrap().creator = method_id;
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::InvalidProof("did:oan")
        );
    }

    #[test]
    fn oan_rejects_proof_algorithm_mismatch() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.proof.as_mut().unwrap().proof_value = "zinvalid".to_owned();
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::InvalidProof("did:oan")
        );
    }

    #[test]
    fn controller_did_must_match_top_level_controller() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.oan_metadata.as_mut().unwrap().controller_did =
            Some("did:oan:QwErT:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo".to_owned());
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::ControllerDidMismatch
        );

        document.oan_metadata.as_mut().unwrap().controller_did =
            Some("did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned());
        assert_eq!(document.validate_oan_resource(), Ok(()));
    }

    #[test]
    fn controller_did_must_be_in_controller_array() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.controller = Some(DidController::Dids(vec![
            "did:oan:QwErT:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo".to_owned(),
            "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
        ]));
        document.oan_metadata.as_mut().unwrap().controller_did =
            Some("did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned());
        assert!(document.validate_oan_resource().is_ok());
    }

    #[test]
    fn validates_all_primary_product_oan_resource_documents() {
        let cases = [
            (
                "did:oan:K7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
                ResourceType::AgentService,
            ),
            (
                "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
                ResourceType::Skill,
            ),
            (
                "did:oan:K7mQ9:3NqV7Yp5TxRb9Wc2Md6Za4Ef8GhKsJuL",
                ResourceType::McpServer,
            ),
            (
                "did:oan:K7mQ9:7BcD3Fg5HjK8Mn9Pq2Rs4Tv6WxYzA1Ee",
                ResourceType::ToolApi,
            ),
        ];

        for (did, resource_type) in cases {
            let subject_type = match resource_type {
                ResourceType::AgentService => SubjectType::AgentService,
                ResourceType::Skill => SubjectType::Skill,
                ResourceType::McpServer => SubjectType::McpServer,
                ResourceType::ToolApi => SubjectType::ToolApi,
                _ => SubjectType::Unspecified,
            };
            let mut document = sample_oan_resource_document(resource_type.clone(), subject_type);
            document.id = did.to_owned();
            for method in &mut document.verification_method {
                method.id = format!("{did}#key-1");
                method.controller = "did:oan:P9aBc:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo".to_owned();
            }
            document.controller = Some(DidController::Did(
                "did:oan:P9aBc:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo".to_owned(),
            ));
            document.authentication = vec![format!("{did}#key-1")];
            document.assertion_method = vec![format!("{did}#key-1")];
            if let Some(proof) = &mut document.proof {
                proof.verification_method = Some(format!("{did}#key-1"));
            }

            let result = document.validate_oan_resource();
            assert!(
                result.is_ok(),
                "{did} should validate as {}: {result:?}",
                resource_type.as_str()
            );
        }
    }

    #[test]
    fn rejects_oan_resource_document_without_oan_metadata() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.oan_metadata = None;
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::MissingOanMetadata
        );
    }

    #[test]
    fn rejects_oan_resource_document_type_mismatch() {
        let document = sample_oan_resource_document(ResourceType::Skill, SubjectType::McpServer);
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::InvalidTypeCombination
        );
    }

    #[test]
    fn rejects_oan_resource_document_subject_code_mismatch() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.id = "did:oan:K7mQ:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::InvalidDidOanIdentifier
        );
    }

    #[test]
    fn rejects_oan_resource_document_with_malformed_oan_did() {
        let invalid_ids = [
            "did:oan:SKLG",
            "did:oan:SK:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
            "did:oan:SKLG:0OIl",
            "did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu:extra",
        ];

        for invalid_id in invalid_ids {
            let mut document =
                sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
            document.id = invalid_id.to_owned();
            assert_eq!(
                document.validate_oan_resource().unwrap_err(),
                DidDocumentError::InvalidDidOanIdentifier
            );
        }
    }

    #[test]
    fn rejects_oan_resource_document_missing_core_verification() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        document.authentication.clear();
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::MissingAuthentication
        );
    }

    #[test]
    fn oan_metadata_serializes_expected_resource_shape() {
        let document = sample_oan_resource_document(ResourceType::Skill, SubjectType::Skill);
        let value = serde_json::to_value(&document).unwrap();
        assert_eq!(value["oanMetadata"]["subjectType"], "skill");
        assert_eq!(value["oanMetadata"]["resourceType"], "skill");
        assert_eq!(
            value["oanMetadata"]["resourceDescription"]["capabilityTags"],
            json!(["legal.contract.review"])
        );
        assert_eq!(
            value["oanMetadata"]["packageInfo"]["packageHash"],
            "sha256:pkg"
        );
    }

    #[test]
    fn capability_tree_matches_authorized_domain_subtrees() {
        let tree = CapabilityTagTree {
            version: 1,
            tags: vec![
                CapabilityTag {
                    id: "text-processing".to_owned(),
                    label: "Text Processing".to_owned(),
                    parent: None,
                    aliases: vec![],
                },
                CapabilityTag {
                    id: "translation".to_owned(),
                    label: "Translation".to_owned(),
                    parent: Some("text-processing".to_owned()),
                    aliases: vec!["translate".to_owned()],
                },
            ],
            tree: vec![],
        };

        assert!(tree.matches_authorized_domains(
            &["translation".to_owned()],
            &["text-processing".to_owned()]
        ));
        assert!(tree.matches_authorized_domains(
            &["translate".to_owned()],
            &["text-processing".to_owned()]
        ));
        assert!(
            !tree.matches_authorized_domains(&["translation".to_owned()], &["finance".to_owned()])
        );
    }

    fn sample_domain_taxonomy() -> AuthorizedDomainTaxonomy {
        AuthorizedDomainTaxonomy {
            version: 1,
            snapshot_hash: Some("sha256:test".to_owned()),
            domains: vec![
                AuthorizedDomain {
                    id: "legal".to_owned(),
                    label: "Legal".to_owned(),
                    parent: None,
                    aliases: vec![],
                },
                AuthorizedDomain {
                    id: "legal.contract".to_owned(),
                    label: "Contract".to_owned(),
                    parent: Some("legal".to_owned()),
                    aliases: vec![],
                },
                AuthorizedDomain {
                    id: "finance".to_owned(),
                    label: "Finance".to_owned(),
                    parent: None,
                    aliases: vec![],
                },
                AuthorizedDomain {
                    id: "finance.banking".to_owned(),
                    label: "Banking".to_owned(),
                    parent: Some("finance".to_owned()),
                    aliases: vec![],
                },
            ],
            tree: vec![],
        }
    }

    #[test]
    fn authorized_domain_taxonomy_validates_canonical_lists() {
        let taxonomy = sample_domain_taxonomy();

        assert_eq!(
            taxonomy
                .validate_authorized_domains(&["finance".to_owned(), "legal.contract".to_owned()])
                .unwrap(),
            vec!["finance".to_owned(), "legal.contract".to_owned()]
        );
        assert_eq!(
            taxonomy
                .validate_authorized_domains(&["*".to_owned()])
                .unwrap(),
            vec!["*".to_owned()]
        );
        assert!(taxonomy
            .validate_authorized_domains(&[])
            .unwrap()
            .is_empty());
        assert_eq!(
            taxonomy
                .validate_authorized_domains(&["*".to_owned(), "legal".to_owned()])
                .unwrap_err(),
            AuthorizedDomainError::WildcardMixed
        );
        assert_eq!(
            taxonomy
                .validate_authorized_domains(&["legal".to_owned(), "legal".to_owned()])
                .unwrap_err(),
            AuthorizedDomainError::DuplicateOrUnsorted
        );
        assert_eq!(
            taxonomy
                .validate_authorized_domains(&["legal.unknown".to_owned()])
                .unwrap_err(),
            AuthorizedDomainError::UnknownDomain
        );
    }

    #[test]
    fn authorized_domain_taxonomy_checks_coverage() {
        let taxonomy = sample_domain_taxonomy();

        assert!(taxonomy
            .covers_authorized_domains(&["legal.contract".to_owned()], &["legal".to_owned()]));
        assert!(!taxonomy
            .covers_authorized_domains(&["legal".to_owned()], &["legal.contract".to_owned()]));
        assert!(taxonomy.covers_authorized_domains(
            &["finance.banking".to_owned(), "legal.contract".to_owned()],
            &["*".to_owned()]
        ));
        assert!(!taxonomy.covers_authorized_domains(&["finance.banking".to_owned()], &[]));
        assert!(taxonomy.covers_authorized_domains(&[], &[]));
    }

    #[test]
    fn loads_authorized_domain_taxonomy_snapshot() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../oan-design-docs/domains/authorized_domain_taxonomy.v1.json");

        let taxonomy = AuthorizedDomainTaxonomy::load_from_path(&path).unwrap();

        assert_eq!(taxonomy.version, 1);
        assert!(taxonomy
            .snapshot_hash
            .as_deref()
            .unwrap_or("")
            .starts_with("sha256:"));
        assert!(taxonomy
            .normalize_domain("finance_and_business.finance")
            .is_some());
        assert!(taxonomy.covers_authorized_domains(
            &["finance_and_business.finance".to_owned()],
            &["finance_and_business".to_owned()]
        ));
    }

    #[test]
    fn loads_and_flattens_nested_tree_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tree.json");
        fs::write(
            &path,
            r#"{"version":1,"tree":[{"id":"a","label":"A","children":[{"id":"b","label":"B","children":[{"id":"c","label":"C"}]}]}]}"#,
        )
        .unwrap();

        let tree = CapabilityTagTree::load_from_path(&path).unwrap();

        assert_eq!(tree.tree.len(), 1);
        assert_eq!(tree.tags.len(), 3);
        assert_eq!(tree.tags[0].id, "a");
        assert_eq!(tree.tags[1].parent.as_deref(), Some("a"));
        assert_eq!(tree.tags[2].parent.as_deref(), Some("b"));
    }

    #[test]
    fn verification_method_prefers_explicit_crypto_suite() {
        let method = VerificationMethod {
            id: "did:oan:AGDM:test#key-1".to_owned(),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: "did:oan:AGDM:test".to_owned(),
            crypto_suite: Some(CryptoSuite::Ed25519Sha256),
            public_key_format: Some("multibase".to_owned()),
            public_key_multibase: Some("zExample".to_owned()),
            public_key_jwk: None,
        };

        assert_eq!(method.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
    }

    #[test]
    fn verification_method_infers_current_suite_for_standard_shape() {
        let method = VerificationMethod {
            id: "did:oan:AGDM:test#key-1".to_owned(),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: "did:oan:AGDM:test".to_owned(),
            crypto_suite: None,
            public_key_format: None,
            public_key_multibase: Some("zExample".to_owned()),
            public_key_jwk: None,
        };

        assert_eq!(method.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
    }

    #[test]
    fn proof_prefers_explicit_crypto_suite() {
        let proof = DataIntegrityProof {
            context: None,
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:oan:AGDM:test#key-1".to_owned(),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "sig".to_owned(),
            crypto_suite: Some(CryptoSuite::Ed25519Sha256),
            hash_algorithm: Some("SHA-256".to_owned()),
            verification_method: Some("did:oan:AGDM:test#key-1".to_owned()),
        };

        assert_eq!(proof.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
    }

    #[test]
    fn proof_infers_current_suite_for_standard_shape() {
        let proof = DataIntegrityProof {
            context: None,
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:oan:AGDM:test#key-1".to_owned(),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "sig".to_owned(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: None,
        };

        assert_eq!(proof.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
    }
}
