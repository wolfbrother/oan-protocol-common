// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Core domain types shared by OAN services.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

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
            "Ed25519VerificationKey2020" => Some(Self::Ed25519Sha256Legacy),
            "SM2VerificationKey2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }

    pub fn from_proof_type(value: &str) -> Option<Self> {
        match value {
            "Ed25519Signature2020" => Some(Self::Ed25519Sha256Legacy),
            "SM2Signature2020" => Some(Self::Sm2Sm3),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectType {
    Agent,
    AgentService,
    Skill,
    McpServer,
    ToolApi,
    Organization,
    Developer,
    InfrastructureNode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    AgentService,
    Skill,
    McpServer,
    ToolApi,
    InfrastructureNode,
    Organization,
    Developer,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentService => "agent_service",
            Self::Skill => "skill",
            Self::McpServer => "mcp_server",
            Self::ToolApi => "tool_api",
            Self::InfrastructureNode => "infrastructure_node",
            Self::Organization => "organization",
            Self::Developer => "developer",
        }
    }

    pub fn expected_subject_code(&self) -> &'static str {
        match self {
            Self::AgentService => "AG",
            Self::Skill => "SK",
            Self::McpServer => "MC",
            Self::ToolApi => "TL",
            Self::InfrastructureNode => "IN",
            Self::Organization => "OR",
            Self::Developer => "DV",
        }
    }

    pub fn from_subject_code(value: &str) -> Option<Self> {
        match value {
            "AG" => Some(Self::AgentService),
            "SK" => Some(Self::Skill),
            "MC" => Some(Self::McpServer),
            "TL" => Some(Self::ToolApi),
            "IN" => Some(Self::InfrastructureNode),
            "OR" => Some(Self::Organization),
            "DV" => Some(Self::Developer),
            _ => None,
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
    pub fn semantic_code(&self) -> &'static str {
        match self {
            Self::Root => "INRT",
            Self::Registrar => "INRG",
            Self::Discovery => "INDS",
            Self::ServiceAgent => "AGDM",
            Self::UserAgent => "AGUS",
            Self::TestAgent => "AGTS",
        }
    }

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
    #[serde(rename = "type")]
    pub proof_type: String,
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
pub struct CredentialRequirement {
    #[serde(rename = "credentialType")]
    pub credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,
    #[serde(rename = "presentationMode", skip_serializing_if = "Option::is_none")]
    pub presentation_mode: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(rename = "bulletinRef", skip_serializing_if = "Option::is_none")]
    pub bulletin_ref: Option<String>,
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
    pub subject_type: ResourceType,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "nodeRole", skip_serializing_if = "Option::is_none")]
    pub node_role: Option<String>,
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
    #[serde(rename = "protocolBindings", default)]
    pub protocol_bindings: Vec<ProtocolBinding>,
    #[serde(rename = "implementationLinks", default)]
    pub implementation_links: Vec<ImplementationLink>,
    #[serde(rename = "credentialRequirements", default)]
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
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod", default)]
    pub assertion_method: Vec<String>,
    #[serde(default)]
    pub service: Vec<ServiceEndpoint>,
    #[serde(rename = "oanMetadata", skip_serializing_if = "Option::is_none")]
    pub oan_metadata: Option<OanMetadata>,
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
    #[error("did subject code and oan resource type do not match")]
    SubjectCodeResourceTypeMismatch,
}

impl DidDocument {
    pub fn validate_mvp(&self) -> Result<(), DidDocumentError> {
        if self.id.is_empty() {
            return Err(DidDocumentError::EmptyId);
        }
        if !self
            .context
            .iter()
            .any(|value| value == "https://www.w3.org/ns/did/v1")
        {
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
        let metadata = self
            .oan_metadata
            .as_ref()
            .ok_or(DidDocumentError::MissingOanMetadata)?;
        if metadata.subject_type != metadata.resource_type {
            return Err(DidDocumentError::ResourceTypeMismatch);
        }
        let parts = self.id.split(':').collect::<Vec<_>>();
        if parts.len() != 4
            || parts[0] != "did"
            || parts[1] != "oan"
            || parts[2].len() != 4
            || !parts[2]
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
            || parts[3].len() != 32
            || !parts[3]
                .chars()
                .all(|ch| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(ch))
        {
            return Err(DidDocumentError::SubjectCodeResourceTypeMismatch);
        }
        let subject_code = &parts[2][..2];
        if subject_code != metadata.resource_type.expected_subject_code() {
            return Err(DidDocumentError::SubjectCodeResourceTypeMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    fn sample_oan_resource_document(
        resource_type: ResourceType,
        subject_type: ResourceType,
    ) -> DidDocument {
        let did = "did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: None,
                public_key_multibase: Some("zExample".to_owned()),
                public_key_jwk: None,
            }],
            authentication: vec![format!("{did}#key-1")],
            assertion_method: vec![format!("{did}#key-1")],
            service: vec![],
            oan_metadata: Some(OanMetadata {
                subject_type,
                resource_type,
                node_role: None,
                identity_type: None,
                controller_did: None,
                publisher_did: Some("did:oan:ORLG:8LcR3Vn5YpQw2Tx7Mb9Zd4Fa6GhKsEuJ".to_owned()),
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
                    bulletin_ref: None,
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
    fn node_role_semantic_codes_use_infrastructure_prefixes() {
        assert_eq!(NodeRole::Root.semantic_code(), "INRT");
        assert_eq!(NodeRole::Registrar.semantic_code(), "INRG");
        assert_eq!(NodeRole::Discovery.semantic_code(), "INDS");
        assert_eq!(NodeRole::ServiceAgent.semantic_code(), "AGDM");
    }

    #[test]
    fn resource_type_maps_to_subject_codes() {
        assert_eq!(ResourceType::AgentService.expected_subject_code(), "AG");
        assert_eq!(ResourceType::Skill.expected_subject_code(), "SK");
        assert_eq!(ResourceType::McpServer.expected_subject_code(), "MC");
        assert_eq!(ResourceType::ToolApi.expected_subject_code(), "TL");
        assert_eq!(
            ResourceType::from_subject_code("SK"),
            Some(ResourceType::Skill)
        );
    }

    #[test]
    fn validates_oan_resource_document_metadata() {
        let document = sample_oan_resource_document(ResourceType::Skill, ResourceType::Skill);

        assert!(document.validate_oan_resource().is_ok());
    }

    #[test]
    fn validates_all_primary_product_oan_resource_documents() {
        let cases = [
            (
                "did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
                ResourceType::AgentService,
            ),
            (
                "did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
                ResourceType::Skill,
            ),
            (
                "did:oan:MCLG:3NqV7Yp5TxRb9Wc2Md6Za4Ef8GhKsJuL",
                ResourceType::McpServer,
            ),
            (
                "did:oan:TLFI:7BcD3Fg5HjK8Mn9Pq2Rs4Tv6WxYzA1Ee",
                ResourceType::ToolApi,
            ),
        ];

        for (did, resource_type) in cases {
            let mut document =
                sample_oan_resource_document(resource_type.clone(), resource_type.clone());
            document.id = did.to_owned();
            for method in &mut document.verification_method {
                method.id = format!("{did}#key-1");
                method.controller = did.to_owned();
            }
            document.authentication = vec![format!("{did}#key-1")];
            document.assertion_method = vec![format!("{did}#key-1")];

            assert!(
                document.validate_oan_resource().is_ok(),
                "{did} should validate as {}",
                resource_type.as_str()
            );
        }
    }

    #[test]
    fn rejects_oan_resource_document_without_oan_metadata() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, ResourceType::Skill);
        document.oan_metadata = None;
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::MissingOanMetadata
        );
    }

    #[test]
    fn rejects_oan_resource_document_type_mismatch() {
        let document = sample_oan_resource_document(ResourceType::Skill, ResourceType::McpServer);
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::ResourceTypeMismatch
        );
    }

    #[test]
    fn rejects_oan_resource_document_subject_code_mismatch() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, ResourceType::Skill);
        document.id = "did:oan:MCLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::SubjectCodeResourceTypeMismatch
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
                sample_oan_resource_document(ResourceType::Skill, ResourceType::Skill);
            document.id = invalid_id.to_owned();
            assert_eq!(
                document.validate_oan_resource().unwrap_err(),
                DidDocumentError::SubjectCodeResourceTypeMismatch
            );
        }
    }

    #[test]
    fn rejects_oan_resource_document_missing_core_verification() {
        let mut document = sample_oan_resource_document(ResourceType::Skill, ResourceType::Skill);
        document.authentication.clear();
        assert_eq!(
            document.validate_oan_resource().unwrap_err(),
            DidDocumentError::MissingAuthentication
        );
    }

    #[test]
    fn oan_metadata_serializes_expected_resource_shape() {
        let document = sample_oan_resource_document(ResourceType::Skill, ResourceType::Skill);
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
    fn verification_method_infers_legacy_suite_for_historical_shape() {
        let method = VerificationMethod {
            id: "did:oan:AGDM:test#key-1".to_owned(),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: "did:oan:AGDM:test".to_owned(),
            crypto_suite: None,
            public_key_format: None,
            public_key_multibase: Some("zExample".to_owned()),
            public_key_jwk: None,
        };

        assert_eq!(
            method.crypto_suite(),
            Some(CryptoSuite::Ed25519Sha256Legacy)
        );
    }

    #[test]
    fn proof_prefers_explicit_crypto_suite() {
        let proof = DataIntegrityProof {
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
    fn proof_infers_legacy_suite_for_historical_shape() {
        let proof = DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:oan:AGDM:test#key-1".to_owned(),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "sig".to_owned(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: None,
        };

        assert_eq!(proof.crypto_suite(), Some(CryptoSuite::Ed25519Sha256Legacy));
    }
}
