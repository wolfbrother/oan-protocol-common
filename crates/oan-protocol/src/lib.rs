// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Protocol models shared across OpenAgenet nodes.

use chrono::{DateTime, Utc};
use oan_core::{DataIntegrityProof, DidDocument, ResourceType, ServiceEndpoint};
use oan_did_oan::DidOan;
use oan_package::ResourcePackage;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OAN_RESOURCE_PROTOCOL_VERSION: &str = "oan-resource-2026";
pub const PROTOCOL_VERSION: &str = OAN_RESOURCE_PROTOCOL_VERSION;
pub const PURPOSE_RESOURCE_REGISTRATION: &str = "resource-registration";
pub const PURPOSE_VERIFY_AND_PUBLISH: &str = "verify-and-publish";
pub const PURPOSE_CDN_PUBLISH: &str = "cdn-publish";
pub const PURPOSE_INFRASTRUCTURE_AUTHORIZATION_VC_ISSUE: &str =
    "infrastructure-authorization-vc-issue";
pub const PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH: &str = "/root/resources/verify-and-publish";
pub const PATH_ROOT_INFRASTRUCTURE_AUTHORIZATION_VCS_ISSUE: &str =
    "/root/infrastructure/authorization-vcs/issue";
pub const PATH_CDN_RESOURCES: &str = "/cdn/resources";
pub const PATH_CDN_RESOURCES_BATCH: &str = "/cdn/resources/batch";
pub const REGISTRATION_FLOW: &str = "did-control";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(rename = "nodeType")]
    pub node_type: String,
    pub did: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeAuthorizeRequest {
    #[serde(rename = "nodeDid")]
    pub node_did: String,
    #[serde(rename = "nodeRole")]
    pub node_role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryAuthorizeRequest {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    pub endpoint: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDomainUpdateRequest {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    #[serde(rename = "authorizedDomains")]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "tagTreeVersion")]
    pub tag_tree_version: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRegisterRequest {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    pub metadata: Value,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedRequestEnvelope {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub purpose: String,
    pub method: String,
    pub path: String,
    pub aud: String,
    #[serde(rename = "requestTimestamp")]
    pub request_timestamp: DateTime<Utc>,
    #[serde(rename = "requestNonce")]
    pub request_nonce: String,
    #[serde(rename = "bodyHash")]
    pub body_hash: String,
    pub proof: DataIntegrityProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DidControlChallenge {
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "draftId")]
    pub draft_id: String,
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    pub purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub nonce: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubjectControlProofBundle {
    pub challenge: DidControlChallenge,
    pub proof: DataIntegrityProof,
    #[serde(rename = "verifiedAt", skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(
        rename = "verifiedVerificationMethod",
        skip_serializing_if = "Option::is_none"
    )]
    pub verified_verification_method: Option<String>,
    #[serde(rename = "proofHash", skip_serializing_if = "Option::is_none")]
    pub proof_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRegistrationSubmission {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    pub metadata: Value,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(
        rename = "registrationCredential",
        default,
        skip_serializing_if = "Value::is_null"
    )]
    pub registration_credential: Value,
    #[serde(rename = "subjectControlProof")]
    pub subject_control_proof: SubjectControlProofBundle,
}

impl ResourceRegistrationSubmission {
    pub fn validate_shape(&self) -> Result<(), String> {
        let did = DidOan::parse(&self.resource_did).map_err(|err| err.to_string())?;
        did.validate_resource_type(self.resource_type.as_str())
            .map_err(|err| err.to_string())?;
        if self.did_document.id != self.resource_did {
            return Err("did_document_id_mismatch".to_owned());
        }
        self.did_document
            .validate_oan_resource()
            .map_err(|err| err.to_string())?;
        if self.package_version.trim().is_empty() {
            return Err("empty_package_version".to_owned());
        }
        if self.hash_algorithm.trim().is_empty() {
            return Err("empty_hash_algorithm".to_owned());
        }
        validate_hash_reference(
            "did_document_hash",
            &self.did_document_hash,
            &self.hash_algorithm,
        )?;
        validate_hash_reference("metadata_hash", &self.metadata_hash, &self.hash_algorithm)?;
        validate_hash_reference("package_hash", &self.package_hash, &self.hash_algorithm)?;
        let challenge = &self.subject_control_proof.challenge;
        if challenge.subject_did != self.resource_did {
            return Err("challenge_subject_did_mismatch".to_owned());
        }
        if challenge.did_document_hash != self.did_document_hash {
            return Err("challenge_did_document_hash_mismatch".to_owned());
        }
        if challenge.purpose != PURPOSE_RESOURCE_REGISTRATION {
            return Err("challenge_purpose_mismatch".to_owned());
        }
        Ok(())
    }
}

fn validate_hash_reference(field_name: &str, value: &str, algorithm: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("empty_{field_name}"));
    }
    let expected_prefix = format!("{algorithm}:");
    if value.contains(':') && !value.starts_with(&expected_prefix) {
        return Err(format!("{field_name}_algorithm_mismatch"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceVerifyAndPublishRequest {
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    pub submission: ResourceRegistrationSubmission,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnPublishRequest {
    pub package: ResourcePackage,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnPublishBatchItem {
    #[serde(rename = "publicationCursor")]
    pub publication_cursor: i64,
    pub package: ResourcePackage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnBatchPublishRequest {
    pub items: Vec<ResourceCdnPublishBatchItem>,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnIndexItem {
    pub cursor: i64,
    pub package: ResourcePackage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceCdnIndexResponse {
    pub items: Vec<ResourceCdnIndexItem>,
    pub count: usize,
    #[serde(rename = "afterCursor")]
    pub after_cursor: i64,
    #[serde(rename = "nextCursor")]
    pub next_cursor: i64,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RootAuthorizeRequest {
    #[serde(rename = "targetDid")]
    pub target_did: String,
    #[serde(rename = "targetRole")]
    pub target_role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureAuthorizationVcIssuePayload {
    #[serde(rename = "subjectDid")]
    pub subject_did: String,
    pub role: String,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentStableHash")]
    pub did_document_stable_hash: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureAuthorizationVcIssueRequest {
    pub payload: InfrastructureAuthorizationVcIssuePayload,
    #[serde(rename = "upstreamAuth")]
    pub upstream_auth: SignedRequestEnvelope,
}

pub type DiscoveryResponseProof = DataIntegrityProof;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceDiscoveryQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<ResourceType>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionMode", default = "default_version_mode")]
    pub version_mode: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    10
}

fn default_version_mode() -> String {
    "latest".to_owned()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceDiscoveryCandidate {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    pub score: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "lifecycleState", skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(default)]
    pub services: Vec<ServiceEndpoint>,
    #[serde(rename = "protocolBindings", default)]
    pub protocol_bindings: Vec<Value>,
    #[serde(rename = "packageInfo", skip_serializing_if = "Option::is_none")]
    pub package_info: Option<Value>,
    #[serde(rename = "rootProof", skip_serializing_if = "Option::is_none")]
    pub root_proof: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceDiscoveryResponse {
    #[serde(rename = "discoveryDid")]
    pub discovery_did: String,
    pub candidates: Vec<ResourceDiscoveryCandidate>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub proof: Option<DiscoveryResponseProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRootDiscoveryNotificationItem {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    pub operation: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
    #[serde(rename = "bulletinSequence")]
    pub bulletin_sequence: u64,
    #[serde(rename = "bulletinEventHash")]
    pub bulletin_event_hash: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRootDiscoveryBatchNotification {
    #[serde(rename = "notificationBatchId")]
    pub notification_batch_id: String,
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "targetDiscoveryDid")]
    pub target_discovery_did: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "sequenceFrom")]
    pub sequence_from: u64,
    #[serde(rename = "sequenceTo")]
    pub sequence_to: u64,
    pub items: Vec<ResourceRootDiscoveryNotificationItem>,
    #[serde(rename = "cdnManifestUrl")]
    pub cdn_manifest_url: String,
    #[serde(rename = "cdnUpdatesUrl")]
    pub cdn_updates_url: String,
    pub proof: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationEnvelope {
    pub id: String,
    #[serde(rename = "callerDid")]
    pub caller_did: String,
    #[serde(rename = "targetDid")]
    pub target_did: String,
    pub protocol: String,
    pub payload: Value,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use oan_core::{DataIntegrityProof, DidDocument};
    use serde_json::json;

    fn sample_proof() -> DataIntegrityProof {
        DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:oan:INRG:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1".to_owned(),
            created: Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "sig".to_owned(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: Some(
                "did:oan:INRG:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1".to_owned(),
            ),
        }
    }

    fn sample_valid_resource_did_document(did: &str) -> DidDocument {
        let key_id = format!("{did}#key-1");
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![oan_core::VerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(oan_core::CryptoSuite::Ed25519Sha256),
                public_key_format: None,
                public_key_multibase: Some("zExample".to_owned()),
                public_key_jwk: None,
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id],
            service: vec![],
            oan_metadata: Some(oan_core::OanMetadata {
                subject_type: oan_core::ResourceType::Skill,
                resource_type: oan_core::ResourceType::Skill,
                node_role: None,
                identity_type: None,
                controller_did: None,
                publisher_did: Some("did:oan:ORLG:8LcR3Vn5YpQw2Tx7Mb9Zd4Fa6GhKsEuJ".to_owned()),
                issuer_did: None,
                ttl: None,
                resource_description: Some(oan_core::ResourceDescription {
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
                package_info: None,
                service_policy: None,
                network_scope: None,
                lifecycle_state: Some("active".to_owned()),
                extra: std::collections::BTreeMap::new(),
            }),
        }
    }

    fn sample_resource_submission() -> ResourceRegistrationSubmission {
        let resource_did = "did:oan:SKFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz";
        let did_document_hash = "sha256:doc";
        let challenge = DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "draft-1".to_owned(),
            subject_did: resource_did.to_owned(),
            did_document_hash: did_document_hash.to_owned(),
            registrar_did: "did:oan:INRG:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            purpose: PURPOSE_RESOURCE_REGISTRATION.to_owned(),
            verification_method: format!("{resource_did}#key-1"),
            nonce: "nonce-1".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        };

        ResourceRegistrationSubmission {
            resource_did: resource_did.to_owned(),
            resource_type: oan_core::ResourceType::Skill,
            did_document: sample_valid_resource_did_document(resource_did),
            did_document_hash: did_document_hash.to_owned(),
            metadata: json!({"resourceType": "skill"}),
            package_version: "1.0.0".to_owned(),
            package_hash: "sha256:pkg".to_owned(),
            metadata_hash: "sha256:meta".to_owned(),
            hash_algorithm: "sha256".to_owned(),
            registration_credential: json!({"status": "active"}),
            subject_control_proof: SubjectControlProofBundle {
                challenge,
                proof: sample_proof(),
                verified_at: Some(Utc::now()),
                verified_verification_method: Some(format!("{resource_did}#key-1")),
                proof_hash: Some("proof-hash".to_owned()),
            },
        }
    }

    #[test]
    fn active_protocol_constants_are_resource_contracts() {
        assert_eq!(OAN_RESOURCE_PROTOCOL_VERSION, "oan-resource-2026");
        assert_eq!(PROTOCOL_VERSION, OAN_RESOURCE_PROTOCOL_VERSION);
        assert_eq!(
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "/root/resources/verify-and-publish"
        );
        assert_eq!(PATH_CDN_RESOURCES, "/cdn/resources");
        assert_eq!(PATH_CDN_RESOURCES_BATCH, "/cdn/resources/batch");
    }

    #[test]
    fn resource_registration_submission_rejects_legacy_did_method() {
        let mut submission = sample_resource_submission();
        submission.resource_did = "did:ans:SKFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned();
        submission.did_document.id = submission.resource_did.clone();
        submission.subject_control_proof.challenge.subject_did = submission.resource_did.clone();

        assert!(submission.validate_shape().is_err());
    }

    #[test]
    fn resource_discovery_query_and_candidate_round_trip() {
        let query = ResourceDiscoveryQuery {
            query: Some("contract review".to_owned()),
            resource_type: Some(oan_core::ResourceType::Skill),
            capability_tags: vec!["legal.contract.review".to_owned()],
            protocol: None,
            version: Some("1.0.0".to_owned()),
            version_mode: "exact".to_owned(),
            limit: 5,
        };
        let value = serde_json::to_value(&query).unwrap();
        assert_eq!(value["resourceType"], "skill");
        assert_eq!(value["versionMode"], "exact");
        let round_trip: ResourceDiscoveryQuery = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, query);

        let response = ResourceDiscoveryResponse {
            discovery_did: "did:oan:INDS:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            candidates: vec![ResourceDiscoveryCandidate {
                resource_did: "did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned(),
                resource_type: oan_core::ResourceType::Skill,
                score: 0.99,
                version: Some("1.0.0".to_owned()),
                lifecycle_state: Some("active".to_owned()),
                capability_tags: vec!["legal.contract.review".to_owned()],
                services: vec![],
                protocol_bindings: vec![],
                package_info: Some(json!({"packageHash": "sha256:pkg"})),
                root_proof: Some(
                    json!({"rootDid": "did:oan:INRT:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz"}),
                ),
            }],
            created_at: Utc::now(),
            proof: None,
        };
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["candidates"][0]["resourceType"], "skill");
        assert_eq!(
            value["candidates"][0]["resourceDid"],
            "did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu"
        );
    }

    #[test]
    fn resource_discovery_query_defaults_to_latest_and_limit_ten() {
        let query: ResourceDiscoveryQuery = serde_json::from_value(json!({
            "query": "legal analysis",
            "resourceType": "mcp_server"
        }))
        .unwrap();

        assert_eq!(query.resource_type, Some(oan_core::ResourceType::McpServer));
        assert_eq!(query.version_mode, "latest");
        assert_eq!(query.limit, 10);
        assert!(query.capability_tags.is_empty());
    }

    #[test]
    fn resource_registration_submission_uses_resource_field_names() {
        let challenge = DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "draft-1".to_owned(),
            subject_did: "did:oan:TLFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            did_document_hash: "sha256:doc".to_owned(),
            registrar_did: "did:oan:INRG:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            purpose: PURPOSE_RESOURCE_REGISTRATION.to_owned(),
            verification_method: "did:oan:TLFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        };
        let submission = ResourceRegistrationSubmission {
            resource_did: "did:oan:TLFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            resource_type: oan_core::ResourceType::ToolApi,
            did_document: sample_valid_resource_did_document(
                "did:oan:TLFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
            ),
            did_document_hash: "sha256:doc".to_owned(),
            metadata: json!({"resourceType": "tool_api"}),
            package_version: "1.0.0".to_owned(),
            package_hash: "sha256:pkg".to_owned(),
            metadata_hash: "sha256:meta".to_owned(),
            hash_algorithm: "sha256".to_owned(),
            registration_credential: json!({"status": "active"}),
            subject_control_proof: SubjectControlProofBundle {
                challenge,
                proof: sample_proof(),
                verified_at: Some(Utc::now()),
                verified_verification_method: Some(
                    "did:oan:TLFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1".to_owned(),
                ),
                proof_hash: Some("proof-hash".to_owned()),
            },
        };
        let value = serde_json::to_value(&submission).unwrap();
        assert_eq!(
            value["resourceDid"],
            "did:oan:TLFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz"
        );
        assert_eq!(value["resourceType"], "tool_api");
        assert_eq!(value["packageVersion"], "1.0.0");
    }

    #[test]
    fn resource_registration_submission_rejects_resource_type_mismatch() {
        let mut submission = sample_resource_submission();
        submission.resource_type = oan_core::ResourceType::McpServer;

        assert!(submission.validate_shape().is_err());
    }

    #[test]
    fn resource_registration_submission_accepts_valid_shape() {
        let submission = sample_resource_submission();

        assert!(submission.validate_shape().is_ok());
    }

    #[test]
    fn resource_registration_submission_rejects_did_document_id_mismatch() {
        let mut submission = sample_resource_submission();
        submission.did_document.id = "did:oan:MCLG:3NqV7Yp5TxRb9Wc2Md6Za4Ef8GhKsJuL".to_owned();

        assert_eq!(
            submission.validate_shape().unwrap_err(),
            "did_document_id_mismatch"
        );
    }

    #[test]
    fn resource_registration_submission_rejects_empty_version_or_hash_fields() {
        let cases = [
            ("package_version", ""),
            ("hash_algorithm", ""),
            ("did_document_hash", ""),
            ("metadata_hash", ""),
            ("package_hash", ""),
        ];

        for (field, value) in cases {
            let mut submission = sample_resource_submission();
            match field {
                "package_version" => submission.package_version = value.to_owned(),
                "hash_algorithm" => submission.hash_algorithm = value.to_owned(),
                "did_document_hash" => submission.did_document_hash = value.to_owned(),
                "metadata_hash" => submission.metadata_hash = value.to_owned(),
                "package_hash" => submission.package_hash = value.to_owned(),
                _ => unreachable!(),
            }
            assert!(submission.validate_shape().is_err(), "{field} should fail");
        }
    }

    #[test]
    fn resource_registration_submission_rejects_hash_algorithm_mismatch() {
        let mut submission = sample_resource_submission();
        submission.metadata_hash = "sm3:meta".to_owned();

        assert_eq!(
            submission.validate_shape().unwrap_err(),
            "metadata_hash_algorithm_mismatch"
        );
    }

    #[test]
    fn resource_registration_submission_rejects_oan_metadata_resource_type_mismatch() {
        let mut submission = sample_resource_submission();
        submission
            .did_document
            .oan_metadata
            .as_mut()
            .unwrap()
            .resource_type = oan_core::ResourceType::McpServer;

        assert_eq!(
            submission.validate_shape().unwrap_err(),
            "oan subject type and resource type must match for discoverable resources"
        );
    }

    #[test]
    fn resource_registration_submission_rejects_unknown_did_subject_code() {
        let mut submission = sample_resource_submission();
        submission.resource_did = "did:oan:ZZFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned();
        submission.did_document.id = submission.resource_did.clone();
        submission.subject_control_proof.challenge.subject_did = submission.resource_did.clone();

        assert_eq!(
            submission.validate_shape().unwrap_err(),
            "unsupported subject code"
        );
    }

    #[test]
    fn resource_registration_submission_rejects_challenge_binding_mismatch() {
        let cases = [
            (
                "subject_did",
                "did:oan:AGFI:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
            ),
            ("did_document_hash", "sha256:other-doc"),
            ("purpose", PURPOSE_VERIFY_AND_PUBLISH),
        ];

        for (field, value) in cases {
            let mut submission = sample_resource_submission();
            match field {
                "subject_did" => {
                    submission.subject_control_proof.challenge.subject_did = value.to_owned()
                }
                "did_document_hash" => {
                    submission.subject_control_proof.challenge.did_document_hash = value.to_owned()
                }
                "purpose" => submission.subject_control_proof.challenge.purpose = value.to_owned(),
                _ => unreachable!(),
            }
            assert!(submission.validate_shape().is_err(), "{field} should fail");
        }
    }

    #[test]
    fn resource_root_discovery_notification_serializes_version_and_hashes() {
        let notification = ResourceRootDiscoveryBatchNotification {
            notification_batch_id: "batch-1".to_owned(),
            root_did: "did:oan:INRT:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            target_discovery_did: "did:oan:INDS:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            authorized_domains: vec!["legal".to_owned()],
            sequence_from: 1,
            sequence_to: 1,
            items: vec![ResourceRootDiscoveryNotificationItem {
                resource_did: "did:oan:MCLG:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
                resource_type: oan_core::ResourceType::McpServer,
                operation: "publish".to_owned(),
                package_version: "2026-06".to_owned(),
                did_document_hash: "sha256:doc".to_owned(),
                metadata_hash: "sha256:meta".to_owned(),
                package_hash: "sha256:pkg".to_owned(),
                hash_algorithm: "sha256".to_owned(),
                lifecycle_state: "active".to_owned(),
                bulletin_sequence: 1,
                bulletin_event_hash: "event-hash".to_owned(),
                capability_tags: vec!["legal.search".to_owned()],
            }],
            cdn_manifest_url: "https://cdn.example.org/manifest.json".to_owned(),
            cdn_updates_url: "https://cdn.example.org/updates.json".to_owned(),
            proof: json!({"type": "DataIntegrityProof"}),
        };

        let value = serde_json::to_value(notification).unwrap();
        assert_eq!(value["items"][0]["resourceType"], "mcp_server");
        assert_eq!(value["items"][0]["packageVersion"], "2026-06");
        assert_eq!(value["items"][0]["packageHash"], "sha256:pkg");
    }
}
