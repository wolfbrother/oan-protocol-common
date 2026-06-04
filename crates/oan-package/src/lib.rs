// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Verified package, manifest, and metadata models.

use chrono::{DateTime, Utc};
use oan_core::{CryptoSuite, DataIntegrityProof, DidDocument, ResourceType, ServiceEndpoint};
use oan_crypto::{hash_json_with_suite, CryptoError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("did document hash mismatch")]
    DidDocumentHashMismatch,
    #[error("metadata hash mismatch")]
    MetadataHashMismatch,
    #[error("package hash mismatch")]
    PackageHashMismatch,
    #[error("root proof claim mismatch")]
    RootProofClaimMismatch,
    #[error("resource type mismatch")]
    ResourceTypeMismatch,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceMetadata {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "subjectType")]
    pub subject_type: ResourceType,
    #[serde(rename = "publisherDid", skip_serializing_if = "Option::is_none")]
    pub publisher_did: Option<String>,
    #[serde(rename = "subjectDid", skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "capabilityTags", default)]
    pub capability_tags: Vec<String>,
    #[serde(rename = "protocolBindings", default)]
    pub protocol_bindings: Vec<serde_json::Value>,
    #[serde(default)]
    pub services: Vec<ServiceEndpoint>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootProof {
    #[serde(rename = "rootDid")]
    pub root_did: String,
    #[serde(rename = "bulletinEventHash")]
    pub bulletin_event_hash: Option<String>,
    pub signature: Option<String>,
    #[serde(rename = "packageClaims", skip_serializing_if = "Option::is_none")]
    pub package_claims: Option<serde_json::Value>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
    #[serde(rename = "cryptoSuite", skip_serializing_if = "Option::is_none")]
    pub crypto_suite: Option<CryptoSuite>,
    #[serde(rename = "hashAlgorithm", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePackageClaims {
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    pub version: String,
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
    #[serde(rename = "bulletinRef", skip_serializing_if = "Option::is_none")]
    pub bulletin_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourcePackage {
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "resourceDid")]
    pub resource_did: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "didDocument")]
    pub did_document: DidDocument,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    pub metadata: ResourceMetadata,
    #[serde(rename = "rootProof")]
    pub root_proof: RootProof,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

impl ResourcePackage {
    fn effective_crypto_suite(&self) -> CryptoSuite {
        self.root_proof
            .crypto_suite
            .clone()
            .or_else(|| {
                self.root_proof
                    .proof
                    .as_ref()
                    .and_then(|proof| proof.crypto_suite())
            })
            .unwrap_or(CryptoSuite::Ed25519Sha256)
    }

    pub fn verify_did_document_hash(&self) -> Result<(), PackageError> {
        let actual_hash = hash_json_with_suite(self.effective_crypto_suite(), &self.did_document)?;
        if hash_matches(&self.did_document_hash, &self.hash_algorithm, &actual_hash) {
            Ok(())
        } else {
            Err(PackageError::DidDocumentHashMismatch)
        }
    }

    pub fn verify_metadata_hash(&self) -> Result<(), PackageError> {
        let actual_hash =
            hash_resource_metadata_with_suite(self.effective_crypto_suite(), &self.metadata)?;
        if hash_matches(&self.metadata_hash, &self.hash_algorithm, &actual_hash) {
            Ok(())
        } else {
            Err(PackageError::MetadataHashMismatch)
        }
    }

    pub fn verify_package_hash(&self) -> Result<(), PackageError> {
        let actual_hash = hash_json_with_suite(
            self.effective_crypto_suite(),
            &serde_json::json!({
                "packageVersion": self.package_version,
                "resourceDid": self.resource_did,
                "resourceType": self.resource_type,
                "didDocumentHash": self.did_document_hash,
                "metadataHash": self.metadata_hash,
                "hashAlgorithm": self.hash_algorithm,
            }),
        )?;
        if hash_matches(&self.package_hash, &self.hash_algorithm, &actual_hash) {
            Ok(())
        } else {
            Err(PackageError::PackageHashMismatch)
        }
    }

    pub fn verify_resource_type_consistency(&self) -> Result<(), PackageError> {
        if self.resource_type == self.metadata.resource_type
            && self.resource_type == self.metadata.subject_type
        {
            Ok(())
        } else {
            Err(PackageError::ResourceTypeMismatch)
        }
    }

    pub fn verify_metadata_consistency(&self) -> Result<(), PackageError> {
        if self.metadata.resource_did == self.resource_did
            && self.metadata.package_version == self.package_version
            && self.metadata.package_hash == self.package_hash
            && self.metadata.metadata_hash == self.metadata_hash
            && self.metadata.hash_algorithm == self.hash_algorithm
        {
            Ok(())
        } else {
            Err(PackageError::RootProofClaimMismatch)
        }
    }

    pub fn verify_root_claim_binding(&self) -> Result<(), PackageError> {
        let Some(claims) = self.root_proof.package_claims.as_ref() else {
            return Err(PackageError::RootProofClaimMismatch);
        };
        let parsed: ResourcePackageClaims = serde_json::from_value(claims.clone())
            .map_err(|_| PackageError::RootProofClaimMismatch)?;

        if parsed.resource_did == self.resource_did
            && parsed.resource_type == self.resource_type
            && parsed.version == self.package_version
            && parsed.did_document_hash == self.did_document_hash
            && parsed.metadata_hash == self.metadata_hash
            && parsed.package_hash == self.package_hash
            && parsed.hash_algorithm == self.hash_algorithm
            && parsed.lifecycle_state == self.metadata.lifecycle_state
        {
            Ok(())
        } else {
            Err(PackageError::RootProofClaimMismatch)
        }
    }
}

pub fn hash_resource_metadata_with_suite(
    suite: CryptoSuite,
    metadata: &ResourceMetadata,
) -> Result<String, CryptoError> {
    let mut normalized = metadata.clone();
    normalized.metadata_hash.clear();
    normalized.package_hash.clear();
    hash_json_with_suite(suite, &normalized)
}

fn hash_matches(expected: &str, algorithm: &str, actual: &str) -> bool {
    expected == actual || expected == format!("{algorithm}:{actual}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_core::{DidDocument, ResourceType};

    #[test]
    fn resource_package_verifies_root_claim_binding() {
        let package = sample_resource_package();

        assert!(package.verify_resource_type_consistency().is_ok());
        assert!(package.verify_metadata_consistency().is_ok());
        assert!(package.verify_root_claim_binding().is_ok());
    }

    fn sample_resource_package() -> ResourcePackage {
        let resource_did = "did:oan:SKLG:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let mut package = ResourcePackage {
            package_version: "1.0.0".to_owned(),
            resource_did: resource_did.to_owned(),
            resource_type: ResourceType::Skill,
            did_document: DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: resource_did.to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                service: vec![],
                oan_metadata: None,
            },
            did_document_hash: String::new(),
            metadata_hash: String::new(),
            package_hash: String::new(),
            hash_algorithm: "sha256".to_owned(),
            metadata: ResourceMetadata {
                resource_did: resource_did.to_owned(),
                resource_type: ResourceType::Skill,
                subject_type: ResourceType::Skill,
                publisher_did: Some("did:oan:ORLG:8LcR3Vn5YpQw2Tx7Mb9Zd4Fa6GhKsEuJ".to_owned()),
                subject_did: None,
                name: "Contract Review Skill".to_owned(),
                description: "Review contracts and identify risk signals.".to_owned(),
                capability_tags: vec!["legal.contract.review".to_owned()],
                protocol_bindings: vec![],
                services: vec![],
                lifecycle_state: "active".to_owned(),
                package_version: "1.0.0".to_owned(),
                package_hash: String::new(),
                metadata_hash: String::new(),
                hash_algorithm: "sha256".to_owned(),
                updated_at: Utc::now(),
            },
            root_proof: RootProof {
                root_did: "did:oan:INRT:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: None,
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        };
        refresh_resource_package_hashes(&mut package);
        package
    }

    fn refresh_resource_package_hashes(package: &mut ResourcePackage) {
        package.did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &package.did_document)
                .map(|hash| format!("sha256:{hash}"))
                .unwrap();
        package.metadata.metadata_hash.clear();
        package.metadata.package_hash.clear();
        package.metadata_hash =
            hash_resource_metadata_with_suite(CryptoSuite::Ed25519Sha256, &package.metadata)
                .map(|hash| format!("sha256:{hash}"))
                .unwrap();
        package.metadata.metadata_hash = package.metadata_hash.clone();
        package.package_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256,
            &serde_json::json!({
                "packageVersion": package.package_version,
                "resourceDid": package.resource_did,
                "resourceType": package.resource_type,
                "didDocumentHash": package.did_document_hash,
                "metadataHash": package.metadata_hash,
                "hashAlgorithm": package.hash_algorithm,
            }),
        )
        .map(|hash| format!("sha256:{hash}"))
        .unwrap();
        package.metadata.package_hash = package.package_hash.clone();
        let claims = ResourcePackageClaims {
            resource_did: package.resource_did.clone(),
            resource_type: package.resource_type.clone(),
            version: package.package_version.clone(),
            did_document_hash: package.did_document_hash.clone(),
            metadata_hash: package.metadata_hash.clone(),
            package_hash: package.package_hash.clone(),
            hash_algorithm: package.hash_algorithm.clone(),
            lifecycle_state: package.metadata.lifecycle_state.clone(),
            bulletin_ref: None,
        };
        package.root_proof.package_claims = Some(serde_json::to_value(claims).unwrap());
    }

    #[test]
    fn resource_package_rejects_root_claim_version_mismatch() {
        let mut package = sample_resource_package();
        package.package_version = "2.0.0".to_owned();

        assert!(matches!(
            package.verify_root_claim_binding(),
            Err(PackageError::RootProofClaimMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_root_claim_hash_algorithm_mismatch() {
        let mut package = sample_resource_package();
        package.hash_algorithm = "sm3".to_owned();

        assert!(matches!(
            package.verify_root_claim_binding(),
            Err(PackageError::RootProofClaimMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_missing_root_claims() {
        let mut package = sample_resource_package();
        package.root_proof.package_claims = None;

        assert!(matches!(
            package.verify_root_claim_binding(),
            Err(PackageError::RootProofClaimMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_unparseable_root_claims() {
        let mut package = sample_resource_package();
        package.root_proof.package_claims =
            Some(serde_json::json!({"resourceDid": package.resource_did}));

        assert!(matches!(
            package.verify_root_claim_binding(),
            Err(PackageError::RootProofClaimMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_metadata_resource_type_mismatch() {
        let mut package = sample_resource_package();
        package.metadata.subject_type = ResourceType::McpServer;

        assert!(matches!(
            package.verify_resource_type_consistency(),
            Err(PackageError::ResourceTypeMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_metadata_did_version_or_hash_mismatch() {
        let mutations = [
            (
                "resource_did",
                "did:oan:SKLG:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
            ),
            ("package_version", "2.0.0"),
            ("package_hash", "sha256:other-pkg"),
            ("metadata_hash", "sha256:other-meta"),
            ("hash_algorithm", "sm3"),
        ];

        for (field, value) in mutations {
            let mut package = sample_resource_package();
            match field {
                "resource_did" => package.metadata.resource_did = value.to_owned(),
                "package_version" => package.metadata.package_version = value.to_owned(),
                "package_hash" => package.metadata.package_hash = value.to_owned(),
                "metadata_hash" => package.metadata.metadata_hash = value.to_owned(),
                "hash_algorithm" => package.metadata.hash_algorithm = value.to_owned(),
                _ => unreachable!(),
            }

            assert!(matches!(
                package.verify_metadata_consistency(),
                Err(PackageError::RootProofClaimMismatch)
            ));
        }
    }

    #[test]
    fn resource_package_rejects_did_document_hash_mismatch() {
        let mut package = sample_resource_package();
        package.did_document_hash = "sha256:wrong-doc".to_owned();

        assert!(matches!(
            package.verify_did_document_hash(),
            Err(PackageError::DidDocumentHashMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_metadata_hash_mismatch() {
        let mut package = sample_resource_package();
        package.metadata_hash = "sha256:wrong-meta".to_owned();

        assert!(matches!(
            package.verify_metadata_hash(),
            Err(PackageError::MetadataHashMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_package_hash_mismatch() {
        let mut package = sample_resource_package();
        package.package_hash = "sha256:wrong-package".to_owned();
        package.metadata.package_hash = package.package_hash.clone();

        assert!(matches!(
            package.verify_package_hash(),
            Err(PackageError::PackageHashMismatch)
        ));
    }

    #[test]
    fn resource_package_rejects_root_claim_lifecycle_mismatch() {
        let mut package = sample_resource_package();
        package.metadata.lifecycle_state = "revoked".to_owned();

        assert!(matches!(
            package.verify_root_claim_binding(),
            Err(PackageError::RootProofClaimMismatch)
        ));
    }

    #[test]
    fn resource_package_accepts_algorithm_prefixed_hashes() {
        let mut package = sample_resource_package();
        refresh_resource_package_hashes(&mut package);

        assert!(package.verify_did_document_hash().is_ok());
        assert!(package.verify_metadata_hash().is_ok());
        assert!(package.verify_package_hash().is_ok());
    }
}
