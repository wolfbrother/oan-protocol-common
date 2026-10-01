// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Credential models and verification helpers.

use chrono::{DateTime, Utc};
use oan_core::{
    CryptoSuite, OanCredentialProof, ResourceType, SubjectType,
};
use oan_crypto::{
    hash_json_with_suite, private_key_jwk, public_key_jwk, signature_input, sign_oan_data_integrity,
    signing_key_from_private_key_jwk,
    verify_oan_data_integrity, verify_oan_payload, verifying_key_from_method, CryptoError,
    SigningKey, VerifyingKey,
};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("credential proof is missing")]
    MissingProof,
    #[error("credential signature is invalid")]
    InvalidSignature,
    #[error("credential type is invalid")]
    InvalidType,
    #[error("credential subject is invalid")]
    InvalidSubject,
    #[error("credential serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// VC proofs use the strict DID/VC current did:oan Data Integrity shape.
///
/// Node-to-node request envelopes deliberately keep their separate
/// `DataIntegrityProof` model in `oan-core`; it is not reused here.
pub type CredentialProof = OanCredentialProof;

pub const VC_INFRASTRUCTURE_AUTHORIZATION: &str = "OANInfrastructureAuthorizationCredential";
pub const VC_RESOURCE_REGISTRATION: &str = "OANResourceRegistrationCredential";
pub const VC_BUSINESS_FACT: &str = "OANBusinessFactCredential";
pub const VC_QUALIFICATION: &str = "OANQualificationCredential";
pub const VC_AUDIT_RESULT: &str = "OANAuditResultCredential";
pub const VC_SELF_CLAIMED_CAPABILITY: &str = "OANSelfClaimedCapabilityCredential";
pub const OAN_VC_CONTEXTS: [&str; 3] = [
    "https://www.w3.org/2018/credentials/v1",
    "https://openagenet.xyz/did-oan-specs/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStatusReference {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    #[serde(rename = "credentialId", skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(rename = "subjectDid", skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(rename = "issuerDid", skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSchemaReference {
    pub id: String,
    #[serde(rename = "type")]
    pub schema_type: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OanVerifiableCredential<T> {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: T,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatusReference>,
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<CredentialSchemaReference>,
    pub proof: CredentialProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureAuthorizationCredentialSubject {
    pub id: String,
    pub role: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRegistrationCredentialSubject {
    pub id: String,
    #[serde(rename = "resourceType")]
    pub resource_type: ResourceType,
    #[serde(rename = "subjectType")]
    pub subject_type: SubjectType,
    #[serde(rename = "registrarDid")]
    pub registrar_did: String,
    #[serde(rename = "didDocumentHash")]
    pub did_document_hash: String,
    #[serde(rename = "metadataHash")]
    pub metadata_hash: String,
    #[serde(rename = "packageHash")]
    pub package_hash: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(rename = "authorizedDomains", default)]
    pub authorized_domains: Vec<String>,
    #[serde(rename = "externalIdentifiers", default)]
    pub external_identifiers: Vec<ExternalIdentifierReference>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BusinessFactCredentialSubject {
    pub id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "factType")]
    pub fact_type: String,
    pub claim: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QualificationCredentialSubject {
    pub id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "qualificationType")]
    pub qualification_type: String,
    pub qualification: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditResultCredentialSubject {
    pub id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "auditType")]
    pub audit_type: String,
    pub result: Value,
    #[serde(rename = "auditedAt")]
    pub audited_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelfClaimedCapabilityCredentialSubject {
    pub id: String,
    pub capability: String,
    pub claim: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentifierReference {
    pub id: String,
}

pub type OanInfrastructureAuthorizationCredential =
    OanVerifiableCredential<InfrastructureAuthorizationCredentialSubject>;
pub type OanResourceRegistrationCredential =
    OanVerifiableCredential<ResourceRegistrationCredentialSubject>;
pub type OanBusinessFactCredential = OanVerifiableCredential<BusinessFactCredentialSubject>;
pub type OanQualificationCredential = OanVerifiableCredential<QualificationCredentialSubject>;
pub type OanAuditResultCredential = OanVerifiableCredential<AuditResultCredentialSubject>;
pub type OanSelfClaimedCapabilityCredential =
    OanVerifiableCredential<SelfClaimedCapabilityCredentialSubject>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OanIdentity {
    pub id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub did: String,
    #[serde(rename = "verificationMethodId")]
    pub verification_method_id: String,
    #[serde(rename = "didDocument")]
    pub did_document: oan_core::DidDocument,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Value,
    #[serde(rename = "privateKeyJwk")]
    pub private_key_jwk: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedInfrastructureRole {
    Root,
    Registrar,
    Discovery,
    VcIssuer,
}

impl GovernedInfrastructureRole {
    pub fn resource_type(&self) -> &'static str {
        match self {
            Self::Root => "root_node",
            Self::Registrar => "registrar_node",
            Self::Discovery => "discovery_node",
            Self::VcIssuer => "vc_issuer_node",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Registrar => "registrar",
            Self::Discovery => "discovery",
            Self::VcIssuer => "vc_issuer",
        }
    }
}

impl OanIdentity {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.did != self.did_document.id {
            return Err(CredentialError::InvalidSubject);
        }
        if self.verification_method_id.is_empty()
            || self
                .did_document
                .verification_method
                .iter()
                .all(|method| method.id != self.verification_method_id)
        {
            return Err(CredentialError::InvalidSubject);
        }
        let method = self
            .did_document
            .verification_method
            .iter()
            .find(|method| method.id == self.verification_method_id)
            .ok_or(CredentialError::InvalidSubject)?;
        if !self
            .did_document
            .controller
            .as_ref()
            .is_some_and(|controller| controller.contains(&method.controller))
            || !self
                .did_document
                .authentication
                .iter()
                .any(|value| value == &self.verification_method_id)
            || !self
                .did_document
                .assertion_method
                .iter()
                .any(|value| value == &self.verification_method_id)
        {
            return Err(CredentialError::InvalidSubject);
        }
        if self
            .did_document
            .oan_metadata
            .as_ref()
            .is_some_and(|metadata| {
                metadata.subject_type == SubjectType::Controller
                    && metadata.resource_type == ResourceType::Controller
            })
            && !self
                .did_document
                .controller
                .as_ref()
                .is_some_and(|controller| controller.contains(&self.did))
        {
            return Err(CredentialError::InvalidSubject);
        }
        if method.public_key_jwk.as_ref() != Some(&self.public_key_jwk) {
            return Err(CredentialError::InvalidSubject);
        }
        let signing_key = signing_key_from_private_key_jwk(
            CryptoSuite::Ed25519Sha256,
            &self.private_key_jwk,
        )
            .map_err(|_| CredentialError::InvalidSubject)?;
        if public_key_jwk(&signing_key.verifying_key()) != self.public_key_jwk {
            return Err(CredentialError::InvalidSubject);
        }
        self.did_document
            .validate_mvp()
            .map_err(|_| CredentialError::InvalidSubject)?;
        let proof = self
            .did_document
            .proof
            .as_ref()
            .ok_or(CredentialError::InvalidSubject)?;
        if proof.verification_method.as_deref() != Some(self.verification_method_id.as_str())
            || !proof.creator.is_empty()
            || proof.crypto_suite.is_some()
            || proof.hash_algorithm.is_some()
        {
            return Err(CredentialError::InvalidSubject);
        }
        let verifying_key =
            verifying_key_from_method(method).map_err(|_| CredentialError::InvalidSubject)?;
        let mut unsigned = self.did_document.clone();
        unsigned.proof = None;
        let proof = OanCredentialProof {
            proof_type: proof.proof_type.clone(),
            created: proof.created,
            proof_purpose: proof.proof_purpose.clone(),
            proof_value: proof.proof_value.clone(),
            verification_method: proof.verification_method.clone().unwrap(),
        };
        verify_oan_payload(&unsigned, &proof, &verifying_key)
            .map_err(|_| CredentialError::InvalidSignature)?;
        Ok(())
    }
}

pub fn proof_payload_hash<T: Serialize>(
    suite: CryptoSuite,
    credential: &T,
) -> Result<String, CredentialError> {
    Ok(hash_json_with_suite(suite, credential)?)
}

pub fn sign_credential<T>(
    credential_without_proof: &T,
    _creator: String,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<CredentialProof, CredentialError>
where
    T: Serialize,
{
    let SigningKey::Ed25519 { key, .. } = signing_key else {
        return Err(CredentialError::InvalidSignature);
    };
    let input = signature_input(CryptoSuite::Ed25519Sha256, credential_without_proof)?;
    let signature = key.sign(&input).to_bytes();
    Ok(CredentialProof {
        proof_type: "Ed25519Signature2020".to_owned(),
        created: Utc::now(),
        proof_purpose: "assertionMethod".to_owned(),
        proof_value: format!("z{}", bs58::encode(signature).into_string()),
        verification_method,
    })
}

/// Sign a VC with the JSON-LD Data Integrity Ed25519Signature2020 suite.
///
/// This is the only signing entry point for externally exchanged VCs. The
/// synchronous `sign_credential` helper remains for internal request proof
/// compatibility and must not be used for DID Documents or VCs.
pub async fn sign_credential_data_integrity<T>(
    credential_without_proof: &T,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<CredentialProof, CredentialError>
where
    T: Serialize,
{
    let mut value = serde_json::to_value(credential_without_proof)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("proof");
    }
    let did = verification_method
        .strip_suffix("#key-1")
        .ok_or(CredentialError::InvalidSignature)?;
    let signed = sign_oan_data_integrity(
        value.take(),
        did,
        private_key_jwk(signing_key),
    )
    .await?;
    let mut proof = signed
        .get("proof")
        .cloned()
        .ok_or(CredentialError::MissingProof)?;
    if let Some(object) = proof.as_object_mut() {
        object.remove("@context");
    }
    serde_json::from_value(proof).map_err(CredentialError::Serialization)
}

pub async fn verify_credential_data_integrity<T>(
    credential: &T,
    issuer_public_key_jwk: Value,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    let value = serde_json::to_value(credential)?;
    let issuer = value
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(CredentialError::InvalidSubject)?;
    let verification_method = value
        .get("proof")
        .and_then(|proof| proof.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or(CredentialError::InvalidSignature)?;
    if verification_method != format!("{issuer}#key-1") {
        return Err(CredentialError::InvalidSignature);
    }
    verify_oan_data_integrity(value, issuer_public_key_jwk).await?;
    Ok(())
}

pub fn verify_signed_payload<T>(
    payload_without_proof: &T,
    proof: Option<&CredentialProof>,
    verifying_key: &VerifyingKey,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    let proof = proof.ok_or(CredentialError::MissingProof)?;
    verify_oan_payload(payload_without_proof, proof, verifying_key)
        .map_err(|_| CredentialError::InvalidSignature)
}

pub fn proof_matches_payload<T>(
    payload_without_proof: &T,
    proof: Option<&CredentialProof>,
) -> Result<String, CredentialError>
where
    T: Serialize,
{
    let proof = proof.ok_or(CredentialError::MissingProof)?;
    let payload_input = signature_input(CryptoSuite::Ed25519Sha256, payload_without_proof)?;
    let actual = hash_json_with_suite(
        CryptoSuite::Ed25519Sha256,
        &serde_json::json!({
            "payloadInput": String::from_utf8_lossy(&payload_input),
            "proofValue": proof.proof_value
        }),
    )?;
    Ok(actual)
}

pub fn validate_infrastructure_authorization_credential(
    credential: &OanInfrastructureAuthorizationCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice()
        != ["VerifiableCredential", VC_INFRASTRUCTURE_AUTHORIZATION]
    {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    let role_resource_matches = matches!(
        (subject.role.as_str(), subject.resource_type.as_str()),
        ("root", "root_node")
            | ("registrar", "registrar_node")
            | ("discovery", "discovery_node")
            | ("vc_issuer", "vc_issuer_node")
    );
    if subject.subject_type != "infrastructure_node" || !role_resource_matches {
        return Err(CredentialError::InvalidSubject);
    }
    if subject.id.is_empty() || subject.did_document_hash.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_resource_registration_credential(
    credential: &OanResourceRegistrationCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_RESOURCE_REGISTRATION] {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty()
        || subject.registrar_did.is_empty()
        || subject.did_document_hash.is_empty()
        || subject.metadata_hash.is_empty()
        || subject.package_hash.is_empty()
        || subject.package_version.is_empty()
        || subject.hash_algorithm.is_empty()
    {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

fn validate_business_subject(
    subject: &BusinessFactCredentialSubject,
) -> Result<(), CredentialError> {
    if subject.id.is_empty() || subject.subject_type.is_empty() || subject.fact_type.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_business_fact_credential(
    credential: &OanBusinessFactCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_BUSINESS_FACT] {
        return Err(CredentialError::InvalidType);
    }
    validate_business_subject(&credential.credential_subject)
}

pub fn validate_qualification_credential(
    credential: &OanQualificationCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_QUALIFICATION] {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty()
        || subject.subject_type.is_empty()
        || subject.qualification_type.is_empty()
    {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_audit_result_credential(
    credential: &OanAuditResultCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_AUDIT_RESULT] {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty() || subject.subject_type.is_empty() || subject.audit_type.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn validate_self_claimed_capability_credential(
    credential: &OanSelfClaimedCapabilityCredential,
) -> Result<(), CredentialError> {
    if credential.credential_type.as_slice() != ["VerifiableCredential", VC_SELF_CLAIMED_CAPABILITY]
    {
        return Err(CredentialError::InvalidType);
    }
    let subject = &credential.credential_subject;
    if subject.id.is_empty() || subject.capability.is_empty() {
        return Err(CredentialError::InvalidSubject);
    }
    Ok(())
}

pub fn verify_oan_credential<T>(
    credential: &OanVerifiableCredential<T>,
    issuer_verifying_key: &VerifyingKey,
) -> Result<(), CredentialError>
where
    T: Serialize,
{
    if credential.context.iter().map(String::as_str).collect::<Vec<_>>()
        != OAN_VC_CONTEXTS
    {
        return Err(CredentialError::InvalidSubject);
    }
    let verification_method = credential
        .proof
        .verification_method
        .as_str();
    if credential.proof.proof_type != "Ed25519Signature2020"
        || credential.proof.proof_purpose != "assertionMethod"
        || !verification_method.starts_with(&format!("{}#", credential.issuer))
        || !credential.proof.proof_value.starts_with('z')
    {
        return Err(CredentialError::InvalidSignature);
    }
    let mut unsigned = serde_json::to_value(credential)?;
    unsigned
        .as_object_mut()
        .ok_or(CredentialError::InvalidSubject)?
        .remove("proof");
    verify_signed_payload(&unsigned, Some(&credential.proof), issuer_verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use oan_crypto::private_key_jwk;
    use oan_crypto::{generate_keypair, public_key_jwk};
    use serde_json::json;

    fn proof_for<T: Serialize>(payload: &T, key_id: &str, key: &SigningKey) -> CredentialProof {
        sign_credential(payload, key_id.to_owned(), key_id.to_owned(), key).unwrap()
    }

    fn private_jwk(key: &SigningKey) -> Value {
        private_key_jwk(key)
    }

    fn did_proof_for<T: Serialize>(
        payload: &T,
        key_id: String,
        key: &SigningKey,
    ) -> oan_core::DataIntegrityProof {
        let proof = sign_credential(payload, key_id.clone(), key_id, key).unwrap();
        oan_core::DataIntegrityProof {
            proof_type: proof.proof_type,
            creator: String::new(),
            created: proof.created,
            proof_purpose: proof.proof_purpose,
            proof_value: proof.proof_value,
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: Some(proof.verification_method),
        }
    }

    #[test]
    fn strict_infrastructure_subject_is_accepted() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let subject = InfrastructureAuthorizationCredentialSubject {
            id: "did:oan:2Xr85:Edi352G96M7kgMB84enoEG2mj8AsDm3u".to_owned(),
            role: "registrar".to_owned(),
            subject_type: "infrastructure_node".to_owned(),
            resource_type: "registrar_node".to_owned(),
            endpoint: None,
            authorized_domains: vec!["technology".to_owned()],
            did_document_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
        let mut vc = OanVerifiableCredential {
            context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
            id: Some("urn:oan:vc:1".to_owned()),
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                VC_INFRASTRUCTURE_AUTHORIZATION.to_owned(),
            ],
            issuer: "did:oan:root".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: subject,
            credential_status: None,
            credential_schema: None,
            proof: proof_for(
                &json!({"credentialSubject": "pending"}),
                "did:oan:root#key-1",
                &key.signing_key,
            ),
        };
        let mut unsigned = serde_json::to_value(&vc).unwrap();
        unsigned.as_object_mut().unwrap().remove("proof");
        vc.proof = proof_for(&unsigned, "did:oan:root#key-1", &key.signing_key);
        validate_infrastructure_authorization_credential(&vc).unwrap();
        verify_oan_credential(&vc, &key.verifying_key).unwrap();
    }

    #[test]
    fn infrastructure_authorization_fact_does_not_embed_governance_projection() {
        let subject = InfrastructureAuthorizationCredentialSubject {
            id: "did:oan:2Xr85:Edi352G96M7kgMB84enoEG2mj8AsDm3u".to_owned(),
            role: "registrar".to_owned(),
            subject_type: "infrastructure_node".to_owned(),
            resource_type: "registrar_node".to_owned(),
            endpoint: None,
            authorized_domains: vec!["technology".to_owned()],
            did_document_hash: "sha256:document".to_owned(),
        };
        let status = CredentialStatusReference {
            id: "https://root.example/v1/credentials/status".to_owned(),
            status_type: "OANIssuerCredentialStatus2026".to_owned(),
            credential_id: Some("urn:oan:credential:1".to_owned()),
            subject_did: Some(subject.id.clone()),
            issuer_did: Some("did:oan:root".to_owned()),
            status: Some("active".to_owned()),
            updated_at: Some(Utc::now()),
            extra: Default::default(),
        };
        let subject_json = serde_json::to_value(subject).unwrap();
        let status_json = serde_json::to_value(status).unwrap();
        for field in [
            "governanceState",
            "governanceBindingId",
            "packageId",
            "bulletinObjectId",
            "eventDigest",
            "expectedGovernanceState",
            "sequence",
        ] {
            assert!(!subject_json.get(field).is_some() && !status_json.get(field).is_some());
        }
    }

    #[tokio::test]
    async fn infrastructure_authorization_data_integrity_credential_verifies_without_remote_oan_context() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let subject = InfrastructureAuthorizationCredentialSubject {
            id: "did:oan:2Xr85:Edi352G96M7kgMB84enoEG2mj8AsDm3u".to_owned(),
            role: "registrar".to_owned(),
            subject_type: "infrastructure_node".to_owned(),
            resource_type: "registrar_node".to_owned(),
            endpoint: Some("https://registrar.example".to_owned()),
            authorized_domains: vec!["technology".to_owned()],
            did_document_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
        let mut credential = OanVerifiableCredential {
            context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
            id: Some("urn:oan:root-authorization:registrar:local-context".to_owned()),
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                VC_INFRASTRUCTURE_AUTHORIZATION.to_owned(),
            ],
            issuer: "did:oan:root".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: subject,
            credential_status: None,
            credential_schema: None,
            proof: proof_for(&json!({}), "did:oan:root#key-1", &key.signing_key),
        };
        let mut unsigned = serde_json::to_value(&credential).unwrap();
        unsigned.as_object_mut().unwrap().remove("proof");
        credential.proof = sign_credential_data_integrity(
            &unsigned,
            "did:oan:root#key-1".to_owned(),
            &key.signing_key,
        )
        .await
        .unwrap();

        verify_credential_data_integrity(&credential, public_key_jwk(&key.verifying_key))
            .await
            .unwrap();

        credential.credential_subject.authorized_domains = vec!["finance".to_owned()];
        assert!(
            verify_credential_data_integrity(&credential, public_key_jwk(&key.verifying_key))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn credential_data_integrity_verification_rejects_non_issuer_method() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let subject = InfrastructureAuthorizationCredentialSubject {
            id: "did:oan:2Xr85:Edi352G96M7kgMB84enoEG2mj8AsDm3u".to_owned(),
            role: "registrar".to_owned(),
            subject_type: "infrastructure_node".to_owned(),
            resource_type: "registrar_node".to_owned(),
            endpoint: None,
            authorized_domains: vec!["technology".to_owned()],
            did_document_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
        let mut credential = OanVerifiableCredential {
            context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
            id: Some("urn:oan:root-authorization:registrar:wrong-issuer".to_owned()),
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                VC_INFRASTRUCTURE_AUTHORIZATION.to_owned(),
            ],
            issuer: "did:oan:root".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: subject,
            credential_status: None,
            credential_schema: None,
            proof: proof_for(&json!({}), "did:oan:root#key-1", &key.signing_key),
        };
        let mut unsigned = serde_json::to_value(&credential).unwrap();
        unsigned.as_object_mut().unwrap().remove("proof");
        credential.proof = sign_credential_data_integrity(
            &unsigned,
            "did:oan:other#key-1".to_owned(),
            &key.signing_key,
        )
        .await
        .unwrap();

        assert!(
            verify_credential_data_integrity(&credential, public_key_jwk(&key.verifying_key))
                .await
                .is_err()
        );
    }

    #[test]
    fn credential_signature_rejects_non_issuer_verification_method() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let subject = InfrastructureAuthorizationCredentialSubject {
            id: "did:oan:2Xr85:Edi352G96M7kgMB84enoEG2mj8AsDm3u".to_owned(),
            role: "registrar".to_owned(),
            subject_type: "infrastructure_node".to_owned(),
            resource_type: "registrar_node".to_owned(),
            endpoint: None,
            authorized_domains: vec![],
            did_document_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
        let mut credential = OanVerifiableCredential {
            context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
            id: Some("urn:oan:vc:issuer-binding".to_owned()),
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                VC_INFRASTRUCTURE_AUTHORIZATION.to_owned(),
            ],
            issuer: "did:oan:root".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: subject,
            credential_status: None,
            credential_schema: None,
            proof: proof_for(&json!({}), "did:oan:root#key-1", &key.signing_key),
        };
        let mut unsigned = serde_json::to_value(&credential).unwrap();
        unsigned.as_object_mut().unwrap().remove("proof");
        credential.proof = proof_for(&unsigned, "did:oan:other#key-1", &key.signing_key);
        assert!(matches!(
            verify_oan_credential(&credential, &key.verifying_key),
            Err(CredentialError::InvalidSignature)
        ));
    }

    #[test]
    fn signed_credential_proof_uses_oan_shape() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let proof = proof_for(
            &json!({"issuer": "did:oan:root", "credentialSubject": {"id": "did:oan:res"}}),
            "did:oan:root#key-1",
            &key.signing_key,
        );
        let value = serde_json::to_value(&proof).unwrap();

        assert_eq!(value["type"], "Ed25519Signature2020");
        assert_eq!(value["proofPurpose"], "assertionMethod");
        assert_eq!(value["verificationMethod"], "did:oan:root#key-1");
        assert!(value["proofValue"]
            .as_str()
            .is_some_and(|proof_value| proof_value.starts_with('z')));
        assert!(value.get("creator").is_none());
        assert!(value.get("cryptoSuite").is_none());
        assert!(value.get("hashAlgorithm").is_none());
    }

    #[test]
    fn credential_verification_rejects_legacy_proof_shape() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let subject = InfrastructureAuthorizationCredentialSubject {
            id: "did:oan:2Xr85:Edi352G96M7kgMB84enoEG2mj8AsDm3u".to_owned(),
            role: "registrar".to_owned(),
            subject_type: "infrastructure_node".to_owned(),
            resource_type: "registrar_node".to_owned(),
            endpoint: None,
            authorized_domains: vec![],
            did_document_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
        let mut credential = OanVerifiableCredential {
            context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
            id: Some("urn:oan:vc:legacy-proof".to_owned()),
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                VC_INFRASTRUCTURE_AUTHORIZATION.to_owned(),
            ],
            issuer: "did:oan:root".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: subject,
            credential_status: None,
            credential_schema: None,
            proof: proof_for(&json!({}), "did:oan:root#key-1", &key.signing_key),
        };
        let mut unsigned = serde_json::to_value(&credential).unwrap();
        unsigned.as_object_mut().unwrap().remove("proof");
        credential.proof = proof_for(&unsigned, "did:oan:root#key-1", &key.signing_key);
        credential.proof.proof_type = "DataIntegrityProof".to_owned();

        assert!(matches!(
            verify_oan_credential(&credential, &key.verifying_key),
            Err(CredentialError::InvalidSignature)
        ));
    }

    #[test]
    fn identity_rejects_proof_from_unselected_method() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        let selected = format!("{did}#key-1");
        let other = format!("{did}#key-2");
        let jwk = public_key_jwk(&key.verifying_key);
        let mut document = oan_core::DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.clone(),
            controller: Some(oan_core::DidController::Did(did.clone())),
            verification_method: vec![
                oan_core::VerificationMethod {
                    id: selected.clone(),
                    method_type: "Ed25519VerificationKey2020".to_owned(),
                    controller: did.clone(),
                    crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                    public_key_format: None,
                    public_key_multibase: None,
                    public_key_jwk: Some(jwk.clone()),
                },
                oan_core::VerificationMethod {
                    id: other.clone(),
                    method_type: "Ed25519VerificationKey2020".to_owned(),
                    controller: did.clone(),
                    crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                    public_key_format: None,
                    public_key_multibase: None,
                    public_key_jwk: Some(jwk.clone()),
                },
            ],
            authentication: vec![selected.clone()],
            assertion_method: vec![selected.clone()],
            capability_invocation: vec![selected.clone()],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let unsigned = document.clone();
        document.proof = Some(
            did_proof_for(&unsigned, other, &key.signing_key),
        );
        let identity = OanIdentity {
            id: "identity-1".to_owned(),
            created_at: Utc::now().to_rfc3339(),
            did,
            verification_method_id: selected,
            did_document: document,
            public_key_jwk: jwk,
            private_key_jwk: json!({}),
        };
        assert!(matches!(
            identity.validate(),
            Err(CredentialError::InvalidSubject)
        ));
    }

    #[test]
    fn identity_accepts_matching_private_key_jwk() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        let method_id = format!("{did}#key-1");
        let jwk = public_key_jwk(&key.verifying_key);
        let mut document = oan_core::DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.clone(),
            controller: Some(oan_core::DidController::Did(did.clone())),
            verification_method: vec![oan_core::VerificationMethod {
                id: method_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.clone(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: None,
                public_key_multibase: None,
                public_key_jwk: Some(jwk.clone()),
            }],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id.clone()],
            capability_invocation: vec![method_id.clone()],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let unsigned = document.clone();
        document.proof = Some(
            did_proof_for(
                &unsigned,
                method_id.clone(),
                &key.signing_key,
            )
        );
        let identity = OanIdentity {
            id: "identity-1".to_owned(),
            created_at: Utc::now().to_rfc3339(),
            did,
            verification_method_id: method_id,
            did_document: document,
            public_key_jwk: jwk,
            private_key_jwk: private_jwk(&key.signing_key),
        };
        identity.validate().unwrap();
    }

    #[test]
    fn identity_rejects_mismatched_private_key_jwk() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let other = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        let method_id = format!("{did}#key-1");
        let jwk = public_key_jwk(&key.verifying_key);
        let mut document = oan_core::DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.clone(),
            controller: Some(oan_core::DidController::Did(did.clone())),
            verification_method: vec![oan_core::VerificationMethod {
                id: method_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.clone(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: None,
                public_key_multibase: None,
                public_key_jwk: Some(jwk.clone()),
            }],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id.clone()],
            capability_invocation: vec![method_id.clone()],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let unsigned = document.clone();
        document.proof = Some(
            did_proof_for(
                &unsigned,
                method_id.clone(),
                &key.signing_key,
            )
        );
        let identity = OanIdentity {
            id: "identity-1".to_owned(),
            created_at: Utc::now().to_rfc3339(),
            did,
            verification_method_id: method_id,
            did_document: document,
            public_key_jwk: jwk,
            private_key_jwk: private_jwk(&other.signing_key),
        };
        assert!(matches!(
            identity.validate(),
            Err(CredentialError::InvalidSubject)
        ));
    }

    #[test]
    fn identity_rejects_mismatched_did_document_id() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        let document_did = "did:oan:K7mQ9:6HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        let method_id = format!("{document_did}#key-1");
        let jwk = public_key_jwk(&key.verifying_key);
        let mut document = oan_core::DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: document_did.clone(),
            controller: Some(oan_core::DidController::Did(document_did.clone())),
            verification_method: vec![oan_core::VerificationMethod {
                id: method_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: document_did.clone(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: None,
                public_key_multibase: None,
                public_key_jwk: Some(jwk.clone()),
            }],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id.clone()],
            capability_invocation: vec![method_id.clone()],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let unsigned = document.clone();
        document.proof = Some(did_proof_for(&unsigned, method_id.clone(), &key.signing_key));
        let identity = OanIdentity {
            id: "identity-1".to_owned(),
            created_at: Utc::now().to_rfc3339(),
            did,
            verification_method_id: method_id,
            did_document: document,
            public_key_jwk: jwk,
            private_key_jwk: private_jwk(&key.signing_key),
        };
        assert!(matches!(
            identity.validate(),
            Err(CredentialError::InvalidSubject)
        ));
    }

    #[test]
    fn identity_rejects_unbound_verification_method_id() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        let document_method_id = format!("{did}#key-1");
        let selected_method_id = format!("{did}#key-2");
        let jwk = public_key_jwk(&key.verifying_key);
        let mut document = oan_core::DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.clone(),
            controller: Some(oan_core::DidController::Did(did.clone())),
            verification_method: vec![oan_core::VerificationMethod {
                id: document_method_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.clone(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: None,
                public_key_multibase: None,
                public_key_jwk: Some(jwk.clone()),
            }],
            authentication: vec![document_method_id.clone()],
            assertion_method: vec![document_method_id.clone()],
            capability_invocation: vec![document_method_id.clone()],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let unsigned = document.clone();
        document.proof = Some(did_proof_for(&unsigned, document_method_id, &key.signing_key));
        let identity = OanIdentity {
            id: "identity-1".to_owned(),
            created_at: Utc::now().to_rfc3339(),
            did,
            verification_method_id: selected_method_id,
            did_document: document,
            public_key_jwk: jwk,
            private_key_jwk: private_jwk(&key.signing_key),
        };
        assert!(matches!(
            identity.validate(),
            Err(CredentialError::InvalidSubject)
        ));
    }

    #[test]
    fn legacy_type_is_rejected() {
        let subject = InfrastructureAuthorizationCredentialSubject {
            id: "did:oan:2Xr85:Edi352G96M7kgMB84enoEG2mj8AsDm3u".to_owned(),
            role: "registrar".to_owned(),
            subject_type: "infrastructure_node".to_owned(),
            resource_type: "registrar_node".to_owned(),
            endpoint: None,
            authorized_domains: vec![],
            did_document_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let unsigned = json!({"credentialSubject": subject});
        let vc = OanVerifiableCredential {
            context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
            id: None,
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                "NodeAuthorizationCredential".to_owned(),
            ],
            issuer: "did:oan:root".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: subject,
            credential_status: None,
            credential_schema: None,
            proof: proof_for(&unsigned, "did:oan:root#key-1", &key.signing_key),
        };
        assert!(matches!(
            validate_infrastructure_authorization_credential(&vc),
            Err(CredentialError::InvalidType)
        ));
    }

    #[test]
    fn business_credential_subject_validators_require_protocol_fields() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let base = |credential_type: &str, subject: Value| {
            let mut credential = OanVerifiableCredential {
                context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
                id: None,
                credential_type: vec![
                    "VerifiableCredential".to_owned(),
                    credential_type.to_owned(),
                ],
                issuer: "did:oan:issuer".to_owned(),
                issuance_date: Utc::now(),
                expiration_date: None,
                credential_subject: subject,
                credential_status: None,
                credential_schema: None,
                proof: proof_for(&json!({}), "did:oan:issuer#key-1", &key.signing_key),
            };
            let mut unsigned = serde_json::to_value(&credential).unwrap();
            unsigned.as_object_mut().unwrap().remove("proof");
            credential.proof = proof_for(&unsigned, "did:oan:issuer#key-1", &key.signing_key);
            credential
        };
        let business: OanBusinessFactCredential = serde_json::from_value(serde_json::to_value(base(
            VC_BUSINESS_FACT,
            json!({"id":"did:oan:subject","subjectType":"organization","factType":"incorporated","claim":{}}),
        )).unwrap()).unwrap();
        assert!(validate_business_fact_credential(&business).is_ok());
        let qualification: OanQualificationCredential = serde_json::from_value(serde_json::to_value(base(
            VC_QUALIFICATION,
            json!({"id":"did:oan:subject","subjectType":"organization","qualificationType":"iso","qualification":{}}),
        )).unwrap()).unwrap();
        assert!(validate_qualification_credential(&qualification).is_ok());
        let audit: OanAuditResultCredential = serde_json::from_value(serde_json::to_value(base(
            VC_AUDIT_RESULT,
            json!({"id":"did:oan:subject","subjectType":"organization","auditType":"security","result":{},"auditedAt":Utc::now()}),
        )).unwrap()).unwrap();
        assert!(validate_audit_result_credential(&audit).is_ok());
        let capability: OanSelfClaimedCapabilityCredential = serde_json::from_value(
            serde_json::to_value(base(
                VC_SELF_CLAIMED_CAPABILITY,
                json!({"id":"did:oan:subject","capability":"streaming","claim":{}}),
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(validate_self_claimed_capability_credential(&capability).is_ok());
    }

    #[test]
    fn business_credential_subject_validators_reject_missing_required_fields() {
        let key = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let mut credential = OanBusinessFactCredential {
            context: OAN_VC_CONTEXTS.iter().map(|value| (*value).to_owned()).collect(),
            id: None,
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                VC_BUSINESS_FACT.to_owned(),
            ],
            issuer: "did:oan:issuer".to_owned(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: BusinessFactCredentialSubject {
                id: String::new(),
                subject_type: "organization".to_owned(),
                fact_type: "incorporated".to_owned(),
                claim: json!({}),
            },
            credential_status: None,
            credential_schema: None,
            proof: proof_for(&json!({}), "did:oan:issuer#key-1", &key.signing_key),
        };
        assert!(matches!(
            validate_business_fact_credential(&credential),
            Err(CredentialError::InvalidSubject)
        ));
        credential.credential_subject.id = "did:oan:subject".to_owned();
        credential.credential_subject.fact_type.clear();
        assert!(matches!(
            validate_business_fact_credential(&credential),
            Err(CredentialError::InvalidSubject)
        ));
    }
}
