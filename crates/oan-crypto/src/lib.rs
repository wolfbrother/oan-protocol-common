// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Cryptographic helpers for OpenAgenet.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey, Verifier as _,
    VerifyingKey as Ed25519VerifyingKey,
};
use iref::{IriBuf, UriBuf};
use oan_core::{
    CryptoSuite, DataIntegrityProof, DidDocument, OanCredentialProof, VerificationMethod,
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use sm2::dsa::{
    signature::{Signer as Sm2Signer, Verifier as Sm2Verifier},
    Signature as Sm2Signature, SigningKey as Sm2SigningKey, VerifyingKey as Sm2VerifyingKey,
};
use sm3::{Digest as Sm3Digest, Sm3};
use ssi_claims::data_integrity::{AnyDataIntegrity, AnySuite, CryptographicSuite, ProofOptions};
use ssi_claims::VerificationParameters;
use ssi_data_integrity::DataIntegrityDocument;
use ssi_jwk::JWK;
use ssi_verification_methods::{AnyMethod, Ed25519VerificationKey2020, SingleSecretSigner};
use thiserror::Error;

const DEFAULT_SM2_DISTINGUISHED_ID: &str = "1234567812345678";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported crypto suite")]
    UnsupportedCryptoSuite,
    #[error("invalid signing key")]
    InvalidSigningKey,
    #[error("invalid verifying key")]
    InvalidVerifyingKey,
    #[error("invalid public key encoding")]
    InvalidPublicKeyEncoding,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("invalid proof")]
    InvalidProof,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("missing key material")]
    MissingKeyMaterial,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("standard Data Integrity operation failed: {0}")]
    StandardDataIntegrity(String),
}

/// Sign a JSON-LD document with the standard Ed25519Signature2020 suite.
///
/// This is the strict Profile v2 path. It deliberately does not use the
/// legacy OAN canonical-JSON/Base64URL path.
pub async fn sign_oan_data_integrity(
    document: serde_json::Value,
    did: &str,
    private_key_jwk: serde_json::Value,
) -> Result<serde_json::Value, CryptoError> {
    let jwk: JWK = serde_json::from_value(private_key_jwk)
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    let private_object = serde_json::to_value(&jwk)?;
    let private_object = private_object
        .as_object()
        .ok_or(CryptoError::InvalidSigningKey)?;
    if private_object.get("kty").and_then(|value| value.as_str()) != Some("OKP")
        || private_object.get("crv").and_then(|value| value.as_str()) != Some("Ed25519")
        || private_object.get("alg").and_then(|value| value.as_str()) == Some("Ed25519")
    {
        return Err(CryptoError::InvalidSigningKey);
    }
    let private_bytes = URL_SAFE_NO_PAD
        .decode(
            private_object
                .get("d")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::MissingKeyMaterial)?,
        )
        .map_err(|_| CryptoError::InvalidSigningKey)?;
    if private_bytes.len() != 32 {
        return Err(CryptoError::InvalidSigningKey);
    }
    let private_bytes: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSigningKey)?;
    let signing_key = Ed25519SigningKey::from_bytes(&private_bytes);
    let declared_public = URL_SAFE_NO_PAD
        .decode(
            private_object
                .get("x")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidSigningKey)?,
        )
        .map_err(|_| CryptoError::InvalidSigningKey)?;
    if declared_public != signing_key.verifying_key().to_bytes() {
        return Err(CryptoError::InvalidSigningKey);
    }
    let verification_method = format!("{did}#key-1");
    let method_id = IriBuf::new(verification_method.clone())
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    let public_key_jwk: JWK = jwk.to_public();
    let key = Ed25519VerificationKey2020::from_public_key(
        method_id.clone(),
        UriBuf::new(did.as_bytes().to_vec()).map_err(|_| CryptoError::InvalidPublicKeyEncoding)?,
        ed25519_dalek::VerifyingKey::from_bytes(
            &URL_SAFE_NO_PAD
                .decode(
                    serde_json::to_value(&public_key_jwk)?
                        .get("x")
                        .and_then(|value| value.as_str())
                        .ok_or(CryptoError::InvalidPublicKeyEncoding)?,
                )
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?
                .try_into()
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?,
        )
        .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?,
    );
    let mut methods = std::collections::HashMap::<IriBuf, AnyMethod>::new();
    methods.insert(method_id.clone(), key.into());
    let input: DataIntegrityDocument = serde_json::from_value(document)
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    let signed: AnyDataIntegrity = AnySuite::Ed25519Signature2020
        .sign(
            input,
            &methods,
            SingleSecretSigner::new(jwk).into_local(),
            ProofOptions::from_method(method_id.into()),
        )
        .await
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    serde_json::to_value(signed).map_err(CryptoError::Serialization)
}

/// Verify a JSON-LD document with the standard Ed25519Signature2020 suite.
pub async fn verify_oan_data_integrity(
    document: serde_json::Value,
    public_key_jwk: serde_json::Value,
) -> Result<(), CryptoError> {
    let key: JWK = serde_json::from_value(public_key_jwk)
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    let method_id = document
        .get("proof")
        .and_then(|proof| proof.get("verificationMethod"))
        .and_then(|value| value.as_str())
        .ok_or(CryptoError::InvalidProof)?;
    let method_id = IriBuf::new(method_id.to_owned())
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    if !method_id.as_iri().to_string().ends_with("#key-1") {
        return Err(CryptoError::InvalidProof);
    }
    let key_object = serde_json::to_value(key.to_public())?;
    let key_object = key_object
        .as_object()
        .ok_or(CryptoError::InvalidVerifyingKey)?;
    if key_object.get("kty").and_then(|value| value.as_str()) != Some("OKP")
        || key_object.get("crv").and_then(|value| value.as_str()) != Some("Ed25519")
        || key_object.get("alg").and_then(|value| value.as_str()) == Some("Ed25519")
    {
        return Err(CryptoError::InvalidVerifyingKey);
    }
    let controller = method_id
        .as_iri()
        .to_string()
        .split('#')
        .next()
        .unwrap_or_default()
        .to_owned();
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(
            serde_json::to_value(key.to_public())?
                .get("x")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidPublicKeyEncoding)?,
        )
        .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
    let key = Ed25519VerificationKey2020::from_public_key(
        method_id.clone(),
        UriBuf::new(controller.as_bytes().to_vec())
            .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?,
        ed25519_dalek::VerifyingKey::from_bytes(
            &public_key_bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?,
        )
        .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?,
    );
    let mut methods = std::collections::HashMap::<IriBuf, AnyMethod>::new();
    methods.insert(method_id, key.into());
    let secured: AnyDataIntegrity = serde_json::from_value(document)
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    secured
        .verify(VerificationParameters::from_resolver(methods))
        .await
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    Ok(())
}

#[derive(Clone, Debug)]
pub enum SigningKey {
    Ed25519 {
        suite: CryptoSuite,
        key: Ed25519SigningKey,
    },
    Sm2 {
        suite: CryptoSuite,
        key: Sm2SigningKey,
    },
}

#[derive(Clone, Debug)]
pub enum VerifyingKey {
    Ed25519 {
        suite: CryptoSuite,
        key: Ed25519VerifyingKey,
    },
    Sm2 {
        suite: CryptoSuite,
        key: Sm2VerifyingKey,
    },
}

#[derive(Clone, Debug)]
pub struct KeypairMaterial {
    pub crypto_suite: CryptoSuite,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl SigningKey {
    pub fn crypto_suite(&self) -> CryptoSuite {
        match self {
            Self::Ed25519 { suite, .. } | Self::Sm2 { suite, .. } => suite.clone(),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Ed25519 { suite, key } => VerifyingKey::Ed25519 {
                suite: suite.clone(),
                key: key.verifying_key(),
            },
            Self::Sm2 { suite, key } => VerifyingKey::Sm2 {
                suite: suite.clone(),
                key: key.verifying_key().clone(),
            },
        }
    }
}

impl VerifyingKey {
    pub fn crypto_suite(&self) -> CryptoSuite {
        match self {
            Self::Ed25519 { suite, .. } | Self::Sm2 { suite, .. } => suite.clone(),
        }
    }
}

pub fn generate_keypair(suite: CryptoSuite) -> Result<KeypairMaterial, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let signing_key = Ed25519SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            Ok(KeypairMaterial {
                crypto_suite: suite.clone(),
                signing_key: SigningKey::Ed25519 {
                    suite: suite.clone(),
                    key: signing_key,
                },
                verifying_key: VerifyingKey::Ed25519 {
                    suite,
                    key: verifying_key,
                },
            })
        }
        CryptoSuite::Sm2Sm3 => {
            let signing_key = generate_sm2_keypair()?;
            let verifying_key = signing_key.verifying_key().clone();
            Ok(KeypairMaterial {
                crypto_suite: suite.clone(),
                signing_key: SigningKey::Sm2 {
                    suite: suite.clone(),
                    key: signing_key,
                },
                verifying_key: VerifyingKey::Sm2 {
                    suite,
                    key: verifying_key,
                },
            })
        }
    }
}

pub fn generate_ed25519_keypair() -> Ed25519SigningKey {
    Ed25519SigningKey::generate(&mut OsRng)
}

pub fn generate_sm2_keypair() -> Result<Sm2SigningKey, CryptoError> {
    for _ in 0..32 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(signing_key) = Sm2SigningKey::from_slice(DEFAULT_SM2_DISTINGUISHED_ID, &bytes) {
            return Ok(signing_key);
        }
    }
    Err(CryptoError::InvalidSigningKey)
}

pub fn signing_key_from_bytes(suite: CryptoSuite, bytes: &[u8]) -> Result<SigningKey, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidSigningKey)?;
            Ok(SigningKey::Ed25519 {
                suite,
                key: Ed25519SigningKey::from_bytes(&bytes),
            })
        }
        CryptoSuite::Sm2Sm3 => Sm2SigningKey::from_slice(DEFAULT_SM2_DISTINGUISHED_ID, bytes)
            .map(|key| SigningKey::Sm2 { suite, key })
            .map_err(|_| CryptoError::InvalidSigningKey),
    }
}

pub fn signing_key_from_private_key_jwk(
    suite: CryptoSuite,
    private_key_jwk: &serde_json::Value,
) -> Result<SigningKey, CryptoError> {
    let d = private_key_jwk
        .get("d")
        .and_then(|value| value.as_str())
        .ok_or(CryptoError::InvalidSigningKey)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|_| CryptoError::InvalidSigningKey)?;
    signing_key_from_bytes(suite, &bytes)
}

pub fn signing_key_from_legacy_ed25519_bytes(
    bytes: &[u8],
) -> Result<Ed25519SigningKey, CryptoError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSigningKey)?;
    Ok(Ed25519SigningKey::from_bytes(&bytes))
}

pub fn verifying_key_from_bytes(
    suite: CryptoSuite,
    bytes: &[u8],
) -> Result<VerifyingKey, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidVerifyingKey)?;
            Ed25519VerifyingKey::from_bytes(&bytes)
                .map(|key| VerifyingKey::Ed25519 { suite, key })
                .map_err(|_| CryptoError::InvalidVerifyingKey)
        }
        CryptoSuite::Sm2Sm3 => {
            Sm2VerifyingKey::from_sec1_bytes(DEFAULT_SM2_DISTINGUISHED_ID, bytes)
                .map(|key| VerifyingKey::Sm2 { suite, key })
                .map_err(|_| CryptoError::InvalidVerifyingKey)
        }
    }
}

pub fn verifying_key_from_legacy_ed25519_bytes(
    bytes: &[u8],
) -> Result<Ed25519VerifyingKey, CryptoError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidVerifyingKey)?;
    Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidVerifyingKey)
}

pub fn verifying_key_from_public_key_multibase(
    suite: CryptoSuite,
    public_key_multibase: &str,
) -> Result<VerifyingKey, CryptoError> {
    let encoded = public_key_multibase
        .strip_prefix('z')
        .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
    verifying_key_from_bytes(suite, &bytes)
}

pub fn verifying_key_from_public_key_jwk(
    suite: CryptoSuite,
    public_key_jwk: &serde_json::Value,
) -> Result<VerifyingKey, CryptoError> {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            let x = public_key_jwk
                .get("x")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
            verifying_key_from_bytes(suite, &bytes)
        }
        CryptoSuite::Sm2Sm3 => {
            let x = public_key_jwk
                .get("x")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
            let y = public_key_jwk
                .get("y")
                .and_then(|value| value.as_str())
                .ok_or(CryptoError::InvalidPublicKeyEncoding)?;
            let x = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
            let y = URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|_| CryptoError::InvalidPublicKeyEncoding)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(CryptoError::InvalidPublicKeyEncoding);
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            verifying_key_from_bytes(suite, &sec1)
        }
    }
}

pub fn sign_bytes(signing_key: &SigningKey, payload: &[u8]) -> Result<String, CryptoError> {
    match signing_key {
        SigningKey::Ed25519 { key, .. } => Ok(URL_SAFE_NO_PAD.encode(key.sign(payload).to_bytes())),
        SigningKey::Sm2 { key, .. } => {
            let signature: Sm2Signature = Sm2Signer::sign(key, payload);
            Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
        }
    }
}

pub fn sign_bytes_multibase(
    signing_key: &SigningKey,
    payload: &[u8],
) -> Result<String, CryptoError> {
    let signature = sign_bytes(signing_key, payload)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(format!("z{}", bs58::encode(signature).into_string()))
}

pub fn verify_bytes_multibase(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_multibase: &str,
) -> Result<(), CryptoError> {
    let encoded = signature_multibase
        .strip_prefix('z')
        .ok_or(CryptoError::InvalidSignature)?;
    let signature = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| CryptoError::InvalidSignature)?;
    if signature.len() != 64 {
        return Err(CryptoError::InvalidSignature);
    }
    match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => key
            .verify(
                payload,
                &Ed25519Signature::from_slice(&signature)
                    .map_err(|_| CryptoError::InvalidSignature)?,
            )
            .map_err(|_| CryptoError::VerificationFailed),
        VerifyingKey::Sm2 { .. } => Err(CryptoError::UnsupportedCryptoSuite),
    }
}

pub fn verify_did_document_proof(document: &DidDocument) -> Result<(), CryptoError> {
    const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
    const OAN_CONTEXT: &str = "https://openagenet.xyz/did-oan-specs/v1";
    const ED25519_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
    if document.context
        != [DID_CONTEXT.to_owned(), OAN_CONTEXT.to_owned(), ED25519_CONTEXT.to_owned()]
    {
        return Err(CryptoError::InvalidProof);
    }
    let proof = document.proof.as_ref().ok_or(CryptoError::InvalidProof)?;
    if proof.proof_type != "Ed25519Signature2020"
        || proof.proof_purpose != "assertionMethod"
        || !proof.creator.is_empty()
        || proof.crypto_suite.is_some()
        || proof.hash_algorithm.is_some()
    {
        return Err(CryptoError::InvalidProof);
    }
    let method_id = format!("{}#key-1", document.id);
    if proof.verification_method.as_deref() != Some(method_id.as_str())
        || !document.assertion_method.iter().any(|id| id == &method_id)
    {
        return Err(CryptoError::InvalidProof);
    }
    let method = document
        .verification_method
        .iter()
        .find(|method| method.id == method_id && method.controller == document.id)
        .ok_or(CryptoError::InvalidProof)?;
    if method.method_type != "Ed25519VerificationKey2020" {
        return Err(CryptoError::InvalidProof);
    }
    if method
        .public_key_jwk
        .as_ref()
        .and_then(|jwk| jwk.get("alg"))
        .and_then(serde_json::Value::as_str)
        == Some("Ed25519")
    {
        return Err(CryptoError::InvalidProof);
    }
    let verifying_key = verifying_key_from_method(method)?;
    let mut unsigned = document.clone();
    unsigned.proof = None;
    let input = did_document_signature_input(&unsigned, CryptoSuite::Ed25519Sha256)?;
    verify_bytes_multibase(&verifying_key, &input, &proof.proof_value)
}

pub fn sign_legacy_ed25519_bytes(signing_key: &Ed25519SigningKey, payload: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(signing_key.sign(payload).to_bytes())
}

pub fn verify_bytes(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_base64url: &str,
) -> Result<(), CryptoError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| CryptoError::InvalidSignature)?;
    match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => {
            let signature = Ed25519Signature::from_slice(&signature_bytes)
                .map_err(|_| CryptoError::InvalidSignature)?;
            key.verify(payload, &signature)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        VerifyingKey::Sm2 { key, .. } => {
            let signature = Sm2Signature::from_slice(&signature_bytes)
                .map_err(|_| CryptoError::InvalidSignature)?;
            Sm2Verifier::verify(key, payload, &signature)
                .map_err(|_| CryptoError::VerificationFailed)
        }
    }
}

pub fn verify_legacy_ed25519_bytes(
    verifying_key: &Ed25519VerifyingKey,
    payload: &[u8],
    signature_base64url: &str,
) -> Result<(), CryptoError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| CryptoError::InvalidSignature)?;
    let signature = Ed25519Signature::from_slice(&signature_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

pub fn hash_hex(suite: CryptoSuite, payload: impl AsRef<[u8]>) -> String {
    match suite {
        CryptoSuite::Ed25519Sha256Legacy | CryptoSuite::Ed25519Sha256 => {
            hex::encode(Sha256::digest(payload.as_ref()))
        }
        CryptoSuite::Sm2Sm3 => hex::encode(Sm3::digest(payload.as_ref())),
    }
}

pub fn sha256_hex(payload: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(payload.as_ref()))
}

pub fn sm3_hex(payload: impl AsRef<[u8]>) -> String {
    hex::encode(Sm3::digest(payload.as_ref()))
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_json_value(&value))
}

pub fn hash_json_with_suite<T: Serialize>(
    suite: CryptoSuite,
    value: &T,
) -> Result<String, CryptoError> {
    Ok(hash_hex(suite, canonical_json(value)?))
}

pub fn hash_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    hash_json_with_suite(CryptoSuite::Ed25519Sha256Legacy, value)
}

pub fn signature_input<T: Serialize>(
    suite: CryptoSuite,
    value: &T,
) -> Result<Vec<u8>, CryptoError> {
    let canonical = canonical_json(value)?;
    match suite {
        CryptoSuite::Ed25519Sha256Legacy => Ok(hash_hex(suite, canonical).into_bytes()),
        CryptoSuite::Ed25519Sha256 | CryptoSuite::Sm2Sm3 => Ok(canonical.into_bytes()),
    }
}

pub fn did_document_signature_input(
    document: &DidDocument,
    suite: CryptoSuite,
) -> Result<Vec<u8>, CryptoError> {
    let mut document_without_proof = document.clone();
    document_without_proof.proof = None;
    signature_input(suite, &document_without_proof)
}

pub fn hash_did_document_with_proof(
    document: &DidDocument,
    suite: CryptoSuite,
) -> Result<String, CryptoError> {
    hash_json_with_suite(suite, document)
}

pub fn public_key_multibase(verifying_key: &VerifyingKey) -> String {
    let bytes = match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => key.as_bytes().to_vec(),
        VerifyingKey::Sm2 { key, .. } => key.to_sec1_bytes().into_vec(),
    };
    format!("z{}", bs58::encode(bytes).into_string())
}

pub fn public_key_jwk(verifying_key: &VerifyingKey) -> serde_json::Value {
    match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(key.as_bytes()),
        }),
        VerifyingKey::Sm2 { key, .. } => {
            let bytes = key.to_sec1_bytes();
            let x = &bytes[1..33];
            let y = &bytes[33..65];
            serde_json::json!({
                "kty": "EC",
                "crv": "SM2",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
            })
        }
    }
}

pub fn private_key_jwk(signing_key: &SigningKey) -> serde_json::Value {
    match signing_key {
        SigningKey::Ed25519 { key, .. } => serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
        }),
        SigningKey::Sm2 { key, .. } => serde_json::json!({
            "kty": "EC",
            "crv": "SM2",
            "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
        }),
    }
}

pub fn crypto_suite_from_verification_method(
    method: &VerificationMethod,
) -> Result<CryptoSuite, CryptoError> {
    method
        .crypto_suite()
        .ok_or(CryptoError::UnsupportedCryptoSuite)
}

pub fn verifying_key_from_method(method: &VerificationMethod) -> Result<VerifyingKey, CryptoError> {
    let suite = crypto_suite_from_verification_method(method)?;
    if let Some(multibase) = &method.public_key_multibase {
        verifying_key_from_public_key_multibase(suite, multibase)
    } else if let Some(jwk) = &method.public_key_jwk {
        verifying_key_from_public_key_jwk(suite, jwk)
    } else {
        Err(CryptoError::MissingKeyMaterial)
    }
}

pub fn crypto_suite_from_proof(proof: &DataIntegrityProof) -> Result<CryptoSuite, CryptoError> {
    proof
        .crypto_suite()
        .ok_or(CryptoError::UnsupportedCryptoSuite)
}

pub fn verify_payload_with_proof<T: Serialize>(
    payload: &T,
    proof: &DataIntegrityProof,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let suite = crypto_suite_from_proof(proof)?;
    if suite != verifying_key.crypto_suite() {
        return Err(CryptoError::VerificationFailed);
    }
    let input = signature_input(suite, payload)?;
    verify_bytes(verifying_key, &input, &proof.proof_value)
}

pub fn verify_oan_payload<T: Serialize>(
    payload: &T,
    proof: &OanCredentialProof,
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    if proof.proof_type != "Ed25519Signature2020"
        || proof.proof_purpose != "assertionMethod"
        || !proof.proof_value.starts_with('z')
    {
        return Err(CryptoError::InvalidProof);
    }
    let signature = bs58::decode(&proof.proof_value[1..])
        .into_vec()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let input = signature_input(CryptoSuite::Ed25519Sha256, payload)?;
    match verifying_key {
        VerifyingKey::Ed25519 { key, .. } => key
            .verify(
                &input,
                &Ed25519Signature::from_bytes(&signature),
            )
            .map_err(|_| CryptoError::VerificationFailed),
        VerifyingKey::Sm2 { .. } => Err(CryptoError::UnsupportedCryptoSuite),
    }
}

pub fn build_data_integrity_proof<T: Serialize>(
    payload: &T,
    creator: String,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<DataIntegrityProof, CryptoError> {
    let suite = signing_key.crypto_suite();
    let input = signature_input(suite.clone(), payload)?;
    Ok(DataIntegrityProof {
        proof_type: suite.proof_type().to_owned(),
        creator,
        created: chrono::Utc::now(),
        proof_purpose: "assertionMethod".to_owned(),
        proof_value: sign_bytes(signing_key, &input)?,
        crypto_suite: Some(suite.clone()),
        hash_algorithm: Some(suite.canonical_hash_algorithm().to_owned()),
        verification_method: Some(verification_method),
    })
}

pub fn canonical_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_owned(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => {
            serde_json::to_string(value).expect("string serialization cannot fail")
        }
        serde_json::Value::Array(values) => {
            let items = values
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{items}]")
        }
        serde_json::Value::Object(map) => {
            let items = map
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serialization cannot fail"),
                        canonical_json_value(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{items}}}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signs_and_verifies_ed25519_payload() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let signature = sign_bytes(&keypair.signing_key, b"hello").unwrap();

        verify_bytes(&keypair.verifying_key, b"hello", &signature).unwrap();
        assert!(verify_bytes(&keypair.verifying_key, b"HELLO", &signature).is_err());
    }

    #[test]
    fn signs_ed25519_payload_as_multibase() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let signature = sign_bytes_multibase(&keypair.signing_key, b"hello").unwrap();
        assert!(signature.starts_with('z'));
        let bytes = bs58::decode(&signature[1..]).into_vec().unwrap();
        assert_eq!(bytes.len(), 64);
        match keypair.verifying_key {
            VerifyingKey::Ed25519 { key, .. } => key
                .verify(b"hello", &Ed25519Signature::from_slice(&bytes).unwrap())
                .unwrap(),
            VerifyingKey::Sm2 { .. } => panic!("expected Ed25519 key"),
        }
        verify_bytes_multibase(
            &generate_keypair(CryptoSuite::Ed25519Sha256)
                .unwrap()
                .verifying_key,
            b"hello",
            &signature,
        )
        .expect_err("different key must not verify");
    }

    #[test]
    fn verifies_complete_did_document_proof_and_rejects_tampering() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let method_id = format!("{did}#key-1");
        let verifying_key = keypair.verifying_key.clone();
        let mut document = DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_owned(),
                "https://openagenet.xyz/did-oan-specs/v1".to_owned(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_owned(),
            ],
            id: did.to_owned(),
            controller: Some(oan_core::DidController::Did(did.to_owned())),
            verification_method: vec![VerificationMethod {
                id: method_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: Some(public_key_jwk(&verifying_key)),
            }],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id.clone()],
            capability_invocation: vec![method_id.clone()],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let input = did_document_signature_input(&document, CryptoSuite::Ed25519Sha256).unwrap();
        document.proof = Some(DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: String::new(),
            created: chrono::Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: sign_bytes_multibase(&keypair.signing_key, &input).unwrap(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: Some(method_id),
        });
        verify_did_document_proof(&document).unwrap();
        document.id.push('x');
        assert!(verify_did_document_proof(&document).is_err());
    }

    #[test]
    fn did_document_proof_rejects_legacy_context_and_jwk_algorithm() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
        let method_id = format!("{did}#key-1");
        let verifying_key = keypair.verifying_key.clone();
        let mut document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            controller: Some(oan_core::DidController::Did(did.to_owned())),
            verification_method: vec![VerificationMethod {
                id: method_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: Some(public_key_jwk(&verifying_key)),
            }],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id.clone()],
            capability_invocation: vec![method_id.clone()],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let input = did_document_signature_input(&document, CryptoSuite::Ed25519Sha256).unwrap();
        document.proof = Some(DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: String::new(),
            created: chrono::Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: sign_bytes_multibase(&keypair.signing_key, &input).unwrap(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: Some(method_id),
        });
        assert!(verify_did_document_proof(&document).is_err());
        document.context = vec![
            "https://www.w3.org/ns/did/v1".to_owned(),
            "https://openagenet.xyz/did-oan-specs/v1".to_owned(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_owned(),
        ];
        document.verification_method[0]
            .public_key_jwk
            .as_mut()
            .unwrap()["alg"] = serde_json::json!("Ed25519");
        assert!(verify_did_document_proof(&document).is_err());
    }

    #[test]
    fn signs_and_verifies_sm2_payload() {
        let keypair = generate_keypair(CryptoSuite::Sm2Sm3).unwrap();
        let signature = sign_bytes(&keypair.signing_key, b"hello").unwrap();

        verify_bytes(&keypair.verifying_key, b"hello", &signature).unwrap();
        assert!(verify_bytes(&keypair.verifying_key, b"HELLO", &signature).is_err());
    }

    #[test]
    fn canonical_json_orders_keys() {
        let value = json!({"b": 2, "a": 1});
        assert_eq!(canonical_json_value(&value), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn parses_ed25519_verifying_key_from_jwk_and_multibase() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let jwk = public_key_jwk(&keypair.verifying_key);
        let multibase = public_key_multibase(&keypair.verifying_key);

        let from_jwk =
            verifying_key_from_public_key_jwk(CryptoSuite::Ed25519Sha256Legacy, &jwk).unwrap();
        let from_multibase =
            verifying_key_from_public_key_multibase(CryptoSuite::Ed25519Sha256Legacy, &multibase)
                .unwrap();

        assert!(matches!(from_jwk, VerifyingKey::Ed25519 { .. }));
        assert!(matches!(from_multibase, VerifyingKey::Ed25519 { .. }));
    }

    #[test]
    fn parses_sm2_verifying_key_from_jwk_and_multibase() {
        let keypair = generate_keypair(CryptoSuite::Sm2Sm3).unwrap();
        let jwk = public_key_jwk(&keypair.verifying_key);
        let multibase = public_key_multibase(&keypair.verifying_key);

        let from_jwk = verifying_key_from_public_key_jwk(CryptoSuite::Sm2Sm3, &jwk).unwrap();
        let from_multibase =
            verifying_key_from_public_key_multibase(CryptoSuite::Sm2Sm3, &multibase).unwrap();

        assert!(matches!(from_jwk, VerifyingKey::Sm2 { .. }));
        assert!(matches!(from_multibase, VerifyingKey::Sm2 { .. }));
    }

    #[test]
    fn signature_input_keeps_legacy_hash_behavior() {
        let payload = json!({"a": 1});
        let legacy =
            String::from_utf8(signature_input(CryptoSuite::Ed25519Sha256Legacy, &payload).unwrap())
                .unwrap();
        let modern =
            String::from_utf8(signature_input(CryptoSuite::Sm2Sm3, &payload).unwrap()).unwrap();

        assert_eq!(legacy.len(), 64);
        assert_eq!(modern, r#"{"a":1}"#);
    }

    #[test]
    fn proof_verification_accepts_legacy_shape_without_crypto_suite() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256Legacy).unwrap();
        let payload = json!({"a": 1});
        let input = signature_input(CryptoSuite::Ed25519Sha256Legacy, &payload).unwrap();
        let proof = DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: "did:oan:AGDM:test#key-1".to_owned(),
            created: chrono::Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: sign_bytes(&keypair.signing_key, &input).unwrap(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: None,
        };

        verify_payload_with_proof(&payload, &proof, &keypair.verifying_key).unwrap();
    }

    #[test]
    fn proof_verification_uses_explicit_suite_without_downgrading() {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let payload = json!({"a": 1});
        let proof = build_data_integrity_proof(
            &payload,
            "did:oan:AGDM:test#key-1".to_owned(),
            "did:oan:AGDM:test#key-1".to_owned(),
            &keypair.signing_key,
        )
        .unwrap();

        assert_eq!(proof.crypto_suite(), Some(CryptoSuite::Ed25519Sha256));
        assert_eq!(proof.hash_algorithm.as_deref(), Some("sha256"));
        verify_payload_with_proof(&payload, &proof, &keypair.verifying_key).unwrap();
    }

    #[test]
    fn did_document_signature_excludes_proof_but_final_hash_includes_it() {
        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:oan:K7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned(),
            controller: Some(oan_core::DidController::Did(
                "did:oan:P9aBc:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo".to_owned(),
            )),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            capability_invocation: vec![],
            service: vec![],
            proof: None,
            oan_metadata: None,
        };
        let without_proof =
            did_document_signature_input(&document, CryptoSuite::Ed25519Sha256).unwrap();
        assert_eq!(
            String::from_utf8(without_proof.clone()).unwrap(),
            r#"{"@context":["https://www.w3.org/ns/did/v1"],"assertionMethod":[],"authentication":[],"controller":"did:oan:P9aBc:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo","id":"did:oan:K7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz","service":[],"verificationMethod":[]}"#
        );
        let mut with_proof = document.clone();
        with_proof.proof = Some(DataIntegrityProof {
            proof_type: "Ed25519Signature2020".to_owned(),
            creator: String::new(),
            created: chrono::Utc::now(),
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: "z4HnYnN6MCvEhMhcjUKpVYCaqXyP714jVJXJVTJprdb9wdTGsY5dkRWPf2wXNJuRWA1XiMZFPizD9PGEM3ZV4vNYF".to_owned(),
            crypto_suite: None,
            hash_algorithm: None,
            verification_method: Some(
                "did:oan:P9aBc:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo#key-1".to_owned(),
            ),
        });
        let with_proof_input =
            did_document_signature_input(&with_proof, CryptoSuite::Ed25519Sha256).unwrap();
        assert_eq!(without_proof, with_proof_input);
        assert_ne!(
            hash_did_document_with_proof(&document, CryptoSuite::Ed25519Sha256).unwrap(),
            hash_did_document_with_proof(&with_proof, CryptoSuite::Ed25519Sha256).unwrap()
        );
        assert_eq!(
            hash_did_document_with_proof(&document, CryptoSuite::Ed25519Sha256).unwrap(),
            "ea22ffc510474c57eea32d8835c9335defa6bb9b4e3226046539027de61ee5cf"
        );
    }

    #[test]
    fn oan_cross_language_vector_matches_canonical_and_hash_outputs() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-fixtures/did-oan-cross-language.json"
        ))
        .unwrap();
        assert_eq!(
            canonical_json_value(&fixture["canonicalJsonCase"]["value"]),
            fixture["canonicalJsonCase"]["canonical"].as_str().unwrap()
        );

        let document_without_proof = fixture["documentWithoutProof"].clone();
        assert!(fixture["proof"].get("creator").is_none());
        assert!(fixture["proof"].get("cryptoSuite").is_none());
        assert!(fixture["proof"].get("hashAlgorithm").is_none());
        assert!(document_without_proof["verificationMethod"][0]
            .get("cryptoSuite")
            .is_none());
        assert_eq!(
            String::from_utf8(
                signature_input(CryptoSuite::Ed25519Sha256, &document_without_proof).unwrap()
            )
            .unwrap(),
            fixture["signatureInputCanonical"].as_str().unwrap()
        );

        let mut complete_document = document_without_proof.clone();
        complete_document["proof"] = fixture["proof"].clone();
        assert_eq!(
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &complete_document).unwrap(),
            fixture["completeDocumentHashSha256"].as_str().unwrap()
        );

        let mut changed_proof = complete_document.clone();
        changed_proof["proof"]["proofValue"] = serde_json::json!("fixture-proof-value-mutated");
        assert_eq!(
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &changed_proof).unwrap(),
            fixture["proofMutationHashSha256"].as_str().unwrap()
        );

        let mut changed_external_id = complete_document;
        changed_external_id["oanMetadata"]["externalIdentifiers"][0]["id"] =
            serde_json::json!("urn:example:skill:changed");
        assert_eq!(
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &changed_external_id).unwrap(),
            fixture["externalIdentifierMutationHashSha256"]
                .as_str()
                .unwrap()
        );
    }
}
