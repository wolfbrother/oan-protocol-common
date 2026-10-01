use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use iref::{IriBuf, UriBuf};
use oan_crypto::{sign_oan_data_integrity, verify_oan_data_integrity};
use serde_json::json;
use ssi_claims::data_integrity::{AnySuite, CryptographicSuite, ProofOptions};
use ssi_claims::VerificationParameters;
use ssi_data_integrity::{AnyDataIntegrity, DataIntegrityDocument};
use ssi_jwk::JWK;
use ssi_verification_methods::{AnyMethod, Ed25519VerificationKey2020, SingleSecretSigner};

#[tokio::test]
async fn ed25519_signature_2020_produces_multibase_proof_and_verifies() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let did = "did:example:issuer";
    let method_id = format!("{did}#key-1");
    let method_id_iri = IriBuf::new(method_id.clone()).unwrap();
    let method = Ed25519VerificationKey2020::from_public_key(
        method_id_iri.clone(),
        UriBuf::new(did.as_bytes().to_vec()).unwrap(),
        signing_key.verifying_key(),
    );
    let mut methods = HashMap::<IriBuf, AnyMethod>::new();
    methods.insert(method_id_iri.clone(), method.into());

    let jwk: JWK = serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.verifying_key().as_bytes()
        ),
        "d": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.to_bytes()
        )
    }))
    .unwrap();

    let document: DataIntegrityDocument = serde_json::from_value(json!({
        "@context": [
            {
                "VerifiableCredential": "https://www.w3.org/2018/credentials#VerifiableCredential",
                "issuer": "https://www.w3.org/2018/credentials#issuer",
                "credentialSubject": "https://www.w3.org/2018/credentials#credentialSubject",
                "id": "@id",
                "type": "@type"
            },
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": ["VerifiableCredential"],
        "issuer": did,
        "credentialSubject": {"id": "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu"}
    }))
    .unwrap();
    let signed: AnyDataIntegrity = AnySuite::Ed25519Signature2020
        .sign(
            document,
            &methods,
            SingleSecretSigner::new(jwk).into_local(),
            ProofOptions::from_method(method_id_iri.clone().into()),
        )
        .await
        .unwrap();

    let json = serde_json::to_value(&signed).unwrap();
    let proof_value = json["proof"]["proofValue"].as_str().unwrap();
    assert!(proof_value.starts_with('z'));
    assert!(bs58::decode(&proof_value[1..]).into_vec().is_ok());
    assert_eq!(
        bs58::decode(&proof_value[1..]).into_vec().unwrap().len(),
        64
    );

    let resolver = methods;
    signed
        .verify(VerificationParameters::from_resolver(resolver))
        .await
        .unwrap()
        .unwrap();

    let mut mutated = json;
    mutated["proof"]["proofValue"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        [0u8; 64],
    ));
    assert!(!mutated["proof"]["proofValue"]
        .as_str()
        .unwrap()
        .starts_with('z'));
}

#[tokio::test]
async fn verifies_typescript_ed25519_signature_2020_fixture() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-fixtures/ed25519-signature-2020-cross-language.json"
    ))
    .unwrap();
    let key = &fixture["key"];
    let method_id = key["id"].as_str().unwrap().to_owned();
    let method_id_iri = IriBuf::new(method_id).unwrap();
    let method: Ed25519VerificationKey2020 = serde_json::from_value(key.clone()).unwrap();
    let mut methods = HashMap::<IriBuf, AnyMethod>::new();
    methods.insert(method_id_iri, method.into());
    let signed: AnyDataIntegrity = serde_json::from_value(fixture["signed"].clone()).unwrap();
    signed
        .verify(VerificationParameters::from_resolver(methods))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shared_oan_adapter_signs_and_verifies() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let private_key = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.verifying_key().as_bytes()
        ),
        "d": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.to_bytes()
        )
    });
    let document = json!({
        "@context": [
            {"VerifiableCredential": "https://www.w3.org/2018/credentials#VerifiableCredential",
             "issuer": "https://www.w3.org/2018/credentials#issuer",
             "credentialSubject": "https://www.w3.org/2018/credentials#credentialSubject",
             "id": "@id", "type": "@type"},
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "credentialSubject": {"id": "did:example:subject"}
    });
    let signed = sign_oan_data_integrity(document, "did:example:issuer", private_key.clone())
        .await
        .unwrap();
    assert!(signed["proof"]["proofValue"]
        .as_str()
        .unwrap()
        .starts_with('z'));
    verify_oan_data_integrity(
        signed,
        json!({
            "kty":"OKP",
            "crv":"Ed25519",
            "x": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                signing_key.verifying_key().as_bytes()
            )
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn oan_adapter_uses_local_oan_context_without_remote_resolution() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let private_key = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.verifying_key().as_bytes()
        ),
        "d": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.to_bytes()
        )
    });
    let public_key = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": private_key["x"]
    });
    let document = json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://openagenet.xyz/did-oan-specs/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": "urn:oan:root-authorization:registrar:local-context-test",
        "type": [
            "VerifiableCredential",
            "OANInfrastructureAuthorizationCredential"
        ],
        "issuer": "did:oan:P9aBc:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo",
        "issuanceDate": "2026-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:oan:2LmNo:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
            "role": "registrar",
            "subjectType": "infrastructure_node",
            "resourceType": "registrar_node",
            "authorizedDomains": ["*"],
            "didDocumentHash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    });

    let signed = sign_oan_data_integrity(
        document,
        "did:oan:P9aBc:2LmNo3PqRsTuVwXyZaBcDeFgHiJkLmNo",
        private_key,
    )
    .await
    .unwrap();
    verify_oan_data_integrity(signed.clone(), public_key.clone())
        .await
        .unwrap();

    let mut tampered = signed;
    tampered["credentialSubject"]["authorizedDomains"] = json!(["finance"]);
    assert!(verify_oan_data_integrity(tampered, public_key)
        .await
        .is_err());
}

#[tokio::test]
async fn oan_adapter_verifies_full_did_document_context_set() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let private_key = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.verifying_key().as_bytes()
        ),
        "d": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.to_bytes()
        )
    });
    let did = "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu";
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://openagenet.xyz/did-oan-specs/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "controller": did,
        "verificationMethod": [{
            "id": format!("{did}#key-1"),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyJwk": private_key
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.as_str() != "d")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<serde_json::Map<_, _>>()
        }],
        "authentication": [format!("{did}#key-1")],
        "assertionMethod": [format!("{did}#key-1")],
        "service": [],
        "oanMetadata": {
            "subjectType": "controller",
            "resourceType": "controller",
            "controllerDid": did,
            "authorizedDomains": ["*"]
        }
    });
    let signed = sign_oan_data_integrity(document, did, private_key.clone())
        .await
        .unwrap();
    verify_oan_data_integrity(
        signed,
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": private_key["x"]
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn oan_adapter_rejects_wrong_method_and_key_algorithm() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let private_key = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.verifying_key().as_bytes()
        ),
        "d": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signing_key.to_bytes()
        )
    });
    let document = json!({
        "@context": [
            {"VerifiableCredential": "https://www.w3.org/2018/credentials#VerifiableCredential",
             "issuer": "https://www.w3.org/2018/credentials#issuer",
             "credentialSubject": "https://www.w3.org/2018/credentials#credentialSubject",
             "id": "@id", "type": "@type"},
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "credentialSubject": {"id": "did:example:subject"}
    });
    let signed = sign_oan_data_integrity(document, "did:example:issuer", private_key.clone())
        .await
        .unwrap();
    let mut wrong_method = signed.clone();
    wrong_method["proof"]["verificationMethod"] =
        serde_json::Value::String("did:example:issuer#key-2".to_owned());
    assert!(verify_oan_data_integrity(
        wrong_method,
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": private_key["x"]
        }),
    )
    .await
    .is_err());
    assert!(sign_oan_data_integrity(
        json!({}),
        "did:example:issuer",
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": private_key["x"],
            "d": private_key["d"],
            "alg": "Ed25519"
        }),
    )
    .await
    .is_err());
}
