#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Symbol, Vec,
};
use crate::{
    did_registry::{DIDRegistry, DIDRegistryError},
    credential_issuer::{CredentialIssuer, CredentialIssuerError},
    reputation_score::{ReputationScore, ReputationScoreError},
    zk_attestation::{CircuitType, ZKAttestation, ZKAttestationError},
    compliance_filter::{ComplianceFilter, ComplianceFilterError},
};

fn setup_env() -> Env {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set(LedgerInfo {
        timestamp: 1_700_000_000,
        protocol_version: 22,
        sequence_number: 1000,
        network_id: [0; 32],
        base_reserve: 10,
        min_temp_entry_ttl: 50000,
        min_persistent_entry_ttl: 50000,
        max_entry_ttl: 50000,
    });
    env
}

fn generate_address(env: &Env) -> Address {
    Address::generate(env)
}

#[test]
fn fuzz_long_did_string() {
    let env = setup_env();
    let controller = generate_address(&env);
    let long_bytes = [b'a'; 10000];
    let long_did = Bytes::from_slice(&env, &long_bytes);
    let vm = crate::VerificationMethod {
        id: Bytes::from_slice(&env, b"#key-1"),
        type_: Bytes::from_slice(&env, b"Ed25519VerificationKey2018"),
        controller: controller.clone(),
        public_key: BytesN::from_array(&env, &[1u8; 32]),
    };

    let result = DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        long_did,
        vec![&env, vm],
        Vec::new(&env),
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), DIDRegistryError::InvalidFormat);
}

#[test]
fn fuzz_empty_credential_claims() {
    let env = setup_env();
    let issuer = generate_address(&env);
    let subject = generate_address(&env);

    let result = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        vec![&env, Bytes::from_slice(&env, b"Test")],
        Bytes::new(&env),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), CredentialIssuerError::InvalidCredential);
}

#[test]
fn fuzz_invalid_credential_type() {
    let env = setup_env();
    let issuer = generate_address(&env);
    let subject = generate_address(&env);

    CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

    let result = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        Vec::new(&env),
        Bytes::from_slice(&env, b"data"),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), CredentialIssuerError::InvalidCredentialType);
}

#[test]
fn fuzz_oversized_reputation_params() {
    let env = setup_env();
    let user = generate_address(&env);
    let _ = ReputationScore::initialize_reputation(env.clone(), user.clone());

    let result = ReputationScore::attest_trust(
        env.clone(),
        user.clone(),
        generate_address(&env),
        1001,
        Bytes::from_slice(&env, b"test"),
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), ReputationScoreError::InvalidScore);
}

#[test]
fn fuzz_invalid_trust_graph_depth() {
    let env = setup_env();
    let user = generate_address(&env);

    let result = ReputationScore::get_trust_graph(env.clone(), user.clone(), 0);
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), ReputationScoreError::InvalidDepth);

    let result = ReputationScore::get_trust_graph(env.clone(), user.clone(), 5);
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), ReputationScoreError::InvalidDepth);
}

#[test]
fn fuzz_duplicate_circuit_registration() {
    let env = setup_env();
    let circuit_id = Symbol::new(&env, "dup_test");
    let name = Bytes::from_slice(&env, b"Test");
    let description = Bytes::from_slice(&env, b"Test circuit");
    let verifier_key = Bytes::from_slice(&env, b"key_data_16_bytes!");
    let attributes = Vec::new(&env);

    assert!(ZKAttestationContract::register_circuit(
        env.clone(),
        circuit_id.clone(),
        name.clone(),
        description.clone(),
        verifier_key.clone(),
        1,
        1,
        CircuitType::RangeProof,
        attributes.clone(),
    )
    .is_ok());

    let result = ZKAttestationContract::register_circuit(
        env.clone(),
        circuit_id,
        name,
        description,
        verifier_key,
        1,
        1,
        CircuitType::RangeProof,
        attributes,
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), ZKAttestationError::InvalidCircuit);
}

#[test]
fn fuzz_nullifier_reuse() {
    let env = setup_env();
    let circuit_id = Symbol::new(&env, "null_test");
    let _ = ZKAttestationContract::register_circuit(
        env.clone(),
        circuit_id.clone(),
        Bytes::from_slice(&env, b"Null Test"),
        Bytes::from_slice(&env, b"Test"),
        Bytes::from_slice(&env, b"key_data_16_bytes!"),
        1,
        1,
        CircuitType::RangeProof,
        Vec::new(&env),
    );

    let nullifier = Bytes::from_slice(&env, b"same_nullifier");
    let mut metadata = soroban_sdk::Map::new(&env);
    metadata.set(Symbol::new(&env, "context"), Bytes::from_slice(&env, b"test"));

    let result1 = ZKAttestationContract::submit_proof(
        env.clone(),
        circuit_id.clone(),
        vec![&env, Bytes::from_slice(&env, b"input")],
        Bytes::from_slice(&env, b"proof"),
        nullifier.clone(),
        Vec::new(&env),
        None,
        metadata.clone(),
    );
    assert!(result1.is_ok());

    let result2 = ZKAttestationContract::submit_proof(
        env.clone(),
        circuit_id,
        vec![&env, Bytes::from_slice(&env, b"input2")],
        Bytes::from_slice(&env, b"proof2"),
        nullifier,
        Vec::new(&env),
        None,
        metadata,
    );
    assert!(result2.is_err());
    assert_eq!(result2.err().unwrap(), ZKAttestationError::NullifierAlreadyUsed);
}

#[test]
fn fuzz_empty_proof() {
    let env = setup_env();
    let circuit_id = Symbol::new(&env, "empty_proof");
    let _ = ZKAttestationContract::register_circuit(
        env.clone(),
        circuit_id.clone(),
        Bytes::from_slice(&env, b"Empty Proof"),
        Bytes::from_slice(&env, b"Test"),
        Bytes::from_slice(&env, b"key_data_16_bytes!"),
        1,
        1,
        CircuitType::RangeProof,
        Vec::new(&env),
    );

    let mut metadata = soroban_sdk::Map::new(&env);
    metadata.set(Symbol::new(&env, "context"), Bytes::from_slice(&env, b"test"));

    let result = ZKAttestationContract::submit_proof(
        env.clone(),
        circuit_id,
        vec![&env, Bytes::from_slice(&env, b"input")],
        Bytes::new(&env),
        Bytes::from_slice(&env, b"null"),
        Vec::new(&env),
        None,
        metadata,
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), ZKAttestationError::InvalidProof);
}

#[test]
fn fuzz_invalid_risk_score() {
    let env = setup_env();
    let oracle = generate_address(&env);
    let user = generate_address(&env);

    let result = ComplianceFilter::update_risk_score(
        env.clone(),
        oracle,
        user,
        101,
        Bytes::from_slice(&env, b"test"),
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), ComplianceFilterError::InvalidRiskScore);
}

#[test]
fn fuzz_invalid_did_format() {
    let env = setup_env();
    let controller = generate_address(&env);

    let bad_did = Bytes::from_slice(&env, b"invalid:did:format");
    let vm = crate::VerificationMethod {
        id: Bytes::from_slice(&env, b"#key-1"),
        type_: Bytes::from_slice(&env, b"Ed25519VerificationKey2018"),
        controller: controller.clone(),
        public_key: BytesN::from_array(&env, &[1u8; 32]),
    };

    let result = DIDRegistry::create_did(
        env.clone(),
        controller,
        bad_did,
        vec![&env, vm],
        Vec::new(&env),
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), DIDRegistryError::InvalidFormat);
}

#[test]
fn fuzz_unregistered_issuer() {
    let env = setup_env();
    let issuer = generate_address(&env);
    let subject = generate_address(&env);

    let long_type = [b'X'; 5000];
    let long_cred_type = vec![&env, Bytes::from_slice(&env, &long_type)];

    let result = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        long_cred_type,
        Bytes::from_slice(&env, b"data"),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    // 5000 > MAX_CREDENTIAL_TYPE_LENGTH (128), so this should fail
    assert!(result.is_err());
}
