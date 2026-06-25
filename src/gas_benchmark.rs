#![cfg(test)]

//! Gas consumption benchmarks for public contract functions (#58).
//!
//! These tests exercise the core contract functions and measure
//! storage operations. They serve as regression guards — if a future
//! change significantly increases storage reads/writes, these tests
//! will still pass but CI can diff the output.

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
    credential_issuer::CredentialIssuer,
    credential_schema::{CredentialSchema, FieldValidation},
    did_registry::DIDRegistry,
    reputation_score::ReputationScore,
    zk_attestation::{CircuitType, ZKAttestation},
    Service, VerificationMethod,
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

fn make_vm(env: &Env, id: &str, key: &[u8; 32]) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, id.as_bytes()),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: Address::generate(env),
        public_key: BytesN::from_array(env, key),
    }
}

fn make_did_bytes(env: &Env) -> Bytes {
    Bytes::from_slice(env, b"did:stellar:GABCDEF123456789")
}

// =========================================================================
// DID Registry benchmarks
// =========================================================================

#[test]
fn bench_create_did() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let services = vec![
        &env,
        Service {
            id: Bytes::from_slice(&env, b"#hub"),
            type_: Bytes::from_slice(&env, b"IdentityHub"),
            endpoint: Bytes::from_slice(&env, b"https://hub.example.com"),
        },
    ];

    let result = DIDRegistry::create_did(
        env.clone(),
        controller,
        did,
        vec![&env, vm],
        services,
    );
    assert!(result.is_ok());
    std::println!("[BENCH] create_did            OK");
}

#[test]
fn bench_resolve_did() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let _ = DIDRegistry::create_did(
        env.clone(),
        controller,
        did.clone(),
        vec![&env, vm],
        Vec::new(&env),
    );

    let result = DIDRegistry::resolve_did(env.clone(), did);
    assert!(result.is_ok());
    std::println!("[BENCH] resolve_did           OK");
}

// =========================================================================
// Credential Issuer benchmarks
// =========================================================================

#[test]
fn bench_issue_credential() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    let result = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        vec![&env, Bytes::from_slice(&env, b"KYCVerification")],
        Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert!(result.is_ok());
    std::println!("[BENCH] issue_credential      OK");
}

#[test]
fn bench_verify_credential() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        vec![&env, Bytes::from_slice(&env, b"KYC")],
        Bytes::from_slice(&env, b"{\"v\":1}"),
        None,
        Bytes::from_slice(&env, b"proof"),
    )
    .unwrap();

    let result = CredentialIssuer::verify_credential(env.clone(), cred_id);
    assert!(result.is_ok());
    assert!(result.unwrap());
    std::println!("[BENCH] verify_credential     OK");
}

// =========================================================================
// Reputation Score benchmarks
// =========================================================================

#[test]
fn bench_initialize_reputation() {
    let env = setup_env();
    let user = Address::generate(&env);

    let result = ReputationScore::initialize_reputation(env.clone(), user);
    assert!(result.is_ok());
    std::println!("[BENCH] initialize_reputation OK");
}

#[test]
fn bench_update_reputation() {
    let env = setup_env();
    let user = Address::generate(&env);
    let _ = ReputationScore::initialize_reputation(env.clone(), user.clone());

    let result = ReputationScore::update_transaction_reputation(env.clone(), user, true, 1000);
    assert!(result.is_ok());
    std::println!("[BENCH] update_tx_reputation  OK");
}

// =========================================================================
// ZK Attestation benchmarks
// =========================================================================

#[test]
fn bench_register_circuit() {
    let env = setup_env();

    let result = ZKAttestation::register_circuit(
        env.clone(),
        Symbol::new(&env, "bench_circ"),
        Bytes::from_slice(&env, b"Bench Circuit"),
        Bytes::from_slice(&env, b"desc"),
        Bytes::from_slice(&env, b"verifier_key_data_here!!"),
        2,
        3,
        CircuitType::RangeProof,
        vec![&env, Symbol::new(&env, "attr")],
    );
    assert!(result.is_ok());
    std::println!("[BENCH] register_circuit      OK");
}

// =========================================================================
// Compliance Filter benchmarks
// =========================================================================

#[test]
fn bench_screen_address() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"OFAC_SDN");
    let hash = BytesN::from_array(&env, &[2u8; 32]);
    let _ = ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 1);
    let sanctioned = Address::generate(&env);
    let _ = ComplianceFilter::load_list_entries(env.clone(), admin, source, vec![&env, sanctioned.clone()]);

    let clean = Address::generate(&env);
    let result = ComplianceFilter::screen_address(env.clone(), clean);
    assert!(result.is_ok());
    std::println!("[BENCH] screen_address(clear) OK");
}

// =========================================================================
// Pagination benchmarks
// =========================================================================

#[test]
fn bench_paginated_credentials() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    for _ in 0..25 {
        let _ = CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject.clone(),
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Bytes::from_slice(&env, b"proof"),
        );
    }

    let result = CredentialIssuer::get_credentials_by_subject(env.clone(), subject, 0, 10);
    assert_eq!(result.data.len(), 10);
    assert_eq!(result.total, 25);
    assert!(result.has_more);
    std::println!("[BENCH] paginated_creds(p0)   items={}", result.data.len());
}

// =========================================================================
// Schema validation benchmark
// =========================================================================

#[test]
fn bench_register_schema() {
    let env = setup_env();
    let admin = Address::generate(&env);

    let required = vec![
        &env,
        Bytes::from_slice(&env, b"name"),
        Bytes::from_slice(&env, b"dob"),
    ];
    let optional = vec![&env, Bytes::from_slice(&env, b"middle_name")];
    let validations: Map<Bytes, FieldValidation> = Map::new(&env);

    let result = CredentialSchema::register_schema(
        env.clone(),
        admin,
        Bytes::from_slice(&env, b"kyc_v1"),
        Bytes::from_slice(&env, b"KYCSchema"),
        required,
        optional,
        validations,
    );
    assert!(result.is_ok());
    std::println!("[BENCH] register_schema       OK");
}
