#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
    credential_issuer::CredentialIssuer,
    credential_schema::{CredentialSchema, FieldValidation},
    did_registry::{DIDRegistry, DIDRegistryError},
    reputation_score::{ReputationData, ReputationScore, ReputationScoreError, TrustAttestation},
    zk_attestation::{CircuitType, ZKAttestation, ZKAttestationError},
    DIDDocument, Service, VerifiableCredential, VerificationMethod,
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

use core::sync::atomic::{AtomicU32, Ordering};
static DID_COUNTER: AtomicU32 = AtomicU32::new(0);

fn make_did_bytes(env: &Env, _addr: &Address) -> Bytes {
    let n = DID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut did = Bytes::from_slice(env, b"did:stellar:GABC");
    did.append(&Bytes::from_slice(env, n.to_string().as_bytes()));
    did
}

fn make_claims(env: &Env) -> Map<Bytes, Bytes> {
    let mut claims = Map::new(env);
    claims.set(
        Bytes::from_slice(env, b"name"),
        Bytes::from_slice(env, b"Alice"),
    );
    claims.set(
        Bytes::from_slice(env, b"dob"),
        Bytes::from_slice(env, b"1990-01-01"),
    );
    claims
}

fn new_address(env: &Env) -> Address {
    Address::generate(env)
}

fn make_vm_vec(env: &Env, vms: Vec<VerificationMethod>) -> Vec<VerificationMethod> {
    vms
}

fn make_services(env: &Env) -> Vec<Service> {
    vec![
        env,
        Service {
            id: Bytes::from_slice(env, b"#hub"),
            type_: Bytes::from_slice(env, b"IdentityHub"),
            endpoint: Bytes::from_slice(env, b"https://hub.example.com"),
        },
    ]
}

// =========================================================================
// Test 1: Full KYC flow
// =========================================================================

#[test]
fn test_full_kyc_flow() {
    let env = setup_env();
    env.mock_all_auths();

    let key = &[1u8; 32];
    let controller = new_address(&env);
    let issuer = new_address(&env);
    let subject = new_address(&env);

    let did = make_did_bytes(&env, &controller);
    let vm = make_vm(&env, "#key-1", key);
    let services = make_services(&env);

    assert!(DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        did.clone(),
        make_vm_vec(&env, vec![&env, vm]),
        services,
    )
    .is_ok());

    let resolved = DIDRegistry::resolve_did(env.clone(), did.clone());
    assert!(resolved.is_ok());
    assert!(!resolved.unwrap().deactivated);

    // Register issuer first
    CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        subject.clone(),
        Bytes::from_slice(&env, b"KYCCredential"),
        make_claims(&env),
    );
    assert!(cred_id.is_ok());
    let cred_id = cred_id.unwrap();

    let verification = CredentialIssuer::verify_credential(env.clone(), cred_id.clone());
    assert!(verification.is_ok());
    assert!(verification.unwrap().valid);

    let revoked = CredentialIssuer::revoke_credential(
        env.clone(),
        issuer.clone(),
        cred_id.clone(),
        Some(Bytes::from_slice(&env, b"KYC expired")),
    );
    assert!(revoked.is_ok());

    let verification_after = CredentialIssuer::verify_credential(env.clone(), cred_id.clone());
    assert!(verification_after.is_ok());
    assert!(!verification_after.unwrap().valid);

    let status = CredentialIssuer::get_credential_status(env.clone(), cred_id.clone());
    assert_eq!(status, Bytes::from_slice(&env, b"revoked"));

    let reason = CredentialIssuer::get_revocation_reason(env.clone(), cred_id.clone());
    assert!(reason.is_some());
}

// =========================================================================
// Test 2: Reputation evolution
// =========================================================================

#[test]
fn test_reputation_evolution() {
    let env = setup_env();
    let user = new_address(&env);

    let init = ReputationScore::initialize_reputation(env.clone(), user.clone());
    assert!(init.is_ok());
    let initial_score = init.unwrap().score;

    for _ in 0..5 {
        let _ = ReputationScore::update_transaction_reputation(
            env.clone(),
            user.clone(),
            true,
            1000,
        );
    }

    let score_after_txns = ReputationScore::get_reputation_score(env.clone(), user.clone());
    assert!(score_after_txns.is_ok());
    assert!(score_after_txns.unwrap() > initial_score);

    let _ = ReputationScore::update_credential_reputation(
        env.clone(),
        user.clone(),
        true,
        Bytes::from_slice(&env, b"KYC"),
    );

    let data = ReputationScore::get_reputation_data(env.clone(), user.clone());
    assert!(data.is_ok());
    assert_eq!(data.unwrap().verified_kyc, 1);

    let history = ReputationScore::get_reputation_history(env.clone(), user.clone(), 10);
    assert!(history.is_ok());
    assert!(history.unwrap().len() >= 6);
}

// =========================================================================
// Test 3: Compliance enforcement
// =========================================================================

#[test]
fn test_compliance_enforcement() {
    let env = setup_env();
    let admin = new_address(&env);
    let sanctioned = new_address(&env);

    let source = Bytes::from_slice(&env, b"OFAC_SDN");
    let hash = BytesN::from_array(&env, &[2u8; 32]);

    let _ = ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash,
        1,
    );

    let entries = vec![&env, sanctioned.clone()];
    let _ = ComplianceFilter::load_list_entries(
        env.clone(),
        admin.clone(),
        source.clone(),
        entries,
    );

    let screening = ComplianceFilter::screen_address(env.clone(), sanctioned.clone());
    assert!(screening.is_err());

    let clean_user = new_address(&env);
    let clean_result = ComplianceFilter::screen_address(env.clone(), clean_user.clone());
    assert!(clean_result.is_ok());
    assert_eq!(
        clean_result.unwrap().status,
        Bytes::from_slice(&env, b"clear")
    );
}

#[test]
fn test_sanctions_list_admin_management() {
    let env = setup_env();
    let admin = new_address(&env);
    let offender = new_address(&env);
    let source = Bytes::from_slice(&env, b"UN_LIST");
    let hash = BytesN::from_array(&env, &[3u8; 32]);

    ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash,
        0,
    )
    .unwrap();

    assert!(!ComplianceFilter::is_sanctioned(env.clone(), offender.clone()));

    ComplianceFilter::add_to_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        offender.clone(),
        Bytes::from_slice(&env, b"terror financing"),
        Bytes::from_slice(&env, b"US"),
    )
    .unwrap();

    assert!(ComplianceFilter::is_sanctioned(env.clone(), offender.clone()));
    let screening = ComplianceFilter::screen_address(env.clone(), offender.clone());
    assert!(screening.is_err());

    ComplianceFilter::remove_from_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        offender.clone(),
    )
    .unwrap();

    assert!(!ComplianceFilter::is_sanctioned(env.clone(), offender.clone()));
}

// =========================================================================
// Test 4: ZK proof lifecycle
// =========================================================================

#[test]
fn test_zk_proof_lifecycle() {
    let env = setup_env();

    let circuit_id = Symbol::new(&env, "age_test");
    let name = Bytes::from_slice(&env, b"Age Range Proof");
    let description = Bytes::from_slice(&env, b"Prove age >= minimum without revealing exact age");
    let verifier_key = Bytes::from_slice(&env, b"test_verifier_key_32_bytes_long!");
    let public_input_count = 2;
    let private_input_count = 3;
    let circuit_type = CircuitType::RangeProof;
    let supported_attributes = vec![&env, Symbol::new(&env, "age_commitment")];

    let register_result = ZKAttestationContract::register_circuit(
        env.clone(),
        circuit_id.clone(),
        name,
        description,
        verifier_key,
        public_input_count,
        private_input_count,
        circuit_type,
        supported_attributes,
    );
    assert!(register_result.is_ok());

    let public_inputs = vec![
        &env,
        Bytes::from_slice(&env, b"commitment_value_1"),
        Bytes::from_slice(&env, b"18"),
    ];
    let proof_bytes = Bytes::from_slice(&env, b"valid_zk_proof_data");
    let nullifier = Bytes::from_slice(&env, b"unique_nullifier_123");
    let revealed_attributes = vec![&env, Symbol::new(&env, "age_commitment")];
    let mut metadata = soroban_sdk::Map::new(&env);
    metadata.set(
        Symbol::new(&env, "context"),
        Bytes::from_slice(&env, b"age_verification"),
    );

    let proof_id = ZKAttestationContract::submit_proof(
        env.clone(),
        circuit_id.clone(),
        public_inputs,
        proof_bytes,
        nullifier,
        revealed_attributes,
        None,
        metadata,
    );
    assert!(proof_id.is_ok());
    let proof_id = proof_id.unwrap();

    let verify_result = ZKAttestationContract::verify_proof(env.clone(), proof_id.clone());
    assert!(verify_result.is_ok());
    assert!(verify_result.unwrap());

    let retrieved = ZKAttestationContract::get_proof(env.clone(), proof_id.clone());
    assert!(retrieved.is_ok());

    let circuits = ZKAttestationContract::get_active_circuits(env.clone());
    assert!(circuits.len() >= 1);
}

// =========================================================================
// Test 5: Admin operations
// =========================================================================

#[test]
fn test_admin_operations() {
    let env = setup_env();
    let admin = new_address(&env);

    let source = Bytes::from_slice(&env, b"UN_LIST");
    let hash = BytesN::from_array(&env, &[3u8; 32]);

    let result = ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash.clone(),
        5,
    );
    assert!(result.is_ok());

    let list = ComplianceFilter::get_sanctions_list(env.clone(), source.clone());
    assert!(list.is_some());
    assert!(list.unwrap().active);

    let deactivate = ComplianceFilter::deactivate_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
    );
    assert!(deactivate.is_ok());

    let list_after = ComplianceFilter::get_sanctions_list(env.clone(), source.clone());
    assert!(list_after.is_some());
    assert!(!list_after.unwrap().active);
}

// =========================================================================
// Test 6: Multi-user scenario
// =========================================================================

#[test]
fn test_multi_user_scenario() {
    let env = setup_env();
    env.mock_all_auths();

    let key1 = &[1u8; 32];
    let key2 = &[2u8; 32];
    let key3 = &[3u8; 32];

    let user1 = new_address(&env);
    let user2 = new_address(&env);
    let user3 = new_address(&env);

    let did1 = make_did_bytes(&env, &user1);
    let did2 = make_did_bytes(&env, &user2);
    let did3 = make_did_bytes(&env, &user3);

    assert!(DIDRegistry::create_did(
        env.clone(),
        user1.clone(),
        did1.clone(),
        make_vm_vec(&env, vec![&env, make_vm(&env, "#key-1", key1)]),
        make_services(&env),
    )
    .is_ok());

    assert!(DIDRegistry::create_did(
        env.clone(),
        user2.clone(),
        did2.clone(),
        make_vm_vec(&env, vec![&env, make_vm(&env, "#key-1", key2)]),
        make_services(&env),
    )
    .is_ok());

    assert!(DIDRegistry::create_did(
        env.clone(),
        user3.clone(),
        did3.clone(),
        make_vm_vec(&env, vec![&env, make_vm(&env, "#key-1", key3)]),
        make_services(&env),
    )
    .is_ok());

    for user in [&user1, &user2, &user3] {
        let _ = ReputationScore::initialize_reputation(env.clone(), (*user).clone());
        let _ = ReputationScore::update_transaction_reputation(
            env.clone(),
            (*user).clone(),
            true,
            500,
        );
    }

    // Register issuer, then issue credential
    CredentialIssuer::register_issuer(env.clone(), user1.clone()).unwrap();

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        user1.clone(),
        user2.clone(),
        Bytes::from_slice(&env, b"KYCCredential"),
        make_claims(&env),
    );
    assert!(cred_id.is_ok());
    let cred_id = cred_id.unwrap();

    let user2_creds = CredentialIssuer::get_subject_credentials(env.clone(), user2.clone());
    assert_eq!(user2_creds.len(), 1);
    assert_eq!(user2_creds.get(0).unwrap(), cred_id);

    let user1_creds = CredentialIssuer::get_issuer_credentials(env.clone(), user1.clone());
    assert_eq!(user1_creds.len(), 1);

    let verification = CredentialIssuer::verify_credential(env.clone(), cred_id);
    assert!(verification.is_ok());
    assert!(verification.unwrap().valid);

    let user3_score = ReputationScore::get_reputation_score(env.clone(), user3.clone());
    assert!(user3_score.is_ok());
}

// =========================================================================
// Test 7: Deterministic test
// =========================================================================

#[test]
fn test_deterministic_parallel_safe() {
    let env = setup_env();
    let alice = new_address(&env);
    let bob = new_address(&env);

    assert!(ReputationScore::initialize_reputation(env.clone(), alice.clone()).is_ok());
    assert!(ReputationScore::initialize_reputation(env.clone(), bob.clone()).is_ok());

    let alice_score = ReputationScore::get_reputation_score(env.clone(), alice.clone()).unwrap();
    let bob_score = ReputationScore::get_reputation_score(env.clone(), bob.clone()).unwrap();

    assert_eq!(alice_score, bob_score);

    for _ in 0..3 {
        let _ = ReputationScore::update_transaction_reputation(
            env.clone(),
            alice.clone(),
            true,
            100,
        );
    }

    let alice_after = ReputationScore::get_reputation_score(env.clone(), alice.clone()).unwrap();
    let bob_after = ReputationScore::get_reputation_score(env.clone(), bob.clone()).unwrap();

    assert!(alice_after > bob_after);
    assert_eq!(bob_after, bob_score);
}

// =========================================================================
// Test 8: Pagination - empty list (#56)
// =========================================================================

#[test]
fn test_pagination_empty_list() {
    let env = setup_env();
    let subject = new_address(&env);

    let result = CredentialIssuer::get_credentials_by_subject(env.clone(), subject, 0, 10);
    assert_eq!(result.data.len(), 0);
    assert_eq!(result.page, 0);
    assert_eq!(result.total, 0);
    assert!(!result.has_more);
}

// =========================================================================
// Test 9: Pagination - single page (#56)
// =========================================================================

#[test]
fn test_pagination_single_page() {
    let env = setup_env();
    let issuer = new_address(&env);
    let subject = new_address(&env);

    for _ in 0..5 {
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
    assert_eq!(result.data.len(), 5);
    assert_eq!(result.total, 5);
    assert!(!result.has_more);
}

// =========================================================================
// Test 10: Pagination - multiple pages (#56)
// =========================================================================

#[test]
fn test_pagination_multiple_pages() {
    let env = setup_env();
    let issuer = new_address(&env);
    let subject = new_address(&env);

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

    let page0 = CredentialIssuer::get_credentials_by_subject(env.clone(), subject.clone(), 0, 10);
    assert_eq!(page0.data.len(), 10);
    assert_eq!(page0.total, 25);
    assert!(page0.has_more);

    let page1 = CredentialIssuer::get_credentials_by_subject(env.clone(), subject.clone(), 1, 10);
    assert_eq!(page1.data.len(), 10);
    assert!(page1.has_more);

    let page2 = CredentialIssuer::get_credentials_by_subject(env.clone(), subject.clone(), 2, 10);
    assert_eq!(page2.data.len(), 5);
    assert!(!page2.has_more);
}

// =========================================================================
// Test 11: Pagination - last page exact (#56)
// =========================================================================

#[test]
fn test_pagination_last_page_exact() {
    let env = setup_env();
    let issuer = new_address(&env);
    let subject = new_address(&env);

    for _ in 0..20 {
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

    let page1 = CredentialIssuer::get_credentials_by_subject(env.clone(), subject.clone(), 1, 10);
    assert_eq!(page1.data.len(), 10);
    assert!(!page1.has_more);
}

// =========================================================================
// Test 12: Pagination - page size clamping (#56)
// =========================================================================

#[test]
fn test_pagination_page_size_clamping() {
    let env = setup_env();
    let issuer = new_address(&env);
    let subject = new_address(&env);

    for _ in 0..60 {
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

    // page_size=0 should default to 10
    let result = CredentialIssuer::get_credentials_by_subject(env.clone(), subject.clone(), 0, 0);
    assert_eq!(result.data.len(), 10);

    // page_size=100 should clamp to 50
    let result = CredentialIssuer::get_credentials_by_subject(env.clone(), subject.clone(), 0, 100);
    assert_eq!(result.data.len(), 50);
}

// =========================================================================
// Test 13: Paginated sanctioned addresses (#56)
// =========================================================================

#[test]
fn test_paginated_sanctioned_addresses() {
    let env = setup_env();
    let admin = new_address(&env);
    let source = Bytes::from_slice(&env, b"TEST_LIST");
    let hash = BytesN::from_array(&env, &[5u8; 32]);

    let _ = ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash,
        3,
    );

    let entries = vec![
        &env,
        new_address(&env),
        new_address(&env),
        new_address(&env),
    ];
    let _ = ComplianceFilter::load_list_entries(
        env.clone(),
        admin.clone(),
        source.clone(),
        entries,
    );

    let page0 = ComplianceFilter::get_sanctioned_addresses(env.clone(), 0, 2);
    assert_eq!(page0.data.len(), 2);
    assert_eq!(page0.total, 3);
    assert!(page0.has_more);

    let page1 = ComplianceFilter::get_sanctioned_addresses(env.clone(), 1, 2);
    assert_eq!(page1.data.len(), 1);
    assert!(!page1.has_more);
}

// =========================================================================
// Test 14: Paginated registered circuits (#56)
// =========================================================================

#[test]
fn test_paginated_registered_circuits() {
    let env = setup_env();

    for i in 0..5u32 {
        let cid = Symbol::new(&env, &format!("circ_{i}"));
        let _ = ZKAttestation::register_circuit(
            env.clone(),
            cid,
            Bytes::from_slice(&env, b"name"),
            Bytes::from_slice(&env, b"desc"),
            Bytes::from_slice(&env, b"vk_data_123456789012345678"),
            1,
            1,
            CircuitType::RangeProof,
            vec![&env, Symbol::new(&env, "attr")],
        );
    }

    let page0 = ZKAttestation::get_registered_circuits(env.clone(), 0, 3);
    assert_eq!(page0.data.len(), 3);
    assert_eq!(page0.total, 5);
    assert!(page0.has_more);

    let page1 = ZKAttestation::get_registered_circuits(env.clone(), 1, 3);
    assert_eq!(page1.data.len(), 2);
    assert!(!page1.has_more);
}

// =========================================================================
// Test 15: Paginated reputation history (#56)
// =========================================================================

#[test]
fn test_paginated_reputation_history() {
    let env = setup_env();
    let user = new_address(&env);

    let _ = ReputationScore::initialize_reputation(env.clone(), user.clone());
    for _ in 0..15 {
        let _ = ReputationScore::update_transaction_reputation(
            env.clone(),
            user.clone(),
            true,
            100,
        );
    }

    // 1 init + 15 updates = 16 entries
    let page0 = ReputationScore::get_reputation_history_paginated(
        env.clone(),
        user.clone(),
        0,
        10,
    )
    .unwrap();
    assert_eq!(page0.data.len(), 10);
    assert_eq!(page0.total, 16);
    assert!(page0.has_more);

    let page1 = ReputationScore::get_reputation_history_paginated(
        env.clone(),
        user.clone(),
        1,
        10,
    )
    .unwrap();
    assert_eq!(page1.data.len(), 6);
    assert!(!page1.has_more);
}

// =========================================================================
// Test 16: Schema registration (#60)
// =========================================================================

#[test]
fn test_schema_registration() {
    let env = setup_env();
    let admin = new_address(&env);

    let schema_id = Bytes::from_slice(&env, b"kyc_schema_v1");
    let schema_type = Bytes::from_slice(&env, b"KYCSchema");
    let required = vec![
        &env,
        Bytes::from_slice(&env, b"name"),
        Bytes::from_slice(&env, b"dob"),
    ];
    let optional = vec![&env, Bytes::from_slice(&env, b"middle_name")];
    let mut validations: Map<Bytes, FieldValidation> = Map::new(&env);
    validations.set(
        Bytes::from_slice(&env, b"name"),
        FieldValidation::StringLength(100),
    );

    let result = CredentialSchema::register_schema(
        env.clone(),
        admin.clone(),
        schema_id.clone(),
        schema_type,
        required,
        optional,
        validations,
    );
    assert!(result.is_ok());

    let schema = CredentialSchema::get_schema(env.clone(), schema_id.clone());
    assert!(schema.is_some());
    let schema = schema.unwrap();
    assert_eq!(schema.version, 1);
    assert!(schema.active);
    assert_eq!(schema.required_fields.len(), 2);

    // Duplicate registration should fail
    let dup = CredentialSchema::register_schema(
        env.clone(),
        admin.clone(),
        schema_id,
        Bytes::from_slice(&env, b"Other"),
        Vec::new(&env),
        Vec::new(&env),
        Map::new(&env),
    );
    assert!(dup.is_err());
}

// =========================================================================
// Test 17: Schema versioning (#60)
// =========================================================================

#[test]
fn test_schema_versioning() {
    let env = setup_env();
    let admin = new_address(&env);
    let schema_id = Bytes::from_slice(&env, b"versioned_schema");

    let _ = CredentialSchema::register_schema(
        env.clone(),
        admin.clone(),
        schema_id.clone(),
        Bytes::from_slice(&env, b"TestSchema"),
        vec![&env, Bytes::from_slice(&env, b"field_a")],
        Vec::new(&env),
        Map::new(&env),
    );

    let v2 = CredentialSchema::register_schema_version(
        env.clone(),
        admin.clone(),
        schema_id.clone(),
        vec![
            &env,
            Bytes::from_slice(&env, b"field_a"),
            Bytes::from_slice(&env, b"field_b"),
        ],
        Vec::new(&env),
        Map::new(&env),
    );
    assert!(v2.is_ok());
    assert_eq!(v2.unwrap(), 2);

    let latest = CredentialSchema::get_schema(env.clone(), schema_id.clone()).unwrap();
    assert_eq!(latest.version, 2);
    assert_eq!(latest.required_fields.len(), 2);

    let v1 = CredentialSchema::get_schema_version(env.clone(), schema_id.clone(), 1).unwrap();
    assert_eq!(v1.version, 1);
    assert_eq!(v1.required_fields.len(), 1);
}

// =========================================================================
// Test 18: Schema deactivation (#60)
// =========================================================================

#[test]
fn test_schema_deactivation() {
    let env = setup_env();
    let admin = new_address(&env);
    let schema_id = Bytes::from_slice(&env, b"deact_schema");

    let _ = CredentialSchema::register_schema(
        env.clone(),
        admin.clone(),
        schema_id.clone(),
        Bytes::from_slice(&env, b"TestSchema"),
        Vec::new(&env),
        Vec::new(&env),
        Map::new(&env),
    );

    let result = CredentialSchema::deactivate_schema(env.clone(), admin, schema_id.clone());
    assert!(result.is_ok());

    let schema = CredentialSchema::get_schema(env.clone(), schema_id).unwrap();
    assert!(!schema.active);
}

// =========================================================================
// Test 19: Schema unauthorized versioning (#60)
// =========================================================================

#[test]
fn test_schema_unauthorized_versioning() {
    let env = setup_env();
    let admin = new_address(&env);
    let other = new_address(&env);
    let schema_id = Bytes::from_slice(&env, b"auth_schema");

    let _ = CredentialSchema::register_schema(
        env.clone(),
        admin.clone(),
        schema_id.clone(),
        Bytes::from_slice(&env, b"TestSchema"),
        Vec::new(&env),
        Vec::new(&env),
        Map::new(&env),
    );

    let result = CredentialSchema::register_schema_version(
        env.clone(),
        other,
        schema_id,
        Vec::new(&env),
        Vec::new(&env),
        Map::new(&env),
    );
    assert!(result.is_err());
}

// =========================================================================
// Test 20: Credential status packed as u8 (#58)
// =========================================================================

#[test]
fn test_credential_status_packing() {
    let env = setup_env();
    let issuer = new_address(&env);
    let subject = new_address(&env);

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        subject.clone(),
        vec![&env, Bytes::from_slice(&env, b"Test")],
        Bytes::from_slice(&env, b"data"),
        None,
        Bytes::from_slice(&env, b"proof"),
    )
    .unwrap();

    // Status should be "active"
    let status = CredentialIssuer::get_credential_status(env.clone(), cred_id.clone());
    assert_eq!(status, Bytes::from_slice(&env, b"active"));

    // After revocation, should be "revoked"
    let _ = CredentialIssuer::revoke_credential(env.clone(), issuer, cred_id.clone(), None);
    let status = CredentialIssuer::get_credential_status(env.clone(), cred_id);
    assert_eq!(status, Bytes::from_slice(&env, b"revoked"));

    // Unknown credential
    let status = CredentialIssuer::get_credential_status(
        env.clone(),
        Bytes::from_slice(&env, b"nonexistent"),
    );
    assert_eq!(status, Bytes::from_slice(&env, b"unknown"));
}

// =========================================================================
// Test 21: Paginated issuer credentials (#56)
// =========================================================================

#[test]
fn test_paginated_issuer_credentials() {
    let env = setup_env();
    let issuer = new_address(&env);

    for i in 0..12u32 {
        let subject = new_address(&env);
        let _ = CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject,
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Bytes::from_slice(&env, b"proof"),
        );
    }

    let page0 = CredentialIssuer::get_credentials_by_issuer(env.clone(), issuer.clone(), 0, 5);
    assert_eq!(page0.data.len(), 5);
    assert_eq!(page0.total, 12);
    assert!(page0.has_more);

    let page2 = CredentialIssuer::get_credentials_by_issuer(env.clone(), issuer, 2, 5);
    assert_eq!(page2.data.len(), 2);
    assert!(!page2.has_more);
}

// =========================================================================
// Test 22: Field validation - StringLength (#60)
// =========================================================================

#[test]
fn test_field_validation_string_length() {
    let env = setup_env();
    let admin = new_address(&env);
    let schema_id = Bytes::from_slice(&env, b"strlen_schema");

    let mut validations: Map<Bytes, FieldValidation> = Map::new(&env);
    validations.set(
        Bytes::from_slice(&env, b"name"),
        FieldValidation::StringLength(5),
    );

    let _ = CredentialSchema::register_schema(
        env.clone(),
        admin,
        schema_id.clone(),
        Bytes::from_slice(&env, b"Test"),
        vec![&env, Bytes::from_slice(&env, b"name")],
        Vec::new(&env),
        validations,
    );

    // Schema exists and is active
    let schema = CredentialSchema::get_schema(env.clone(), schema_id);
    assert!(schema.is_some());
    assert!(schema.unwrap().active);
}

// =========================================================================
// Test 23: List schemas (#60)
// =========================================================================

#[test]
fn test_list_schemas() {
    let env = setup_env();
    let admin = new_address(&env);

    for name in [b"schema_a", b"schema_b", b"schema_c"] {
        let _ = CredentialSchema::register_schema(
            env.clone(),
            admin.clone(),
            Bytes::from_slice(&env, name),
            Bytes::from_slice(&env, b"Type"),
            Vec::new(&env),
            Vec::new(&env),
            Map::new(&env),
        );
    }

    let schemas = CredentialSchema::list_schemas(env.clone());
    assert_eq!(schemas.len(), 3);
}
