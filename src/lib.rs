extern crate alloc;

pub mod did_registry;
pub mod credential_issuer;
pub mod credential_schema;
pub mod reputation_score;
pub mod zk_attestation;
pub mod compliance_filter;
pub mod storage_optimization;
pub mod gas_benchmark;

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod fuzz_test_script;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec};

pub use did_registry::DIDRegistry;
pub use credential_issuer::CredentialIssuer;
pub use credential_schema::CredentialSchema;
pub use reputation_score::ReputationScore;
pub use zk_attestation::ZKAttestation;
pub use zk_attestation::ZKAttestationRecord;
pub use compliance_filter::ComplianceFilter;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct DIDDocument {
    pub id: Bytes,
    pub controller: Address,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<Bytes>,
    pub service: Vec<Service>,
    pub created: u64,
    pub updated: u64,
    pub deactivated: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct VerificationMethod {
    pub id: Bytes,
    pub type_: Bytes,
    pub controller: Address,
    pub public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub struct Service {
    pub id: Bytes,
    pub type_: Bytes,
    pub endpoint: Bytes,
}

#[contracttype]
#[derive(Clone)]
pub struct VerifiableCredential {
    pub id: Bytes,
    pub issuer: Address,
    pub subject: Address,
    pub type_: Vec<Bytes>,
    pub credential_data: Bytes,
    pub issuance_date: u64,
    pub expiration_date: Option<u64>,
    pub schema_id: Option<Bytes>,
    pub revocation: Option<Bytes>,
    pub proof: Option<Bytes>,
}

// ---------------------------------------------------------------------------
// Pagination (#56)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedCredentials {
    pub data: Vec<Bytes>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedAddresses {
    pub data: Vec<Address>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedCircuits {
    pub data: Vec<Symbol>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedReputationHistory {
    pub data: Vec<reputation_score::ReputationHistoryEntry>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

pub const DEFAULT_PAGE_SIZE: u32 = 10;
pub const MAX_PAGE_SIZE: u32 = 50;

pub fn clamp_page_size(page_size: u32) -> u32 {
    if page_size == 0 {
        DEFAULT_PAGE_SIZE
    } else if page_size > MAX_PAGE_SIZE {
        MAX_PAGE_SIZE
    } else {
        page_size
    }
}

// ---------------------------------------------------------------------------
// Storage key namespacing (#58) — avoids collisions across contracts
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum StorageKey {
    DidRegistry,
    CredentialIssuer,
    ReputationScore,
    ZkAttestation,
    ComplianceFilter,
}

#[contract]
pub struct StellarIdentity;

#[contractimpl]
impl StellarIdentity {
    pub fn initialize(
        env: Env,
        did_registry_address: Address,
        credential_issuer_address: Address,
        reputation_score_address: Address,
        zk_attestation_address: Address,
        compliance_filter_address: Address,
    ) {
        env.storage().instance().set(&StorageKey::DidRegistry, &did_registry_address);
        env.storage().instance().set(&StorageKey::CredentialIssuer, &credential_issuer_address);
        env.storage().instance().set(&StorageKey::ReputationScore, &reputation_score_address);
        env.storage().instance().set(&StorageKey::ZkAttestation, &zk_attestation_address);
        env.storage().instance().set(&StorageKey::ComplianceFilter, &compliance_filter_address);
    }

    pub fn get_did_registry_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::DidRegistry)
    }

    pub fn get_credential_issuer_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::CredentialIssuer)
    }

    pub fn get_reputation_score_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::ReputationScore)
    }

    pub fn get_zk_attestation_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::ZkAttestation)
    }

    pub fn get_compliance_filter_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::ComplianceFilter)
    }
}
