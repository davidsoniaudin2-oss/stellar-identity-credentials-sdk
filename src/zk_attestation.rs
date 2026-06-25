use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, Env, Map, Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedCircuits};

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum ZkKey {
    Circuit(Symbol),
    Proof(Bytes),
    Nullifier(Bytes),
    CircuitProofs(Symbol),
    Attestation(Bytes),
    ActiveCircuits,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ZKAttestationError {
    InvalidProof = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidCircuit = 4,
    VerificationFailed = 5,
    Expired = 6,
    NullifierAlreadyUsed = 7,
    InvalidPublicInputs = 8,
    CircuitDeactivated = 9,
    RevokedCredential = 10,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ZKProof {
    pub proof_id: Bytes,
    pub circuit_id: Symbol,
    pub public_inputs: Vec<Bytes>,
    pub proof_bytes: Bytes,
    pub verifying_key_hash: Bytes,
    pub nullifier: Bytes,
    pub verifier_address: Address,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub metadata: Map<Symbol, Bytes>,
    pub revealed_attributes: Vec<Symbol>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ZKCircuit {
    pub circuit_id: Symbol,
    pub name: Bytes,
    pub description: Bytes,
    pub verifier_key: Bytes,
    pub verifying_key_hash: Bytes,
    pub public_input_count: u32,
    pub private_input_count: u32,
    pub created_by: Address,
    pub created_at: u64,
    pub active: bool,
    pub circuit_type: CircuitType,
    pub supported_attributes: Vec<Symbol>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum CircuitType {
    RangeProof,
    SetMembership,
    CredentialOwnership,
    CompositeProof,
    EqualityProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ZKAttestationRecord {
    pub credential_id: Bytes,
    pub proof_hash: Bytes,
    pub nullifier: Bytes,
    pub revealed_attributes: Vec<Symbol>,
    pub circuit_id: Symbol,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct NullifierRecord {
    pub nullifier: Bytes,
    pub used_at: u64,
    pub context: Bytes,
    pub proof_id: Bytes,
}

#[contract]
pub struct ZKAttestationContract;

#[contractimpl]
impl ZKAttestation {
    pub fn register_circuit(
        env: Env,
        circuit_id: Symbol,
        name: Bytes,
        description: Bytes,
        verifier_key: Bytes,
        public_input_count: u32,
        private_input_count: u32,
        circuit_type: CircuitType,
        supported_attributes: Vec<Symbol>,
    ) -> Result<(), ZKAttestationError> {
        let creator = env.current_contract_address();

        if env
            .storage()
            .persistent()
            .has(&ZkKey::Circuit(circuit_id.clone()))
        {
            return Err(ZKAttestationError::InvalidCircuit);
        }

        let verifying_key_hash = Self::hash_verifying_key(&env, &verifier_key);

        let circuit = ZKCircuit {
            circuit_id: circuit_id.clone(),
            name,
            description,
            verifier_key,
            verifying_key_hash,
            public_input_count,
            private_input_count,
            created_by: creator,
            created_at: env.ledger().timestamp(),
            active: true,
            circuit_type,
            supported_attributes,
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Circuit(circuit_id.clone()), &circuit);

        let mut active: Vec<Symbol> = env
            .storage()
            .persistent()
            .get(&ZkKey::ActiveCircuits)
            .unwrap_or_else(|| Vec::new(&env));
        active.push_back(circuit_id);
        env.storage()
            .persistent()
            .set(&ZkKey::ActiveCircuits, &active);

        Ok(())
    }

    pub fn submit_proof(
        env: Env,
        circuit_id: Symbol,
        public_inputs: Vec<Bytes>,
        proof_bytes: Bytes,
        nullifier: Bytes,
        revealed_attributes: Vec<Symbol>,
        expires_at: Option<u64>,
        metadata: Map<Symbol, Bytes>,
    ) -> Result<Bytes, ZKAttestationError> {
        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        if !circuit.active {
            return Err(ZKAttestationError::CircuitDeactivated);
        }

        if public_inputs.len() != circuit.public_input_count {
            return Err(ZKAttestationError::InvalidPublicInputs);
        }

        if env
            .storage()
            .persistent()
            .has(&ZkKey::Nullifier(nullifier.clone()))
        {
            return Err(ZKAttestationError::NullifierAlreadyUsed);
        }

        let proof_id = Self::generate_proof_id(&env, &circuit_id);

        let is_valid =
            Self::verify_zk_proof(&env, &circuit.verifier_key, &public_inputs, &proof_bytes)?;

        if !is_valid {
            return Err(ZKAttestationError::VerificationFailed);
        }

        let nullifier_record = NullifierRecord {
            nullifier: nullifier.clone(),
            used_at: env.ledger().timestamp(),
            context: metadata
                .get(Symbol::new(&env, "context"))
                .unwrap_or_else(|| Bytes::from_slice(&env, b"default")),
            proof_id: proof_id.clone(),
        };
        env.storage()
            .persistent()
            .set(&ZkKey::Nullifier(nullifier.clone()), &nullifier_record);

        let proof = ZKProof {
            proof_id: proof_id.clone(),
            circuit_id: circuit_id.clone(),
            public_inputs: public_inputs.clone(),
            proof_bytes: proof_bytes.clone(),
            verifying_key_hash: circuit.verifying_key_hash.clone(),
            nullifier: nullifier.clone(),
            verifier_address: env.current_contract_address(),
            created_at: env.ledger().timestamp(),
            expires_at,
            metadata,
            revealed_attributes: revealed_attributes.clone(),
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Proof(proof_id.clone()), &proof);

        let mut circuit_proofs: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&ZkKey::CircuitProofs(circuit_id.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        circuit_proofs.push_back(proof_id.clone());
        env.storage()
            .persistent()
            .set(&ZkKey::CircuitProofs(circuit_id.clone()), &circuit_proofs);

        let attestation = ZKAttestationRecord {
            credential_id: Bytes::from_slice(&env, b"unknown"),
            proof_hash: Self::hash_proof(&env, &proof_bytes),
            nullifier,
            revealed_attributes,
            circuit_id,
            created_at: env.ledger().timestamp(),
            expires_at,
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Attestation(proof_id.clone()), &attestation);

        Ok(proof_id)
    }

    pub fn verify_proof(env: Env, proof_id: Bytes) -> Result<bool, ZKAttestationError> {
        let proof: ZKProof = env
            .storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id))
            .ok_or(ZKAttestationError::NotFound)?;

        if let Some(expires_at) = proof.expires_at {
            if env.ledger().timestamp() > expires_at {
                return Ok(false);
            }
        }

        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(proof.circuit_id))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        Self::verify_zk_proof(
            &env,
            &circuit.verifier_key,
            &proof.public_inputs,
            &proof.proof_bytes,
        )
    }

    pub fn get_proof(env: Env, proof_id: Bytes) -> Result<ZKProof, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id))
            .ok_or(ZKAttestationError::NotFound)
    }

    pub fn get_circuit(env: Env, circuit_id: Symbol) -> Result<ZKCircuit, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id))
            .ok_or(ZKAttestationError::InvalidCircuit)
    }

    pub fn get_circuit_proofs(env: Env, circuit_id: Symbol) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&ZkKey::CircuitProofs(circuit_id))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Paginated list of registered circuits (#56).
    pub fn get_registered_circuits(
        env: Env,
        page: u32,
        page_size: u32,
    ) -> PaginatedCircuits {
        let all: Vec<Symbol> = env
            .storage()
            .persistent()
            .get(&ZkKey::ActiveCircuits)
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = all.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(item) = all.get(i) {
                    data.push_back(item);
                }
            }
        }

        PaginatedCircuits {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }

    pub fn get_active_circuits(env: Env) -> Vec<Symbol> {
        env.storage()
            .persistent()
            .get(&ZkKey::ActiveCircuits)
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn deactivate_circuit(env: Env, circuit_id: Symbol) -> Result<(), ZKAttestationError> {
        let mut circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        let creator = env.current_contract_address();
        if circuit.created_by != creator {
            return Err(ZKAttestationError::Unauthorized);
        }

        circuit.active = false;
        env.storage()
            .persistent()
            .set(&ZkKey::Circuit(circuit_id), &circuit);

        Ok(())
    }

    pub fn reactivate_circuit(env: Env, circuit_id: Symbol) -> Result<(), ZKAttestationError> {
        let mut circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        let creator = env.current_contract_address();
        if circuit.created_by != creator {
            return Err(ZKAttestationError::Unauthorized);
        }

        circuit.active = true;
        env.storage()
            .persistent()
            .set(&ZkKey::Circuit(circuit_id), &circuit);

        Ok(())
    }

    pub fn batch_verify_proofs(env: Env, proof_ids: Vec<Bytes>) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for proof_id in proof_ids.iter() {
            let is_valid = Self::verify_proof(env.clone(), proof_id.clone()).unwrap_or(false);
            results.push_back(is_valid);
        }
        results
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn generate_proof_id(env: &Env, _circuit_id: &Symbol) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"zk:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, env.ledger().sequence().to_string().as_bytes()));
        id
    }

    fn verify_zk_proof(
        _env: &Env,
        verifier_key: &Bytes,
        _public_inputs: &Vec<Bytes>,
        proof_bytes: &Bytes,
    ) -> Result<bool, ZKAttestationError> {
        if proof_bytes.is_empty() {
            return Err(ZKAttestationError::InvalidProof);
        }
        if verifier_key.is_empty() {
            return Err(ZKAttestationError::InvalidCircuit);
        }
        Ok(true)
    }

    fn hash_verifying_key(env: &Env, verifier_key: &Bytes) -> Bytes {
        let hash = env.crypto().sha256(verifier_key);
        let hash_bytes: BytesN<32> = hash.into();
        Bytes::from_slice(env, hash_bytes.to_array().as_slice())
    }

    fn hash_proof(env: &Env, proof_bytes: &Bytes) -> Bytes {
        let hash = env.crypto().sha256(proof_bytes);
        let hash_bytes: BytesN<32> = hash.into();
        Bytes::from_slice(env, hash_bytes.to_array().as_slice())
    }

    fn compute_nullifier(
        env: &Env,
        credential_id: &Bytes,
        _circuit_id: &Symbol,
        context: &Bytes,
    ) -> Bytes {
        let mut data = credential_id.clone();
        data.append(context);
        let hash = env.crypto().sha256(&data);
        let hash_bytes: BytesN<32> = hash.into();
        Bytes::from_slice(env, hash_bytes.to_array().as_slice())
    }
}
