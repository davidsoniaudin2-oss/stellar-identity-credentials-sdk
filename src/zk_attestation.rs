use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, Env, Map, Symbol, Vec,
};

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
impl ZKAttestationContract {
    /// Register a new ZK circuit
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

        // Check if circuit already exists
        if env.storage().persistent().has(&circuit_id) {
            return Err(ZKAttestationError::InvalidCircuit);
        }

        // Generate verifying key hash
        let verifying_key_hash = Self::hash_verifying_key(&env, &verifier_key);

        let circuit = ZKCircuit {
            circuit_id: circuit_id.clone(),
            name: name.clone(),
            description: description.clone(),
            verifier_key: verifier_key.clone(),
            verifying_key_hash: verifying_key_hash.clone(),
            public_input_count,
            private_input_count,
            created_by: creator,
            created_at: env.ledger().timestamp(),
            active: true,
            circuit_type,
            supported_attributes: supported_attributes.clone(),
        };

        // Store circuit
        env.storage().persistent().set(&circuit_id, &circuit);

        // Add to active circuits index
        let active_circuits_key = Symbol::new(&env, "active_circuits");
        let mut active_circuits: Vec<Symbol> = env
            .storage()
            .persistent()
            .get(&active_circuits_key)
            .unwrap_or_else(|| Vec::new(&env));
        active_circuits.push_back(circuit_id.clone());
        env.storage()
            .persistent()
            .set(&active_circuits_key, &active_circuits);

        Ok(())
    }

    /// Submit a zero-knowledge proof for verification
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
        // Verify circuit exists and is active
        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&circuit_id)
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        if !circuit.active {
            return Err(ZKAttestationError::CircuitDeactivated);
        }

        // Validate public inputs count
        if public_inputs.len() != circuit.public_input_count {
            return Err(ZKAttestationError::InvalidPublicInputs);
        }

        // Check nullifier hasn't been used before
        let nullifier_key = symbol_short!("nul_used");
        if env.storage().persistent().has(&nullifier_key) {
            return Err(ZKAttestationError::NullifierAlreadyUsed);
        }

        // Generate proof ID
        let proof_id = Self::generate_proof_id(&env, &circuit_id);

        // Verify the zero-knowledge proof
        let is_valid =
            Self::verify_zk_proof(&env, &circuit.verifier_key, &public_inputs, &proof_bytes)?;

        if !is_valid {
            return Err(ZKAttestationError::VerificationFailed);
        }

        // Create nullifier record
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
            .set(&nullifier_key, &nullifier_record);

        // Create proof record
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

        // Store proof
        env.storage().persistent().set(&proof_id, &proof);

        // Store proof by circuit for lookup
        let circuit_proofs_key = symbol_short!("cirprfs");
        let mut circuit_proofs: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&circuit_proofs_key)
            .unwrap_or_else(|| Vec::new(&env));
        circuit_proofs.push_back(proof_id.clone());
        env.storage()
            .persistent()
            .set(&circuit_proofs_key, &circuit_proofs);

        // Create attestation record
        let attestation = ZKAttestationRecord {
            credential_id: proof.metadata
                .get(Symbol::new(&env, "credential_id"))
                .unwrap_or_else(|| Bytes::from_slice(&env, b"unknown")),
            proof_hash: Self::hash_proof(&env, &proof_bytes),
            nullifier: nullifier.clone(),
            revealed_attributes: revealed_attributes.clone(),
            circuit_id: circuit_id.clone(),
            created_at: env.ledger().timestamp(),
            expires_at,
        };

        let attestation_key = symbol_short!("attest");
        env.storage()
            .persistent()
            .set(&attestation_key, &attestation);

        Ok(proof_id)
    }

    /// Verify a submitted proof
    pub fn verify_proof(env: Env, proof_id: Bytes) -> Result<bool, ZKAttestationError> {
        let proof: ZKProof = env
            .storage()
            .persistent()
            .get(&proof_id)
            .ok_or(ZKAttestationError::NotFound)?;

        // Check expiration
        if let Some(expires_at) = proof.expires_at {
            if env.ledger().timestamp() > expires_at {
                return Ok(false);
            }
        }

        // Get circuit
        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&proof.circuit_id)
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        // Re-verify the proof
        Self::verify_zk_proof(
            &env,
            &circuit.verifier_key,
            &proof.public_inputs,
            &proof.proof_bytes,
        )
    }

    /// Get proof details
    pub fn get_proof(env: Env, proof_id: Bytes) -> Result<ZKProof, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&proof_id)
            .ok_or(ZKAttestationError::NotFound)
    }

    /// Get circuit details
    pub fn get_circuit(env: Env, circuit_id: Symbol) -> Result<ZKCircuit, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&circuit_id)
            .ok_or(ZKAttestationError::InvalidCircuit)
    }

    /// Get all proofs for a circuit
    pub fn get_circuit_proofs(env: Env, circuit_id: Symbol) -> Vec<Bytes> {
        let circuit_proofs_key = symbol_short!("cirprfs");
        env.storage()
            .persistent()
            .get(&circuit_proofs_key)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Deactivate a circuit
    pub fn deactivate_circuit(env: Env, circuit_id: Symbol) -> Result<(), ZKAttestationError> {
        let mut circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&circuit_id)
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        // Only circuit creator can deactivate (simplified authorization)
        let creator = env.current_contract_address();
        if circuit.created_by != creator {
            return Err(ZKAttestationError::Unauthorized);
        }

        circuit.active = false;
        env.storage().persistent().set(&circuit_id, &circuit);

        Ok(())
    }

    /// Reactivate a circuit
    pub fn reactivate_circuit(env: Env, circuit_id: Symbol) -> Result<(), ZKAttestationError> {
        let mut circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&circuit_id)
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        // Only circuit creator can reactivate
        let creator = env.current_contract_address();
        if circuit.created_by != creator {
            return Err(ZKAttestationError::Unauthorized);
        }

        circuit.active = true;
        env.storage().persistent().set(&circuit_id, &circuit);

        Ok(())
    }

    /// Generate proof ID
    fn generate_proof_id(env: &Env, _circuit_id: &Symbol) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let id_string = alloc::format!("zk:{}", timestamp);
        Bytes::from_slice(env, id_string.as_bytes())
    }

    /// Verify zero-knowledge proof (simplified implementation)
    /// In practice, this would integrate with a ZK verification library
    fn verify_zk_proof(
        env: &Env,
        verifier_key: &Bytes,
        public_inputs: &Vec<Bytes>,
        proof_bytes: &Bytes,
    ) -> Result<bool, ZKAttestationError> {
        // Simplified verification - in practice, this would:
        // 1. Parse the proof bytes according to the ZK system format
        // 2. Use the verifier key to verify the proof against public inputs
        // 3. Return true if proof is valid, false otherwise

        // For now, just check that proof is not empty and has reasonable format
        if proof_bytes.is_empty() {
            return Err(ZKAttestationError::InvalidProof);
        }

        // Check that verifier key is not empty
        if verifier_key.is_empty() {
            return Err(ZKAttestationError::InvalidCircuit);
        }

        // In a real implementation, you would use a ZK library like:
        // - bellman for Groth16 proofs
        // - arkworks for various proof systems
        // - circom for JavaScript verification
        // or integrate with native Soroban ZK capabilities when available

        Ok(true) // Simplified - always return true for demo
    }

    /// Hash verifying key for integrity verification
    fn hash_verifying_key(env: &Env, verifier_key: &Bytes) -> Bytes {
        let hash = env.crypto().sha256(verifier_key);
        Bytes::from_slice(env, hash.to_array().as_slice())
    }

    fn hash_proof(env: &Env, proof_bytes: &Bytes) -> Bytes {
        let hash = env.crypto().sha256(proof_bytes);
        Bytes::from_slice(env, hash.to_array().as_slice())
    }

    /// Generate nullifier for proof
    fn generate_nullifier(env: &Env, credential_id: &Bytes, context: &Bytes) -> Bytes {
        let mut combined = credential_id.clone();
        combined.append(context);
        let hash = env.crypto().sha256(&combined);
        Bytes::from_slice(env, hash.to_array().as_slice())
    }

    /// Get all active circuits
    pub fn get_active_circuits(env: Env) -> Vec<Symbol> {
        let active_circuits_key = Symbol::new(&env, "active_circuits");
        env.storage()
            .persistent()
            .get(&active_circuits_key)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Batch verify multiple proofs
    pub fn batch_verify_proofs(env: Env, proof_ids: Vec<Bytes>) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for proof_id in proof_ids.iter() {
            let is_valid = Self::verify_proof(env.clone(), proof_id.clone()).unwrap_or(false);
            results.push_back(is_valid);
        }
        results
    }

    pub fn create_age_proof(
        env: Env,
        circuit_id: Symbol,
        commitment: Bytes,
        min_age: u32,
        proof_bytes: Bytes,
    ) -> Result<Bytes, ZKAttestationError> {
        let mut public_inputs = Vec::new(&env);
        public_inputs.push_back(commitment);
        let age_str = alloc::format!("{}", min_age);
        public_inputs.push_back(Bytes::from_slice(&env, age_str.as_bytes()));

        let nullifier = Bytes::from_slice(&env, b"age_proof_nullifier");
        let revealed = Vec::new(&env);
        let metadata = Map::new(&env);
        Self::submit_proof(
            env,
            circuit_id,
            public_inputs,
            proof_bytes,
            nullifier,
            revealed,
            None,
            metadata,
        )
    }

    pub fn verify_age_proof(
        env: Env,
        proof_id: Bytes,
        _min_age: u32,
    ) -> Result<bool, ZKAttestationError> {
        Self::verify_proof(env, proof_id)
    }
}
