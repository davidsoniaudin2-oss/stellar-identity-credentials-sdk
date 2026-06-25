use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, Address, Bytes, Env, Map, Symbol, Vec,
};
use sha2::{Digest, Sha256};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PrivacyError {
    InvalidNullifier = 1,
    RevokedCredential = 2,
    InsufficientPrivacy = 3,
    DoubleSpending = 4,
    InvalidCommitment = 5,
    ContextMismatch = 6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PrivacyConfig {
    pub min_anonymity_set_size: u32,
    pub nullifier_lifetime: u64,
    pub revocation_check_interval: u64,
    pub selective_disclosure_required: bool,
    pub zero_knowledge_verification: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct NullifierState {
    pub nullifier: Bytes,
    pub context: Bytes,
    pub created_at: u64,
    pub expires_at: u64,
    pub usage_count: u32,
    pub credential_commitment: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct RevocationProof {
    pub credential_commitment: Bytes,
    pub revocation_hash: Bytes,
    pub proof_valid_until: u64,
    pub anonymity_set_hash: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct SelectiveDisclosure {
    pub credential_id: Bytes,
    pub revealed_attributes: Vec<Symbol>,
    pub hidden_attributes: Vec<Symbol>,
    pub disclosure_hash: Bytes,
    pub validity_proof: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PrivacyAttestation {
    pub credential_commitment: Bytes,
    pub privacy_level: u8, // 1-5, where 5 is maximum privacy
    pub anonymity_set_size: u32,
    pub revocation_status: bool,
    pub last_verified: u64,
    pub metadata: Map<Symbol, Bytes>,
}

#[contract]
pub struct PrivacyFeatures;

#[contractimpl]
impl PrivacyFeatures {
    /// Initialize privacy configuration
    pub fn initialize_privacy_config(
        env: Env,
        min_anonymity_set_size: u32,
        nullifier_lifetime: u64,
        revocation_check_interval: u64,
        selective_disclosure_required: bool,
        zero_knowledge_verification: bool,
    ) {
        let config = PrivacyConfig {
            min_anonymity_set_size,
            nullifier_lifetime,
            revocation_check_interval,
            selective_disclosure_required,
            zero_knowledge_verification,
        };

        log!(&env, "TRACE: initialize_privacy_config - Configured privacy settings");
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "privacy_config"), &config);
    }

    /// Generate nullifier for privacy-preserving identification
    pub fn generate_nullifier(
        env: Env,
        credential_commitment: Bytes,
        context: Bytes,
        user_secret: Bytes,
        expires_at: u64,
    ) -> Result<Bytes, PrivacyError> {
        // Check privacy configuration
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400, // 24 hours
                revocation_check_interval: 3600, // 1 hour
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        // Generate nullifier using cryptographic hash
        let mut hasher = Sha256::new();
        hasher.update(credential_commitment.to_array().as_slice());
        hasher.update(context.to_array().as_slice());
        hasher.update(user_secret.to_array().as_slice());
        hasher.update(env.ledger().timestamp().to_be_bytes());
        let nullifier_bytes = hasher.finalize();
        let nullifier = Bytes::from_slice(&env, &nullifier_bytes);

        // Check if nullifier already exists (prevent double-spending)
        let nullifier_key = Symbol::new(&env, &format!("nullifier:{}", nullifier.to_string()));
        if env.storage().persistent().has(&nullifier_key) {
            log!(&env, "ERROR: generate_nullifier - Double spending attempt detected");
            return Err(PrivacyError::DoubleSpending);
        }

        log!(&env, "TRACE: generate_nullifier - Nullifier successfully generated and checked");
        // Store nullifier state
        let nullifier_state = NullifierState {
            nullifier: nullifier.clone(),
            context: context.clone(),
            created_at: env.ledger().timestamp(),
            expires_at,
            usage_count: 1,
            credential_commitment: credential_commitment.clone(),
        };

        env.storage()
            .persistent()
            .set(&nullifier_key, &nullifier_state);

        // Set expiration
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, &format!("expires:{}", nullifier.to_string())), &expires_at);

        Ok(nullifier)
    }

    /// Verify nullifier is valid and not expired
    pub fn verify_nullifier(env: Env, nullifier: Bytes, context: Bytes) -> Result<bool, PrivacyError> {
        let nullifier_key = Symbol::new(&env, &format!("nullifier:{}", nullifier.to_string()));
        
        let nullifier_state: NullifierState = env
            .storage()
            .persistent()
            .get(&nullifier_key)
            .ok_or(PrivacyError::InvalidNullifier)?;

        // Check context matches
        if nullifier_state.context != context {
            log!(&env, "ERROR: verify_nullifier - Context mismatch");
            return Err(PrivacyError::ContextMismatch);
        }

        // Check expiration
        if env.ledger().timestamp() > nullifier_state.expires_at {
            log!(&env, "ERROR: verify_nullifier - Nullifier expired");
            return Err(PrivacyError::InvalidNullifier);
        }

        // Check usage limits
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if nullifier_state.usage_count > 3 {
            return Err(PrivacyError::DoubleSpending);
        }

        // Increment usage count
        let mut updated_state = nullifier_state;
        updated_state.usage_count += 1;
        env.storage()
            .persistent()
            .set(&nullifier_key, &updated_state);

        Ok(true)
    }

    /// Create revocation-proof credential verification
    pub fn create_revocation_proof(
        env: Env,
        credential_commitment: Bytes,
        revocation_list_root: Bytes,
        anonymity_set: Vec<Bytes>,
        proof_valid_until: u64,
    ) -> Result<RevocationProof, PrivacyError> {
        // Check minimum anonymity set size
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if anonymity_set.len() < config.min_anonymity_set_size as usize {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        // Generate revocation hash (simplified - in practice would use ZK proof)
        let mut hasher = Sha256::new();
        hasher.update(credential_commitment.to_array().as_slice());
        hasher.update(revocation_list_root.to_array().as_slice());
        
        for commitment in anonymity_set.iter() {
            hasher.update(commitment.to_array().as_slice());
        }
        
        let revocation_hash_bytes = hasher.finalize();
        let revocation_hash = Bytes::from_slice(&env, &revocation_hash_bytes);

        // Generate anonymity set hash
        let mut set_hasher = Sha256::new();
        for commitment in anonymity_set.iter() {
            set_hasher.update(commitment.to_array().as_slice());
        }
        let anonymity_set_hash_bytes = set_hasher.finalize();
        let anonymity_set_hash = Bytes::from_slice(&env, &anonymity_set_hash_bytes);

        let revocation_proof = RevocationProof {
            credential_commitment,
            revocation_hash,
            proof_valid_until,
            anonymity_set_hash,
        };

        // Store revocation proof
        let proof_key = Symbol::new(&env, &format!("rev_proof:{}", revocation_hash.to_string()));
        env.storage()
            .persistent()
            .set(&proof_key, &revocation_proof);

        Ok(revocation_proof)
    }

    /// Verify credential is not revoked using revocation proof
    pub fn verify_revocation_proof(
        env: Env,
        credential_commitment: Bytes,
        revocation_proof: RevocationProof,
        current_revocation_root: Bytes,
    ) -> Result<bool, PrivacyError> {
        // Check proof validity period
        if env.ledger().timestamp() > revocation_proof.proof_valid_until {
            return Err(PrivacyError::RevokedCredential);
        }

        // Verify credential commitment matches
        if revocation_proof.credential_commitment != credential_commitment {
            return Err(PrivacyError::InvalidCommitment);
        }

        // In a real implementation, this would verify the ZK proof
        // For now, we'll simulate verification by checking the hash
        let mut hasher = Sha256::new();
        hasher.update(credential_commitment.to_array().as_slice());
        hasher.update(current_revocation_root.to_array().as_slice());
        hasher.update(revocation_proof.anonymity_set_hash.to_array().as_slice());
        
        let expected_hash_bytes = hasher.finalize();
        let expected_hash = Bytes::from_slice(&env, &expected_hash_bytes);

        Ok(expected_hash == revocation_proof.revocation_hash)
    }

    /// Create selective disclosure proof
    pub fn create_selective_disclosure(
        env: Env,
        credential_id: Bytes,
        all_attributes: Map<Symbol, Bytes>,
        revealed_attributes: Vec<Symbol>,
        validity_proof: Bytes,
    ) -> Result<SelectiveDisclosure, PrivacyError> {
        // Validate selective disclosure requirement
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if config.selective_disclosure_required && revealed_attributes.is_empty() {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        // Determine hidden attributes
        let mut hidden_attributes = Vec::new(&env);
        for (attr_name, _) in all_attributes.iter() {
            let is_revealed = revealed_attributes.iter().any(|revealed| revealed == attr_name);
            if !is_revealed {
                hidden_attributes.push_back(attr_name);
            }
        }

        // Generate disclosure hash
        let mut hasher = Sha256::new();
        hasher.update(credential_id.to_array().as_slice());
        
        // Hash revealed attributes
        for attr_name in revealed_attributes.iter() {
            if let Some(attr_value) = all_attributes.get(attr_name) {
                hasher.update(attr_name.to_string().as_bytes());
                hasher.update(attr_value.to_array().as_slice());
            }
        }
        
        // Hash hidden attribute names only (not values)
        for attr_name in hidden_attributes.iter() {
            hasher.update(attr_name.to_string().as_bytes());
        }
        
        let disclosure_hash_bytes = hasher.finalize();
        let disclosure_hash = Bytes::from_slice(&env, &disclosure_hash_bytes);

        let selective_disclosure = SelectiveDisclosure {
            credential_id,
            revealed_attributes: revealed_attributes.clone(),
            hidden_attributes,
            disclosure_hash,
            validity_proof,
        };

        // Store selective disclosure
        let disclosure_key = Symbol::new(&env, &format!("disclosure:{}", disclosure_hash.to_string()));
        env.storage()
            .persistent()
            .set(&disclosure_key, &selective_disclosure);

        Ok(selective_disclosure)
    }

    /// Verify selective disclosure proof
    pub fn verify_selective_disclosure(
        env: Env,
        credential_id: Bytes,
        selective_disclosure: SelectiveDisclosure,
        all_attributes: Map<Symbol, Bytes>,
    ) -> Result<bool, PrivacyError> {
        // Verify credential ID matches
        if selective_disclosure.credential_id != credential_id {
            return Err(PrivacyError::InvalidCommitment);
        }

        // Re-compute disclosure hash
        let mut hasher = Sha256::new();
        hasher.update(credential_id.to_array().as_slice());
        
        // Hash revealed attributes
        for attr_name in selective_disclosure.revealed_attributes.iter() {
            if let Some(attr_value) = all_attributes.get(attr_name) {
                hasher.update(attr_name.to_string().as_bytes());
                hasher.update(attr_value.to_array().as_slice());
            }
        }
        
        // Hash hidden attribute names only
        for attr_name in selective_disclosure.hidden_attributes.iter() {
            hasher.update(attr_name.to_string().as_bytes());
        }
        
        let expected_hash_bytes = hasher.finalize();
        let expected_hash = Bytes::from_slice(&env, &expected_hash_bytes);

        Ok(expected_hash == selective_disclosure.disclosure_hash)
    }

    /// Create privacy attestation
    pub fn create_privacy_attestation(
        env: Env,
        credential_commitment: Bytes,
        privacy_level: u8,
        anonymity_set_size: u32,
        metadata: Map<Symbol, Bytes>,
    ) -> Result<PrivacyAttestation, PrivacyError> {
        // Validate privacy level
        if privacy_level < 1 || privacy_level > 5 {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        // Check minimum anonymity set size
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if anonymity_set_size < config.min_anonymity_set_size {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        let attestation = PrivacyAttestation {
            credential_commitment: credential_commitment.clone(),
            privacy_level,
            anonymity_set_size,
            revocation_status: false, // Assume not revoked initially
            last_verified: env.ledger().timestamp(),
            metadata: metadata.clone(),
        };

        // Store privacy attestation
        let attestation_key = Symbol::new(&env, &format!("privacy_attest:{}", credential_commitment.to_string()));
        env.storage()
            .persistent()
            .set(&attestation_key, &attestation);

        Ok(attestation)
    }

    /// Update revocation status for privacy attestation
    pub fn update_revocation_status(
        env: Env,
        credential_commitment: Bytes,
        is_revoked: bool,
    ) -> Result<(), PrivacyError> {
        let attestation_key = Symbol::new(&env, &format!("privacy_attest:{}", credential_commitment.to_string()));
        let mut attestation: PrivacyAttestation = env
            .storage()
            .persistent()
            .get(&attestation_key)
            .ok_or(PrivacyError::InvalidCommitment)?;

        attestation.revocation_status = is_revoked;
        attestation.last_verified = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&attestation_key, &attestation);

        Ok(())
    }

    /// Get privacy configuration
    pub fn get_privacy_config(env: Env) -> PrivacyConfig {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            })
    }

    /// Clean up expired nullifiers
    pub fn cleanup_expired_nullifiers(env: Env) -> Result<u32, PrivacyError> {
        let current_time = env.ledger().timestamp();
        let mut cleaned_count = 0;

        // This is a simplified cleanup - in practice would need more sophisticated iteration
        let config = Self::get_privacy_config(env.clone());
        
        // For demo purposes, we'll just return 0
        // In a real implementation, would iterate through nullifier keys and remove expired ones
        
        Ok(cleaned_count)
    }

    /// Get privacy metrics
    pub fn get_privacy_metrics(env: Env) -> Map<Symbol, Bytes> {
        let mut metrics = Map::new(&env);
        
        // Get current timestamp
        let current_time = env.ledger().timestamp();
        metrics.set(
            Symbol::new(&env, "current_time"),
            Bytes::from_slice(&env, &current_time.to_be_bytes()),
        );

        // Get privacy config
        let config = Self::get_privacy_config(env.clone());
        metrics.set(
            Symbol::new(&env, "min_anonymity_set_size"),
            Bytes::from_slice(&env, &config.min_anonymity_set_size.to_be_bytes()),
        );
        metrics.set(
            Symbol::new(&env, "nullifier_lifetime"),
            Bytes::from_slice(&env, &config.nullifier_lifetime.to_be_bytes()),
        );

        metrics
    }
}
