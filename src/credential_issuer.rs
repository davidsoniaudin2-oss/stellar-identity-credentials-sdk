use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedCredentials, VerifiableCredential};

// ---------------------------------------------------------------------------
// Delegated Credential Issuance Types (#92)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct DelegationAuthorization {
    pub id: Bytes,
    pub delegator: Address,
    pub delegate: Address,
    pub authorized_types: Vec<Bytes>,
    pub max_issuances: u32,
    pub issued_count: u32,
    pub expires_at: u64,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct DelegationChainEntry {
    pub delegator: Address,
    pub delegate: Address,
    pub authorized_types: Vec<Bytes>,
    pub timestamp: u64,
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Revocation Registry Types (#91)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct RevocationRegistryEntry {
    pub id: Bytes,
    pub issuer: Address,
    pub credential_ids: Vec<Bytes>,
    pub nonce: Bytes,
    pub created: u64,
    pub revoked_count: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RevocationProof {
    pub registry_id: Bytes,
    pub credential_id: Bytes,
    pub nonce: Bytes,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchRevocationRecord {
    pub batch_id: Bytes,
    pub issuer: Address,
    pub credential_ids: Vec<Bytes>,
    pub reason: Option<Bytes>,
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum CredKey {
    Credential(Bytes),
    Status(Bytes),
    Reason(Bytes),
    IssuerCreds(Address),
    SubjectCreds(Address),
    Schema(Bytes),
    Delegation(Bytes),
    DelegateAuths(Address),
    DelegatorAuths(Address),
    RevocationRegistry(Bytes),
    RevocationProof(Bytes),
    BatchRevocation(Bytes),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum CredentialIssuerError {
    Unauthorized = 1,
    NotFound = 2,
    InvalidCredential = 3,
    AlreadyRevoked = 4,
    Expired = 5,
    InvalidSignature = 6,
    InvalidIssuer = 7,
    SchemaValidationFailed = 8,
    SchemaNotFound = 9,
    DelegationNotFound = 10,
    DelegationExpired = 11,
    DelegationLimitExceeded = 12,
    UnauthorizedCredentialType = 13,
    DelegationRevoked = 14,
    RegistryNotFound = 15,
    InvalidNonce = 16,
}

#[contract]
pub struct CredentialIssuer;

#[contractimpl]
impl CredentialIssuer {
    const MAX_CREDENTIAL_TYPE_LENGTH: u32 = 128;
    const MAX_CREDENTIAL_DATA_LENGTH: u32 = 10240;

    pub fn issue_credential(
        env: Env,
        issuer: Address,
        subject: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        if credential_type.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        for ct in credential_type.iter() {
            if ct.len() > Self::MAX_CREDENTIAL_TYPE_LENGTH {
                return Err(CredentialIssuerError::InvalidCredential);
            }
        }
        if credential_data.is_empty() || credential_data.len() > Self::MAX_CREDENTIAL_DATA_LENGTH {
            return Err(CredentialIssuerError::InvalidCredential);
        }

        let credential_id = Self::generate_credential_id(&env, &issuer, &subject);
        let now = env.ledger().timestamp();

        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            type_: credential_type,
            credential_data,
            issuance_date: now,
            expiration_date,
            schema_id: None,
            revocation: None,
            proof: Some(proof),
        };

        Self::validate_credential(&env, &credential)?;

        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);

        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &0u32);

        let mut issuer_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::IssuerCreds(issuer.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        issuer_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::IssuerCreds(issuer), &issuer_creds);

        let mut subject_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        subject_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::SubjectCreds(subject), &subject_creds);

        env.events().publish(
            (Symbol::new(&env, "CredentialIssued"),),
            (credential_id.clone(), issuer),
        );

        Ok(credential_id)
    }

    pub fn issue_credential_with_schema(
        env: Env,
        issuer: Address,
        subject: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        schema_id: Bytes,
        expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        use crate::credential_schema::CredentialSchema;
        let _schema = CredentialSchema::get_schema(env.clone(), schema_id.clone())
            .ok_or(CredentialIssuerError::SchemaNotFound)?;

        CredentialSchema::validate_credential_data(env.clone(), schema_id.clone(), credential_data.clone())
            .map_err(|_| CredentialIssuerError::SchemaValidationFailed)?;

        for ct in credential_type.iter() {
            if ct.len() > Self::MAX_CREDENTIAL_TYPE_LENGTH {
                return Err(CredentialIssuerError::InvalidCredential);
            }
        }
        if credential_data.len() > Self::MAX_CREDENTIAL_DATA_LENGTH {
            return Err(CredentialIssuerError::InvalidCredential);
        }

        let credential_id = Self::generate_credential_id(&env, &issuer, &subject);
        let now = env.ledger().timestamp();

        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            type_: credential_type.clone(),
            credential_data,
            issuance_date: now,
            expiration_date,
            schema_id: Some(schema_id),
            revocation: None,
            proof: Some(proof),
        };

        Self::validate_credential(&env, &credential)?;

        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &0u32);

        let mut issuer_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::IssuerCreds(issuer.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        issuer_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::IssuerCreds(issuer), &issuer_creds);

        let mut subject_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        subject_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::SubjectCreds(subject), &subject_creds);

        Ok(credential_id)
    }

    pub fn verify_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<bool, CredentialIssuerError> {
        let credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&CredKey::Credential(credential_id.clone()))
            .ok_or(CredentialIssuerError::NotFound)?;

        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(0);
        if status == 1 {
            return Ok(false);
        }

        if let Some(expiration) = credential.expiration_date {
            if env.ledger().timestamp() > expiration {
                return Ok(false);
            }
        }

        if let Some(ref proof) = credential.proof {
            Self::verify_proof(&env, proof, &credential)?;
        }

        Ok(true)
    }

    pub fn revoke_credential(
        env: Env,
        issuer: Address,
        credential_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<(), CredentialIssuerError> {
        issuer.require_auth();

        let mut credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&CredKey::Credential(credential_id.clone()))
            .ok_or(CredentialIssuerError::NotFound)?;

        if credential.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id.clone()))
            .unwrap_or(0);
        if status == 1 {
            return Err(CredentialIssuerError::AlreadyRevoked);
        }

        credential.revocation = Some(Bytes::from_slice(
            &env,
            env.ledger().timestamp().to_string().as_bytes(),
        ));
        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &1u32);

        if let Some(reason_bytes) = reason {
            env.storage()
                .persistent()
                .set(&CredKey::Reason(credential_id), &reason_bytes);
        }

        env.events().publish(
            (Symbol::new(&env, "CredentialRevoked"),),
            (credential_id, issuer, reason),
        );

        Ok(())
    }

    pub fn get_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<VerifiableCredential, CredentialIssuerError> {
        env.storage()
            .persistent()
            .get(&CredKey::Credential(credential_id))
            .ok_or(CredentialIssuerError::NotFound)
    }

    pub fn get_issuer_credentials(env: Env, issuer: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::IssuerCreds(issuer))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_subject_credentials(env: Env, subject: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_credentials_by_subject(
        env: Env,
        subject: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedCredentials {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject))
            .unwrap_or_else(|| Vec::new(&env));
        Self::paginate_bytes(&env, &all, page, page_size)
    }

    pub fn get_credentials_by_issuer(
        env: Env,
        issuer: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedCredentials {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::IssuerCreds(issuer))
            .unwrap_or_else(|| Vec::new(&env));
        Self::paginate_bytes(&env, &all, page, page_size)
    }

    pub fn get_credential_status(env: Env, credential_id: Bytes) -> Bytes {
        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(255);
        match status {
            0 => Bytes::from_slice(&env, b"active"),
            1 => Bytes::from_slice(&env, b"revoked"),
            _ => Bytes::from_slice(&env, b"unknown"),
        }
    }

    pub fn batch_verify_credentials(env: Env, credential_ids: Vec<Bytes>) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for credential_id in credential_ids.iter() {
            let is_valid =
                Self::verify_credential(env.clone(), credential_id.clone()).unwrap_or(false);
            results.push_back(is_valid);
        }
        results
    }

    pub fn get_revocation_reason(env: Env, credential_id: Bytes) -> Option<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::Reason(credential_id))
    }

    pub fn search_credentials_by_type(
        env: Env,
        _credential_type: Bytes,
        _max_results: u32,
    ) -> Vec<Bytes> {
        Vec::new(&env)
    }

    // -----------------------------------------------------------------------
    // Delegated Credential Issuance (#92)
    // -----------------------------------------------------------------------

    pub fn authorize_delegation(
        env: Env,
        delegator: Address,
        delegate: Address,
        authorized_types: Vec<Bytes>,
        max_issuances: u32,
        expires_at: u64,
    ) -> Result<Bytes, CredentialIssuerError> {
        delegator.require_auth();

        if authorized_types.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        if max_issuances == 0 {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        if expires_at <= env.ledger().timestamp() {
            return Err(CredentialIssuerError::DelegationExpired);
        }

        let auth_id = Self::generate_delegation_id(&env, &delegator, &delegate);

        let auth = DelegationAuthorization {
            id: auth_id.clone(),
            delegator: delegator.clone(),
            delegate: delegate.clone(),
            authorized_types: authorized_types.clone(),
            max_issuances,
            issued_count: 0,
            expires_at,
            active: true,
        };

        env.storage()
            .persistent()
            .set(&CredKey::Delegation(auth_id.clone()), &auth);

        let mut delegate_auths: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::DelegateAuths(delegate.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        delegate_auths.push_back(auth_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::DelegateAuths(delegate), &delegate_auths);

        let mut delegator_auths: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::DelegatorAuths(delegator.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        delegator_auths.push_back(auth_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::DelegatorAuths(delegator), &delegator_auths);

        env.events().publish(
            (Symbol::new(&env, "DelegationAuthorized"),),
            (auth_id.clone(), delegator, delegate),
        );

        Ok(auth_id)
    }

    pub fn revoke_delegation(
        env: Env,
        delegator: Address,
        auth_id: Bytes,
    ) -> Result<(), CredentialIssuerError> {
        delegator.require_auth();

        let mut auth: DelegationAuthorization = env
            .storage()
            .persistent()
            .get(&CredKey::Delegation(auth_id.clone()))
            .ok_or(CredentialIssuerError::DelegationNotFound)?;

        if auth.delegator != delegator {
            return Err(CredentialIssuerError::Unauthorized);
        }

        if !auth.active {
            return Err(CredentialIssuerError::DelegationRevoked);
        }

        auth.active = false;
        env.storage()
            .persistent()
            .set(&CredKey::Delegation(auth_id.clone()), &auth);

        env.events().publish(
            (Symbol::new(&env, "DelegationRevoked"),),
            (auth_id, delegator),
        );

        Ok(())
    }

    pub fn issue_delegated_credential(
        env: Env,
        delegate: Address,
        auth_id: Bytes,
        subject: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        delegate.require_auth();

        let mut auth: DelegationAuthorization = env
            .storage()
            .persistent()
            .get(&CredKey::Delegation(auth_id.clone()))
            .ok_or(CredentialIssuerError::DelegationNotFound)?;

        if !auth.active {
            return Err(CredentialIssuerError::DelegationRevoked);
        }

        if auth.delegate != delegate {
            return Err(CredentialIssuerError::Unauthorized);
        }

        if env.ledger().timestamp() > auth.expires_at {
            auth.active = false;
            env.storage()
                .persistent()
                .set(&CredKey::Delegation(auth_id), &auth);
            return Err(CredentialIssuerError::DelegationExpired);
        }

        if auth.issued_count >= auth.max_issuances {
            return Err(CredentialIssuerError::DelegationLimitExceeded);
        }

        for ct in credential_type.iter() {
            let mut authorized = false;
            for at in auth.authorized_types.iter() {
                if ct == at {
                    authorized = true;
                    break;
                }
            }
            if !authorized {
                return Err(CredentialIssuerError::UnauthorizedCredentialType);
            }
        }

        if credential_type.is_empty() || credential_data.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        for ct in credential_type.iter() {
            if ct.len() > Self::MAX_CREDENTIAL_TYPE_LENGTH {
                return Err(CredentialIssuerError::InvalidCredential);
            }
        }
        if credential_data.len() > Self::MAX_CREDENTIAL_DATA_LENGTH {
            return Err(CredentialIssuerError::InvalidCredential);
        }

        let credential_id = Self::generate_credential_id(&env, &auth.delegator, &subject);
        let now = env.ledger().timestamp();

        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: auth.delegator.clone(),
            subject: subject.clone(),
            type_: credential_type,
            credential_data,
            issuance_date: now,
            expiration_date,
            schema_id: None,
            revocation: None,
            proof: Some(proof),
        };

        Self::validate_credential(&env, &credential)?;

        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &0u32);

        let mut issuer_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::IssuerCreds(auth.delegator.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        issuer_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::IssuerCreds(auth.delegator), &issuer_creds);

        let mut subject_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        subject_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::SubjectCreds(subject), &subject_creds);

        auth.issued_count += 1;
        env.storage()
            .persistent()
            .set(&CredKey::Delegation(auth_id), &auth);

        env.events().publish(
            (Symbol::new(&env, "DelegatedCredentialIssued"),),
            (credential_id.clone(), delegate),
        );

        Ok(credential_id)
    }

    pub fn get_delegation(
        env: Env,
        auth_id: Bytes,
    ) -> Option<DelegationAuthorization> {
        env.storage()
            .persistent()
            .get(&CredKey::Delegation(auth_id))
    }

    pub fn get_delegate_authorizations(env: Env, delegate: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::DelegateAuths(delegate))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_delegator_authorizations(env: Env, delegator: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::DelegatorAuths(delegator))
            .unwrap_or_else(|| Vec::new(&env))
    }

    // -----------------------------------------------------------------------
    // Credential Revocation Registry (#91)
    // -----------------------------------------------------------------------

    pub fn create_revocation_registry(
        env: Env,
        issuer: Address,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        let registry_id = Self::generate_registry_id(&env, &issuer);
        let now = env.ledger().timestamp();

        let nonce = Bytes::from_slice(
            &env,
            env.crypto()
                .sha256(&Bytes::from_slice(&env, now.to_string().as_bytes()))
                .to_array()
                .as_slice(),
        );

        let registry = RevocationRegistryEntry {
            id: registry_id.clone(),
            issuer: issuer.clone(),
            credential_ids: Vec::new(&env),
            nonce,
            created: now,
            revoked_count: 0,
        };

        env.storage()
            .persistent()
            .set(&CredKey::RevocationRegistry(registry_id.clone()), &registry);

        env.events().publish(
            (Symbol::new(&env, "RevocationRegistryCreated"),),
            (registry_id.clone(), issuer),
        );

        Ok(registry_id)
    }

    pub fn revoke_credential_with_registry(
        env: Env,
        issuer: Address,
        credential_id: Bytes,
        registry_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<(), CredentialIssuerError> {
        Self::revoke_credential(env.clone(), issuer.clone(), credential_id.clone(), reason.clone())?;

        let mut registry: RevocationRegistryEntry = env
            .storage()
            .persistent()
            .get(&CredKey::RevocationRegistry(registry_id.clone()))
            .ok_or(CredentialIssuerError::RegistryNotFound)?;

        if registry.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        let nonce = Bytes::from_slice(
            &env,
            env.crypto()
                .sha256(&Bytes::from_slice(&env, env.ledger().timestamp().to_string().as_bytes()))
                .to_array()
                .as_slice(),
        );

        let proof = RevocationProof {
            registry_id: registry_id.clone(),
            credential_id: credential_id.clone(),
            nonce: nonce.clone(),
            timestamp: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&CredKey::RevocationProof(credential_id.clone()), &proof);

        registry.credential_ids.push_back(credential_id.clone());
        registry.revoked_count += 1;
        registry.nonce = nonce;
        env.storage()
            .persistent()
            .set(&CredKey::RevocationRegistry(registry_id), &registry);

        Ok(())
    }

    pub fn batch_revoke_credentials(
        env: Env,
        issuer: Address,
        credential_ids: Vec<Bytes>,
        registry_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        let mut registry: RevocationRegistryEntry = env
            .storage()
            .persistent()
            .get(&CredKey::RevocationRegistry(registry_id.clone()))
            .ok_or(CredentialIssuerError::RegistryNotFound)?;

        if registry.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        let now = env.ledger().timestamp();

        for credential_id in credential_ids.iter() {
            let mut credential: VerifiableCredential = env
                .storage()
                .persistent()
                .get(&CredKey::Credential(credential_id.clone()))
                .ok_or(CredentialIssuerError::NotFound)?;

            if credential.issuer != issuer {
                return Err(CredentialIssuerError::Unauthorized);
            }

            let status: u32 = env
                .storage()
                .persistent()
                .get(&CredKey::Status(credential_id.clone()))
                .unwrap_or(0);

            if status == 0 {
                credential.revocation = Some(Bytes::from_slice(
                    &env,
                    now.to_string().as_bytes(),
                ));
                env.storage()
                    .persistent()
                    .set(&CredKey::Credential(credential_id.clone()), &credential);
                env.storage()
                    .persistent()
                    .set(&CredKey::Status(credential_id.clone()), &1u32);

                if let Some(ref r) = reason {
                    env.storage()
                        .persistent()
                        .set(&CredKey::Reason(credential_id.clone()), r);
                }

                let proof_nonce = Bytes::from_slice(
                    &env,
                    env.crypto()
                        .sha256(&Bytes::from_slice(&env, format!("{}{}", now, credential_id.clone()).as_bytes()))
                        .to_array()
                        .as_slice(),
                );

                let proof = RevocationProof {
                    registry_id: registry_id.clone(),
                    credential_id: credential_id.clone(),
                    nonce: proof_nonce,
                    timestamp: now,
                };

                env.storage()
                    .persistent()
                    .set(&CredKey::RevocationProof(credential_id.clone()), &proof);

                registry.credential_ids.push_back(credential_id.clone());
                registry.revoked_count += 1;
            }
        }

        registry.nonce = Bytes::from_slice(
            &env,
            env.crypto()
                .sha256(&Bytes::from_slice(&env, now.to_string().as_bytes()))
                .to_array()
                .as_slice(),
        );

        env.storage()
            .persistent()
            .set(&CredKey::RevocationRegistry(registry_id.clone()), &registry);

        let batch_id = Self::generate_batch_id(&env, &issuer);

        let batch_record = BatchRevocationRecord {
            batch_id: batch_id.clone(),
            issuer: issuer.clone(),
            credential_ids: credential_ids.clone(),
            reason,
            timestamp: now,
        };

        env.storage()
            .persistent()
            .set(&CredKey::BatchRevocation(batch_id.clone()), &batch_record);

        env.events().publish(
            (Symbol::new(&env, "BatchRevocationExecuted"),),
            (batch_id.clone(), registry_id, issuer),
        );

        Ok(batch_id)
    }

    pub fn check_revocation_status(
        env: Env,
        credential_id: Bytes,
    ) -> bool {
        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(0);
        status == 1
    }

    pub fn get_revocation_proof(
        env: Env,
        credential_id: Bytes,
    ) -> Option<RevocationProof> {
        env.storage()
            .persistent()
            .get(&CredKey::RevocationProof(credential_id))
    }

    pub fn verify_revocation_proof(
        env: Env,
        credential_id: Bytes,
        proof: RevocationProof,
    ) -> Result<bool, CredentialIssuerError> {
        let stored: RevocationProof = env
            .storage()
            .persistent()
            .get(&CredKey::RevocationProof(credential_id.clone()))
            .ok_or(CredentialIssuerError::RegistryNotFound)?;

        if stored.credential_id != proof.credential_id {
            return Ok(false);
        }
        if stored.registry_id != proof.registry_id {
            return Ok(false);
        }
        if stored.nonce != proof.nonce {
            return Ok(false);
        }

        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(0);

        Ok(status == 1)
    }

    pub fn get_revocation_registry(
        env: Env,
        registry_id: Bytes,
    ) -> Option<RevocationRegistryEntry> {
        env.storage()
            .persistent()
            .get(&CredKey::RevocationRegistry(registry_id))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn generate_credential_id(env: &Env, _issuer: &Address, _subject: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"vc:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, env.ledger().sequence().to_string().as_bytes()));
        id
    }

    fn generate_delegation_id(env: &Env, _delegator: &Address, _delegate: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"del:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, env.ledger().sequence().to_string().as_bytes()));
        id
    }

    fn generate_registry_id(env: &Env, _issuer: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"reg:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, env.ledger().sequence().to_string().as_bytes()));
        id
    }

    fn generate_batch_id(env: &Env, _issuer: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"batch:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, env.ledger().sequence().to_string().as_bytes()));
        id
    }

    fn validate_credential(
        _env: &Env,
        credential: &VerifiableCredential,
    ) -> Result<(), CredentialIssuerError> {
        if credential.credential_data.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        if credential.type_.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        if let Some(proof) = &credential.proof {
            if proof.is_empty() {
                return Err(CredentialIssuerError::InvalidSignature);
            }
        }
        Ok(())
    }

    fn verify_proof(
        _env: &Env,
        proof: &Bytes,
        _credential: &VerifiableCredential,
    ) -> Result<(), CredentialIssuerError> {
        if proof.is_empty() {
            return Err(CredentialIssuerError::InvalidSignature);
        }
        Ok(())
    }

    fn paginate_bytes(
        env: &Env,
        items: &Vec<Bytes>,
        page: u32,
        page_size: u32,
    ) -> PaginatedCredentials {
        let size = clamp_page_size(page_size);
        let total = items.len() as u32;
        let start = page * size;
        let mut data = Vec::new(env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(item) = items.get(i) {
                    data.push_back(item);
                }
            }
        }

        PaginatedCredentials {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }
}
