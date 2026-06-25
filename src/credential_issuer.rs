use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Vec,
};

use crate::{clamp_page_size, PaginatedCredentials, VerifiableCredential};

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
}

#[contract]
pub struct CredentialIssuer;

#[contractimpl]
impl CredentialIssuer {
    const MAX_CREDENTIAL_TYPE_LENGTH: u32 = 128;
    const MAX_CREDENTIAL_DATA_LENGTH: u32 = 10240;

    /// Issue a new verifiable credential.
    /// If `schema_id` is provided, validates `credential_data` against the
    /// registered schema before storing.
    pub fn issue_credential(
        env: Env,
        issuer: Address,
        subject: Address,
        credential_type: Bytes,
        claims: Map<Bytes, Bytes>,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        if !Self::is_issuer_registered(env.clone(), issuer.clone()) {
            return Err(CredentialIssuerError::InvalidIssuer);
        }

        if !Self::is_valid_credential_type(&env, &credential_type) {
            return Err(CredentialIssuerError::InvalidCredentialType);
        }

        if credential_type.len() > Self::MAX_CREDENTIAL_TYPE_LENGTH {
            return Err(CredentialIssuerError::InvalidCredential);
        }

        if claims.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }

        let credential_id = Self::generate_credential_id(&env, &issuer, &subject);
        let now = env.ledger().timestamp();

        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            type_: credential_type.clone(),
            credential_data: credential_data.clone(),
            issuance_date: now,
            expiration_date,
            schema_id: None,
            revocation: None,
            proof: Some(proof.clone()),
        };

        Self::validate_credential(&env, &credential)?;

        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);

        // Active / revoked status packed as a single u8 (0 = active, 1 = revoked)
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

    /// Issue a credential with schema validation.
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

    /// Verify a verifiable credential.
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
                return Ok(CredentialVerification {
                    valid: false,
                    reason: Some(Bytes::from_slice(&env, b"Credential expired")),
                });
            }
        }

        if let Some(ref proof) = credential.proof {
            Self::verify_proof(&env, proof, &credential)?;
        }

        Ok(true)
    }

    /// Revoke a verifiable credential.
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

    /// Get credential details.
    pub fn get_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<VerifiableCredential, CredentialIssuerError> {
        env.storage()
            .persistent()
            .get(&CredKey::Credential(credential_id))
            .ok_or(CredentialIssuerError::NotFound)
    }

    /// Get all credentials for an issuer (unpaginated, kept for backwards compat).
    pub fn get_issuer_credentials(env: Env, issuer: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::IssuerCreds(issuer))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get all credentials for a subject (unpaginated).
    pub fn get_subject_credentials(env: Env, subject: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    // -----------------------------------------------------------------------
    // Paginated queries (#56)
    // -----------------------------------------------------------------------

    /// Paginated credential list for a subject.
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

    /// Paginated credential list for an issuer.
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

    /// Get credential status (packed u8: 0 = active, 1 = revoked).
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

    /// Batch verify multiple credentials.
    pub fn batch_verify_credentials(env: Env, credential_ids: Vec<Bytes>) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for credential_id in credential_ids.iter() {
            let is_valid =
                Self::verify_credential(env.clone(), credential_id.clone()).unwrap_or(false);
            results.push_back(is_valid);
        }
        results
    }

    /// Get revocation reason.
    pub fn get_revocation_reason(env: Env, credential_id: Bytes) -> Option<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::Reason(credential_id))
    }

    /// Search credentials by type (placeholder).
    pub fn search_credentials_by_type(
        env: Env,
        _credential_type: Bytes,
        _max_results: u32,
    ) -> Vec<Bytes> {
        Vec::new(&env)
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
