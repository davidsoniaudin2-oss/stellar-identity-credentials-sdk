use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Map, Symbol, Vec,
};

use crate::{CredentialVerification, VerifiableCredential};

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
    InvalidCredentialType = 8,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Credential(Bytes),
    CredentialStatus(Bytes),
    RevocationReason(Bytes),
    IssuerCredentials(Address),
    SubjectCredentials(Address),
    RegisteredIssuer(Address),
    CredentialCounter,
}

#[contract]
pub struct CredentialIssuer;

#[contractimpl]
impl CredentialIssuer {
    const MAX_CREDENTIAL_TYPE_LENGTH: u32 = 128;
    const MAX_CLAIM_KEY_LENGTH: u32 = 128;
    const MAX_CLAIM_VALUE_LENGTH: u32 = 2048;

    pub fn register_issuer(env: Env, issuer: Address) -> Result<(), CredentialIssuerError> {
        issuer.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::RegisteredIssuer(issuer), &true);
        Ok(())
    }

    pub fn is_issuer_registered(env: Env, issuer: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::RegisteredIssuer(issuer))
            .unwrap_or(false)
    }

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

        for (key, value) in claims.iter() {
            if key.len() > Self::MAX_CLAIM_KEY_LENGTH {
                return Err(CredentialIssuerError::InvalidCredential);
            }
            if value.len() > Self::MAX_CLAIM_VALUE_LENGTH {
                return Err(CredentialIssuerError::InvalidCredential);
            }
        }

        let credential_id = Self::generate_credential_id(&env);

        let now = env.ledger().timestamp();
        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            credential_type: credential_type.clone(),
            claims,
            issuance_date: now,
            expiration_date: Some(now + 365 * 24 * 60 * 60),
            revoked: false,
            revocation_reason: None,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Credential(credential_id.clone()), &credential);
        env.storage().persistent().set(
            &DataKey::CredentialStatus(credential_id.clone()),
            &Bytes::from_slice(&env, b"active"),
        );

        let mut issuer_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&DataKey::IssuerCredentials(issuer.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        issuer_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&DataKey::IssuerCredentials(issuer.clone()), &issuer_creds);

        let mut subject_creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        subject_creds.push_back(credential_id.clone());
        env.storage()
            .persistent()
            .set(&DataKey::SubjectCredentials(subject.clone()), &subject_creds);

        env.events().publish(
            (Symbol::new(&env, "CredentialIssued"),),
            (credential_id.clone(), issuer, subject, credential_type),
        );

        Ok(credential_id)
    }

    pub fn verify_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<CredentialVerification, CredentialIssuerError> {
        let credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&DataKey::Credential(credential_id.clone()))
            .ok_or(CredentialIssuerError::NotFound)?;

        if credential.revoked {
            return Ok(CredentialVerification {
                valid: false,
                reason: Some(
                    credential
                        .revocation_reason
                        .unwrap_or_else(|| Bytes::from_slice(&env, b"Credential revoked")),
                ),
            });
        }

        if let Some(expiration) = credential.expiration_date {
            if env.ledger().timestamp() > expiration {
                return Ok(CredentialVerification {
                    valid: false,
                    reason: Some(Bytes::from_slice(&env, b"Credential expired")),
                });
            }
        }

        Ok(CredentialVerification {
            valid: true,
            reason: None,
        })
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
            .get(&DataKey::Credential(credential_id.clone()))
            .ok_or(CredentialIssuerError::NotFound)?;

        if credential.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        if credential.revoked {
            return Err(CredentialIssuerError::AlreadyRevoked);
        }

        credential.revoked = true;
        credential.revocation_reason = reason.clone();

        env.storage()
            .persistent()
            .set(&DataKey::Credential(credential_id.clone()), &credential);
        env.storage().persistent().set(
            &DataKey::CredentialStatus(credential_id.clone()),
            &Bytes::from_slice(&env, b"revoked"),
        );

        if let Some(ref reason_bytes) = reason {
            env.storage().persistent().set(
                &DataKey::RevocationReason(credential_id.clone()),
                reason_bytes,
            );
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
            .get(&DataKey::Credential(credential_id))
            .ok_or(CredentialIssuerError::NotFound)
    }

    pub fn get_issuer_credentials(env: Env, issuer: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&DataKey::IssuerCredentials(issuer))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_subject_credentials(env: Env, subject: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_credential_status(env: Env, credential_id: Bytes) -> Bytes {
        env.storage()
            .persistent()
            .get(&DataKey::CredentialStatus(credential_id))
            .unwrap_or_else(|| Bytes::from_slice(&env, b"unknown"))
    }

    pub fn get_revocation_reason(env: Env, credential_id: Bytes) -> Option<Bytes> {
        env.storage()
            .persistent()
            .get(&DataKey::RevocationReason(credential_id))
    }

    pub fn batch_verify_credentials(
        env: Env,
        credential_ids: Vec<Bytes>,
    ) -> Vec<CredentialVerification> {
        let mut results = Vec::new(&env);
        for credential_id in credential_ids.iter() {
            let verification = Self::verify_credential(env.clone(), credential_id)
                .unwrap_or_else(|_| CredentialVerification {
                    valid: false,
                    reason: Some(Bytes::from_slice(&env, b"Credential not found")),
                });
            results.push_back(verification);
        }
        results
    }

    fn generate_credential_id(env: &Env) -> Bytes {
        let counter: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialCounter)
            .unwrap_or(0);
        let next = counter + 1;
        env.storage()
            .persistent()
            .set(&DataKey::CredentialCounter, &next);

        let timestamp = env.ledger().timestamp();
        let id_string = alloc::format!("vc:{}:{}", timestamp, next);
        Bytes::from_slice(env, id_string.as_bytes())
    }

    fn is_valid_credential_type(env: &Env, credential_type: &Bytes) -> bool {
        let valid_types: [&[u8]; 3] = [
            b"KYCCredential",
            b"AgeCredential",
            b"IncomeCredential",
        ];

        for valid in valid_types.iter() {
            if *credential_type == Bytes::from_slice(env, valid) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Env, Map,
    };

    fn setup_env() -> Env {
        let env = Env::default();
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

    fn register_and_issue(
        env: &Env,
        issuer: &Address,
        subject: &Address,
        cred_type: &[u8],
    ) -> Bytes {
        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();
        CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject.clone(),
            Bytes::from_slice(env, cred_type),
            make_claims(env),
        )
        .unwrap()
    }

    // ── Issue #14: issue_credential tests ──

    #[test]
    fn test_issue_credential_success() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let cred_id = register_and_issue(&env, &issuer, &subject, b"KYCCredential");

        let cred = CredentialIssuer::get_credential(env.clone(), cred_id.clone()).unwrap();
        assert_eq!(cred.issuer, issuer);
        assert_eq!(cred.subject, subject);
        assert_eq!(
            cred.credential_type,
            Bytes::from_slice(&env, b"KYCCredential")
        );
        assert_eq!(cred.issuance_date, 1_700_000_000);
        assert!(!cred.revoked);

        let status = CredentialIssuer::get_credential_status(env.clone(), cred_id.clone());
        assert_eq!(status, Bytes::from_slice(&env, b"active"));

        let issuer_creds = CredentialIssuer::get_issuer_credentials(env.clone(), issuer);
        assert_eq!(issuer_creds.len(), 1);
        assert_eq!(issuer_creds.get(0).unwrap(), cred_id.clone());

        let subject_creds = CredentialIssuer::get_subject_credentials(env.clone(), subject);
        assert_eq!(subject_creds.len(), 1);
        assert_eq!(subject_creds.get(0).unwrap(), cred_id);
    }

    #[test]
    fn test_issue_credential_unauthorized_issuer() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            Bytes::from_slice(&env, b"KYCCredential"),
            make_claims(&env),
        );
        assert_eq!(result.err().unwrap(), CredentialIssuerError::InvalidIssuer);
    }

    #[test]
    fn test_issue_credential_invalid_type() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            Bytes::from_slice(&env, b"InvalidType"),
            make_claims(&env),
        );
        assert_eq!(
            result.err().unwrap(),
            CredentialIssuerError::InvalidCredentialType
        );
    }

    #[test]
    fn test_issue_credential_empty_claims() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            Bytes::from_slice(&env, b"KYCCredential"),
            Map::new(&env),
        );
        assert_eq!(
            result.err().unwrap(),
            CredentialIssuerError::InvalidCredential
        );
    }

    #[test]
    fn test_issue_all_valid_credential_types() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

        for cred_type in [b"KYCCredential", b"AgeCredential", b"IncomeCredential"] {
            let result = CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject.clone(),
                Bytes::from_slice(&env, cred_type),
                make_claims(&env),
            );
            assert!(result.is_ok());
        }
    }

    // ── Issue #15: verify_credential tests ──

    #[test]
    fn test_verify_credential_valid() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let cred_id = register_and_issue(&env, &issuer, &subject, b"KYCCredential");

        let verification =
            CredentialIssuer::verify_credential(env.clone(), cred_id).unwrap();
        assert!(verification.valid);
        assert!(verification.reason.is_none());
    }

    #[test]
    fn test_verify_credential_revoked() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let cred_id = register_and_issue(&env, &issuer, &subject, b"KYCCredential");

        CredentialIssuer::revoke_credential(
            env.clone(),
            issuer,
            cred_id.clone(),
            Some(Bytes::from_slice(&env, b"KYC expired")),
        )
        .unwrap();

        let verification =
            CredentialIssuer::verify_credential(env.clone(), cred_id).unwrap();
        assert!(!verification.valid);
        assert_eq!(
            verification.reason.unwrap(),
            Bytes::from_slice(&env, b"KYC expired")
        );
    }

    #[test]
    fn test_verify_credential_expired() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let cred_id = register_and_issue(&env, &issuer, &subject, b"KYCCredential");

        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000 + 366 * 24 * 60 * 60,
            protocol_version: 22,
            sequence_number: 2000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50000,
            min_persistent_entry_ttl: 50000,
            max_entry_ttl: 50000,
        });

        let verification =
            CredentialIssuer::verify_credential(env.clone(), cred_id).unwrap();
        assert!(!verification.valid);
        assert_eq!(
            verification.reason.unwrap(),
            Bytes::from_slice(&env, b"Credential expired")
        );
    }

    #[test]
    fn test_verify_credential_not_found() {
        let env = setup_env();
        let fake_id = Bytes::from_slice(&env, b"vc:nonexistent");
        let result = CredentialIssuer::verify_credential(env.clone(), fake_id);
        assert_eq!(result.err().unwrap(), CredentialIssuerError::NotFound);
    }

    // ── Issue #15: revoke_credential tests ──

    #[test]
    fn test_revoke_credential_success() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let cred_id = register_and_issue(&env, &issuer, &subject, b"KYCCredential");

        CredentialIssuer::revoke_credential(
            env.clone(),
            issuer,
            cred_id.clone(),
            Some(Bytes::from_slice(&env, b"Fraudulent")),
        )
        .unwrap();

        let cred = CredentialIssuer::get_credential(env.clone(), cred_id.clone()).unwrap();
        assert!(cred.revoked);

        let status = CredentialIssuer::get_credential_status(env.clone(), cred_id.clone());
        assert_eq!(status, Bytes::from_slice(&env, b"revoked"));

        let reason = CredentialIssuer::get_revocation_reason(env.clone(), cred_id);
        assert_eq!(reason.unwrap(), Bytes::from_slice(&env, b"Fraudulent"));
    }

    #[test]
    fn test_revoke_credential_unauthorized() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let other = Address::generate(&env);
        let subject = Address::generate(&env);

        let cred_id = register_and_issue(&env, &issuer, &subject, b"KYCCredential");

        let result = CredentialIssuer::revoke_credential(env.clone(), other, cred_id, None);
        assert_eq!(result.err().unwrap(), CredentialIssuerError::Unauthorized);
    }

    #[test]
    fn test_revoke_credential_already_revoked() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let cred_id = register_and_issue(&env, &issuer, &subject, b"KYCCredential");

        CredentialIssuer::revoke_credential(env.clone(), issuer.clone(), cred_id.clone(), None)
            .unwrap();

        let result =
            CredentialIssuer::revoke_credential(env.clone(), issuer, cred_id, None);
        assert_eq!(result.err().unwrap(), CredentialIssuerError::AlreadyRevoked);
    }

    #[test]
    fn test_revoke_credential_not_found() {
        let env = setup_env();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let fake_id = Bytes::from_slice(&env, b"vc:nonexistent");

        let result = CredentialIssuer::revoke_credential(env.clone(), issuer, fake_id, None);
        assert_eq!(result.err().unwrap(), CredentialIssuerError::NotFound);
    }
}
