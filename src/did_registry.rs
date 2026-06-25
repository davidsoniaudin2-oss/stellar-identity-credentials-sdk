use soroban_sdk::{
    contract, contracterror, contractimpl, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::{DIDDocument, Service, VerificationMethod};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DIDRegistryError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidFormat = 4,
    Deactivated = 5,
    InvalidSignature = 6,
    AlreadyDeactivated = 7,
}

#[contract]
pub struct DIDRegistry;

#[contractimpl]
impl DIDRegistry {
    const MAX_DID_LENGTH: u32 = 256;
    const MAX_VM_ID_LENGTH: u32 = 128;
    const MAX_SERVICE_ID_LENGTH: u32 = 128;
    const MAX_SERVICE_ENDPOINT_LENGTH: u32 = 512;

    pub fn create_did(
        env: Env,
        controller: Address,
        did_id: Bytes,
        verification_methods: Vec<VerificationMethod>,
        services: Vec<Service>,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        if !Self::check_did_prefix(&env, &did_id) {
            return Err(DIDRegistryError::InvalidFormat);
        }

        if did_id.len() > Self::MAX_DID_LENGTH {
            return Err(DIDRegistryError::InvalidFormat);
        }

        for vm in verification_methods.iter() {
            if vm.id.len() > Self::MAX_VM_ID_LENGTH {
                return Err(DIDRegistryError::InvalidFormat);
            }
        }

        for svc in services.iter() {
            if svc.id.len() > Self::MAX_SERVICE_ID_LENGTH || svc.endpoint.len() > Self::MAX_SERVICE_ENDPOINT_LENGTH {
                return Err(DIDRegistryError::InvalidFormat);
            }
        }

        if env.storage().persistent().has(&did_id) {
            return Err(DIDRegistryError::AlreadyExists);
        }

        let now = env.ledger().timestamp();
        let doc = DIDDocument {
            id: did_id.clone(),
            controller: controller.clone(),
            verification_method: verification_methods,
            authentication: Vec::new(&env),
            service: services,
            created: now,
            updated: now,
            deactivated: false,
        };

        env.storage().persistent().set(&did_id, &doc);
        env.storage().persistent().set(&controller, &did_id);

        env.events().publish(
            (Symbol::new(&env, "DIDCreated"),),
            (did_id, controller),
        );

        Ok(())
    }

    /// Resolve a DID document by its DID string.
    /// Returns the document even when deactivated (W3C DID Core §7.1.2).
    pub fn resolve_did(env: Env, did: Bytes) -> Result<DIDDocument, DIDRegistryError> {
        env.storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)
    }

    /// Update verification methods and/or service endpoints.
    /// Deactivated DIDs cannot be updated.
    pub fn update_did(
        env: Env,
        controller: Address,
        verification_methods: Option<Vec<VerificationMethod>>,
        services: Option<Vec<Service>>,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        if let Some(methods) = verification_methods {
            doc.verification_method = methods;
        }
        if let Some(svcs) = services {
            doc.service = svcs;
        }

        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        env.events().publish(
            (Symbol::new(&env, "DIDUpdated"),),
            (did, controller),
        );

        Ok(())
    }

    /// Soft-delete a DID document (tombstone).
    /// The document is preserved on-chain with `deactivated = true` for audit.
    pub fn deactivate_did(env: Env, controller: Address) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::AlreadyDeactivated);
        }

        doc.deactivated = true;
        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        env.events().publish(
            (Symbol::new(&env, "DIDDeactivated"),),
            (did, controller),
        );

        Ok(())
    }

    pub fn add_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        doc.authentication.push_back(authentication_method);
        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        Ok(())
    }

    pub fn remove_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let mut found = false;
        let mut new_auth: Vec<Bytes> = Vec::new(&env);
        for auth in doc.authentication.iter() {
            if auth != authentication_method {
                new_auth.push_back(auth);
            } else {
                found = true;
            }
        }

        if !found {
            return Err(DIDRegistryError::NotFound);
        }

        doc.authentication = new_auth;
        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        Ok(())
    }

    pub fn verify_signature(
        env: Env,
        did: Bytes,
        message: Bytes,
        signature: BytesN<64>,
    ) -> Result<bool, DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(0)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto().ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

    pub fn verify_signature_with_method(
        env: Env,
        did: Bytes,
        message: Bytes,
        signature: BytesN<64>,
        method_index: u32,
    ) -> Result<bool, DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(method_index)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto().ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

    pub fn did_exists(env: Env, did: Bytes) -> bool {
        env.storage().persistent().has(&did)
    }

    pub fn get_controller_did(env: Env, controller: Address) -> Option<Bytes> {
        env.storage().persistent().get(&controller)
    }

    fn check_did_prefix(env: &Env, did: &Bytes) -> bool {
        let prefix = Bytes::from_slice(env, b"did:stellar:");
        let prefix_len = prefix.len();

        if did.len() < prefix_len {
            return false;
        }

        for i in 0..prefix_len {
            if did.get(i) != prefix.get(i) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        vec, BytesN, Env,
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

    fn make_did_bytes(env: &Env, addr: &Address) -> Bytes {
        let s = alloc::format!("did:stellar:{}", addr.to_string());
        Bytes::from_slice(env, s.as_bytes())
    }

    fn make_vm(env: &Env, id: &str, key: &[u8; 32]) -> VerificationMethod {
        VerificationMethod {
            id: Bytes::from_slice(env, id.as_bytes()),
            type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
            controller: Address::generate(env),
            public_key: BytesN::from_array(env, key),
        }
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

    // ── Issue #12: resolve_did tests ──

    #[test]
    fn test_resolve_did_success() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did.clone()).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.controller, controller);
        assert!(!doc.deactivated);
        assert_eq!(doc.created, 1_700_000_000);
        assert_eq!(doc.updated, 1_700_000_000);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.service.len(), 1);
    }

    #[test]
    fn test_resolve_did_not_found() {
        let env = setup_env();
        let fake_did = Bytes::from_slice(&env, b"did:stellar:NONEXISTENT");
        let result = DIDRegistry::resolve_did(env.clone(), fake_did);
        assert_eq!(result.err().unwrap(), DIDRegistryError::NotFound);
    }

    // ── Issue #13: update_did tests ──

    #[test]
    fn test_update_did_verification_methods() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        let new_vm = make_vm(&env, "#key-2", &[2u8; 32]);
        DIDRegistry::update_did(
            env.clone(),
            controller.clone(),
            Some(vec![&env, new_vm]),
            None,
        )
        .unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method.get(0).unwrap().id,
            Bytes::from_slice(&env, b"#key-2")
        );
    }

    #[test]
    fn test_update_did_services() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        let new_services: Vec<Service> = Vec::new(&env);
        DIDRegistry::update_did(
            env.clone(),
            controller.clone(),
            None,
            Some(new_services),
        )
        .unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
        assert_eq!(doc.service.len(), 0);
    }

    #[test]
    fn test_update_deactivated_did_fails() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::deactivate_did(env.clone(), controller.clone()).unwrap();

        let result = DIDRegistry::update_did(env.clone(), controller, None, None);
        assert_eq!(result.err().unwrap(), DIDRegistryError::Deactivated);
    }

    // ── Issue #13: deactivate_did tests ──

    #[test]
    fn test_deactivate_did_success() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::deactivate_did(env.clone(), controller).unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
        assert!(doc.deactivated);
    }

    #[test]
    fn test_deactivate_already_deactivated_did_fails() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::deactivate_did(env.clone(), controller.clone()).unwrap();

        let result = DIDRegistry::deactivate_did(env.clone(), controller);
        assert_eq!(result.err().unwrap(), DIDRegistryError::AlreadyDeactivated);
    }

    #[test]
    fn test_deactivate_nonexistent_did_fails() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);

        let result = DIDRegistry::deactivate_did(env.clone(), controller);
        assert_eq!(result.err().unwrap(), DIDRegistryError::NotFound);
    }
}
