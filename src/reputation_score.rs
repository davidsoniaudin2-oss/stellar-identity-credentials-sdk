use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, Env, Map,
    Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedReputationHistory};

const SCORE_SCALE: u32 = 10;
const MAX_SCORE: u32 = 1000 * SCORE_SCALE;
const BASE_SCORE: u32 = 80 * SCORE_SCALE;
const CHECKPOINT_INTERVAL: u64 = 60 * 60 * 24;
const MAX_HISTORY_POINTS: u32 = 120;
const MAX_GRAPH_EDGES: u32 = 64;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationScoreError {
    NotInitialized = 1,
    NotAdmin = 2,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReputationScoreEvent {
    ReputationScoreUpdated(Address, u32, Bytes),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub max_score: u32,
    pub transaction_success_weight: u32,
    pub transaction_failure_weight: u32,
    pub credential_valid_weight: u32,
    pub credential_invalid_weight: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Config,
    Admin,
    Score(Address),
}

#[contract]
pub struct ReputationScore;

#[contractimpl]
impl ReputationScore {
    pub fn initialize(env: Env, admin: Address, config: Config) {
        if env.storage().instance().has(&Symbol::new(&env, "admin")) {
            panic!("Already initialized");
        }
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
        env.storage().instance().set(&Symbol::new(&env, "config"), &config);
    }

    fn get_admin(env: &Env) -> Address {
        env.storage().instance().get(&Symbol::new(env, "admin"))
            .expect("Not initialized")
    }

    fn get_config(env: &Env) -> Config {
        env.storage().instance().get(&Symbol::new(env, "config"))
            .expect("Not initialized")
    }

    pub fn get_reputation_score(env: Env, address: Address) -> u32 {
        env.storage().persistent().get(&DataKey::Score(address)).unwrap_or(0)
    }

    pub fn update_transaction_reputation(
        env: Env,
        address: Address,
        success: bool,
        _amount: i128,
    ) -> Result<u32, ReputationScoreError> {
        let config = Self::get_config(&env);
        let mut score = Self::get_reputation_score(env.clone(), address.clone());

    pub fn get_reputation_history(
        env: Env,
        did: Address,
        limit: u32,
    ) -> Result<Vec<ReputationHistoryEntry>, ReputationScoreError> {
        let history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(did.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        let len = history.len();
        let start = if len > limit { len - limit } else { 0 };
        let mut result = Vec::new(&env);
        for index in start..len {
            if let Some(entry) = history.get(index) {
                result.push_back(entry);
            }
        }
        Ok(result)
    }

    /// Paginated reputation history (#56).
    pub fn get_reputation_history_paginated(
        env: Env,
        address: Address,
        page: u32,
        page_size: u32,
    ) -> Result<PaginatedReputationHistory, ReputationScoreError> {
        let history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(address))
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = history.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(entry) = history.get(i) {
                    data.push_back(entry);
                }
            }
        }

        Ok(PaginatedReputationHistory {
            data,
            page,
            total,
            has_more: (start + size) < total,
        })
    }

    pub fn get_reputation_percentile(env: Env, did: Address) -> Result<u32, ReputationScoreError> {
        let target = Self::load_profile(&env, &did)?.score;
        let population = Self::population(&env);
        if population.is_empty() {
            return Ok(0);
        }

        let mut below_or_equal = 0u32;
        for subject in population.iter() {
            if let Ok(candidate) = Self::load_profile(&env, &subject) {
                if candidate.score <= target {
                    below_or_equal += 1;
                }
            }
        }

        Ok((below_or_equal * 100) / population.len())
    }

    pub fn meets_reputation_threshold(
        env: Env,
        did: Address,
        threshold: u32,
    ) -> Result<bool, ReputationScoreError> {
        Ok(Self::load_profile(&env, &did)?.score >= threshold * SCORE_SCALE)
    }

    const MAX_REASON_LENGTH: u32 = 1024;

    pub fn attest_trust(
        env: Env,
        truster: Address,
        subject: Address,
        weight: u32,
        reason: Bytes,
    ) -> Result<TrustAttestation, ReputationScoreError> {
        truster.require_auth();
        if weight > 1000 {
            return Err(ReputationScoreError::InvalidScore);
        }
        if reason.len() > Self::MAX_REASON_LENGTH {
            return Err(ReputationScoreError::InvalidScore);
        }

        let timestamp = env.ledger().timestamp();
        let edge = TrustAttestation {
            truster: truster.clone(),
            subject: subject.clone(),
            weight,
            reason,
            timestamp,
        };

        if score > config.max_score {
            score = config.max_score;
        }

        env.storage().persistent().set(&DataKey::Score(address.clone()), &score);
        env.events().publish(
            symbol_short!("reputation_updated"),
            ReputationScoreEvent::ReputationScoreUpdated(
                address.clone(),
                score,
                reason.clone(),
            ),
        );

        Ok(score)
    }

    pub fn update_credential_reputation(
        env: Env,
        address: Address,
        valid: bool,
        credential_type: Bytes,
    ) -> Result<u32, ReputationScoreError> {
        let config = Self::get_config(&env);
        let mut score = Self::get_reputation_score(env.clone(), address.clone());

        let reason = if valid {
            score = score.saturating_add(config.credential_valid_weight);
            Bytes::from_array(&env, b"Credential Valid")
        } else {
            score = score.saturating_sub(config.credential_invalid_weight);
            Bytes::from_array(&env, b"Credential Invalid")
        };

        if score > config.max_score {
            score = config.max_score;
        }

        env.storage().persistent().set(&DataKey::Score(address.clone()), &score);
        env.events().publish(
            symbol_short!("reputation_updated"),
            ReputationScoreEvent::ReputationScoreUpdated(
                address.clone(),
                score,
                reason.clone(),
            ),
        );

        Ok(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env};

    #[test]
    fn test_initialization_and_score_bounds() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let config = Config {
            max_score: 100,
            transaction_success_weight: 10,
            transaction_failure_weight: 5,
            credential_valid_weight: 20,
            credential_invalid_weight: 15,
        };

        ReputationScore::initialize(env.clone(), admin, config);

        // Score should be 0 initially
        assert_eq!(ReputationScore::get_reputation_score(env.clone(), user.clone()), 0);

        // Test upper bound
        for _ in 0..15 {
            ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 0).unwrap();
        }
        assert_eq!(ReputationScore::get_reputation_score(env.clone(), user.clone()), 100);

        // Test lower bound
        for _ in 0..20 {
            ReputationScore::update_transaction_reputation(env.clone(), user.clone(), false, 0).unwrap();
        }
        assert_eq!(ReputationScore::get_reputation_score(env.clone(), user.clone()), 0);
    }

    #[test]
    fn test_transaction_updates() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let config = Config {
            max_score: 100,
            transaction_success_weight: 10,
            transaction_failure_weight: 5,
            credential_valid_weight: 20,
            credential_invalid_weight: 15,
        };

        ReputationScore::initialize(env.clone(), admin, config);

        // Successful transaction
        let score = ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 100).unwrap();
        assert_eq!(score, 10);

        // Failed transaction
        let score = ReputationScore::update_transaction_reputation(env.clone(), user.clone(), false, 0).unwrap();
        assert_eq!(score, 5);
    }

    #[test]
    fn test_credential_updates() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let config = Config {
            max_score: 100,
            transaction_success_weight: 10,
            transaction_failure_weight: 5,
            credential_valid_weight: 20,
            credential_invalid_weight: 15,
        };

        ReputationScore::initialize(env.clone(), admin, config);

        // Valid credential
        let cred_type = Bytes::from_array(&env, b"KYC");
        let score = ReputationScore::update_credential_reputation(env.clone(), user.clone(), true, cred_type.clone()).unwrap();
        assert_eq!(score, 20);

        // Invalid credential
        let score = ReputationScore::update_credential_reputation(env.clone(), user.clone(), false, cred_type).unwrap();
        assert_eq!(score, 5);
    }
}
