use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, Env, Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedReputationHistory};

const SCORE_SCALE: u32 = 10;
const MAX_SCORE: u32 = 1000 * SCORE_SCALE;
const BASE_SCORE: u32 = 80 * SCORE_SCALE;
const CHECKPOINT_INTERVAL: u64 = 60 * 60 * 24;
const MAX_HISTORY_POINTS: u32 = 120;
const MAX_GRAPH_EDGES: u32 = 64;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationData {
    pub score: u32,
    pub total_transactions: u32,
    pub successful_transactions: u32,
    pub failed_transactions: u32,
    pub total_credentials: u32,
    pub valid_credentials: u32,
    pub invalid_credentials: u32,
    pub last_updated: u64,
    pub volume: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationHistoryEntry {
    pub timestamp: u64,
    pub score: u32,
    pub event: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAttestation {
    pub truster: Address,
    pub subject: Address,
    pub weight: u32,
    pub reason: Bytes,
    pub timestamp: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationScoreError {
    NotInitialized = 1,
    NotAdmin = 2,
    InvalidScore = 3,
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
    Profile(Address),
    Working(Address),
    History(Address),
    Trust(Address),
    Population,
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

    pub fn initialize_reputation(env: Env, address: Address) -> Result<(), ReputationScoreError> {
        if env.storage().persistent().has(&DataKey::Score(address.clone())) {
            return Ok(());
        }

        let data = ReputationData {
            score: BASE_SCORE,
            total_transactions: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            total_credentials: 0,
            valid_credentials: 0,
            invalid_credentials: 0,
            last_updated: env.ledger().timestamp(),
            volume: 0,
        };

        env.storage().persistent().set(&DataKey::Profile(address.clone()), &data);
        env.storage().persistent().set(&DataKey::Score(address.clone()), &BASE_SCORE);

        let mut population: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Population)
            .unwrap_or_else(|| Vec::new(&env));
        population.push_back(address);
        env.storage().persistent().set(&DataKey::Population, &population);

        Ok(())
    }

    pub fn load_profile(env: &Env, address: &Address) -> Result<ReputationData, ReputationScoreError> {
        env.storage()
            .persistent()
            .get(&DataKey::Profile(address.clone()))
            .ok_or(ReputationScoreError::NotInitialized)
    }

    pub fn update_transaction_reputation(
        env: Env,
        address: Address,
        success: bool,
        _amount: i128,
    ) -> Result<u32, ReputationScoreError> {
        let config = Self::get_config(&env);
        let mut profile = Self::load_profile(&env, &address)?;

        profile.total_transactions += 1;
        if success {
            profile.successful_transactions += 1;
            profile.score = profile.score.saturating_add(config.transaction_success_weight);
        } else {
            profile.failed_transactions += 1;
            profile.score = profile.score.saturating_sub(config.transaction_failure_weight);
        }

        if profile.score > config.max_score {
            profile.score = config.max_score;
        }

        profile.last_updated = env.ledger().timestamp();
        profile.volume = profile.volume.saturating_add(_amount.unsigned_abs() as u64);

        env.storage().persistent().set(&DataKey::Profile(address.clone()), &profile);
        env.storage().persistent().set(&DataKey::Score(address.clone()), &profile.score);

        Self::append_history(&env, &address, profile.score, Bytes::from_slice(&env, if success { b"tx_success" } else { b"tx_failure" }));

        Ok(profile.score)
    }

    pub fn update_credential_reputation(
        env: Env,
        address: Address,
        valid: bool,
        credential_type: Bytes,
    ) -> Result<u32, ReputationScoreError> {
        let config = Self::get_config(&env);
        let mut profile = Self::load_profile(&env, &address)?;

        profile.total_credentials += 1;
        if valid {
            profile.valid_credentials += 1;
            profile.score = profile.score.saturating_add(config.credential_valid_weight);
        } else {
            profile.invalid_credentials += 1;
            profile.score = profile.score.saturating_sub(config.credential_invalid_weight);
        }

        if profile.score > config.max_score {
            profile.score = config.max_score;
        }

        profile.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&DataKey::Profile(address.clone()), &profile);
        env.storage().persistent().set(&DataKey::Score(address.clone()), &profile.score);

        Self::append_history(&env, &address, profile.score, credential_type);

        Ok(profile.score)
    }

    pub fn get_reputation_history(
        env: Env,
        address: Address,
        limit: u32,
    ) -> Result<Vec<ReputationHistoryEntry>, ReputationScoreError> {
        let history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(address.clone()))
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

    pub fn get_reputation_percentile(env: Env, address: Address) -> Result<u32, ReputationScoreError> {
        let target = Self::load_profile(&env, &address)?.score;
        let population: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Population)
            .unwrap_or_else(|| Vec::new(&env));

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
        address: Address,
        threshold: u32,
    ) -> Result<bool, ReputationScoreError> {
        Ok(Self::load_profile(&env, &address)?.score >= threshold * SCORE_SCALE)
    }

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

        let timestamp = env.ledger().timestamp();
        let attestation = TrustAttestation {
            truster: truster.clone(),
            subject: subject.clone(),
            weight,
            reason,
            timestamp,
        };

        let mut attestations: Vec<TrustAttestation> = env
            .storage()
            .persistent()
            .get(&DataKey::Trust(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        attestations.push_back(attestation.clone());
        env.storage().persistent().set(&DataKey::Trust(subject), &attestations);

        Ok(attestation)
    }

    pub fn get_trust_attestations(env: Env, subject: Address) -> Vec<TrustAttestation> {
        env.storage()
            .persistent()
            .get(&DataKey::Trust(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn population(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::Population)
            .unwrap_or_else(|| Vec::new(&env))
    }

    fn append_history(env: &Env, address: &Address, score: u32, event: Bytes) {
        let mut history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(address.clone()))
            .unwrap_or_else(|| Vec::new(env));

        let entry = ReputationHistoryEntry {
            timestamp: env.ledger().timestamp(),
            score,
            event,
        };

        history.push_back(entry);

        if history.len() > MAX_HISTORY_POINTS {
            let mut trimmed: Vec<ReputationHistoryEntry> = Vec::new(env);
            let start = history.len() - MAX_HISTORY_POINTS;
            for i in start..history.len() {
                if let Some(e) = history.get(i) {
                    trimmed.push_back(e);
                }
            }
            history = trimmed;
        }

        env.storage().persistent().set(&DataKey::History(address.clone()), &history);
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
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

        let score = ReputationScore::get_reputation_score(env.clone(), user.clone());
        assert_eq!(score, BASE_SCORE);

        for _ in 0..15 {
            ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 0).unwrap();
        }
        assert_eq!(ReputationScore::get_reputation_score(env.clone(), user.clone()), 100);

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
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

        let score = ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 100).unwrap();
        assert_eq!(score, BASE_SCORE + 10);

        let score = ReputationScore::update_transaction_reputation(env.clone(), user.clone(), false, 0).unwrap();
        assert_eq!(score, BASE_SCORE + 5);
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
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

        let cred_type = Bytes::from_slice(&env, b"KYC");
        let score = ReputationScore::update_credential_reputation(env.clone(), user.clone(), true, cred_type.clone()).unwrap();
        assert_eq!(score, BASE_SCORE + 20);

        let score = ReputationScore::update_credential_reputation(env.clone(), user.clone(), false, cred_type).unwrap();
        assert_eq!(score, BASE_SCORE + 5);
    }
}
