use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol, symbol_short};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationScoreError {
    NotInitialized = 1,
    NotAdmin = 2,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationScoreUpdated {
    pub address: Address,
    pub new_score: u32,
    pub reason: Bytes,
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

        let reason = if success {
            score = score.saturating_add(config.transaction_success_weight);
            Bytes::from_array(&env, b"Transaction Success")
        } else {
            score = score.saturating_sub(config.transaction_failure_weight);
            Bytes::from_array(&env, b"Transaction Failure")
        };

        if score > config.max_score {
            score = config.max_score;
        }

        env.storage().persistent().set(&DataKey::Score(address.clone()), &score);
        env.events().publish(
            symbol_short!("reputation_updated"),
            ReputationScoreUpdated {
                address: address.clone(),
                new_score: score,
                reason: reason.clone(),
            },
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
            ReputationScoreUpdated {
                address: address.clone(),
                new_score: score,
                reason: reason.clone(),
            },
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
