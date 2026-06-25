use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Vec,
};

use crate::{clamp_page_size, PaginatedAddresses};

const COMPLIANCE_TTL_LEDGERS: u32 = 6_307_200;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ComplianceFilterError {
    AddressBlocked    = 1,
    HighRisk          = 2,
    Unauthorized      = 3,
    NotFound          = 4,
    InvalidRiskScore  = 5,
    OracleStale       = 6,
    InvalidHash       = 7,
}

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum CfKey {
    List(Bytes),
    Entries(Bytes),
    Screening(Address),
    Rule(Bytes),
    Audit(Address, u64),
    AuditIndex(Address),
    ListIndex,
}

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct SanctionsList {
    pub source: Bytes,
    pub last_updated: u64,
    pub hash: BytesN<32>,
    pub active: bool,
    pub entry_count: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct ScreeningResult {
    pub address: Address,
    pub status: Bytes,
    pub risk_score: u32,
    pub matches: Vec<Bytes>,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct ComplianceRule {
    pub jurisdiction: Bytes,
    pub requirement: Bytes,
    pub enforcement: Bytes,
    pub active: bool,
    pub created: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct RegulatoryReport {
    pub subject: Address,
    pub activity_summary: Bytes,
    pub risk_flags: Bytes,
    pub timestamp: u64,
    pub ledger_sequence: u32,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ComplianceFilter;

#[contractimpl]
impl ComplianceFilter {
    // -----------------------------------------------------------------------
    // Sanctions list management
    // -----------------------------------------------------------------------

    pub fn update_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
        hash: BytesN<32>,
        entry_count: u32,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();

        let list = SanctionsList {
            source: source.clone(),
            last_updated: env.ledger().timestamp(),
            hash,
            active: true,
            entry_count,
        };

        let k = CfKey::List(source.clone());
        env.storage().persistent().set(&k, &list);
        env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);

        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CfKey::ListIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let mut found = false;
        for s in index.iter() {
            if s == source {
                found = true;
                break;
            }
        }
        if !found {
            index.push_back(source);
            env.storage().persistent().set(&CfKey::ListIndex, &index);
            env.storage().persistent().extend_ttl(&CfKey::ListIndex, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
        }

        Ok(())
    }

    pub fn load_list_entries(
        env: Env,
        admin: Address,
        source: Bytes,
        entries: Vec<Address>,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();

        if !env.storage().persistent().has(&CfKey::List(source.clone())) {
            return Err(ComplianceFilterError::NotFound);
        }

        let k = CfKey::Entries(source);
        env.storage().persistent().set(&k, &entries);
        env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
        Ok(())
    }

    pub fn deactivate_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        let k = CfKey::List(source);
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&k)
            .ok_or(ComplianceFilterError::NotFound)?;
        list.active = false;
        list.last_updated = env.ledger().timestamp();
        env.storage().persistent().set(&k, &list);
        Ok(())
    }

    pub fn get_sanctions_list(env: Env, source: Bytes) -> Option<SanctionsList> {
        env.storage().persistent().get(&CfKey::List(source))
    }

    // -----------------------------------------------------------------------
    // Paginated sanctions list entries (#56)
    // -----------------------------------------------------------------------

    pub fn get_sanctioned_addresses(
        env: Env,
        page: u32,
        page_size: u32,
    ) -> PaginatedAddresses {
        let sources: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CfKey::ListIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let mut all_addresses: Vec<Address> = Vec::new(&env);
        for source in sources.iter() {
            let list: Option<SanctionsList> = env
                .storage()
                .persistent()
                .get(&CfKey::List(source.clone()));
            if let Some(l) = list {
                if !l.active {
                    continue;
                }
                let entries: Vec<Address> = env
                    .storage()
                    .persistent()
                    .get(&CfKey::Entries(source))
                    .unwrap_or_else(|| Vec::new(&env));
                for entry in entries.iter() {
                    all_addresses.push_back(entry);
                }
            }
        }

        Self::paginate_addresses(&env, &all_addresses, page, page_size)
    }

    // -----------------------------------------------------------------------
    // Screening
    // -----------------------------------------------------------------------

    pub fn screen_address(
        env: Env,
        address: Address,
    ) -> Result<ScreeningResult, ComplianceFilterError> {
        let (result, blocked) = Self::run_screening(&env, &address);

        let sk = CfKey::Screening(address.clone());
        env.storage().persistent().set(&sk, &result);
        env.storage().persistent().extend_ttl(&sk, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);

        Self::append_audit(
            &env,
            &address,
            b"screen_address",
            &result.risk_flags_bytes(&env),
        );

        if blocked {
            return Err(ComplianceFilterError::AddressBlocked);
        }
        if result.risk_score > 70 {
            return Err(ComplianceFilterError::HighRisk);
        }

        Ok(result)
    }

    pub fn screen_did(
        env: Env,
        did_bytes: Bytes,
    ) -> Result<ScreeningResult, ComplianceFilterError> {
        let address = Self::did_bytes_to_address(&env, &did_bytes)?;
        Self::screen_address(env, address)
    }

    pub fn update_risk_score(
        env: Env,
        oracle: Address,
        address: Address,
        new_score: u32,
        reason: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        oracle.require_auth();
        if new_score > 100 {
            return Err(ComplianceFilterError::InvalidRiskScore);
        }

        let sk = CfKey::Screening(address.clone());
        let mut result: ScreeningResult = env
            .storage()
            .persistent()
            .get(&sk)
            .unwrap_or_else(|| ScreeningResult {
                address: address.clone(),
                status: Bytes::from_slice(&env, b"clear"),
                risk_score: 0,
                matches: Vec::new(&env),
                timestamp: 0,
            });

        result.risk_score = new_score;
        result.status = Self::status_from_score(&env, new_score, !result.matches.is_empty());
        result.timestamp = env.ledger().timestamp();

        env.storage().persistent().set(&sk, &result);
        env.storage().persistent().extend_ttl(&sk, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);

        Self::append_audit(&env, &address, b"risk_score_update", &reason);
        Ok(())
    }

    pub fn get_screening_result(env: Env, address: Address) -> Option<ScreeningResult> {
        env.storage().persistent().get(&CfKey::Screening(address))
    }

    // -----------------------------------------------------------------------
    // Compliance rules
    // -----------------------------------------------------------------------

    pub fn register_compliance_rule(
        env: Env,
        admin: Address,
        jurisdiction: Bytes,
        requirement: Bytes,
        enforcement: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        let rule = ComplianceRule {
            jurisdiction: jurisdiction.clone(),
            requirement,
            enforcement,
            active: true,
            created: env.ledger().timestamp(),
        };
        let k = CfKey::Rule(jurisdiction);
        env.storage().persistent().set(&k, &rule);
        env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
        Ok(())
    }

    pub fn get_compliance_rule(env: Env, jurisdiction: Bytes) -> Option<ComplianceRule> {
        env.storage().persistent().get(&CfKey::Rule(jurisdiction))
    }

    // -----------------------------------------------------------------------
    // Regulatory reporting / audit trail
    // -----------------------------------------------------------------------

    pub fn file_regulatory_report(
        env: Env,
        reporter: Address,
        subject: Address,
        activity_summary: Bytes,
        risk_flags: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        reporter.require_auth();
        let ts = env.ledger().timestamp();
        let report = RegulatoryReport {
            subject: subject.clone(),
            activity_summary,
            risk_flags,
            timestamp: ts,
            ledger_sequence: env.ledger().sequence(),
        };
        let k = CfKey::Audit(subject.clone(), ts);
        if !env.storage().persistent().has(&k) {
            env.storage().persistent().set(&k, &report);
            env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
            Self::append_audit_ts(&env, &subject, ts);
        }
        Ok(())
    }

    pub fn get_audit_trail(env: Env, subject: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&CfKey::AuditIndex(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_regulatory_report(env: Env, subject: Address, timestamp: u64) -> Option<RegulatoryReport> {
        env.storage().persistent().get(&CfKey::Audit(subject, timestamp))
    }

    // -----------------------------------------------------------------------
    // Batch operations
    // -----------------------------------------------------------------------

    pub fn batch_screen_addresses(env: Env, addresses: Vec<Address>) -> Vec<ScreeningResult> {
        let mut results = Vec::new(&env);
        for addr in addresses.iter() {
            let (result, _) = Self::run_screening(&env, &addr);
            results.push_back(result);
        }
        results
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn run_screening(env: &Env, address: &Address) -> (ScreeningResult, bool) {
        let sources: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CfKey::ListIndex)
            .unwrap_or_else(|| Vec::new(env));

        let mut matches: Vec<Bytes> = Vec::new(env);
        let mut blocked = false;

        for source in sources.iter() {
            let list: Option<SanctionsList> = env.storage().persistent().get(&CfKey::List(source.clone()));
            if let Some(l) = list {
                if !l.active {
                    continue;
                }
                let entries: Vec<Address> = env
                    .storage()
                    .persistent()
                    .get(&CfKey::Entries(source.clone()))
                    .unwrap_or_else(|| Vec::new(env));
                for entry in entries.iter() {
                    if entry == *address {
                        matches.push_back(source.clone());
                        blocked = true;
                        break;
                    }
                }
            }
        }

        let risk_score: u32 = if blocked { 100 } else { 0 };
        let status = Self::status_from_score(env, risk_score, blocked);

        let result = ScreeningResult {
            address: address.clone(),
            status,
            risk_score,
            matches,
            timestamp: env.ledger().timestamp(),
        };

        (result, blocked)
    }

    fn status_from_score(env: &Env, score: u32, blocked: bool) -> Bytes {
        if blocked || score >= 100 {
            Bytes::from_slice(env, b"blocked")
        } else if score > 70 {
            Bytes::from_slice(env, b"suspicious")
        } else {
            Bytes::from_slice(env, b"clear")
        }
    }

    fn append_audit(env: &Env, address: &Address, action: &[u8], detail: &Bytes) {
        let ts = env.ledger().timestamp();
        let mut summary = Bytes::from_slice(env, action);
        summary.append(&Bytes::from_slice(env, b":"));
        summary.append(detail);

        let report = RegulatoryReport {
            subject: address.clone(),
            activity_summary: summary,
            risk_flags: detail.clone(),
            timestamp: ts,
            ledger_sequence: env.ledger().sequence(),
        };
        let k = CfKey::Audit(address.clone(), ts);
        if !env.storage().persistent().has(&k) {
            env.storage().persistent().set(&k, &report);
            env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
            Self::append_audit_ts(env, address, ts);
        }
    }

    fn append_audit_ts(env: &Env, address: &Address, ts: u64) {
        let idx = CfKey::AuditIndex(address.clone());
        let mut timestamps: Vec<u64> = env
            .storage()
            .persistent()
            .get(&idx)
            .unwrap_or_else(|| Vec::new(env));
        timestamps.push_back(ts);
        env.storage().persistent().set(&idx, &timestamps);
        env.storage().persistent().extend_ttl(&idx, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
    }

    fn did_bytes_to_address(env: &Env, did: &Bytes) -> Result<Address, ComplianceFilterError> {
        let prefix_len = 12u32;
        if did.len() <= prefix_len {
            return Err(ComplianceFilterError::NotFound);
        }
        let mut addr_buf = [0u8; 56];
        let mut len = 0usize;
        for i in prefix_len..did.len() {
            let b = did.get(i).unwrap_or(0);
            if b == b':' {
                break;
            }
            if len < 56 {
                addr_buf[len] = b;
                len += 1;
            }
        }
        let addr_str = core::str::from_utf8(&addr_buf[..len]).unwrap_or("");
        Ok(Address::from_str(env, addr_str))
    }

    fn paginate_addresses(
        env: &Env,
        items: &Vec<Address>,
        page: u32,
        page_size: u32,
    ) -> PaginatedAddresses {
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

        PaginatedAddresses {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }
}

impl ScreeningResult {
    fn risk_flags_bytes(&self, env: &Env) -> Bytes {
        if self.matches.is_empty() {
            Bytes::from_slice(env, b"none")
        } else {
            let mut out = Bytes::from_slice(env, b"matched:");
            for m in self.matches.iter() {
                out.append(&m);
                out.append(&Bytes::from_slice(env, b","));
            }
            out
        }
    }
}
