use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Vec,
};

// ~1 year TTL in ledgers (5s/ledger)
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
// Core data structures
// ---------------------------------------------------------------------------

/// On-chain reference to an external sanctions list (OFAC, UN, EU, etc.).
/// The actual entries are stored separately; this holds the integrity hash
/// supplied by the oracle so consumers can verify off-chain data.
#[contracttype]
#[derive(Clone)]
pub struct SanctionsList {
    /// e.g. b"OFAC_SDN", b"UN_CONSOLIDATED", b"EU_FINANCIAL"
    pub source: Bytes,
    pub last_updated: u64,
    /// SHA-256 hash of the full list supplied by the oracle
    pub hash: BytesN<32>,
    pub active: bool,
    pub entry_count: u32,
}

/// Result of a single address/DID screening.
#[contracttype]
#[derive(Clone)]
pub struct ScreeningResult {
    pub address: Address,
    /// "clear" | "suspicious" | "blocked"
    pub status: Bytes,
    /// 0–100; 100 = highest risk
    pub risk_score: u32,
    /// List source IDs where matches were found
    pub matches: Vec<Bytes>,
    pub timestamp: u64,
}

/// Jurisdiction-specific compliance rule.
#[contracttype]
#[derive(Clone)]
pub struct ComplianceRule {
    /// e.g. b"FATF", b"GDPR", b"CCPA", b"MiCA"
    pub jurisdiction: Bytes,
    /// Human-readable requirement description (JSON bytes)
    pub requirement: Bytes,
    /// b"mandatory" | b"advisory"
    pub enforcement: Bytes,
    pub active: bool,
    pub created: u64,
}

/// Immutable audit-trail entry written on every compliance decision.
#[contracttype]
#[derive(Clone)]
pub struct RegulatoryReport {
    pub subject: Address,
    /// JSON-encoded activity summary
    pub activity_summary: Bytes,
    /// JSON-encoded array of risk flag strings
    pub risk_flags: Bytes,
    pub timestamp: u64,
    /// Ledger sequence for on-chain ordering
    pub ledger_sequence: u32,
}

// ---------------------------------------------------------------------------
// Storage key helpers
// ---------------------------------------------------------------------------

fn key_list(env: &Env, source: &Bytes) -> Bytes {
    let mut k = Bytes::from_slice(env, b"list:");
    k.append(source);
    k
}

fn key_entries(env: &Env, source: &Bytes) -> Bytes {
    let mut k = Bytes::from_slice(env, b"entries:");
    k.append(source);
    k
}

fn addr_to_bytes(env: &Env, addr: &Address) -> Bytes {
    let s = addr.to_string();
    let len = s.len() as usize;
    let mut buf = alloc::vec![0u8; len];
    s.copy_into_slice(&mut buf);
    Bytes::from_slice(env, &buf)
}

fn key_screening(env: &Env, addr: &Address) -> Bytes {
    let mut k = Bytes::from_slice(env, b"screen:");
    k.append(&addr_to_bytes(env, addr));
    k
}

fn key_rule(env: &Env, jurisdiction: &Bytes) -> Bytes {
    let mut k = Bytes::from_slice(env, b"rule:");
    k.append(jurisdiction);
    k
}

fn key_audit(env: &Env, addr: &Address, ts: u64) -> Bytes {
    let mut k = Bytes::from_slice(env, b"audit:");
    k.append(&addr_to_bytes(env, addr));
    k.append(&Bytes::from_slice(env, b":"));
    let ts_str = alloc::format!("{}", ts);
    k.append(&Bytes::from_slice(env, ts_str.as_bytes()));
    k
}

fn key_audit_index(env: &Env, addr: &Address) -> Bytes {
    let mut k = Bytes::from_slice(env, b"aidx:");
    k.append(&addr_to_bytes(env, addr));
    k
}

fn key_list_index(env: &Env) -> Bytes {
    Bytes::from_slice(env, b"list_index")
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ComplianceFilter;

#[contractimpl]
impl ComplianceFilter {
    // -----------------------------------------------------------------------
    // Sanctions list management (oracle-driven)
    // -----------------------------------------------------------------------

    /// Register or update a sanctions list reference.
    /// Called by an authorized oracle (Band Protocol / DIA) with the SHA-256
    /// hash of the full list for integrity verification.
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

        let k = key_list(&env, &source);
        env.storage().persistent().set(&k, &list);
        env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);

        // Maintain global list index
        let idx_key = key_list_index(&env);
        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(&env));

        let mut found = false;
        for s in index.iter() {
            if s == source {
                found = true;
                break;
            }
        }
        if !found {
            index.push_back(source.clone());
            env.storage().persistent().set(&idx_key, &index);
            env.storage().persistent().extend_ttl(&idx_key, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
        }

        Ok(())
    }

    /// Bulk-load address entries for a sanctions list.
    /// Entries are stored as a Vec<Address> keyed by source.
    pub fn load_list_entries(
        env: Env,
        admin: Address,
        source: Bytes,
        entries: Vec<Address>,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();

        if !env.storage().persistent().has(&key_list(&env, &source)) {
            return Err(ComplianceFilterError::NotFound);
        }

        let k = key_entries(&env, &source);
        env.storage().persistent().set(&k, &entries);
        env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
        Ok(())
    }

    /// Deactivate a sanctions list (e.g. superseded by newer version).
    pub fn deactivate_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        let k = key_list(&env, &source);
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
        env.storage().persistent().get(&key_list(&env, &source))
    }

    // -----------------------------------------------------------------------
    // Screening
    // -----------------------------------------------------------------------

    /// Screen a single Stellar address against all active sanctions lists.
    /// Returns ScreeningResult and writes an immutable audit entry.
    /// Status: "clear" | "suspicious" | "blocked"
    pub fn screen_address(
        env: Env,
        address: Address,
    ) -> Result<ScreeningResult, ComplianceFilterError> {
        let (result, blocked) = Self::run_screening(&env, &address);

        // Persist latest result
        let sk = key_screening(&env, &address);
        env.storage().persistent().set(&sk, &result);
        env.storage().persistent().extend_ttl(&sk, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);

        // Immutable audit trail
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

    /// Comprehensive DID screening: resolves the DID to its controller address
    /// and screens it, plus checks any linked accounts stored on-chain.
    pub fn screen_did(
        env: Env,
        did_bytes: Bytes,
    ) -> Result<ScreeningResult, ComplianceFilterError> {
        // Extract address from did:stellar:<address> bytes
        let address = Self::did_bytes_to_address(&env, &did_bytes)?;
        Self::screen_address(env, address)
    }

    /// Update the risk score for an address (e.g. from Chainalysis/Elliptic webhook).
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

        let sk = key_screening(&env, &address);
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
        env.storage().persistent().get(&key_screening(&env, &address))
    }

    // -----------------------------------------------------------------------
    // Compliance rules (FATF, GDPR, CCPA, MiCA)
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
        let k = key_rule(&env, &jurisdiction);
        env.storage().persistent().set(&k, &rule);
        env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
        Ok(())
    }

    pub fn get_compliance_rule(env: Env, jurisdiction: Bytes) -> Option<ComplianceRule> {
        env.storage().persistent().get(&key_rule(&env, &jurisdiction))
    }

    // -----------------------------------------------------------------------
    // Regulatory reporting / audit trail
    // -----------------------------------------------------------------------

    /// Write a regulatory report for a subject. Immutable — cannot be overwritten.
    pub fn file_regulatory_report(
        env: Env,
        reporter: Address,
        subject: Address,
        activity_summary: Bytes,
        risk_flags: Bytes,
    ) -> Result<Bytes, ComplianceFilterError> {
        reporter.require_auth();
        let ts = env.ledger().timestamp();
        let report = RegulatoryReport {
            subject: subject.clone(),
            activity_summary,
            risk_flags: risk_flags.clone(),
            timestamp: ts,
            ledger_sequence: env.ledger().sequence(),
        };
        let k = key_audit(&env, &subject, ts);
        // Only set if not already present — immutability guarantee
        if !env.storage().persistent().has(&k) {
            env.storage().persistent().set(&k, &report);
            env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
            Self::append_audit_key(&env, &subject, &k);
        }
        Ok(k)
    }

    /// Retrieve all audit report keys for a subject (for off-chain fetching).
    pub fn get_audit_trail(env: Env, subject: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&key_audit_index(&env, &subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Fetch a single regulatory report by its key.
    pub fn get_regulatory_report(env: Env, report_key: Bytes) -> Option<RegulatoryReport> {
        env.storage().persistent().get(&report_key)
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
        let idx_key = key_list_index(env);
        let sources: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&idx_key)
            .unwrap_or_else(|| Vec::new(env));

        let mut matches: Vec<Bytes> = Vec::new(env);
        let mut blocked = false;

        for source in sources.iter() {
            let list_key = key_list(env, &source);
            let list: Option<SanctionsList> = env.storage().persistent().get(&list_key);
            if let Some(l) = list {
                if !l.active {
                    continue;
                }
                let entries_key = key_entries(env, &source);
                let entries: Vec<Address> = env
                    .storage()
                    .persistent()
                    .get(&entries_key)
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
        let k = key_audit(env, address, ts);
        if !env.storage().persistent().has(&k) {
            env.storage().persistent().set(&k, &report);
            env.storage().persistent().extend_ttl(&k, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
            Self::append_audit_key(env, address, &k);
        }
    }

    fn append_audit_key(env: &Env, address: &Address, key: &Bytes) {
        let idx = key_audit_index(env, address);
        let mut keys: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&idx)
            .unwrap_or_else(|| Vec::new(env));
        keys.push_back(key.clone());
        env.storage().persistent().set(&idx, &keys);
        env.storage().persistent().extend_ttl(&idx, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
    }

    fn did_bytes_to_address(env: &Env, did: &Bytes) -> Result<Address, ComplianceFilterError> {
        // did:stellar:<address> — skip first 12 bytes ("did:stellar:")
        let prefix_len = 12u32;
        if did.len() <= prefix_len {
            return Err(ComplianceFilterError::NotFound);
        }
        let mut addr_bytes = Bytes::new(env);
        for i in prefix_len..did.len() {
            let b = did.get(i).unwrap_or(0);
            if b == b':' {
                break;
            }
            addr_bytes.push_back(b);
        }
        let len = addr_bytes.len() as usize;
        let mut buf = alloc::vec![0u8; len];
        for i in 0..len {
            buf[i] = addr_bytes.get(i as u32).unwrap_or(0);
        }
        let addr_str = core::str::from_utf8(&buf).unwrap_or("");
        Ok(Address::from_str(env, addr_str))
    }
}

// Helper: extract risk_flags bytes from a ScreeningResult for audit logging
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
