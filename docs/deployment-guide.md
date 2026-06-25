# Deployment & Operations Guide

## Prerequisites

- Rust toolchain (stable) with `wasm32-unknown-unknown` target
- Soroban CLI (`cargo install soroban-cli`)
- Access to Stellar testnet/mainnet RPC endpoints

## Building

```bash
# Add WASM target
rustup target add wasm32-unknown-unknown

# Build the contract
cargo build --release

# The compiled WASM will be at:
# target/wasm32-unknown-unknown/release/stellar_identity_credentials_sdk.wasm
```

## Deploying to Testnet

### 1. Install Soroban CLI

```bash
cargo install soroban-cli
```

### 2. Configure Identity

```bash
# Generate or import an identity
soroban config identity generate alice
# or
soroban config identity import alice --private-key <YOUR_PRIVATE_KEY>
```

### 3. Deploy Contract

```bash
# Deploy to testnet
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/stellar_identity_credentials_sdk.wasm \
  --source alice \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015"
```

### 4. Initialize Contract

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source alice \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015" \
  -- \
  initialize \
  --did_registry_address <DID_REGISTRY_ADDR> \
  --credential_issuer_address <CREDENTIAL_ISSUER_ADDR> \
  --reputation_score_address <REPUTATION_SCORE_ADDR> \
  --zk_attestation_address <ZK_ATTESTATION_ADDR> \
  --compliance_filter_address <COMPLIANCE_FILTER_ADDR>
```

## Deploying to Mainnet

Follow the same steps as testnet deployment, replacing the RPC URL and network passphrase:

```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/stellar_identity_credentials_sdk.wasm \
  --source alice \
  --rpc-url https://soroban-rpc.stellar.org \
  --network-passphrase "Public Global Stellar Network ; September 2015"
```

## Production Deployment Checklist

- [ ] All contract tests pass (`cargo test`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] WASM binary is optimized (`cargo build --release`)
- [ ] Contract addresses are securely stored
- [ ] Admin keys are stored in a hardware wallet or HSM
- [ ] Multi-sig is configured for admin operations
- [ ] Monitoring and alerting is set up (see below)
- [ ] Backup and recovery procedures are documented
- [ ] Rollback plan is in place

## Monitoring and Alerts

### Key Metrics to Monitor

- **Transaction throughput**: Credentials issued per hour
- **Revocation rate**: Percentage of credentials revoked
- **Storage growth**: Size of persistent storage entries
- **Gas costs**: Average gas per transaction type
- **Error rates**: Frequency of `Unauthorized`, `NotFound`, etc.

### Recommended Alerts

- **High error rate**: >5% of transactions returning errors
- **Unusual revocation activity**: Spike in revocation calls
- **Storage approaching limits**: Persistent storage TTL refresh rate
- **Contract not initialized**: Missing initialization call

## Backup and Recovery

### Backup Strategy

1. **Contract state**: Regularly call contract query functions to export state
2. **Configuration**: Store contract addresses and admin public keys securely
3. **Schema definitions**: Backup all registered credential schemas

### Recovery Procedures

1. **Lost admin key**: Revoke admin via multi-sig recovery
2. **Corrupt state**: Deploy new contract and migrate data
3. **Emergency pause**: Deactivate affected schemas and credentials

## Migration Guide

### Upgrading Contracts

Soroban contracts are immutable once deployed. To upgrade:

1. Deploy a new version of the contract
2. Migrate data from the old contract to the new one
3. Update any references to the old contract address
4. Deactivate the old contract

### Data Migration

```bash
# Export credentials from old contract
soroban contract invoke \
  --id <OLD_CONTRACT_ID> \
  --source alice \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015" \
  -- \
  get_issuer_credentials \
  --issuer <ISSUER_ADDR>

# Import into new contract
soroban contract invoke \
  --id <NEW_CONTRACT_ID> \
  --source alice \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015" \
  -- \
  issue_credential \
  --issuer <ISSUER_ADDR> \
  --subject <SUBJECT_ADDR> \
  --credential_type '["KYCVerification"]' \
  --credential_data <DATA> \
  --expiration_date <EXPIRY> \
  --proof <PROOF>
```

## Incident Response Runbook

### Credential Compromise

1. Revoke compromised credentials
2. Update revocation registry
3. Notify affected subjects
4. Issue replacement credentials

### Contract Exploit

1. Deactivate all schemas
2. Revoke all credentials issued by affected contracts
3. Deploy patched contract
4. Re-issue credentials from the new contract

### Network Outage

1. Switch to backup RPC provider
2. Queue transactions for retry
3. Monitor for transaction confirmation

## Upgrade Procedures

### Deploying a New Version

1. Build the new WASM binary
2. Deploy to testnet first
3. Run integration tests against testnet deployment
4. Deploy to mainnet
5. Migrate data
6. Deactivate old contract

### Rolling Back

1. Keep the previous contract address and WASM binary
2. Store snapshots of contract state before upgrades
3. To roll back, deploy the previous version and restore state

## Operations Checklist

### Daily
- [ ] Monitor error rates and transaction volumes
- [ ] Check for any failed transactions

### Weekly
- [ ] Review credential issuance and revocation trends
- [ ] Update sanctions lists (ComplianceFilter)
- [ ] Check storage growth and TTL refresh rates

### Monthly
- [ ] Audit all issued credentials
- [ ] Review admin access and multi-sig configurations
- [ ] Update schema versions if needed
- [ ] Run backup of contract state

### Quarterly
- [ ] Full security audit
- [ ] Penetration testing
- [ ] Review and update incident response procedures
- [ ] Compliance review for regulatory requirements
