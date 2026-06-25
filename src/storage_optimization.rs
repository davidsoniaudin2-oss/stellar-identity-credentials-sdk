//! Storage optimization utilities for Soroban contracts (#58).
//!
//! ## Storage Schema
//!
//! Each contract uses a namespaced enum (`DidKey`, `CredKey`, `ZkKey`,
//! `CfKey`, `DataKey`) as its storage key type, which prevents cross-contract
//! key collisions in shared-ledger deployments.
//!
//! ### DID Registry (`DidKey`)
//! | Variant              | Value type     | Storage tier |
//! |----------------------|----------------|-------------|
//! | `Doc(Bytes)`         | `DIDDocument`  | Persistent  |
//! | `Controller(Address)`| `Bytes`        | Persistent  |
//!
//! ### Credential Issuer (`CredKey`)
//! | Variant                | Value type             | Storage tier |
//! |------------------------|------------------------|-------------|
//! | `Credential(Bytes)`    | `VerifiableCredential` | Persistent  |
//! | `Status(Bytes)`        | `u8` (0=active,1=rev)  | Persistent  |
//! | `Reason(Bytes)`        | `Bytes`                | Persistent  |
//! | `IssuerCreds(Address)` | `Vec<Bytes>`           | Persistent  |
//! | `SubjectCreds(Address)`| `Vec<Bytes>`           | Persistent  |
//! | `Schema(Bytes)`        | `SchemaDefinition`     | Persistent  |
//!
//! ### Reputation Score (`DataKey`)
//! | Variant            | Value type                    | Storage tier |
//! |--------------------|-------------------------------|-------------|
//! | `Profile(Address)` | `ReputationData`              | Persistent  |
//! | `Working(Address)` | `ReputationData`              | Temporary   |
//! | `History(Address)` | `Vec<ReputationHistoryEntry>` | Persistent  |
//! | `Trust(Address)`   | `Vec<TrustAttestation>`       | Persistent  |
//! | `Population`       | `Vec<Address>`                | Persistent  |
//!
//! ### ZK Attestation (`ZkKey`)
//! | Variant               | Value type       | Storage tier |
//! |-----------------------|------------------|-------------|
//! | `Circuit(Symbol)`     | `ZKCircuit`      | Persistent  |
//! | `Proof(Bytes)`        | `ZKProof`        | Persistent  |
//! | `Nullifier(Bytes)`    | `NullifierRecord`| Persistent  |
//! | `CircuitProofs(Symbol)`| `Vec<Bytes>`    | Persistent  |
//! | `Attestation(Bytes)`  | `ZKAttestation`  | Persistent  |
//! | `ActiveCircuits`      | `Vec<Symbol>`    | Persistent  |
//!
//! ### Compliance Filter (`CfKey`)
//! | Variant                 | Value type        | Storage tier |
//! |-------------------------|-------------------|-------------|
//! | `List(Bytes)`           | `SanctionsList`   | Persistent  |
//! | `Entries(Bytes)`        | `Vec<Address>`    | Persistent  |
//! | `Screening(Address)`    | `ScreeningResult` | Persistent  |
//! | `Rule(Bytes)`           | `ComplianceRule`  | Persistent  |
//! | `Audit(Address, u64)`   | `RegulatoryReport`| Persistent  |
//! | `AuditIndex(Address)`   | `Vec<u64>`        | Persistent  |
//! | `ListIndex`             | `Vec<Bytes>`      | Persistent  |
//!
//! ### Credential Schema (`SchemaKey`)
//! | Variant                    | Value type         | Storage tier |
//! |----------------------------|--------------------|-------------|
//! | `Schema(Bytes)`            | `SchemaDefinition` | Persistent  |
//! | `Version(Bytes, u32)`      | `SchemaDefinition` | Persistent  |
//! | `LatestVersion(Bytes)`     | `u32`              | Persistent  |
//! | `SchemaIndex`              | `Vec<Bytes>`       | Persistent  |
//!
//! ## Data Packing
//!
//! - **Credential status** is stored as `u8` (0 = active, 1 = revoked)
//!   instead of a full `Bytes` string, saving ~10 bytes per credential.
//! - **DIDDocument.deactivated** remains `bool` (1 byte) in the struct.
//!   Timestamps (`created`, `updated`) are `u64`, which Soroban already
//!   encodes compactly as XDR integers.
//! - **ReputationData** uses `u32` counters and a single `u64` for volume,
//!   keeping the struct well under the 256-byte threshold for efficient
//!   single-entry storage.
//!
//! ## Lookup Optimization
//!
//! - All credential lookups use `Map`-style direct keying via enum variants
//!   rather than scanning `Vec`s.
//! - Reputation `DataKey::Working` lives in temporary storage to avoid
//!   persistent writes on every score recalculation; a checkpoint flush
//!   occurs after each `CHECKPOINT_INTERVAL`.
