export interface DIDDocument {
  id: string;
  controller: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  service: Service[];
  created: number;
  updated: number;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKey: string;
}

export interface Service {
  id: string;
  type: string;
  endpoint: string;
}

export interface VerifiableCredential {
  id: string;
  issuer: string;
  subject: string;
  type: string[];
  credentialData: any;
  issuanceDate: number;
  expirationDate?: number;
  revocation?: string;
  proof?: string;
}

export interface ReputationFactors {
  transactionVolume: number;
  transactionConsistency: number;
  credentialCount: number;
  credentialDiversity: number;
  accountAge: number;
  disputeHistory: number;
}

export interface ReputationData {
  did: string;
  score: number;
  transactionCount: number;
  successfulTransactions: number;
  credentialCount: number;
  validCredentials: number;
  lastUpdated: number;
  createdAt: number;
  reputationFactors: ReputationFactors;
  transactionVolumeSum: number;
  counterpartyDiversity: number;
  feeConsistency: number;
  contractInteractions: number;
  verifiedKyc: number;
  employmentCredentials: number;
  academicCredentials: number;
  selfClaimedCredentials: number;
  sanctionsMatches: number;
  credentialRevocations: number;
  disputes: number;
}

export interface ReputationHistoryPoint {
  timestamp: number;
  score: number;
  eventType: string;
}

export interface TrustEdge {
  truster: string;
  subject: string;
  weight: number;
  reason: string;
  timestamp: number;
}

export interface ReputationBreakdown {
  did: string;
  score: number;
  rawScore: number;
  percentile: number;
  tier: string;
  factors: ReputationFactors;
  penalties: {
    sanctionsMatches: number;
    credentialRevocations: number;
    disputes: number;
  };
  lastUpdated: number;
}

export interface ReputationComparison {
  didA: ReputationBreakdown;
  didB: ReputationBreakdown;
  delta: {
    score: number;
    percentile: number;
    factors: ReputationFactors;
  };
  winner: 'didA' | 'didB' | 'tie';
}

export interface ReputationTierProof {
  did: string;
  tier: string;
  scoreRange: [number, number];
  commitment: string;
  generatedAt: number;
}

export interface ZKProof {
  proofId: string;
  circuitId: string;
  publicInputs: string[];
  proofBytes: string;
  verifyingKeyHash: string;
  nullifier: string;
  verifierAddress: string;
  createdAt: number;
  expiresAt?: number;
  metadata: Record<string, string>;
  revealedAttributes: string[];
}

export interface ZKCircuit {
  circuitId: string;
  name: string;
  description: string;
  verifierKey: string;
  verifyingKeyHash: string;
  publicInputCount: number;
  privateInputCount: number;
  createdBy: string;
  createdAt: number;
  active: boolean;
  circuitType: CircuitType;
  supportedAttributes: string[];
}

export enum CircuitType {
  RangeProof = 'RangeProof',
  SetMembership = 'SetMembership',
  CredentialOwnership = 'CredentialOwnership',
  CompositeProof = 'CompositeProof',
  EqualityProof = 'EqualityProof',
}

export interface ZKAttestation {
  credentialId: string;
  proofHash: string;
  nullifier: string;
  revealedAttributes: string[];
  circuitId: string;
  createdAt: number;
  expiresAt?: number;
}

export interface NullifierRecord {
  nullifier: string;
  usedAt: number;
  context: string;
  proofId: string;
}

export interface ComplianceRecord {
  address: string;
  riskScore: number;
  sanctionsList: string[];
  lastChecked: number;
  checkCount: number;
  status: 'cleared' | 'flagged' | 'blocked';
  metadata: Record<string, string>;
}

export interface SanctionsList {
  listId: string;
  name: string;
  source: string;
  lastUpdated: number;
  active: boolean;
  entries: string[];
}

export interface StellarIdentityConfig {
  network: 'mainnet' | 'testnet' | 'futurenet';
  contracts: {
    didRegistry: string;
    credentialIssuer: string;
    reputationScore: string;
    zkAttestation: string;
    complianceFilter: string;
  };
  rpcUrl?: string;
  horizonUrl?: string;
}

export interface CreateDIDOptions {
  verificationMethods: VerificationMethod[];
  services: Service[];
}

export interface IssueCredentialOptions {
  subject: string;
  credentialType: string[];
  credentialData: any;
  expirationDate?: number;
  proof: string;
}

export interface ZKProofOptions {
  circuitId: string;
  publicInputs: string[];
  proofBytes: string;
  nullifier: string;
  revealedAttributes: string[];
  expiresAt?: number;
  metadata?: Record<string, string>;
  context?: string;
  txOptions?: TransactionOptions;
}

export interface ProofGenerationInputs {
  [key: string]: any;
}

export interface AgeProofInputs {
  birthYear: number;
  currentYear: number;
  minAge: number;
  randomness: string;
}

export interface IncomeProofInputs {
  income: number;
  minIncome: number;
  randomness: string;
}

export interface KYCCredentialInputs {
  credentialId: string;
  subjectPrivateKey: string;
  issuanceTimestamp: number;
  personalInfoHash: string;
  verificationScore: number;
  issuerPublicKey: { x: string; y: string };
  subjectAddress: string;
  expirationTimestamp: number;
  birthYear?: number;
  currentYear?: number;
  minAge?: number;
  ageRandomness?: string;
  countryCode?: string;
  countryMerkleProof?: string[][];
  countryIndex?: number;
  countryMerkleRoot?: string;
}

export interface LoanApplicationInputs {
  income: number;
  creditScore: number;
  employmentMonths: number;
  debtAmount: number;
  residenceProof: string;
  incomeRandomness: string;
  creditRandomness: string;
  employmentRandomness: string;
  residenceRandomness: string;
  residenceMerkleProof: string[][];
  residenceIndex: number;
}

export interface CircuitPerformance {
  circuitName: string;
  proofGenerationTime: number;
  verificationTime: number;
  proofSize: number;
  memoryUsage: number;
  lastUpdated: number;
}

export interface BatchProofResult {
  proofId: string;
  circuitId: string;
  success: boolean;
  generationTime: number;
  error?: string;
}

export interface ComplianceCheckOptions {
  address: string;
  updateRiskScore?: boolean;
}

export interface TransactionOptions {
  fee?: number;
  timeout?: number;
  memo?: string;
}

export type DIDMethod = 'stellar';

export interface DIDResolutionResult {
  didDocument: DIDDocument;
  resolverMetadata?: Record<string, any>;
  documentMetadata?: Record<string, any>;
}

export interface CredentialVerificationResult {
  valid: boolean;
  revoked: boolean;
  expired: boolean;
  issuer: string;
  subject: string;
  issuanceDate: number;
  expirationDate?: number;
}

export interface ReputationScoreResult {
  score: number;
  percentile: number;
  factors: Record<string, number>;
  history: number[];
  lastUpdated: number;
}

export interface ZKVerificationResult {
  valid: boolean;
  circuitId: string;
  proofId: string;
  verifiedAt: number;
  expiresAt?: number;
}

export interface ComplianceResult {
  address: string;
  status: 'cleared' | 'flagged' | 'blocked';
  riskScore: number;
  sanctionsLists: string[];
  lastChecked: number;
  recommendations: string[];
}
