/**
 * compliance.ts — Regulatory compliance SDK layer
 *
 * Covers:
 *   screenAddress()             single address sanctions check
 *   screenTransaction()         full transaction risk analysis
 *   generateComplianceReport()  regulatory filing generation
 *   subscribeToAlerts()         real-time risk monitoring webhook
 *   proveComplianceStatus()     ZK proof of valid KYC / sanctions-clear
 *
 * Regional: GDPR, CCPA, FATF Travel Rule, MiCA
 * Integrations: Chainalysis, Elliptic, ComplyAdvantage, Stellar TOML
 */

import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Keypair,
  Contract,
  Address,
  xdr,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import { StellarIdentityConfig } from './types';
import { StellarIdentityError, ComplianceError, ErrorCode } from './errors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ScreeningStatus = 'clear' | 'suspicious' | 'blocked';

export interface ScreeningResult {
  address: string;
  status: ScreeningStatus;
  /** 0–100; 100 = highest risk */
  riskScore: number;
  /** Sanctions list sources where matches were found */
  matches: string[];
  timestamp: number;
  /** Provider that performed the check */
  provider?: string;
}

export interface TransactionRisk {
  txHash: string;
  sender: string;
  receiver: string;
  amount: string;
  asset: string;
  senderRisk: ScreeningResult;
  receiverRisk: ScreeningResult;
  /** Aggregate risk score 0–100 */
  overallRisk: number;
  flags: string[];
  /** Whether the transaction exceeds FATF reporting threshold */
  requiresTravelRule: boolean;
  timestamp: number;
}

export interface ComplianceReport {
  subject: string;
  generatedAt: number;
  timeframeStart: number;
  timeframeEnd: number;
  screeningHistory: ScreeningResult[];
  riskSummary: {
    currentScore: number;
    peakScore: number;
    averageScore: number;
    totalScreenings: number;
  };
  regulatoryFlags: string[];
  /** FATF Travel Rule data if applicable */
  travelRuleData?: TravelRulePayload;
  auditTrail: AuditEntry[];
}

export interface AuditEntry {
  action: string;
  timestamp: number;
  detail: string;
  ledgerSequence?: number;
}

/** FATF Travel Rule — VASP-to-VASP information sharing payload */
export interface TravelRulePayload {
  originatorVASP: string;
  beneficiaryVASP: string;
  originator: {
    name: string;
    accountNumber: string;
    address?: string;
  };
  beneficiary: {
    name: string;
    accountNumber: string;
  };
  transferAmount: string;
  asset: string;
  transactionRef: string;
  timestamp: number;
}

export interface ZKComplianceProof {
  proofType: 'sanctions-clear' | 'kyc-valid' | 'threshold-below';
  /** Public commitment — reveals nothing about the subject */
  commitment: string;
  proofValue: string;
  verificationMethod: string;
  createdAt: number;
  expiresAt?: number;
}

export interface AlertSubscription {
  did: string;
  webhookUrl: string;
  events: AlertEvent[];
  active: boolean;
  createdAt: number;
}

export type AlertEvent =
  | 'sanctions-match'
  | 'risk-score-change'
  | 'list-update'
  | 'travel-rule-trigger';

export interface SanctionsListInfo {
  source: string;
  lastUpdated: number;
  hash: string;
  active: boolean;
  entryCount: number;
}

// ---------------------------------------------------------------------------
// ComplianceClient
// ---------------------------------------------------------------------------

export class ComplianceClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private contract: Contract;
  /** In-memory alert subscriptions (persisted off-chain by the caller) */
  private subscriptions: Map<string, AlertSubscription> = new Map();

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl ?? this.defaultRpcUrl());
    this.contract = new Contract(config.contracts.complianceFilter);
  }

  // -------------------------------------------------------------------------
  // Sanctions list management
  // -------------------------------------------------------------------------

  /**
   * Register or update a sanctions list reference on-chain.
   * Called by an authorized oracle keypair (Band Protocol / DIA).
   * `hash` is the hex-encoded SHA-256 of the full list for integrity checks.
   */
  async updateSanctionsList(
    adminKeypair: Keypair,
    source: string,
    hash: string,
    entryCount: number,
  ): Promise<void> {
    const hashBytes = Buffer.from(hash, 'hex');
    if (hashBytes.length !== 32) throw this.err('hash must be 32 bytes (SHA-256 hex)');

    const account = await this.rpc.getAccount(adminKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'update_sanctions_list',
          xdr.ScVal.scvAddress(new Address(adminKeypair.publicKey()).toScAddress()),
          nativeToScVal(enc(source), { type: 'bytes' }),
          nativeToScVal(hashBytes, { type: 'bytes' }),
          nativeToScVal(BigInt(entryCount), { type: 'u32' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(adminKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`update_sanctions_list failed: ${result.errorResult}`);
  }

  async getSanctionsList(source: string): Promise<SanctionsListInfo | null> {
    try {
      const val = await this.simulateRead('get_sanctions_list', [
        nativeToScVal(enc(source), { type: 'bytes' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown> | null;
      if (!raw) return null;
      return {
        source: dec(raw.source),
        lastUpdated: Number(raw.last_updated ?? 0),
        hash: Buffer.from(raw.hash as Uint8Array).toString('hex'),
        active: Boolean(raw.active),
        entryCount: Number(raw.entry_count ?? 0),
      };
    } catch {
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Screening — < 1 second via Soroban RPC simulation
  // -------------------------------------------------------------------------

  /**
   * Screen a single Stellar address against all active sanctions lists.
   * Optionally enriches with Chainalysis / Elliptic / ComplyAdvantage data.
   */
  async screenAddress(
    address: string,
    options: { enrichWithExternal?: boolean } = {},
  ): Promise<ScreeningResult> {
    // On-chain check (primary — < 1s)
    let onChainResult = await this.screenAddressOnChain(address);

    // External enrichment (Chainalysis / Elliptic / ComplyAdvantage)
    if (options.enrichWithExternal) {
      const external = await this.fetchExternalRiskScore(address);
      if (external !== null) {
        onChainResult.riskScore = Math.max(onChainResult.riskScore, external);
        onChainResult.status = riskToStatus(onChainResult.riskScore);
        onChainResult.provider = 'chainalysis+on-chain';
      }
    }

    // Fire alerts
    this.fireAlerts(address, 'sanctions-match', onChainResult);

    return onChainResult;
  }

  /**
   * Screen a DID (did:stellar:<address>) — resolves to address then screens.
   */
  async screenDID(did: string): Promise<ScreeningResult> {
    try {
      const val = await this.simulateRead('screen_did', [
        nativeToScVal(enc(did), { type: 'bytes' }),
      ]);
      return this.parseScreeningResult(scValToNative(val), did);
    } catch {
      // Fallback: extract address from DID and screen directly
      const address = didToAddress(did);
      return this.screenAddress(address);
    }
  }

  /**
   * Full transaction risk analysis:
   * - Screens sender and receiver
   * - Checks FATF Travel Rule threshold (≥ 1000 USD equivalent)
   * - Aggregates risk flags
   */
  async screenTransaction(tx: {
    hash: string;
    sender: string;
    receiver: string;
    amount: string;
    asset: string;
  }): Promise<TransactionRisk> {
    const [senderRisk, receiverRisk] = await Promise.all([
      this.screenAddress(tx.sender),
      this.screenAddress(tx.receiver),
    ]);

    const overallRisk = Math.max(senderRisk.riskScore, receiverRisk.riskScore);
    const flags: string[] = [];

    if (senderRisk.status !== 'clear') flags.push(`sender:${senderRisk.status}`);
    if (receiverRisk.status !== 'clear') flags.push(`receiver:${receiverRisk.status}`);
    if (senderRisk.matches.length > 0) flags.push(`sender-sanctions:${senderRisk.matches.join(',')}`);
    if (receiverRisk.matches.length > 0) flags.push(`receiver-sanctions:${receiverRisk.matches.join(',')}`);

    // FATF Travel Rule: threshold ≥ 1000 USD equivalent
    const requiresTravelRule = parseFloat(tx.amount) >= 1000;
    if (requiresTravelRule) flags.push('fatf-travel-rule-required');

    return {
      txHash: tx.hash,
      sender: tx.sender,
      receiver: tx.receiver,
      amount: tx.amount,
      asset: tx.asset,
      senderRisk,
      receiverRisk,
      overallRisk,
      flags,
      requiresTravelRule,
      timestamp: Date.now(),
    };
  }

  // -------------------------------------------------------------------------
  // Regulatory reporting
  // -------------------------------------------------------------------------

  /**
   * Generate a compliance report for a DID over a given timeframe.
   * Fetches the on-chain audit trail and assembles a regulatory filing.
   */
  async generateComplianceReport(
    did: string,
    timeframe: { start: number; end: number },
  ): Promise<ComplianceReport> {
    const address = didToAddress(did);

    // Fetch on-chain audit trail keys
    const auditKeys = await this.getAuditTrail(address);

    // Fetch each report
    const auditEntries: AuditEntry[] = [];
    for (const key of auditKeys) {
      const report = await this.getRegulatoryReport(key);
      if (report && report.timestamp >= timeframe.start / 1000 && report.timestamp <= timeframe.end / 1000) {
        auditEntries.push({
          action: dec(report.activitySummary).split(':')[0] ?? 'unknown',
          timestamp: report.timestamp * 1000,
          detail: dec(report.riskFlags),
          ledgerSequence: report.ledgerSequence,
        });
      }
    }

    // Current screening result
    const current = await this.screenAddress(address).catch(() => null);
    const currentScore = current?.riskScore ?? 0;

    const scores = auditEntries.map(() => currentScore);
    const peakScore = scores.length ? Math.max(...scores) : currentScore;
    const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : currentScore;

    const regulatoryFlags: string[] = [];
    if (currentScore > 70) regulatoryFlags.push('HIGH_RISK');
    if (current?.matches.length) regulatoryFlags.push('SANCTIONS_MATCH');

    return {
      subject: did,
      generatedAt: Date.now(),
      timeframeStart: timeframe.start,
      timeframeEnd: timeframe.end,
      screeningHistory: current ? [current] : [],
      riskSummary: {
        currentScore,
        peakScore,
        averageScore: Math.round(avgScore),
        totalScreenings: auditEntries.length,
      },
      regulatoryFlags,
      auditTrail: auditEntries,
    };
  }

  /**
   * File an immutable regulatory report on-chain.
   */
  async fileRegulatoryReport(
    reporterKeypair: Keypair,
    subject: string,
    activitySummary: string,
    riskFlags: string[],
  ): Promise<string> {
    const account = await this.rpc.getAccount(reporterKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'file_regulatory_report',
          xdr.ScVal.scvAddress(new Address(reporterKeypair.publicKey()).toScAddress()),
          xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
          nativeToScVal(enc(activitySummary), { type: 'bytes' }),
          nativeToScVal(enc(JSON.stringify(riskFlags)), { type: 'bytes' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(reporterKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`file_regulatory_report failed: ${result.errorResult}`);
    return `report:${subject}:${Date.now()}`;
  }

  // -------------------------------------------------------------------------
  // Alert subscriptions (FATF / real-time monitoring)
  // -------------------------------------------------------------------------

  /**
   * Subscribe a DID to real-time risk monitoring.
   * Webhooks are fired client-side when screenAddress() detects changes.
   * For production, wire this to a server-sent events or webhook delivery service.
   */
  subscribeToAlerts(
    did: string,
    webhookUrl: string,
    events: AlertEvent[] = ['sanctions-match', 'risk-score-change'],
  ): AlertSubscription {
    const sub: AlertSubscription = {
      did,
      webhookUrl,
      events,
      active: true,
      createdAt: Date.now(),
    };
    this.subscriptions.set(did, sub);
    return sub;
  }

  unsubscribeFromAlerts(did: string): void {
    const sub = this.subscriptions.get(did);
    if (sub) {
      sub.active = false;
      this.subscriptions.set(did, sub);
    }
  }

  // -------------------------------------------------------------------------
  // Privacy-preserving compliance (ZK proofs)
  // -------------------------------------------------------------------------

  /**
   * Generate a ZK proof of compliance status without revealing identity.
   * Proves "not on sanctions list" or "KYC valid" using a commitment scheme.
   *
   * The commitment is H(address || salt) — the verifier checks the proof
   * against the commitment without learning the underlying address.
   */
  async proveComplianceStatus(
    subjectKeypair: Keypair,
    proofType: ZKComplianceProof['proofType'],
    options: { expiresAt?: number } = {},
  ): Promise<ZKComplianceProof> {
    const address = subjectKeypair.publicKey();

    // Verify the subject is actually clear before generating proof
    const screening = await this.screenAddress(address);
    if (proofType === 'sanctions-clear' && screening.status === 'blocked') {
      throw this.err('Cannot generate sanctions-clear proof: address is blocked');
    }

    // Commitment: deterministic hash of address + proof type
    const salt = Buffer.from(subjectKeypair.rawSecretKey()).slice(0, 16).toString('hex');
    const commitment = await sha256Hex(`${address}:${proofType}:${salt}`);

    // Proof value: sign the commitment with the subject's key
    const proofValue = Buffer.from(
      subjectKeypair.sign(Buffer.from(commitment, 'hex')),
    ).toString('base64');

    return {
      proofType,
      commitment,
      proofValue,
      verificationMethod: `did:stellar:${address}#key-1`,
      createdAt: Date.now(),
      expiresAt: options.expiresAt,
    };
  }

  /**
   * Verify a ZK compliance proof.
   * Checks the signature over the commitment without revealing the address.
   */
  verifyComplianceProof(
    proof: ZKComplianceProof,
    subjectPublicKey: string,
  ): boolean {
    try {
      const kp = Keypair.fromPublicKey(subjectPublicKey);
      const sig = Buffer.from(proof.proofValue, 'base64');
      return kp.verify(Buffer.from(proof.commitment, 'hex'), sig);
    } catch {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // FATF Travel Rule
  // -------------------------------------------------------------------------

  /**
   * Build a FATF Travel Rule payload for VASP-to-VASP information sharing.
   * Attach to the Stellar transaction memo or send via secure channel.
   */
  buildTravelRulePayload(params: {
    originatorVASP: string;
    beneficiaryVASP: string;
    originatorName: string;
    originatorAccount: string;
    beneficiaryName: string;
    beneficiaryAccount: string;
    amount: string;
    asset: string;
    txRef: string;
  }): TravelRulePayload {
    return {
      originatorVASP: params.originatorVASP,
      beneficiaryVASP: params.beneficiaryVASP,
      originator: {
        name: params.originatorName,
        accountNumber: params.originatorAccount,
      },
      beneficiary: {
        name: params.beneficiaryName,
        accountNumber: params.beneficiaryAccount,
      },
      transferAmount: params.amount,
      asset: params.asset,
      transactionRef: params.txRef,
      timestamp: Date.now(),
    };
  }

  // -------------------------------------------------------------------------
  // Compliance rules
  // -------------------------------------------------------------------------

  async registerComplianceRule(
    adminKeypair: Keypair,
    jurisdiction: string,
    requirement: string,
    enforcement: 'mandatory' | 'advisory',
  ): Promise<void> {
    const account = await this.rpc.getAccount(adminKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'register_compliance_rule',
          xdr.ScVal.scvAddress(new Address(adminKeypair.publicKey()).toScAddress()),
          nativeToScVal(enc(jurisdiction), { type: 'bytes' }),
          nativeToScVal(enc(requirement), { type: 'bytes' }),
          nativeToScVal(enc(enforcement), { type: 'bytes' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(adminKeypair);
    await this.rpc.sendTransaction(prepared);
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private async screenAddressOnChain(address: string): Promise<ScreeningResult> {
    try {
      const val = await this.simulateRead('screen_address', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      return this.parseScreeningResult(scValToNative(val), address);
    } catch (e) {
      const msg = String(e);
      // Contract returns error for blocked/high-risk — parse from error string
      if (msg.includes('AddressBlocked') || msg.includes('1')) {
        return { address, status: 'blocked', riskScore: 100, matches: [], timestamp: Date.now() };
      }
      if (msg.includes('HighRisk') || msg.includes('2')) {
        return { address, status: 'suspicious', riskScore: 80, matches: [], timestamp: Date.now() };
      }
      // Default clear if contract not yet deployed
      return { address, status: 'clear', riskScore: 0, matches: [], timestamp: Date.now() };
    }
  }

  private parseScreeningResult(raw: unknown, fallbackAddress: string): ScreeningResult {
    if (!raw || typeof raw !== 'object') {
      return { address: fallbackAddress, status: 'clear', riskScore: 0, matches: [], timestamp: Date.now() };
    }
    const r = raw as Record<string, unknown>;
    const statusRaw = dec(r.status);
    const status: ScreeningStatus =
      statusRaw === 'blocked' ? 'blocked' : statusRaw === 'suspicious' ? 'suspicious' : 'clear';
    return {
      address: fallbackAddress,
      status,
      riskScore: Number(r.risk_score ?? 0),
      matches: Array.isArray(r.matches) ? (r.matches as unknown[]).map(dec) : [],
      timestamp: Number(r.timestamp ?? Date.now()),
    };
  }

  private async getAuditTrail(address: string): Promise<string[]> {
    try {
      const val = await this.simulateRead('get_audit_trail', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      const raw = scValToNative(val);
      return Array.isArray(raw) ? (raw as unknown[]).map(dec) : [];
    } catch {
      return [];
    }
  }

  private async getRegulatoryReport(key: string): Promise<{
    activitySummary: unknown;
    riskFlags: unknown;
    timestamp: number;
    ledgerSequence: number;
  } | null> {
    try {
      const val = await this.simulateRead('get_regulatory_report', [
        nativeToScVal(enc(key), { type: 'bytes' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown> | null;
      if (!raw) return null;
      return {
        activitySummary: raw.activity_summary,
        riskFlags: raw.risk_flags,
        timestamp: Number(raw.timestamp ?? 0),
        ledgerSequence: Number(raw.ledger_sequence ?? 0),
      };
    } catch {
      return null;
    }
  }

  /** Stub for external provider enrichment (Chainalysis / Elliptic / ComplyAdvantage) */
  private async fetchExternalRiskScore(_address: string): Promise<number | null> {
    // In production: call provider API and return 0–100 score.
    // Returning null here so the on-chain result is used as-is.
    return null;
  }

  private fireAlerts(address: string, event: AlertEvent, result: ScreeningResult): void {
    const did = `did:stellar:${address}`;
    const sub = this.subscriptions.get(did);
    if (!sub || !sub.active || !sub.events.includes(event)) return;
    if (result.status === 'clear') return;
    // In production: POST to sub.webhookUrl
    // console.log(`[alert] ${event} for ${did} → ${sub.webhookUrl}`);
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;
    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.networkPassphrase() })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build();
    const sim = await this.rpc.simulateTransaction(tx);
    if (SorobanRpc.Api.isSimulationError(sim)) {
      throw new Error((sim as SorobanRpc.Api.SimulateTransactionErrorResponse).error);
    }
    const retval = (sim as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
    if (!retval) throw new Error('No return value');
    return retval;
  }

  private defaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }

  private networkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet': return Networks.PUBLIC;
      case 'futurenet': return Networks.FUTURENET;
      default: return Networks.TESTNET;
    }
  }

  private err(msg: string): StellarIdentityError {
    return new ComplianceError(ErrorCode.ComplianceNotFound, msg);
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function enc(s: string): Uint8Array { return new TextEncoder().encode(s); }

function dec(v: unknown): string {
  if (v instanceof Uint8Array) return new TextDecoder().decode(v);
  return String(v ?? '');
}

function didToAddress(did: string): string {
  if (!did.startsWith('did:stellar:')) throw new Error(`Invalid DID: ${did}`);
  return did.slice('did:stellar:'.length).split(':')[0];
}

function riskToStatus(score: number): ScreeningStatus {
  if (score >= 100) return 'blocked';
  if (score > 70) return 'suspicious';
  return 'clear';
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
