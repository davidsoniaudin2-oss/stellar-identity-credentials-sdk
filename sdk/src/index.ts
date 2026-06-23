// Ambient declaration so require() compiles without @types/node installed.
/* eslint-disable no-var */
declare var require: (id: string) => any;
/* eslint-enable no-var */

import { Keypair } from 'stellar-sdk';

export { DIDClient } from './didClient';
export { CredentialClient } from './credentialClient';
export { ReputationClient } from './reputation';
export { ZKProofsClient } from './zkProofs';
export { CacheManager, DataType } from './cacheManager';
export { EventSubscriber } from './eventSubscriber';

export {
  ErrorCode,
  StellarIdentityError,
  DIDError,
  CredentialError,
  ReputationError,
  ZKProofError,
  ComplianceError,
  ConfigurationError,
  NetworkError,
  mapContractError,
  mapErrorCode,
  isDIDError,
  isCredentialError,
  isReputationError,
  isZKProofError,
  isComplianceError,
  isConfigurationError,
  isNetworkError,
} from './errors';

export { DIDResolver } from './didResolver';
export type {
  W3CResolutionResult,
  DIDResolutionMetadata,
  DIDDocumentMetadata,
  DereferencingResult,
} from './didResolver';

export type {
  DIDDocument,
  VerificationMethod,
  Service,
  VerifiableCredential,
  ReputationData,
  ReputationFactors,
  ReputationHistoryPoint,
  ReputationBreakdown,
  ReputationComparison,
  ReputationTierProof,
  TrustEdge,
  ZKProof,
  ZKCircuit,
  ComplianceRecord,
  SanctionsList,
  StellarIdentityConfig,
  CreateDIDOptions,
  IssueCredentialOptions,
  ZKProofOptions,
  ComplianceCheckOptions,
  TransactionOptions,
  DIDMethod,
  DIDResolutionResult,
  CredentialVerificationResult,
  ReputationScoreResult,
  ZKVerificationResult,
  ComplianceResult,
} from './types';

import { DIDClient } from './didClient';
import { CredentialClient } from './credentialClient';
import { ReputationClient } from './reputation';
import { ZKProofsClient } from './zkProofs';
import { CacheManager } from './cacheManager';
import { EventSubscriber } from './eventSubscriber';
import { StellarIdentityConfig } from './types';

export class StellarIdentitySDK {
  public did: DIDClient;
  public credentials: CredentialClient;
  public reputation: ReputationClient;
  public zkProofs: ZKProofsClient;
  public cache: CacheManager;
  public events: EventSubscriber;

  constructor(config: StellarIdentityConfig) {
    this.did = new DIDClient(config);
    this.credentials = new CredentialClient(config);
    this.reputation = new ReputationClient(config);
    this.zkProofs = new ZKProofsClient(config);
    this.cache = new CacheManager();
    this.events = new EventSubscriber(config);
  }

  async initializeUserIdentity(
    keypair: Keypair,
    verificationMethods: any[],
    services: any[]
  ) {
    const stellarAddress = keypair.publicKey();
    const did = await this.did.createDID(keypair, {
      verificationMethods,
      services
    });

    await this.reputation.initializeReputation(keypair);

    return {
      did,
      address: stellarAddress
    };
  }

  async getIdentityProfile(address: string) {
    const [didDocument, reputationData, credentials] = await Promise.all([
      this.did.resolveDID(this.did.generateDID(address)).catch(() => null),
      this.reputation.getReputationData(address).catch(() => null),
      this.credentials.getSubjectCredentials(address).catch(() => [])
    ]);

    return {
      address,
      didDocument,
      reputationData,
      credentialCount: credentials.length,
      credentials
    };
  }

  async performComplianceCheck(address: string) {
    const [reputationSnapshot, credentials] = await Promise.all([
      this.reputation.getReputationScore(address).catch(() => ({ score: 80 })),
      this.credentials.getSubjectCredentials(address).catch(() => [])
    ]);

    const credentialVerifications = await this.credentials.batchVerifyCredentials(credentials);
    const validCredentials = credentialVerifications.filter(v => v.valid).length;
    const revokedCredentials = credentialVerifications.filter(v => v.revoked).length;
    const expiredCredentials = credentialVerifications.filter(v => v.expired).length;

    return {
      address,
      reputationScore: reputationSnapshot.score,
      totalCredentials: credentials.length,
      validCredentials,
      revokedCredentials,
      expiredCredentials,
      complianceScore: this.calculateComplianceScore(reputationSnapshot.score, validCredentials, credentials.length),
      recommendations: this.generateComplianceRecommendations(reputationSnapshot.score, validCredentials, credentials.length)
    };
  }

  private calculateComplianceScore(reputationScore: number, validCredentials: number, totalCredentials: number): number {
    const credentialScore = totalCredentials > 0 ? (validCredentials / totalCredentials) * 50 : 0;
    return Math.min(100, reputationScore * 0.1 + credentialScore);
  }

  private generateComplianceRecommendations(reputationScore: number, validCredentials: number, totalCredentials: number): string[] {
    const recommendations: string[] = [];

    if (reputationScore < 550) {
      recommendations.push('Increase verified on-chain activity to move beyond the emerging trust tier.');
    }

    if (validCredentials < totalCredentials * 0.8) {
      recommendations.push('Refresh revoked or expired credentials to recover credential-weighted reputation.');
    }

    if (totalCredentials < 3) {
      recommendations.push('Add more verifiable credentials to improve diversity and lender confidence.');
    }

    if (recommendations.length === 0) {
      recommendations.push('Identity profile is in good standing.');
    }

    return recommendations;
  }
}
