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
import {
  VerifiableCredential,
  StellarIdentityConfig,
  IssueCredentialOptions,
  TransactionOptions,
  CredentialVerificationResult,
} from './types';
import { StellarIdentityError, ConfigurationError, ErrorCode, mapContractError } from './errors';
import { DIDClient } from './didClient';

export class CredentialClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private credentialIssuerContract: Contract;
  private didClient: DIDClient;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.credentialIssuerContract = new Contract(config.contracts.credentialIssuer);
    this.didClient = new DIDClient(config);
  }

  private validateInput(condition: boolean, message: string): void {
    if (!condition) {
      throw new ConfigurationError(ErrorCode.ConfigInvalidRpcUrl, message);
    }
  }

  async issueCredential(
    issuerKeypair: Keypair,
    options: IssueCredentialOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const address = issuerKeypair.publicKey();
      this.validateInput(address.length > 0, 'Keypair public key must not be empty');
      this.validateInput(this.isValidStellarAddress(options.subject), 'Invalid subject Stellar address');
      this.validateInput(options.credentialType.length > 0, 'At least one credential type required');
      this.validateInput(options.credentialType.length <= 10, 'Too many credential types (max 10)');
      this.validateInput(options.credentialData != null, 'Credential data must not be null');
      const dataStr = JSON.stringify(options.credentialData);
      this.validateInput(dataStr.length <= 10240, 'Credential data too large (max 10KB)');
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.credentialIssuerContract.call(
            'issue_credential',
            xdr.ScVal.scvAddress(new Address(options.subject).toScAddress()),
            nativeToScVal(options.credentialType.map(t => new TextEncoder().encode(t)), { type: 'vec' }),
            nativeToScVal(new TextEncoder().encode(JSON.stringify(options.credentialData)), { type: 'bytes' }),
            options.expirationDate != null ? nativeToScVal(BigInt(options.expirationDate), { type: 'u64' }) : xdr.ScVal.scvVoid(),
            nativeToScVal(new TextEncoder().encode(options.proof), { type: 'bytes' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(issuerKeypair);
      const result = await this.rpc.sendTransaction(prepared);

      if (result.status === 'ERROR') throw new Error(`Transaction failed: ${result.errorResult}`);
      return this.extractCredentialId(result);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async verifyCredential(credentialId: string): Promise<CredentialVerificationResult> {
    try {
      const credential = await this.getCredential(credentialId);
      const isValidVal = await this.simulateRead('verify_credential', [
        nativeToScVal(new TextEncoder().encode(credentialId), { type: 'bytes' }),
      ]);
      const statusVal = await this.simulateRead('get_credential_status', [
        nativeToScVal(new TextEncoder().encode(credentialId), { type: 'bytes' }),
      ]);

      return {
        valid: scValToNative(isValidVal) as boolean,
        revoked: scValToNative(statusVal) === 'revoked',
        expired: this.isCredentialExpired(credential),
        issuer: credential.issuer,
        subject: credential.subject,
        issuanceDate: credential.issuanceDate,
        expirationDate: credential.expirationDate,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async revokeCredential(
    issuerKeypair: Keypair,
    credentialId: string,
    reason?: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const address = issuerKeypair.publicKey();
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.credentialIssuerContract.call(
            'revoke_credential',
            nativeToScVal(new TextEncoder().encode(credentialId), { type: 'bytes' }),
            reason != null ? nativeToScVal(new TextEncoder().encode(reason), { type: 'bytes' }) : xdr.ScVal.scvVoid()
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(issuerKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCredential(credentialId: string): Promise<VerifiableCredential> {
    try {
      const retval = await this.simulateRead('get_credential', [
        nativeToScVal(new TextEncoder().encode(credentialId), { type: 'bytes' }),
      ]);
      return this.parseCredential(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getIssuerCredentials(issuerAddress: string): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_issuer_credentials', [
        xdr.ScVal.scvAddress(new Address(issuerAddress).toScAddress()),
      ]);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getSubjectCredentials(subjectAddress: string): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_subject_credentials', [
        xdr.ScVal.scvAddress(new Address(subjectAddress).toScAddress()),
      ]);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCredentialStatus(credentialId: string): Promise<string> {
    try {
      const retval = await this.simulateRead('get_credential_status', [
        nativeToScVal(new TextEncoder().encode(credentialId), { type: 'bytes' }),
      ]);
      const raw = scValToNative(retval);
      return raw instanceof Uint8Array ? new TextDecoder().decode(raw) : String(raw);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async batchVerifyCredentials(credentialIds: string[]): Promise<CredentialVerificationResult[]> {
    return Promise.all(credentialIds.map(id => this.verifyCredential(id)));
  }

  async getRevocationReason(credentialId: string): Promise<string | null> {
    try {
      const retval = await this.simulateRead('get_revocation_reason', [
        nativeToScVal(new TextEncoder().encode(credentialId), { type: 'bytes' }),
      ]);
      const raw = scValToNative(retval);
      if (!raw) return null;
      return raw instanceof Uint8Array ? new TextDecoder().decode(raw) : String(raw);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async createPresentation(
    credentials: VerifiableCredential[],
    holderKeypair: Keypair,
    domain?: string,
    challenge?: string
  ): Promise<Record<string, unknown>> {
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      holder: this.didClient.generateDID(holderKeypair.publicKey()),
      verifiableCredential: credentials,
      proof: await this.createPresentationProof(holderKeypair, domain, challenge),
    };
  }

  async verifyPresentation(presentation: Record<string, unknown>): Promise<boolean> {
    try {
      const proofValid = await this.verifyPresentationProof(
        presentation.proof,
        presentation.holder as string
      );
      if (!proofValid) return false;

      const creds = presentation.verifiableCredential as VerifiableCredential[];
      const verifications = await Promise.all(creds.map(c => this.verifyCredential(c.id)));
      return verifications.every(v => v.valid);
    } catch {
      return false;
    }
  }

  async issueKYCCredential(
    issuerKeypair: Keypair,
    subjectAddress: string,
    kycData: {
      firstName: string;
      lastName: string;
      dateOfBirth: string;
      nationality: string;
      documentType: string;
      documentNumber: string;
      expiryDate: string;
    },
    expirationDate?: number,
    txOptions?: TransactionOptions
  ): Promise<string> {
    const credentialData = {
      type: 'KYCVerification',
      data: kycData,
      verificationLevel: 'Standard',
      issuedBy: issuerKeypair.publicKey(),
      timestamp: Date.now(),
    };

    return this.issueCredential(
      issuerKeypair,
      {
        subject: subjectAddress,
        credentialType: ['KYCVerification', 'VerifiableCredential'],
        credentialData,
        expirationDate: expirationDate ?? Date.now() + 365 * 24 * 60 * 60 * 1000,
        proof: await this.generateProof(credentialData, issuerKeypair),
      },
      txOptions
    );
  }

  async issueEducationCredential(
    issuerKeypair: Keypair,
    subjectAddress: string,
    educationData: {
      degree: string;
      institution: string;
      fieldOfStudy: string;
      graduationDate: string;
      gpa?: number;
    },
    expirationDate?: number,
    txOptions?: TransactionOptions
  ): Promise<string> {
    const credentialData = {
      type: 'EducationCredential',
      data: educationData,
      issuedBy: issuerKeypair.publicKey(),
      timestamp: Date.now(),
    };

    return this.issueCredential(
      issuerKeypair,
      {
        subject: subjectAddress,
        credentialType: ['EducationCredential', 'VerifiableCredential'],
        credentialData,
        expirationDate: expirationDate ?? Date.now() + 10 * 365 * 24 * 60 * 60 * 1000,
        proof: await this.generateProof(credentialData, issuerKeypair),
      },
      txOptions
    );
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;

    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.getNetworkPassphrase() })
      .addOperation(this.credentialIssuerContract.call(method, ...args))
      .setTimeout(30)
      .build();

    const sim = await this.rpc.simulateTransaction(tx);
    if (SorobanRpc.Api.isSimulationError(sim)) {
      throw new Error((sim as SorobanRpc.Api.SimulateTransactionErrorResponse).error);
    }
    const retval = (sim as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
    if (!retval) throw new Error('No return value from contract');
    return retval;
  }

  private parseCredential(raw: unknown): VerifiableCredential {
    const r = raw as Record<string, unknown>;
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      id: toStr(r[0] ?? r.id),
      issuer: toStr(r[1] ?? r.issuer),
      subject: toStr(r[2] ?? r.subject),
      type: Array.isArray(r[3] ?? r.type) ? ((r[3] ?? r.type) as unknown[]).map(toStr) : [],
      credentialData: JSON.parse(toStr(r[4] ?? r.credential_data) || '{}'),
      issuanceDate: Number(r[5] ?? r.issuance_date ?? 0),
      expirationDate: r[6] ?? r.expiration_date ? Number(r[6] ?? r.expiration_date) : undefined,
      revocation: r[7] ?? r.revocation ? toStr(r[7] ?? r.revocation) : undefined,
      proof: r[8] ?? r.proof ? toStr(r[8] ?? r.proof) : undefined,
    };
  }

  private isCredentialExpired(credential: VerifiableCredential): boolean {
    return credential.expirationDate != null && Date.now() > credential.expirationDate;
  }

  private extractCredentialId(_result: unknown): string {
    return `cred-${Date.now()}`;
  }

  private async createPresentationProof(
    keypair: Keypair,
    domain?: string,
    challenge?: string
  ): Promise<Record<string, string>> {
    const message = JSON.stringify({ domain: domain ?? '', challenge: challenge ?? '', timestamp: Date.now() });
    const sig = Array.from(keypair.sign(Buffer.from(message)) as Uint8Array)
      .map((b: number) => b.toString(16).padStart(2, '0')).join('');

    return {
      type: 'Ed25519Signature2018',
      created: new Date().toISOString(),
      verificationMethod: `${this.didClient.generateDID(keypair.publicKey())}#key-1`,
      proofPurpose: 'authentication',
      domain: domain ?? '',
      challenge: challenge ?? '',
      jws: sig,
    };
  }

  private async verifyPresentationProof(proof: unknown, _holder: string): Promise<boolean> {
    const p = proof as Record<string, string>;
    return p?.type === 'Ed25519Signature2018' && Boolean(p?.jws);
  }

  private async generateProof(data: unknown, keypair: Keypair): Promise<string> {
    const message = JSON.stringify(data);
    return Array.from(keypair.sign(Buffer.from(message)) as Uint8Array)
      .map((b: number) => b.toString(16).padStart(2, '0')).join('');
  }

  private isValidStellarAddress(address: string): boolean {
    try { Address.fromString(address); return true; } catch { return false; }
  }

  private getDefaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }

  private getNetworkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet': return Networks.PUBLIC;
      case 'futurenet': return Networks.FUTURENET;
      default: return Networks.TESTNET;
    }
  }

  private handleError(error: unknown): StellarIdentityError {
    return mapContractError(error);
  }
}
