import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Keypair,
  Contract,
  xdr,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import * as snarkjs from 'snarkjs';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  ZKProof,
  ZKCircuit,
  ZKProofOptions,
  ZKVerificationResult,
  StellarIdentityConfig,
  TransactionOptions,
  CircuitType,
  ProofGenerationInputs,
} from './types';
import { StellarIdentityError, mapContractError } from './errors';

export class ZKProofsClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private zkAttestationContract: Contract;
  private circuitCache: Map<string, any> = new Map();
  private wasmCache: Map<string, any> = new Map();
  private zkeyCache: Map<string, any> = new Map();

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.zkAttestationContract = new Contract(config.contracts.zkAttestation);
  }

  /**
   * Generate a zero-knowledge proof using WASM witness generation
   */
  async generateProof(
    circuitName: string,
    privateInputs: any,
    publicInputs: any,
    options?: { wasmPath?: string; zkeyPath?: string }
  ): Promise<{ proof: any; publicSignals: any }> {
    try {
      const wasmPath = options?.wasmPath || this.getCircuitPath(circuitName, '.wasm');
      const zkeyPath = options?.zkeyPath || this.getCircuitPath(circuitName, '.zkey');

      // Load WASM and zkey with caching
      const wasm = await this.loadWasm(wasmPath);
      const zkey = await this.loadZkey(zkeyPath);

      // Generate proof
      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        privateInputs,
        wasm,
        zkey
      );
      const generationTime = Date.now() - startTime;

      console.log(`Proof generated in ${generationTime}ms`);

      return { proof, publicSignals };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Verify a proof on-chain
   */
  async verifyProofOnChain(
    proofId: string,
    publicInputs: string[]
  ): Promise<ZKVerificationResult> {
    try {
      const retval = await this.simulateRead('verify_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      
      const isValid = scValToNative(retval) as boolean;
      const proof = await this.getProof(proofId);
      
      return {
        valid: isValid,
        circuitId: proof.circuitId,
        proofId: proof.proofId,
        verifiedAt: Date.now(),
        expiresAt: proof.expiresAt,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create high-level age proof
   */
  async createAgeProof(
    birthYear: number,
    currentYear: number,
    minAge: number,
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const age = currentYear - birthYear;
      const randomness = this.generateSalt();
      
      // Generate age commitment
      const commitment = this.generateCommitment(age.toString(), randomness);
      
      // Generate ZK proof
      const { proof, publicSignals } = await this.generateProof(
        'age_range_proof',
        {
          birth_year: birthYear,
          current_year: currentYear,
          min_age: minAge,
          randomness: this.hexToField(randomness),
        },
        {
          commitment: commitment.split(',').map((s, i) => i === 0 ? this.hexToField(s) : s),
          min_age: minAge,
        }
      );

      // Submit proof to contract
      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        `age_${birthYear}`,
        'age_range_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair,
        {
          circuitId: 'age_range_proof',
          publicInputs: [commitment, minAge.toString()],
          proofBytes,
          nullifier,
          revealedAttributes: ['age_commitment'],
          expiresAt: options?.expiresAt,
          metadata: {
            type: 'age_verification',
            minAge: minAge.toString(),
            context: options?.context || 'default',
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create high-level income proof
   */
  async createIncomeProof(
    income: number,
    minIncome: number,
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const randomness = this.generateSalt();
      const commitment = this.generateCommitment(income.toString(), randomness);
      
      const { proof, publicSignals } = await this.generateProof(
        'income_range_proof',
        {
          income: income,
          min_income: minIncome,
          randomness: this.hexToField(randomness),
        },
        {
          commitment: commitment.split(',').map((s, i) => i === 0 ? this.hexToField(s) : s),
          min_income: minIncome,
        }
      );

      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        `income_${income}`,
        'income_range_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair,
        {
          circuitId: 'income_range_proof',
          publicInputs: [commitment, minIncome.toString()],
          proofBytes,
          nullifier,
          revealedAttributes: ['income_commitment'],
          expiresAt: options?.expiresAt,
          metadata: {
            type: 'income_verification',
            minIncome: minIncome.toString(),
            context: options?.context || 'default',
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create composite KYC proof
   */
  async createKYCProof(
    credential: any,
    requiredChecks: string[],
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const inputs: any = {
        credential_id: credential.id,
        subject_private_key: this.hexToField(credential.privateKey),
        issuance_timestamp: credential.issuedAt,
        personal_info_hash: this.hexToField(credential.personalInfoHash),
        verification_score: credential.verificationScore,
        issuer_public_key: [
          this.hexToField(credential.issuerPubKey.x),
          this.hexToField(credential.issuerPubKey.y),
        ],
        subject_address: this.hexToField(credential.subjectAddress),
        expiration_timestamp: credential.expiresAt,
      };

      // Add age-specific inputs if required
      if (requiredChecks.includes('age')) {
        inputs.birth_year = credential.birthYear;
        inputs.current_year = new Date().getFullYear();
        inputs.min_age = 18;
        inputs.age_randomness = this.hexToField(this.generateSalt());
      }

      // Add country-specific inputs if required
      if (requiredChecks.includes('country')) {
        inputs.country_code = this.hexToField(credential.countryCode);
        inputs.country_merkle_proof = credential.countryMerkleProof;
        inputs.country_index = credential.countryIndex;
        inputs.country_merkle_root = this.hexToField(credential.countryMerkleRoot);
      }

      const { proof, publicSignals } = await this.generateProof(
        'kyc_composite_proof',
        inputs,
        {
          credential_hash: this.hexToField(credential.hash),
          // Add other public inputs as needed
        }
      );

      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        credential.id,
        'kyc_composite_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair,
        {
          circuitId: 'kyc_composite_proof',
          publicInputs: [credential.hash],
          proofBytes,
          nullifier,
           revealedAttributes: requiredChecks.map(check => check),

          expiresAt: options?.expiresAt,
          metadata: {
            type: 'kyc_verification',
            requiredChecks: requiredChecks.join(','),
            context: options?.context || 'default',
            credential_id: credential.id,
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create loan application proof with multiple requirements
   */
  async createLoanApplicationProof(
    application: any,
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const inputs = {
        income: application.income,
        credit_score: application.creditScore,
        employment_months: application.employmentMonths,
        debt_amount: application.debtAmount,
        residence_proof: this.hexToField(application.residenceProof),
        income_randomness: this.hexToField(this.generateSalt()),
        credit_randomness: this.hexToField(this.generateSalt()),
        employment_randomness: this.hexToField(this.generateSalt()),
        residence_randomness: this.hexToField(this.generateSalt()),
        residence_merkle_proof: application.residenceMerkleProof,
        residence_index: application.residenceIndex,
      };

      const publicInputs = {
        min_income: application.minIncome,
        min_credit_score: application.minCreditScore,
        max_debt_to_income: application.maxDebtToIncome,
        min_employment_months: application.minEmploymentMonths,
        residence_merkle_root: this.hexToField(application.residenceMerkleRoot),
      };

      const { proof, publicSignals } = await this.generateProof(
        'loan_application_composite_proof',
        inputs,
        publicInputs
      );

      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        `loan_${application.applicantId}`,
        'loan_application_composite_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair,
        {
          circuitId: 'loan_application_composite_proof',
          publicInputs: Object.values(publicInputs).map(v => v.toString()),
          proofBytes,
          nullifier,
          revealedAttributes: ['income_commitment', 'credit_commitment', 'employment_status'],
          expiresAt: options?.expiresAt,
          metadata: {
            type: 'loan_application',
            applicant_id: application.applicantId,
            loan_amount: application.loanAmount,
            context: options?.context || 'default',
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Batch generate multiple proofs for efficiency
   */
  async batchGenerateProofs(
    proofs: Array<{
      circuitName: string;
      privateInputs: any;
      publicInputs: any;
    }>
  ): Promise<Array<{ proof: any; publicSignals: any; generationTime: number }>> {
    const results = [];
    
    for (const proofRequest of proofs) {
      const startTime = Date.now();
      try {
        const result = await this.generateProof(
          proofRequest.circuitName,
          proofRequest.privateInputs,
          proofRequest.publicInputs
        );
        results.push({
          ...result,
          generationTime: Date.now() - startTime,
        });
       } catch (error: any) {
         results.push({
           proof: null,
           publicSignals: null,
           generationTime: Date.now() - startTime,
           error: error.message,
         });
       }

    }
    
    return results;
  }

  /**
   * Load WASM file with caching
   */
  private async loadWasm(wasmPath: string): Promise<any> {
    if (this.wasmCache.has(wasmPath)) {
      return this.wasmCache.get(wasmPath);
    }

    try {
      const wasmBuffer = readFileSync(wasmPath);
      const wasm = await WebAssembly.compile(wasmBuffer);
      this.wasmCache.set(wasmPath, wasm);
      return wasm;
     } catch (error: any) {
       throw new Error(`Failed to load WASM from ${wasmPath}: ${error.message}`);
     }

  }

  /**
   * Load zkey file with caching
   */
  private async loadZkey(zkeyPath: string): Promise<any> {
    if (this.zkeyCache.has(zkeyPath)) {
      return this.zkeyCache.get(zkeyPath);
    }

    try {
      const zkeyBuffer = readFileSync(zkeyPath);
      const zkey = JSON.parse(zkeyBuffer.toString());
      this.zkeyCache.set(zkeyPath, zkey);
      return zkey;
     } catch (error: any) {
       throw new Error(`Failed to load zkey from ${zkeyPath}: ${error.message}`);
     }

  }

  /**
   * Get circuit file path
   */
  private getCircuitPath(circuitName: string, extension: string): string {
    const circuitsDir = join(__dirname, '..', '..', 'circuits');
    return join(circuitsDir, `${circuitName}${extension}`);
  }

  /**
   * Convert hex string to field element
   */
  private hexToField(hex: string): string {
    // Remove 0x prefix if present
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    // Convert to decimal string
    return BigInt('0x' + cleanHex).toString();
  }

  /**
   * Generate nullifier for proof
   */
  private generateNullifier(credentialId: string, circuitId: string, context: string): string {
    const crypto = require('crypto') as typeof import('crypto');
    const data = `${credentialId}${circuitId}${context}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  async registerCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    name: string,
    description: string,
    verifierKey: string,
    publicInputCount: number,
    privateInputCount: number,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'register_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(name), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(description), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(verifierKey), { type: 'bytes' }),
            nativeToScVal(BigInt(publicInputCount), { type: 'u32' }),
            nativeToScVal(BigInt(privateInputCount), { type: 'u32' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(adminKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async submitProof(
    submitterKeypair: Keypair,
    options: ZKProofOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const account = await this.rpc.getAccount(submitterKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'submit_proof',
            nativeToScVal(new TextEncoder().encode(options.circuitId), { type: 'bytes' }),
            nativeToScVal(options.publicInputs.map(i => new TextEncoder().encode(i)), { type: 'vec' }),
            nativeToScVal(new TextEncoder().encode(options.proofBytes), { type: 'bytes' }),
            options.expiresAt != null ? nativeToScVal(BigInt(options.expiresAt), { type: 'u64' }) : xdr.ScVal.scvVoid(),
            options.metadata ? nativeToScVal(new TextEncoder().encode(JSON.stringify(options.metadata)), { type: 'bytes' }) : xdr.ScVal.scvVoid()
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(submitterKeypair);
      await this.rpc.sendTransaction(prepared);
      return `proof-${Date.now()}`;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async verifyProof(proofId: string): Promise<ZKVerificationResult> {
    try {
      const isValidVal = await this.simulateRead('verify_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      const proof = await this.getProof(proofId);
      return {
        valid: scValToNative(isValidVal) as boolean,
        circuitId: proof.circuitId,
        proofId: proof.proofId,
        verifiedAt: Date.now(),
        expiresAt: proof.expiresAt,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getProof(proofId: string): Promise<ZKProof> {
    try {
      const retval = await this.simulateRead('get_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      return this.parseZKProof(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCircuit(circuitId: string): Promise<ZKCircuit> {
    try {
      const retval = await this.simulateRead('get_circuit', [
        nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
      ]);
      return this.parseZKCircuit(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCircuitProofs(circuitId: string): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_circuit_proofs', [
        nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
      ]);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async deactivateCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'deactivate_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(adminKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async reactivateCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'reactivate_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(adminKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getActiveCircuits(): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_active_circuits', []);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async batchVerifyProofs(proofIds: string[]): Promise<ZKVerificationResult[]> {
    return Promise.all(proofIds.map(id => this.verifyProof(id)));
  }

  async submitAgeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minAge: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minAge)],
        proofBytes,
        nullifier: this.generateNullifier(`age_${minAge}`, circuitId, 'manual'),
        revealedAttributes: ['age_commitment'],
        metadata: { type: 'age_verification', minAge: String(minAge) },
      },
      txOptions
    );
  }


  async verifyAgeProof(proofId: string, minAge: number): Promise<boolean> {
    try {
      const retval = await this.simulateRead('verify_age_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
        nativeToScVal(BigInt(minAge), { type: 'u32' }),
      ]);
      return scValToNative(retval) as boolean;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async submitIncomeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minIncome: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minIncome)],
        proofBytes,
        nullifier: this.generateNullifier(`income_${minIncome}`, circuitId, 'manual'),
        revealedAttributes: ['income_commitment'],
        metadata: { type: 'income_verification', minIncome: String(minIncome) },
      },
      txOptions
    );
  }



  async submitCredentialOwnershipProof(
    submitterKeypair: Keypair,
    circuitId: string,
    credentialHash: string,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [credentialHash],
        proofBytes,
        nullifier: this.generateNullifier(credentialHash, circuitId, 'manual'),
        revealedAttributes: ['credential_ownership'],
        metadata: { type: 'credential_ownership' },
      },
      txOptions
    );
  }

  async submitRangeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minValue: number,
    maxValue: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minValue), String(maxValue)],
        proofBytes,
        nullifier: this.generateNullifier(`range_${minValue}_${maxValue}`, circuitId, 'manual'),
        revealedAttributes: ['range_verification'],
        metadata: { type: 'range_verification', min: String(minValue), max: String(maxValue) },
      },
      txOptions
    );
  }

  generateCommitment(privateData: string, salt?: string): string {
    const crypto = require('crypto') as typeof import('crypto');
    const actualSalt = salt ?? (crypto.randomBytes(32).toString('hex'));
    return crypto.createHash('sha256').update(privateData + actualSalt).digest('hex');
  }

  generateSalt(): string {
    const crypto = require('crypto') as typeof import('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;

    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.getNetworkPassphrase() })
      .addOperation(this.zkAttestationContract.call(method, ...args))
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

  private parseZKProof(raw: unknown): ZKProof {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      proofId: toStr(r[0]),
      circuitId: toStr(r[1]),
      publicInputs: Array.isArray(r[2]) ? (r[2] as unknown[]).map(toStr) : [],
      proofBytes: toStr(r[3]),
      verifyingKeyHash: toStr(r[4]),
      nullifier: toStr(r[5]),
      verifierAddress: toStr(r[6]),
      createdAt: Number(r[7] ?? 0),
      expiresAt: r[8] != null ? Number(r[8]) : undefined,
      metadata: this.parseMetadata(r[9]),
      revealedAttributes: Array.isArray(r[10]) ? (r[10] as unknown[]).map(toStr) : [],
    };
  }

  private parseZKCircuit(raw: unknown): ZKCircuit {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      circuitId: toStr(r[0]),
      name: toStr(r[1]),
      description: toStr(r[2]),
      verifierKey: toStr(r[3]),
      verifyingKeyHash: toStr(r[4]),
      publicInputCount: Number(r[5] ?? 0),
      privateInputCount: Number(r[6] ?? 0),
      createdBy: toStr(r[7]),
      createdAt: Number(r[8] ?? 0),
      active: Boolean(r[9]),
      circuitType: (r[10] as any) || CircuitType.RangeProof,
      supportedAttributes: Array.isArray(r[11]) ? (r[11] as unknown[]).map(toStr) : [],
    };
  }

  private parseMetadata(metadata: unknown): Record<string, string> {
    const result: Record<string, string> = {};
    if (metadata && typeof metadata === 'object') {
      for (const [key, value] of Object.entries(metadata as Record<string, unknown>)) {
        result[key] = value instanceof Uint8Array ? new TextDecoder().decode(value) : String(value);
      }
    }
    return result;
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
