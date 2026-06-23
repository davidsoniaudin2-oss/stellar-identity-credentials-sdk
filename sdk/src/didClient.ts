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
  DIDDocument,
  VerificationMethod,
  Service,
  StellarIdentityConfig,
  CreateDIDOptions,
  TransactionOptions,
  DIDResolutionResult,
} from './types';
import {
  StellarIdentityError,
  DIDError,
  ConfigurationError,
  ErrorCode,
  mapContractError,
} from './errors';

export class DIDClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private didRegistryContract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.didRegistryContract = new Contract(config.contracts.didRegistry);
  }

  private validateInput(condition: boolean, message: string): void {
    if (!condition) {
      throw new ConfigurationError(ErrorCode.ConfigInvalidRpcUrl, message);
    }
  }

  async createDID(
    keypair: Keypair,
    options: CreateDIDOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const address = keypair.publicKey();
      this.validateInput(address.length > 0, 'Keypair public key must not be empty');
      this.validateInput(options.verificationMethods.length <= 20, 'Too many verification methods (max 20)');
      this.validateInput(options.services.length <= 20, 'Too many services (max 20)');

      for (const vm of options.verificationMethods) {
        this.validateInput(vm.id.length <= 256, 'Verification method ID too long (max 256 chars)');
        this.validateInput(vm.type.length <= 64, 'Verification method type too long (max 64 chars)');
        this.validateInput(this.isValidStellarAddress(vm.controller), 'Invalid controller address in verification method');
      }

      for (const svc of options.services) {
        this.validateInput(svc.id.length <= 256, 'Service ID too long (max 256 chars)');
        this.validateInput(svc.endpoint.length <= 1024, 'Service endpoint too long (max 1024 chars)');
      }

      const did = this.generateDID(address);
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call(
            'create_did',
            xdr.ScVal.scvAddress(new Address(address).toScAddress()),
            nativeToScVal(new TextEncoder().encode(did), { type: 'bytes' }),
            nativeToScVal(options.verificationMethods.map(vm => ({
              id: new TextEncoder().encode(vm.id),
              type_: new TextEncoder().encode(vm.type),
              controller: new Address(vm.controller),
              public_key: Uint8Array.from((vm.publicKey.match(/.{2}/g) ?? []).map(b => parseInt(b, 16))),
            })), { type: 'vec' }),
            nativeToScVal(options.services.map(s => ({
              id: new TextEncoder().encode(s.id),
              type_: new TextEncoder().encode(s.type),
              endpoint: new TextEncoder().encode(s.endpoint),
            })), { type: 'vec' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(keypair);
      const result = await this.rpc.sendTransaction(prepared);

      if (result.status === 'ERROR') throw new Error(`Transaction failed: ${result.errorResult}`);
      return did;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async resolveDID(did: string): Promise<DIDResolutionResult> {
    try {
      const retval = await this.simulateRead('resolve_did', [
        nativeToScVal(new TextEncoder().encode(did), { type: 'bytes' }),
      ]);
      const raw = scValToNative(retval) as Record<string, unknown>;
      const didDocument = this.parseDIDDocument(raw, did);

      return {
        didDocument,
        resolverMetadata: { method: 'stellar', network: this.config.network },
        documentMetadata: {
          created: didDocument.created,
          updated: didDocument.updated,
        },
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async updateDID(
    keypair: Keypair,
    verificationMethods?: VerificationMethod[],
    services?: Service[],
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const address = keypair.publicKey();
      const account = await this.rpc.getAccount(address);

      const methodsScVal = verificationMethods
        ? xdr.ScVal.scvVec([nativeToScVal(verificationMethods.map(vm => ({
            id: new TextEncoder().encode(vm.id),
            type_: new TextEncoder().encode(vm.type),
            controller: new Address(vm.controller),
            public_key: Uint8Array.from((vm.publicKey.match(/.{2}/g) ?? []).map(b => parseInt(b, 16))),
          })), { type: 'vec' })])
        : xdr.ScVal.scvVoid();

      const servicesScVal = services
        ? xdr.ScVal.scvVec([nativeToScVal(services.map(s => ({
            id: new TextEncoder().encode(s.id),
            type_: new TextEncoder().encode(s.type),
            endpoint: new TextEncoder().encode(s.endpoint),
          })), { type: 'vec' })])
        : xdr.ScVal.scvVoid();

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call(
            'update_did',
            xdr.ScVal.scvAddress(new Address(address).toScAddress()),
            methodsScVal,
            servicesScVal
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(keypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async deactivateDID(keypair: Keypair, txOptions?: TransactionOptions): Promise<void> {
    try {
      const address = keypair.publicKey();
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call(
            'deactivate_did',
            xdr.ScVal.scvAddress(new Address(address).toScAddress())
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(keypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async addAuthentication(
    keypair: Keypair,
    authenticationMethod: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const address = keypair.publicKey();
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call(
            'add_authentication',
            xdr.ScVal.scvAddress(new Address(address).toScAddress()),
            nativeToScVal(new TextEncoder().encode(authenticationMethod), { type: 'bytes' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(keypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async removeAuthentication(
    keypair: Keypair,
    authenticationMethod: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const address = keypair.publicKey();
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call(
            'remove_authentication',
            xdr.ScVal.scvAddress(new Address(address).toScAddress()),
            nativeToScVal(new TextEncoder().encode(authenticationMethod), { type: 'bytes' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(keypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async didExists(did: string): Promise<boolean> {
    try {
      const retval = await this.simulateRead('did_exists', [
        nativeToScVal(new TextEncoder().encode(did), { type: 'bytes' }),
      ]);
      return scValToNative(retval) as boolean;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getControllerDID(address: string): Promise<string | null> {
    try {
      const retval = await this.simulateRead('get_controller_did', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      const raw = scValToNative(retval);
      if (!raw) return null;
      return raw instanceof Uint8Array ? new TextDecoder().decode(raw) : String(raw);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  validateDIDFormat(did: string): boolean {
    return did.startsWith('did:stellar:') && this.isValidStellarAddress(did.substring(12).split(':')[0]);
  }

  generateDID(address: string, suffix?: string): string {
    if (!this.isValidStellarAddress(address)) throw new Error('Invalid Stellar address');
    return suffix ? `did:stellar:${address}:${suffix}` : `did:stellar:${address}`;
  }

  extractStellarAddress(did: string): string {
    if (!this.validateDIDFormat(did)) throw new Error('Invalid DID format');
    return did.substring(12).split(':')[0];
  }

  async resolveDIDWithTOML(did: string): Promise<DIDDocument> {
    const stellarAddress = this.extractStellarAddress(did);
    const toml = await this.fetchStellarTOML(stellarAddress);
    return this.parseDIDFromTOML(toml, stellarAddress);
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    const account = {
      accountId: () => dummy.publicKey(),
      sequenceNumber: () => '0',
      incrementSequenceNumber: () => {},
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any;

    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.getNetworkPassphrase(),
    })
      .addOperation(this.didRegistryContract.call(method, ...args))
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

  private parseDIDDocument(raw: Record<string, unknown>, did: string): DIDDocument {
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      id: toStr(raw.id) || did,
      controller: toStr(raw.controller),
      verificationMethod: Array.isArray(raw.verification_method)
        ? raw.verification_method.map((vm: unknown) => {
            const v = vm as Record<string, unknown>;
            return {
              id: toStr(v.id),
              type: toStr(v.type_),
              controller: toStr(v.controller),
              publicKey: Array.from((v.public_key as Uint8Array) ?? [])
                .map((b: number) => b.toString(16).padStart(2, '0')).join(''),
            };
          })
        : [],
      authentication: Array.isArray(raw.authentication) ? raw.authentication.map(toStr) : [],
      service: Array.isArray(raw.service)
        ? raw.service.map((s: unknown) => {
            const sv = s as Record<string, unknown>;
            return { id: toStr(sv.id), type: toStr(sv.type_), endpoint: toStr(sv.endpoint) };
          })
        : [],
      created: Number(raw.created ?? 0),
      updated: Number(raw.updated ?? 0),
    };
  }

  private async fetchStellarTOML(address: string): Promise<Record<string, string>> {
    const domain = this.getDomainFromAddress(address);
    const response = await fetch(`https://${domain}/.well-known/stellar.toml`);
    const text = await response.text();
    return this.parseTOML(text);
  }

  private getDomainFromAddress(_address: string): string {
    return 'stellar.org';
  }

  private parseTOML(text: string): Record<string, string> {
    const result: Record<string, string> = {};
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const eq = trimmed.indexOf('=');
        if (eq !== -1) {
          result[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim().replace(/"/g, '');
        }
      }
    }
    return result;
  }

  private parseDIDFromTOML(toml: Record<string, string>, address: string): DIDDocument {
    return {
      id: `did:stellar:${address}`,
      controller: toml['ACCOUNTS'] || address,
      verificationMethod: [],
      authentication: [],
      service: [],
      created: Date.now(),
      updated: Date.now(),
    };
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
