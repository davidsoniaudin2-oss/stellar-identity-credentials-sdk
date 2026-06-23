import {
  SorobanRpc,
  Contract,
  Keypair,
  TransactionBuilder,
  Networks,
  Address,
  xdr,
  scValToNative,
  nativeToScVal,
} from 'stellar-sdk';
import {
  DIDDocument,
  VerificationMethod,
  Service,
  StellarIdentityConfig,
  CreateDIDOptions,
  TransactionOptions,
} from './types';
import { StellarIdentityError, ErrorCode } from './errors';

export interface DIDResolutionMetadata {
  contentType?: string;
  retrieved?: string;
  error?: string;
  message?: string;
  duration?: number;
  method?: string;
  network?: string;
}

export interface DIDDocumentMetadata {
  created?: string;
  updated?: string;
  deactivated?: boolean;
  versionId?: string;
  canonicalId?: string;
  equivalentId?: string[];
}

export interface W3CResolutionResult {
  didDocument: DIDDocument | Record<string, never>;
  didResolutionMetadata: DIDResolutionMetadata;
  didDocumentMetadata: DIDDocumentMetadata;
}

export interface DereferencingResult {
  contentStream: VerificationMethod | Service | DIDDocument | null;
  contentMetadata: { contentType: string };
  dereferencingMetadata: { error?: string; message?: string };
}

interface CacheEntry {
  result: W3CResolutionResult;
  expiresAt: number;
}

const DID_STELLAR_PREFIX = 'did:stellar:';
const DEFAULT_CACHE_TTL_MS = 30_000;

export class DIDResolver {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private contract: Contract;
  private cache: Map<string, CacheEntry>;
  private cacheTtlMs: number;

  constructor(config: StellarIdentityConfig, cacheTtlMs = DEFAULT_CACHE_TTL_MS) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.defaultRpcUrl());
    this.contract = new Contract(config.contracts.didRegistry);
    this.cache = new Map();
    this.cacheTtlMs = cacheTtlMs;
  }

  async resolve(did: string): Promise<W3CResolutionResult> {
    const startMs = Date.now();

    const validationError = this.validateDIDFormat(did);
    if (validationError) {
      return this.errorResult('invalidDid', validationError, startMs);
    }

    const cached = this.cache.get(did);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.result;
    }

    try {
      const scDid = nativeToScVal(new TextEncoder().encode(did), { type: 'bytes' });
      const simResult = await this.rpc.simulateTransaction(
        await this.buildReadCall('resolve_did', [scDid])
      );

      if (SorobanRpc.Api.isSimulationError(simResult)) {
        const msg = simResult.error || 'Contract simulation error';
        if (msg.includes('NotFound')) {
          return this.errorResult('notFound', `DID not found: ${did}`, startMs);
        }
        throw new Error(msg);
      }

      const retval = (simResult as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
      if (!retval) {
        return this.errorResult('notFound', `DID not found: ${did}`, startMs);
      }

      const raw = scValToNative(retval) as Record<string, unknown>;
      const didDocument = this.parseContractDocument(raw, did);

      const docMeta: DIDDocumentMetadata = {
        created: raw.created ? new Date(Number(raw.created) * 1000).toISOString() : undefined,
        updated: raw.updated ? new Date(Number(raw.updated) * 1000).toISOString() : undefined,
        deactivated: Boolean(raw.deactivated),
        canonicalId: did,
      };

      const resMeta: DIDResolutionMetadata = {
        contentType: 'application/did+ld+json',
        retrieved: new Date().toISOString(),
        duration: Date.now() - startMs,
        method: 'stellar',
        network: this.config.network,
      };

      const resolution: W3CResolutionResult = { didDocument, didResolutionMetadata: resMeta, didDocumentMetadata: docMeta };
      this.cache.set(did, { result: resolution, expiresAt: Date.now() + this.cacheTtlMs });
      return resolution;
    } catch (err: unknown) {
      return this.errorResult('internalError', err instanceof Error ? err.message : String(err), startMs);
    }
  }

  async dereference(didUrl: string): Promise<DereferencingResult> {
    const notFound = (msg: string): DereferencingResult => ({
      contentStream: null,
      contentMetadata: { contentType: 'application/did+ld+json' },
      dereferencingMetadata: { error: 'notFound', message: msg },
    });

    const { did, fragment, query } = this.parseDIDUrl(didUrl);
    const resolution = await this.resolve(did);

    if (resolution.didResolutionMetadata.error) {
      return notFound(resolution.didResolutionMetadata.message || 'Resolution failed');
    }

    const doc = resolution.didDocument as DIDDocument;

    if (fragment) {
      const vm = doc.verificationMethod?.find(m => m.id === `${did}#${fragment}` || m.id === `#${fragment}`);
      if (vm) return { contentStream: vm, contentMetadata: { contentType: 'application/did+ld+json' }, dereferencingMetadata: {} };

      const svc = doc.service?.find(s => s.id === `${did}#${fragment}` || s.id === `#${fragment}`);
      if (svc) return { contentStream: svc, contentMetadata: { contentType: 'application/did+ld+json' }, dereferencingMetadata: {} };

      return notFound(`Fragment #${fragment} not found`);
    }

    if (query) {
      const params = new URLSearchParams(query);
      const serviceType = params.get('service');
      if (serviceType) {
        const svc = doc.service?.find(s => s.type === serviceType || s.id.includes(serviceType));
        if (svc) return { contentStream: svc, contentMetadata: { contentType: 'application/did+ld+json' }, dereferencingMetadata: {} };
        return notFound(`Service '${serviceType}' not found`);
      }
    }

    return { contentStream: doc, contentMetadata: { contentType: 'application/did+ld+json' }, dereferencingMetadata: {} };
  }

  async createDID(
    keypair: Keypair,
    options: CreateDIDOptions,
    suffix?: string,
    txOpts?: TransactionOptions
  ): Promise<string> {
    const address = keypair.publicKey();
    const did = suffix ? `${DID_STELLAR_PREFIX}${address}:${suffix}` : `${DID_STELLAR_PREFIX}${address}`;

    const account = await this.rpc.getAccount(address);

    const tx = new TransactionBuilder(account, {
      fee: String(txOpts?.fee ?? 300),
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'create_did',
          xdr.ScVal.scvAddress(new Address(address).toScAddress()),
          nativeToScVal(new TextEncoder().encode(did), { type: 'bytes' }),
          nativeToScVal(options.verificationMethods.map(vm => this.vmToScObject(vm)), { type: 'vec' }),
          nativeToScVal(options.services.map(s => this.serviceToScObject(s)), { type: 'vec' })
        )
      )
      .setTimeout(txOpts?.timeout ?? 30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(keypair);
    const result = await this.rpc.sendTransaction(prepared);

    if (result.status === 'ERROR') {
      throw this.makeError(`create_did failed: ${result.errorResult}`, ErrorCode.NetworkTransactionFailed);
    }

    this.cache.delete(did);
    return did;
  }

  async updateVerificationMethod(
    keypair: Keypair,
    did: string,
    keyType: string,
    publicKey: string,
    methodIndex = 0
  ): Promise<void> {
    const resolution = await this.resolve(did);
    if (resolution.didResolutionMetadata.error) {
      throw this.makeError(`DID not found: ${did}`, 404, 'NotFound');
    }

    const doc = resolution.didDocument as DIDDocument;
    if (doc.verificationMethod.length <= methodIndex) {
      throw this.makeError(`Method index ${methodIndex} out of range`, ErrorCode.DIDInvalidFormat);
    }

    const updatedMethods = doc.verificationMethod.map((vm, i) =>
      i !== methodIndex ? vm : { id: vm.id, type: keyType, controller: keypair.publicKey(), publicKey }
    );

    await this.submitUpdateDID(keypair, updatedMethods, doc.service);
    this.cache.delete(did);
  }

  async addService(
    keypair: Keypair,
    did: string,
    type: string,
    endpoint: string,
    id?: string
  ): Promise<void> {
    const resolution = await this.resolve(did);
    if (resolution.didResolutionMetadata.error) {
      throw this.makeError(`DID not found: ${did}`, ErrorCode.DIDNotFound);
    }

    const doc = resolution.didDocument as DIDDocument;
    const serviceId = id ?? `#${type.toLowerCase()}-${Date.now()}`;

    await this.submitUpdateDID(keypair, doc.verificationMethod, [
      ...doc.service,
      { id: serviceId, type, endpoint },
    ]);

    this.cache.delete(did);
  }

  async resolveWithTOML(did: string, domain: string): Promise<DIDDocument | null> {
    const resolution = await this.resolve(did);
    if (resolution.didResolutionMetadata.error) return null;

    const doc = resolution.didDocument as DIDDocument;
    try {
      const tomlServices = await this.fetchDIDStellarTOML(domain);
      return { ...doc, service: [...doc.service, ...tomlServices] };
    } catch {
      return doc;
    }
  }

  static addressToDID(address: string, suffix?: string): string {
    const base = `${DID_STELLAR_PREFIX}${address}`;
    return suffix ? `${base}:${suffix}` : base;
  }

  static didToAddress(did: string): string {
    if (!did.startsWith(DID_STELLAR_PREFIX)) throw new Error(`Not a did:stellar DID: ${did}`);
    const rest = did.slice(DID_STELLAR_PREFIX.length);
    const idx = rest.indexOf(':');
    return idx === -1 ? rest : rest.slice(0, idx);
  }

  static didSuffix(did: string): string | undefined {
    if (!did.startsWith(DID_STELLAR_PREFIX)) return undefined;
    const rest = did.slice(DID_STELLAR_PREFIX.length);
    const idx = rest.indexOf(':');
    return idx === -1 ? undefined : rest.slice(idx + 1);
  }

  validateDIDFormat(did: string): string | null {
    if (!did || typeof did !== 'string') return 'DID must be a non-empty string';
    if (!did.startsWith(DID_STELLAR_PREFIX)) return `DID must start with '${DID_STELLAR_PREFIX}'`;
    const address = did.slice(DID_STELLAR_PREFIX.length).split(':')[0];
    if (!address) return 'DID is missing the Stellar account address';
    if (!this.isValidStellarAddress(address)) return `'${address}' is not a valid Stellar account address`;
    return null;
  }

  clearCache(): void {
    this.cache.clear();
  }

  private async submitUpdateDID(keypair: Keypair, verificationMethods: VerificationMethod[], services: Service[]): Promise<void> {
    const address = keypair.publicKey();
    const account = await this.rpc.getAccount(address);

    const tx = new TransactionBuilder(account, {
      fee: '300',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'update_did',
          xdr.ScVal.scvAddress(new Address(address).toScAddress()),
          xdr.ScVal.scvVec([nativeToScVal(verificationMethods.map(vm => this.vmToScObject(vm)), { type: 'vec' })]),
          xdr.ScVal.scvVec([nativeToScVal(services.map(s => this.serviceToScObject(s)), { type: 'vec' })])
        )
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(keypair);
    const result = await this.rpc.sendTransaction(prepared);

    if (result.status === 'ERROR') {
      throw this.makeError(`update_did failed: ${result.errorResult}`, ErrorCode.NetworkTransactionFailed);
    }
  }

  private async buildReadCall(method: string, args: xdr.ScVal[]): Promise<import('stellar-sdk').Transaction> {
    const dummy = Keypair.random();
    const account = {
      accountId: () => dummy.publicKey(),
      sequenceNumber: () => '0',
      incrementSequenceNumber: () => {},
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any;

    return new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build() as unknown as import('stellar-sdk').Transaction;
  }

  private parseContractDocument(raw: Record<string, unknown>, did: string): DIDDocument {
    const toStr = (v: unknown): string => {
      if (v instanceof Uint8Array) return new TextDecoder().decode(v);
      return String(v ?? '');
    };

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
              publicKey: Array.from((v.public_key as Uint8Array) ?? []).map(b => b.toString(16).padStart(2, '0')).join(''),
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

  private vmToScObject(vm: VerificationMethod): Record<string, unknown> {
    return {
      id: new TextEncoder().encode(vm.id),
      type_: new TextEncoder().encode(vm.type),
      controller: new Address(vm.controller),
      public_key: Uint8Array.from(vm.publicKey.match(/.{2}/g)!.map(b => parseInt(b, 16))),
    };
  }

  private serviceToScObject(s: Service): Record<string, unknown> {
    return {
      id: new TextEncoder().encode(s.id),
      type_: new TextEncoder().encode(s.type),
      endpoint: new TextEncoder().encode(s.endpoint),
    };
  }

  private parseDIDUrl(didUrl: string): { did: string; fragment?: string; query?: string } {
    const fragIdx = didUrl.indexOf('#');
    const queryIdx = didUrl.indexOf('?');

    if (fragIdx !== -1) return { did: didUrl.slice(0, fragIdx), fragment: didUrl.slice(fragIdx + 1) };
    if (queryIdx !== -1) return { did: didUrl.slice(0, queryIdx), query: didUrl.slice(queryIdx + 1) };
    return { did: didUrl };
  }

  private async fetchDIDStellarTOML(domain: string): Promise<Service[]> {
    const response = await fetch(`https://${domain}/.well-known/did-stellar.toml`);
    if (!response.ok) return [];
    return this.parseDIDStellarTOML(await response.text());
  }

  private parseDIDStellarTOML(toml: string): Service[] {
    const services: Service[] = [];
    const block = /\[\[DID_SERVICES\]\]([\s\S]*?)(?=\[\[|$)/g;
    let match: RegExpExecArray | null;
    while ((match = block.exec(toml)) !== null) {
      const segment = match[1];
      const get = (key: string) => { const m = segment.match(new RegExp(`${key}\\s*=\\s*"([^"]+)"`)); return m ? m[1] : ''; };
      const id = get('id'), type = get('type'), endpoint = get('serviceEndpoint');
      if (id && type && endpoint) services.push({ id, type, endpoint });
    }
    return services;
  }

  private errorResult(code: string, message: string, startMs: number): W3CResolutionResult {
    return {
      didDocument: {},
      didResolutionMetadata: { error: code, message, duration: Date.now() - startMs, retrieved: new Date().toISOString() },
      didDocumentMetadata: {},
    };
  }

  private isValidStellarAddress(address: string): boolean {
    try { Address.fromString(address); return true; } catch { return false; }
  }

  private networkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet': return Networks.PUBLIC;
      case 'futurenet': return Networks.FUTURENET;
      default: return Networks.TESTNET;
    }
  }

  private defaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }

  private makeError(message: string, code: number): StellarIdentityError {
    return new StellarIdentityError(code as ErrorCode, message);
  }
}
