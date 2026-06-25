export type WalletType = 'freighter' | 'xbull' | 'albedo';

export interface WalletInfo {
  type: WalletType;
  name: string;
  installed: boolean;
}

export abstract class WalletConnector {
  protected _publicKey: string | null = null;
  protected _connected = false;
  protected _network: string;

  constructor(network: string = 'testnet') {
    this._network = network;
  }

  abstract get walletType(): WalletType;
  abstract get walletName(): string;

  abstract connectWallet(): Promise<string>;
  abstract signTransaction(xdr: string): Promise<string>;
  abstract isInstalled(): Promise<boolean>;

  getPublicKey(): string | null {
    return this._publicKey;
  }

  isConnected(): boolean {
    return this._connected;
  }

  disconnect(): void {
    this._publicKey = null;
    this._connected = false;
  }
}

export class FreighterConnector extends WalletConnector {
  get walletType(): WalletType {
    return 'freighter';
  }

  get walletName(): string {
    return 'Freighter';
  }

  async isInstalled(): Promise<boolean> {
    if (typeof window === 'undefined') return false;
    const freighter = (window as any).freighterApi;
    if (!freighter) return false;
    try {
      return await freighter.isConnected();
    } catch {
      return false;
    }
  }

  async connectWallet(): Promise<string> {
    const freighter = (window as any).freighterApi;
    if (!freighter) {
      throw new Error('Freighter wallet is not installed');
    }

    const publicKey = await freighter.getPublicKey();
    if (!publicKey) {
      throw new Error('User denied Freighter connection');
    }

    this._publicKey = publicKey;
    this._connected = true;
    return publicKey;
  }

  async signTransaction(xdr: string): Promise<string> {
    if (!this._connected) {
      throw new Error('Wallet not connected');
    }

    const freighter = (window as any).freighterApi;
    if (!freighter) {
      throw new Error('Freighter wallet is not installed');
    }

    const networkPassphrase = this._network === 'mainnet'
      ? 'Public Global Stellar Network ; September 2015'
      : 'Test SDF Network ; September 2015';

    const signed = await freighter.signTransaction(xdr, {
      networkPassphrase,
    });

    return signed;
  }
}

export class XBullConnector extends WalletConnector {
  get walletType(): WalletType {
    return 'xbull';
  }

  get walletName(): string {
    return 'xBull';
  }

  async isInstalled(): Promise<boolean> {
    if (typeof window === 'undefined') return false;
    return !!(window as any).xBullSDK;
  }

  async connectWallet(): Promise<string> {
    const xBull = (window as any).xBullSDK;
    if (!xBull) {
      throw new Error('xBull wallet is not installed');
    }

    const publicKey = await xBull.connect();
    if (!publicKey) {
      throw new Error('User denied xBull connection');
    }

    this._publicKey = publicKey;
    this._connected = true;
    return publicKey;
  }

  async signTransaction(xdr: string): Promise<string> {
    if (!this._connected) {
      throw new Error('Wallet not connected');
    }

    const xBull = (window as any).xBullSDK;
    if (!xBull) {
      throw new Error('xBull wallet is not installed');
    }

    const networkPassphrase = this._network === 'mainnet'
      ? 'Public Global Stellar Network ; September 2015'
      : 'Test SDF Network ; September 2015';

    const signed = await xBull.signXDR(xdr, { networkPassphrase });
    return signed;
  }
}

export class AlbedoConnector extends WalletConnector {
  get walletType(): WalletType {
    return 'albedo';
  }

  get walletName(): string {
    return 'Albedo';
  }

  async isInstalled(): Promise<boolean> {
    return true;
  }

  async connectWallet(): Promise<string> {
    const albedo = await this.getAlbedo();
    const result = await albedo.publicKey({});
    if (!result?.pubkey) {
      throw new Error('User denied Albedo connection');
    }

    this._publicKey = result.pubkey;
    this._connected = true;
    return result.pubkey;
  }

  async signTransaction(xdr: string): Promise<string> {
    if (!this._connected) {
      throw new Error('Wallet not connected');
    }

    const albedo = await this.getAlbedo();
    const network = this._network === 'mainnet' ? 'public' : 'testnet';
    const result = await albedo.tx({ xdr, network });

    return result.signed_envelope_xdr;
  }

  private async getAlbedo(): Promise<any> {
    if (typeof window !== 'undefined' && (window as any).albedo) {
      return (window as any).albedo;
    }
    try {
      return await import('@albedo-link/intent');
    } catch {
      throw new Error('Albedo is not available');
    }
  }
}

const CONNECTOR_MAP: Record<WalletType, new (network?: string) => WalletConnector> = {
  freighter: FreighterConnector,
  xbull: XBullConnector,
  albedo: AlbedoConnector,
};

export function connectWallet(walletType: WalletType, network?: string): WalletConnector {
  const ConnectorClass = CONNECTOR_MAP[walletType];
  if (!ConnectorClass) {
    throw new Error(`Unsupported wallet type: ${walletType}`);
  }
  return new ConnectorClass(network);
}

export async function detectInstalledWallets(network?: string): Promise<WalletInfo[]> {
  const wallets: WalletInfo[] = [];

  for (const [type, ConnectorClass] of Object.entries(CONNECTOR_MAP)) {
    const connector = new ConnectorClass(network);
    const installed = await connector.isInstalled();
    wallets.push({
      type: type as WalletType,
      name: connector.walletName,
      installed,
    });
  }

  return wallets;
}
