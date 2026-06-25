import {
  WalletConnector,
  FreighterConnector,
  XBullConnector,
  AlbedoConnector,
  connectWallet,
  detectInstalledWallets,
  WalletType,
} from '../walletConnector';

const mockFreighterApi = {
  isConnected: jest.fn().mockResolvedValue(true),
  getPublicKey: jest.fn().mockResolvedValue('GABCDEFG'),
  signTransaction: jest.fn().mockResolvedValue('signed_xdr_freighter'),
};

const mockXBullSDK = {
  connect: jest.fn().mockResolvedValue('GABCDEFG'),
  signXDR: jest.fn().mockResolvedValue('signed_xdr_xbull'),
};

const mockAlbedo = {
  publicKey: jest.fn().mockResolvedValue({ pubkey: 'GABCDEFG' }),
  tx: jest.fn().mockResolvedValue({ signed_envelope_xdr: 'signed_xdr_albedo' }),
};

beforeEach(() => {
  jest.clearAllMocks();
  (global as any).window = {};
});

afterEach(() => {
  delete (global as any).window;
});

describe('FreighterConnector', () => {
  let connector: FreighterConnector;

  beforeEach(() => {
    connector = new FreighterConnector('testnet');
    (global as any).window = { freighterApi: mockFreighterApi };
  });

  test('has correct wallet type and name', () => {
    expect(connector.walletType).toBe('freighter');
    expect(connector.walletName).toBe('Freighter');
  });

  test('detects installation', async () => {
    expect(await connector.isInstalled()).toBe(true);
  });

  test('returns false when not installed', async () => {
    (global as any).window = {};
    expect(await connector.isInstalled()).toBe(false);
  });

  test('connects and returns public key', async () => {
    const key = await connector.connectWallet();
    expect(key).toBe('GABCDEFG');
    expect(connector.getPublicKey()).toBe('GABCDEFG');
    expect(connector.isConnected()).toBe(true);
  });

  test('throws when connecting without installation', async () => {
    (global as any).window = {};
    await expect(connector.connectWallet()).rejects.toThrow('not installed');
  });

  test('signs transaction', async () => {
    await connector.connectWallet();
    const signed = await connector.signTransaction('test_xdr');
    expect(signed).toBe('signed_xdr_freighter');
    expect(mockFreighterApi.signTransaction).toHaveBeenCalledWith('test_xdr', {
      networkPassphrase: 'Test SDF Network ; September 2015',
    });
  });

  test('throws when signing without connection', async () => {
    await expect(connector.signTransaction('test_xdr')).rejects.toThrow('not connected');
  });

  test('disconnects properly', async () => {
    await connector.connectWallet();
    expect(connector.isConnected()).toBe(true);
    connector.disconnect();
    expect(connector.isConnected()).toBe(false);
    expect(connector.getPublicKey()).toBeNull();
  });
});

describe('XBullConnector', () => {
  let connector: XBullConnector;

  beforeEach(() => {
    connector = new XBullConnector('testnet');
    (global as any).window = { xBullSDK: mockXBullSDK };
  });

  test('has correct wallet type and name', () => {
    expect(connector.walletType).toBe('xbull');
    expect(connector.walletName).toBe('xBull');
  });

  test('detects installation', async () => {
    expect(await connector.isInstalled()).toBe(true);
  });

  test('returns false when not installed', async () => {
    (global as any).window = {};
    expect(await connector.isInstalled()).toBe(false);
  });

  test('connects and returns public key', async () => {
    const key = await connector.connectWallet();
    expect(key).toBe('GABCDEFG');
    expect(connector.isConnected()).toBe(true);
  });

  test('signs transaction', async () => {
    await connector.connectWallet();
    const signed = await connector.signTransaction('test_xdr');
    expect(signed).toBe('signed_xdr_xbull');
  });

  test('throws when signing without connection', async () => {
    await expect(connector.signTransaction('xdr')).rejects.toThrow('not connected');
  });
});

describe('AlbedoConnector', () => {
  let connector: AlbedoConnector;

  beforeEach(() => {
    connector = new AlbedoConnector('testnet');
    (global as any).window = { albedo: mockAlbedo };
  });

  test('has correct wallet type and name', () => {
    expect(connector.walletType).toBe('albedo');
    expect(connector.walletName).toBe('Albedo');
  });

  test('is always considered installed (web-based)', async () => {
    (global as any).window = {};
    expect(await connector.isInstalled()).toBe(true);
  });

  test('connects and returns public key', async () => {
    const key = await connector.connectWallet();
    expect(key).toBe('GABCDEFG');
    expect(connector.isConnected()).toBe(true);
  });

  test('signs transaction', async () => {
    await connector.connectWallet();
    const signed = await connector.signTransaction('test_xdr');
    expect(signed).toBe('signed_xdr_albedo');
    expect(mockAlbedo.tx).toHaveBeenCalledWith({ xdr: 'test_xdr', network: 'testnet' });
  });

  test('throws when signing without connection', async () => {
    await expect(connector.signTransaction('xdr')).rejects.toThrow('not connected');
  });
});

describe('connectWallet factory', () => {
  test('creates FreighterConnector', () => {
    const connector = connectWallet('freighter');
    expect(connector).toBeInstanceOf(FreighterConnector);
  });

  test('creates XBullConnector', () => {
    const connector = connectWallet('xbull');
    expect(connector).toBeInstanceOf(XBullConnector);
  });

  test('creates AlbedoConnector', () => {
    const connector = connectWallet('albedo');
    expect(connector).toBeInstanceOf(AlbedoConnector);
  });

  test('throws for unsupported wallet type', () => {
    expect(() => connectWallet('unknown' as WalletType)).toThrow('Unsupported wallet type');
  });
});

describe('detectInstalledWallets', () => {
  test('returns info for all wallet types', async () => {
    (global as any).window = {
      freighterApi: mockFreighterApi,
      xBullSDK: mockXBullSDK,
    };

    const wallets = await detectInstalledWallets();
    expect(wallets).toHaveLength(3);

    const freighter = wallets.find(w => w.type === 'freighter');
    expect(freighter).toBeDefined();
    expect(freighter!.installed).toBe(true);
    expect(freighter!.name).toBe('Freighter');

    const xbull = wallets.find(w => w.type === 'xbull');
    expect(xbull).toBeDefined();
    expect(xbull!.installed).toBe(true);

    const albedo = wallets.find(w => w.type === 'albedo');
    expect(albedo).toBeDefined();
    expect(albedo!.installed).toBe(true);
  });

  test('detects when wallets are not installed', async () => {
    (global as any).window = {};

    const wallets = await detectInstalledWallets();
    const freighter = wallets.find(w => w.type === 'freighter');
    expect(freighter!.installed).toBe(false);

    const xbull = wallets.find(w => w.type === 'xbull');
    expect(xbull!.installed).toBe(false);
  });
});

describe('WalletConnector base class', () => {
  test('initial state is disconnected with no key', () => {
    const connector = new FreighterConnector();
    expect(connector.isConnected()).toBe(false);
    expect(connector.getPublicKey()).toBeNull();
  });

  test('uses mainnet network passphrase', async () => {
    const connector = new FreighterConnector('mainnet');
    (global as any).window = { freighterApi: mockFreighterApi };

    await connector.connectWallet();
    await connector.signTransaction('xdr');

    expect(mockFreighterApi.signTransaction).toHaveBeenCalledWith('xdr', {
      networkPassphrase: 'Public Global Stellar Network ; September 2015',
    });
  });
});
