import { useState, useEffect, useCallback, useRef } from 'react';
import { StellarIdentitySDK, StellarIdentityConfig } from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';

interface UseStellarIdentityOptions {
  config: StellarIdentityConfig;
  autoConnect?: boolean;
}

interface UseStellarIdentityReturn<T extends StellarIdentitySDK = StellarIdentitySDK> {
  sdk: T | null;
  isConnected: boolean;
  isLoading: boolean;
  error: string | null;
  address: string | null;
  keypair: Keypair | null;
  connect: (secretKey?: string) => Promise<void>;
  disconnect: () => void;
  createKeypair: () => Keypair;
  getBalance: () => Promise<number>;
  sendTransaction: (destination: string, amount: number, memo?: string) => Promise<string>;
}

export function useStellarIdentity<T extends StellarIdentitySDK = StellarIdentitySDK>(
  options: UseStellarIdentityOptions
): UseStellarIdentityReturn<T> {
  const [sdk, setSdk] = useState<T | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [keypair, setKeypair] = useState<Keypair | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    try {
      const stellarSDK = new StellarIdentitySDK(options.config) as unknown as T;
      setSdk(stellarSDK);
    } catch (err: any) {
      setError(err.message || 'Failed to initialize SDK');
    }

    return () => {
      setSdk(null);
      setKeypair(null);
      setAddress(null);
      setIsConnected(false);
    };
  }, [options.config]);

  useEffect(() => {
    if (options.autoConnect && sdk) {
      const storedSecret = localStorage.getItem('stellar_identity_secret');
      if (storedSecret) {
        connect(storedSecret);
      }
    }
  }, [options.autoConnect, sdk]);

  const connect = useCallback(async (secretKey?: string) => {
    if (!sdk) {
      setError('SDK not initialized');
      return;
    }

    try {
      setIsLoading(true);
      setError(null);

      let kp: Keypair;
      
      if (secretKey) {
        kp = Keypair.fromSecret(secretKey);
      } else {
        kp = Keypair.random();
      }

      const publicKey = kp.publicKey();
      
      setKeypair(kp);
      setAddress(publicKey);
      setIsConnected(true);

      if (secretKey) {
        localStorage.setItem('stellar_identity_secret', secretKey);
      }
    } catch (err: any) {
      if (mountedRef.current) {
        setError(err.message || 'Failed to connect wallet');
      }
    } finally {
      if (mountedRef.current) {
        setIsLoading(false);
      }
    }
  }, [sdk]);

  const disconnect = useCallback(() => {
    setKeypair(null);
    setAddress(null);
    setIsConnected(false);
    setError(null);
    localStorage.removeItem('stellar_identity_secret');
  }, []);

  const createKeypair = useCallback((): Keypair => {
    return Keypair.random();
  }, []);

  const getBalance = useCallback(async (): Promise<number> => {
    if (!sdk || !address) {
      throw new Error('Not connected');
    }

    try {
      const server = sdk.server;
      const account = await server.loadAccount(address);
      return parseFloat(account.balances[0]?.balance || '0');
    } catch (err: any) {
      throw new Error(err.message || 'Failed to get balance');
    }
  }, [sdk, address]);

  const sendTransaction = useCallback(async (
    destination: string, 
    amount: number, 
    memo?: string
  ): Promise<string> => {
    if (!sdk || !keypair || !address) {
      throw new Error('Not connected');
    }

    try {
      const server = sdk.server;
      const sourceAccount = await server.loadAccount(address);
      
      const transaction = new sdk.TransactionBuilder(sourceAccount, {
        fee: '100',
        networkPassphrase: sdk.getNetworkPassphrase(),
      })
        .addOperation(
          sdk.PaymentOperation({
            destination,
            asset: sdk.Asset.native(),
            amount: amount.toString(),
          })
        )
        .setTimeout(30)
        .build();

      if (memo) {
        transaction.addMemo(sdk.Memo.text(memo));
      }

      transaction.sign(keypair);
      const result = await server.sendTransaction(transaction);
      
      return result.hash;
    } catch (err: any) {
      throw new Error(err.message || 'Failed to send transaction');
    }
  }, [sdk, keypair, address]);

  return {
    sdk,
    isConnected,
    isLoading,
    error,
    address,
    keypair,
    connect,
    disconnect,
    createKeypair,
    getBalance,
    sendTransaction,
  };
}

// Hook for DID operations
export const useDID = (sdk: StellarIdentitySDK | null, address: string | null) => {
  const [didDocument, setDidDocument] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resolveDID = useCallback(async () => {
    if (!sdk || !address) return;

    try {
      setLoading(true);
      setError(null);
      
      const did = sdk.did.generateDID(address);
      const result = await sdk.did.resolveDID(did);
      setDidDocument(result.didDocument);
    } catch (err: any) {
      setError(err.message || 'Failed to resolve DID');
    } finally {
      setLoading(false);
    }
  }, [sdk, address]);

  const createDID = useCallback(async (verificationMethods: any[], services: any[]) => {
    if (!sdk || !address) throw new Error('Not connected');

    try {
      setLoading(true);
      setError(null);
      
      const did = await sdk.did.createDID(address, {
        verificationMethods,
        services
      });
      
      await resolveDID();
      return did;
    } catch (err: any) {
      setError(err.message || 'Failed to create DID');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [sdk, address, resolveDID]);

  useEffect(() => {
    if (address) {
      resolveDID();
    }
  }, [address, resolveDID]);

  return {
    didDocument,
    loading,
    error,
    resolveDID,
    createDID,
  };
};

// Hook for credential operations
export const useCredentials = (sdk: StellarIdentitySDK | null, address: string | null) => {
  const [credentials, setCredentials] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadCredentials = useCallback(async () => {
    if (!sdk || !address) return;

    try {
      setLoading(true);
      setError(null);
      
      const credentialIds = await sdk.credentials.getSubjectCredentials(address);
      const credentialPromises = credentialIds.map(id => sdk.credentials.getCredential(id));
      const loadedCredentials = await Promise.all(credentialPromises);
      setCredentials(loadedCredentials);
    } catch (err: any) {
      setError(err.message || 'Failed to load credentials');
    } finally {
      setLoading(false);
    }
  }, [sdk, address]);

  const issueCredential = useCallback(async (options: any) => {
    if (!sdk || !address) throw new Error('Not connected');

    try {
      setLoading(true);
      setError(null);
      
      const credentialId = await sdk.credentials.issueCredential(address, options);
      await loadCredentials();
      return credentialId;
    } catch (err: any) {
      setError(err.message || 'Failed to issue credential');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [sdk, address, loadCredentials]);

  const verifyCredential = useCallback(async (credentialId: string) => {
    if (!sdk) throw new Error('SDK not initialized');

    try {
      return await sdk.credentials.verifyCredential(credentialId);
    } catch (err: any) {
      setError(err.message || 'Failed to verify credential');
      throw err;
    }
  }, [sdk]);

  useEffect(() => {
    if (address) {
      loadCredentials();
    }
  }, [address, loadCredentials]);

  return {
    credentials,
    loading,
    error,
    loadCredentials,
    issueCredential,
    verifyCredential,
  };
};

// Hook for reputation operations
export const useReputation = (sdk: StellarIdentitySDK | null, address: string | null) => {
  const [reputationData, setReputationData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadReputation = useCallback(async () => {
    if (!sdk || !address) return;

    try {
      setLoading(true);
      setError(null);
      
      const data = await sdk.reputation.getReputationAnalysis(address);
      setReputationData(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load reputation data');
    } finally {
      setLoading(false);
    }
  }, [sdk, address]);

  const updateReputation = useCallback(async (type: 'transaction' | 'credential', data: any) => {
    if (!sdk || !address) throw new Error('Not connected');

    try {
      setLoading(true);
      setError(null);
      
      let newScore: number;
      
      if (type === 'transaction') {
        newScore = await sdk.reputation.updateTransactionReputation(
          address,
          data.successful,
          data.amount
        );
      } else {
        newScore = await sdk.reputation.updateCredentialReputation(
          address,
          data.valid,
          data.credentialType
        );
      }
      
      await loadReputation();
      return newScore;
    } catch (err: any) {
      setError(err.message || 'Failed to update reputation');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [sdk, address, loadReputation]);

  useEffect(() => {
    if (address) {
      loadReputation();
    }
  }, [address, loadReputation]);

  return {
    reputationData,
    loading,
    error,
    loadReputation,
    updateReputation,
  };
};

// Hook for compliance operations
export const useCompliance = (sdk: StellarIdentitySDK | null, address: string | null) => {
  const [complianceData, setComplianceData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const checkCompliance = useCallback(async (addr?: string) => {
    if (!sdk) throw new Error('SDK not initialized');

    const targetAddress = addr || address;
    if (!targetAddress) throw new Error('No address provided');

    try {
      setLoading(true);
      setError(null);
      
      const result = await sdk.performComplianceCheck(targetAddress);
      setComplianceData(result);
      return result;
    } catch (err: any) {
      setError(err.message || 'Failed to perform compliance check');
      throw err;
    } finally {
      setLoading(false);
    }
  }, [sdk, address]);

  useEffect(() => {
    if (address) {
      checkCompliance();
    }
  }, [address, checkCompliance]);

  return {
    complianceData,
    loading,
    error,
    checkCompliance,
  };
};
