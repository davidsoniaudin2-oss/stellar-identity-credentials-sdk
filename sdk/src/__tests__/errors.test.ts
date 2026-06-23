import {
  StellarIdentityError,
  DIDError,
  CredentialError,
  ReputationError,
  ZKProofError,
  ComplianceError,
  ConfigurationError,
  NetworkError,
  ErrorCode,
  mapContractError,
  mapErrorCode,
  isDIDError,
  isCredentialError,
  isReputationError,
  isZKProofError,
  isComplianceError,
  isConfigurationError,
  isNetworkError,
} from '../errors';

describe('StellarIdentityError', () => {
  test('should create base error with code and message', () => {
    const err = new StellarIdentityError(ErrorCode.DIDNotFound, 'Custom message');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(StellarIdentityError);
    expect(err.code).toBe(ErrorCode.DIDNotFound);
    expect(err.message).toBe('Custom message');
    expect(err.name).toBe('StellarIdentityError');
  });

  test('should use default message when not provided', () => {
    const err = new StellarIdentityError(ErrorCode.DIDAlreadyExists);
    expect(err.message).toBe('DID already exists');
  });

  test('should store details', () => {
    const details = { did: 'did:stellar:GC...' };
    const err = new StellarIdentityError(ErrorCode.DIDNotFound, 'msg', details);
    expect(err.details).toEqual(details);
  });
});

describe('DIDError', () => {
  test('should create DID error', () => {
    const err = new DIDError(ErrorCode.DIDAlreadyExists);
    expect(err).toBeInstanceOf(StellarIdentityError);
    expect(err).toBeInstanceOf(DIDError);
    expect(err.name).toBe('DIDError');
  });
});

describe('CredentialError', () => {
  test('should create credential error', () => {
    const err = new CredentialError(ErrorCode.CredentialExpired);
    expect(err).toBeInstanceOf(StellarIdentityError);
    expect(err).toBeInstanceOf(CredentialError);
    expect(err.name).toBe('CredentialError');
  });
});

describe('ReputationError', () => {
  test('should create reputation error', () => {
    const err = new ReputationError(ErrorCode.ReputationNotFound);
    expect(err.name).toBe('ReputationError');
  });
});

describe('ZKProofError', () => {
  test('should create ZK proof error', () => {
    const err = new ZKProofError(ErrorCode.ZKInvalidProof);
    expect(err.name).toBe('ZKProofError');
  });
});

describe('ComplianceError', () => {
  test('should create compliance error', () => {
    const err = new ComplianceError(ErrorCode.ComplianceAddressBlocked);
    expect(err.name).toBe('ComplianceError');
  });
});

describe('ConfigurationError', () => {
  test('should create configuration error', () => {
    const err = new ConfigurationError(ErrorCode.ConfigInvalidNetwork);
    expect(err.name).toBe('ConfigurationError');
  });
});

describe('NetworkError', () => {
  test('should create network error', () => {
    const err = new NetworkError(ErrorCode.NetworkTimeout);
    expect(err.name).toBe('NetworkError');
  });
});

describe('type guards', () => {
  test('isDIDError should identify DIDError', () => {
    expect(isDIDError(new DIDError(ErrorCode.DIDNotFound))).toBe(true);
    expect(isDIDError(new CredentialError(ErrorCode.CredentialNotFound))).toBe(false);
    expect(isDIDError(null)).toBe(false);
    expect(isDIDError({})).toBe(false);
  });

  test('isCredentialError should identify CredentialError', () => {
    expect(isCredentialError(new CredentialError(ErrorCode.CredentialNotFound))).toBe(true);
    expect(isCredentialError(new DIDError(ErrorCode.DIDNotFound))).toBe(false);
  });

  test('isReputationError should identify ReputationError', () => {
    expect(isReputationError(new ReputationError(ErrorCode.ReputationNotFound))).toBe(true);
  });

  test('isZKProofError should identify ZKProofError', () => {
    expect(isZKProofError(new ZKProofError(ErrorCode.ZKInvalidProof))).toBe(true);
  });

  test('isComplianceError should identify ComplianceError', () => {
    expect(isComplianceError(new ComplianceError(ErrorCode.ComplianceHighRisk))).toBe(true);
  });

  test('isConfigurationError should identify ConfigurationError', () => {
    expect(isConfigurationError(new ConfigurationError(ErrorCode.ConfigInvalidNetwork))).toBe(true);
  });

  test('isNetworkError should identify NetworkError', () => {
    expect(isNetworkError(new NetworkError(ErrorCode.NetworkTimeout))).toBe(true);
  });
});

describe('mapContractError', () => {
  test('should pass through StellarIdentityError instances', () => {
    const original = new DIDError(ErrorCode.DIDNotFound);
    const mapped = mapContractError(original);
    expect(mapped).toBe(original);
  });

  test('should map DIDRegistryError:NotFound in message', () => {
    const error = new Error('Contract call failed: DIDRegistryError:NotFound');
    const mapped = mapContractError(error);
    expect(mapped).toBeInstanceOf(DIDError);
    expect(mapped.code).toBe(ErrorCode.DIDNotFound);
  });

  test('should map CredentialIssuerError:Expired in message', () => {
    const error = new Error('CredentialIssuerError:Expired');
    const mapped = mapContractError(error);
    expect(mapped).toBeInstanceOf(CredentialError);
    expect(mapped.code).toBe(ErrorCode.CredentialExpired);
  });

  test('should map network errors', () => {
    const error = new Error('fetch failed: network timeout');
    const mapped = mapContractError(error);
    expect(mapped).toBeInstanceOf(NetworkError);
    expect(mapped.code).toBe(ErrorCode.NetworkConnectionFailed);
  });

  test('should return generic error for unknown messages', () => {
    const error = new Error('Something unexpected happened');
    const mapped = mapContractError(error);
    expect(mapped).toBeInstanceOf(StellarIdentityError);
  });

  test('should handle non-Error input', () => {
    const mapped = mapContractError('string error');
    expect(mapped).toBeInstanceOf(StellarIdentityError);
  });
});

describe('mapErrorCode', () => {
  test('should map DID error codes', () => {
    expect(mapErrorCode(1)).toBeInstanceOf(DIDError);
    expect(mapErrorCode(2)).toBeInstanceOf(DIDError);
    expect(mapErrorCode(6)).toBeInstanceOf(DIDError);
  });

  test('should map credential error codes', () => {
    expect(mapErrorCode(101)).toBeInstanceOf(CredentialError);
    expect(mapErrorCode(107)).toBeInstanceOf(CredentialError);
  });

  test('should map reputation error codes', () => {
    expect(mapErrorCode(201)).toBeInstanceOf(ReputationError);
    expect(mapErrorCode(205)).toBeInstanceOf(ReputationError);
  });

  test('should map ZK error codes', () => {
    expect(mapErrorCode(301)).toBeInstanceOf(ZKProofError);
    expect(mapErrorCode(310)).toBeInstanceOf(ZKProofError);
  });

  test('should map compliance error codes', () => {
    expect(mapErrorCode(401)).toBeInstanceOf(ComplianceError);
    expect(mapErrorCode(407)).toBeInstanceOf(ComplianceError);
  });

  test('should return null for unknown codes', () => {
    expect(mapErrorCode(999)).toBeNull();
    expect(mapErrorCode(0)).toBeNull();
  });
});

describe('ErrorCode enum', () => {
  test('should have unique values', () => {
    const values = Object.values(ErrorCode).filter(v => typeof v === 'number');
    const uniqueValues = new Set(values);
    expect(values.length).toBe(uniqueValues.size);
  });

  test('should have all DID error codes in 1000-1999 range', () => {
    const didCodes = [
      ErrorCode.DIDAlreadyExists,
      ErrorCode.DIDNotFound,
      ErrorCode.DIDUnauthorized,
      ErrorCode.DIDInvalidFormat,
      ErrorCode.DIDDeactivated,
      ErrorCode.DIDInvalidSignature,
    ];
    didCodes.forEach(code => {
      expect(code).toBeGreaterThanOrEqual(1000);
      expect(code).toBeLessThan(2000);
    });
  });
});
