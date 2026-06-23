export enum ErrorCode {
  // DID errors (maps to DIDRegistryError)
  DIDAlreadyExists = 1001,
  DIDNotFound = 1002,
  DIDUnauthorized = 1003,
  DIDInvalidFormat = 1004,
  DIDDeactivated = 1005,
  DIDInvalidSignature = 1006,

  // Credential errors (maps to CredentialIssuerError)
  CredentialUnauthorized = 2001,
  CredentialNotFound = 2002,
  CredentialInvalid = 2003,
  CredentialAlreadyRevoked = 2004,
  CredentialExpired = 2005,
  CredentialInvalidSignature = 2006,
  CredentialInvalidIssuer = 2007,

  // Reputation errors (maps to ReputationScoreError)
  ReputationAlreadyExists = 3001,
  ReputationNotFound = 3002,
  ReputationUnauthorized = 3003,
  ReputationInvalidScore = 3004,
  ReputationInvalidDepth = 3005,

  // ZK Proof errors (maps to ZKAttestationError)
  ZKInvalidProof = 4001,
  ZKNotFound = 4002,
  ZKUnauthorized = 4003,
  ZKInvalidCircuit = 4004,
  ZKVerificationFailed = 4005,
  ZKExpired = 4006,
  ZKNullifierAlreadyUsed = 4007,
  ZKInvalidPublicInputs = 4008,
  ZKCircuitDeactivated = 4009,
  ZKRevokedCredential = 4010,

  // Compliance errors (maps to ComplianceFilterError)
  ComplianceAddressBlocked = 5001,
  ComplianceHighRisk = 5002,
  ComplianceUnauthorized = 5003,
  ComplianceNotFound = 5004,
  ComplianceInvalidRiskScore = 5005,
  ComplianceOracleStale = 5006,
  ComplianceInvalidHash = 5007,

  // Configuration errors
  ConfigInvalidNetwork = 6001,
  ConfigMissingContract = 6002,
  ConfigInvalidRpcUrl = 6003,

  // Network errors
  NetworkConnectionFailed = 7001,
  NetworkTransactionFailed = 7002,
  NetworkTimeout = 7003,
  NetworkSimulationError = 7004,
}

const ERROR_MESSAGES: Record<ErrorCode, string> = {
  [ErrorCode.DIDAlreadyExists]: 'DID already exists',
  [ErrorCode.DIDNotFound]: 'DID not found',
  [ErrorCode.DIDUnauthorized]: 'Unauthorized DID operation',
  [ErrorCode.DIDInvalidFormat]: 'Invalid DID format',
  [ErrorCode.DIDDeactivated]: 'DID has been deactivated',
  [ErrorCode.DIDInvalidSignature]: 'Invalid DID signature',

  [ErrorCode.CredentialUnauthorized]: 'Unauthorized credential operation',
  [ErrorCode.CredentialNotFound]: 'Credential not found',
  [ErrorCode.CredentialInvalid]: 'Invalid credential',
  [ErrorCode.CredentialAlreadyRevoked]: 'Credential already revoked',
  [ErrorCode.CredentialExpired]: 'Credential has expired',
  [ErrorCode.CredentialInvalidSignature]: 'Invalid credential signature',
  [ErrorCode.CredentialInvalidIssuer]: 'Invalid credential issuer',

  [ErrorCode.ReputationAlreadyExists]: 'Reputation already exists',
  [ErrorCode.ReputationNotFound]: 'Reputation not found',
  [ErrorCode.ReputationUnauthorized]: 'Unauthorized reputation operation',
  [ErrorCode.ReputationInvalidScore]: 'Invalid reputation score',
  [ErrorCode.ReputationInvalidDepth]: 'Invalid reputation depth',

  [ErrorCode.ZKInvalidProof]: 'Invalid ZK proof',
  [ErrorCode.ZKNotFound]: 'ZK proof not found',
  [ErrorCode.ZKUnauthorized]: 'Unauthorized ZK proof operation',
  [ErrorCode.ZKInvalidCircuit]: 'Invalid ZK circuit',
  [ErrorCode.ZKVerificationFailed]: 'ZK verification failed',
  [ErrorCode.ZKExpired]: 'ZK proof has expired',
  [ErrorCode.ZKNullifierAlreadyUsed]: 'ZK nullifier already used',
  [ErrorCode.ZKInvalidPublicInputs]: 'Invalid ZK public inputs',
  [ErrorCode.ZKCircuitDeactivated]: 'ZK circuit deactivated',
  [ErrorCode.ZKRevokedCredential]: 'ZK proof uses revoked credential',

  [ErrorCode.ComplianceAddressBlocked]: 'Address is blocked',
  [ErrorCode.ComplianceHighRisk]: 'Address has high risk score',
  [ErrorCode.ComplianceUnauthorized]: 'Unauthorized compliance operation',
  [ErrorCode.ComplianceNotFound]: 'Compliance record not found',
  [ErrorCode.ComplianceInvalidRiskScore]: 'Invalid risk score',
  [ErrorCode.ComplianceOracleStale]: 'Compliance oracle data is stale',
  [ErrorCode.ComplianceInvalidHash]: 'Invalid compliance hash',

  [ErrorCode.ConfigInvalidNetwork]: 'Invalid network configuration',
  [ErrorCode.ConfigMissingContract]: 'Missing contract address in configuration',
  [ErrorCode.ConfigInvalidRpcUrl]: 'Invalid RPC URL',

  [ErrorCode.NetworkConnectionFailed]: 'Network connection failed',
  [ErrorCode.NetworkTransactionFailed]: 'Transaction failed',
  [ErrorCode.NetworkTimeout]: 'Network timeout',
  [ErrorCode.NetworkSimulationError]: 'Contract simulation error',
};

export class StellarIdentityError extends Error {
  public readonly code: ErrorCode;
  public readonly details: Record<string, unknown>;

  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(message || ERROR_MESSAGES[code] || 'Unknown error');
    this.name = 'StellarIdentityError';
    this.code = code;
    this.details = details || {};
    Object.setPrototypeOf(this, StellarIdentityError.prototype);
  }
}

export class DIDError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'DIDError';
    Object.setPrototypeOf(this, DIDError.prototype);
  }
}

export class CredentialError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'CredentialError';
    Object.setPrototypeOf(this, CredentialError.prototype);
  }
}

export class ReputationError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ReputationError';
    Object.setPrototypeOf(this, ReputationError.prototype);
  }
}

export class ZKProofError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ZKProofError';
    Object.setPrototypeOf(this, ZKProofError.prototype);
  }
}

export class ComplianceError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ComplianceError';
    Object.setPrototypeOf(this, ComplianceError.prototype);
  }
}

export class ConfigurationError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

export class NetworkError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

type ErrorClass = new (code: ErrorCode, message?: string, details?: Record<string, unknown>) => StellarIdentityError;

const ERROR_CLASS_MAP: Record<string, ErrorClass> = {
  DIDRegistryError: DIDError,
  CredentialIssuerError: CredentialError,
  ReputationScoreError: ReputationError,
  ZKAttestationError: ZKProofError,
  ComplianceFilterError: ComplianceError,
};

const ERROR_CODE_MAP: Record<string, [ErrorCode, ErrorClass]> = {
  'DIDRegistryError:AlreadyExists': [ErrorCode.DIDAlreadyExists, DIDError],
  'DIDRegistryError:NotFound': [ErrorCode.DIDNotFound, DIDError],
  'DIDRegistryError:Unauthorized': [ErrorCode.DIDUnauthorized, DIDError],
  'DIDRegistryError:InvalidFormat': [ErrorCode.DIDInvalidFormat, DIDError],
  'DIDRegistryError:Deactivated': [ErrorCode.DIDDeactivated, DIDError],
  'DIDRegistryError:InvalidSignature': [ErrorCode.DIDInvalidSignature, DIDError],

  'CredentialIssuerError:Unauthorized': [ErrorCode.CredentialUnauthorized, CredentialError],
  'CredentialIssuerError:NotFound': [ErrorCode.CredentialNotFound, CredentialError],
  'CredentialIssuerError:InvalidCredential': [ErrorCode.CredentialInvalid, CredentialError],
  'CredentialIssuerError:AlreadyRevoked': [ErrorCode.CredentialAlreadyRevoked, CredentialError],
  'CredentialIssuerError:Expired': [ErrorCode.CredentialExpired, CredentialError],
  'CredentialIssuerError:InvalidSignature': [ErrorCode.CredentialInvalidSignature, CredentialError],
  'CredentialIssuerError:InvalidIssuer': [ErrorCode.CredentialInvalidIssuer, CredentialError],

  'ReputationScoreError:AlreadyExists': [ErrorCode.ReputationAlreadyExists, ReputationError],
  'ReputationScoreError:NotFound': [ErrorCode.ReputationNotFound, ReputationError],
  'ReputationScoreError:Unauthorized': [ErrorCode.ReputationUnauthorized, ReputationError],
  'ReputationScoreError:InvalidScore': [ErrorCode.ReputationInvalidScore, ReputationError],
  'ReputationScoreError:InvalidDepth': [ErrorCode.ReputationInvalidDepth, ReputationError],

  'ZKAttestationError:InvalidProof': [ErrorCode.ZKInvalidProof, ZKProofError],
  'ZKAttestationError:NotFound': [ErrorCode.ZKNotFound, ZKProofError],
  'ZKAttestationError:Unauthorized': [ErrorCode.ZKUnauthorized, ZKProofError],
  'ZKAttestationError:InvalidCircuit': [ErrorCode.ZKInvalidCircuit, ZKProofError],
  'ZKAttestationError:VerificationFailed': [ErrorCode.ZKVerificationFailed, ZKProofError],
  'ZKAttestationError:Expired': [ErrorCode.ZKExpired, ZKProofError],
  'ZKAttestationError:NullifierAlreadyUsed': [ErrorCode.ZKNullifierAlreadyUsed, ZKProofError],
  'ZKAttestationError:InvalidPublicInputs': [ErrorCode.ZKInvalidPublicInputs, ZKProofError],
  'ZKAttestationError:CircuitDeactivated': [ErrorCode.ZKCircuitDeactivated, ZKProofError],
  'ZKAttestationError:RevokedCredential': [ErrorCode.ZKRevokedCredential, ZKProofError],

  'ComplianceFilterError:AddressBlocked': [ErrorCode.ComplianceAddressBlocked, ComplianceError],
  'ComplianceFilterError:HighRisk': [ErrorCode.ComplianceHighRisk, ComplianceError],
  'ComplianceFilterError:Unauthorized': [ErrorCode.ComplianceUnauthorized, ComplianceError],
  'ComplianceFilterError:NotFound': [ErrorCode.ComplianceNotFound, ComplianceError],
  'ComplianceFilterError:InvalidRiskScore': [ErrorCode.ComplianceInvalidRiskScore, ComplianceError],
  'ComplianceFilterError:OracleStale': [ErrorCode.ComplianceOracleStale, ComplianceError],
  'ComplianceFilterError:InvalidHash': [ErrorCode.ComplianceInvalidHash, ComplianceError],
};

const RUST_REVERT_PATTERN = /Error\(Contract\(#(\d+)\),?.*?\)/;
const RUST_ERROR_NAME_PATTERN = /(?<name>[A-Za-z]+Error):(?<variant>[A-Za-z]+)/;

export function mapContractError(error: unknown): StellarIdentityError {
  if (error instanceof StellarIdentityError) {
    return error;
  }

  const message = error instanceof Error ? error.message : String(error);

  // Try exact contract error format: "Error(Contract(#n), ...)"
  const contractMatch = message.match(RUST_REVERT_PATTERN);
  if (contractMatch) {
    const code = parseInt(contractMatch[1], 10);
    const mapped = mapErrorCode(code);
    if (mapped) return mapped;
  }

  // Try "ContractNameError:Variant" pattern
  for (const [pattern, mapped] of Object.entries(ERROR_CODE_MAP)) {
    if (message.includes(pattern)) {
      const [code, ErrorClass] = mapped;
      return new ErrorClass(code, message);
    }
  }

  // Try to identify by error class name in message
  for (const [name, ErrorClass] of Object.entries(ERROR_CLASS_MAP)) {
    if (message.includes(name)) {
      return new ErrorClass(ErrorCode.NetworkTransactionFailed, message);
    }
  }

  // Network or unknown error
  if (message.includes('fetch') || message.includes('network') || message.includes('timeout')) {
    return new NetworkError(ErrorCode.NetworkConnectionFailed, message);
  }

  return new StellarIdentityError(ErrorCode.NetworkTransactionFailed, message);
}

export function mapErrorCode(code: number): StellarIdentityError | null {
  // DID errors: codes 1-99
  if (code >= 1 && code <= 99) {
    switch (code) {
      case 1: return new DIDError(ErrorCode.DIDAlreadyExists);
      case 2: return new DIDError(ErrorCode.DIDNotFound);
      case 3: return new DIDError(ErrorCode.DIDUnauthorized);
      case 4: return new DIDError(ErrorCode.DIDInvalidFormat);
      case 5: return new DIDError(ErrorCode.DIDDeactivated);
      case 6: return new DIDError(ErrorCode.DIDInvalidSignature);
    }
  }

  // Credential errors: codes 100-199
  if (code >= 100 && code <= 199) {
    switch (code) {
      case 101: return new CredentialError(ErrorCode.CredentialUnauthorized);
      case 102: return new CredentialError(ErrorCode.CredentialNotFound);
      case 103: return new CredentialError(ErrorCode.CredentialInvalid);
      case 104: return new CredentialError(ErrorCode.CredentialAlreadyRevoked);
      case 105: return new CredentialError(ErrorCode.CredentialExpired);
      case 106: return new CredentialError(ErrorCode.CredentialInvalidSignature);
      case 107: return new CredentialError(ErrorCode.CredentialInvalidIssuer);
    }
  }

  // Reputation errors: codes 200-299
  if (code >= 200 && code <= 299) {
    switch (code) {
      case 201: return new ReputationError(ErrorCode.ReputationAlreadyExists);
      case 202: return new ReputationError(ErrorCode.ReputationNotFound);
      case 203: return new ReputationError(ErrorCode.ReputationUnauthorized);
      case 204: return new ReputationError(ErrorCode.ReputationInvalidScore);
      case 205: return new ReputationError(ErrorCode.ReputationInvalidDepth);
    }
  }

  // ZK errors: codes 300-399
  if (code >= 300 && code <= 399) {
    switch (code) {
      case 301: return new ZKProofError(ErrorCode.ZKInvalidProof);
      case 302: return new ZKProofError(ErrorCode.ZKNotFound);
      case 303: return new ZKProofError(ErrorCode.ZKUnauthorized);
      case 304: return new ZKProofError(ErrorCode.ZKInvalidCircuit);
      case 305: return new ZKProofError(ErrorCode.ZKVerificationFailed);
      case 306: return new ZKProofError(ErrorCode.ZKExpired);
      case 307: return new ZKProofError(ErrorCode.ZKNullifierAlreadyUsed);
      case 308: return new ZKProofError(ErrorCode.ZKInvalidPublicInputs);
      case 309: return new ZKProofError(ErrorCode.ZKCircuitDeactivated);
      case 310: return new ZKProofError(ErrorCode.ZKRevokedCredential);
    }
  }

  // Compliance errors: codes 400-499
  if (code >= 400 && code <= 499) {
    switch (code) {
      case 401: return new ComplianceError(ErrorCode.ComplianceAddressBlocked);
      case 402: return new ComplianceError(ErrorCode.ComplianceHighRisk);
      case 403: return new ComplianceError(ErrorCode.ComplianceUnauthorized);
      case 404: return new ComplianceError(ErrorCode.ComplianceNotFound);
      case 405: return new ComplianceError(ErrorCode.ComplianceInvalidRiskScore);
      case 406: return new ComplianceError(ErrorCode.ComplianceOracleStale);
      case 407: return new ComplianceError(ErrorCode.ComplianceInvalidHash);
    }
  }

  return null;
}

export function isDIDError(error: unknown): error is DIDError {
  return error instanceof DIDError;
}

export function isCredentialError(error: unknown): error is CredentialError {
  return error instanceof CredentialError;
}

export function isReputationError(error: unknown): error is ReputationError {
  return error instanceof ReputationError;
}

export function isZKProofError(error: unknown): error is ZKProofError {
  return error instanceof ZKProofError;
}

export function isComplianceError(error: unknown): error is ComplianceError {
  return error instanceof ComplianceError;
}

export function isConfigurationError(error: unknown): error is ConfigurationError {
  return error instanceof ConfigurationError;
}

export function isNetworkError(error: unknown): error is NetworkError {
  return error instanceof NetworkError;
}
