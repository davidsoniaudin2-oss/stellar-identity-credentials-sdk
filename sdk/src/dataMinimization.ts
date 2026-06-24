import { VerifiableCredential } from './types';
import * as crypto from 'crypto';

export interface BlindedAttribute {
  originalValue: unknown;
  blindingFactor: string;
}

export interface SaltedHashCommitment {
  hash: string;
  salt: string;
}

export interface AttributeExpiration {
  attributeName: string;
  expirationDate: number; // timestamp
}

export interface MinimalDisclosurePolicy {
  allowedAttributes: string[];
  requireBlindingFor?: string[];
  attributeExpirations?: AttributeExpiration[];
}

export class DataMinimizationEngine {
  
  /**
   * Generates a salted hash commitment for a given attribute value.
   */
  public generateSaltedHash(value: string | number | boolean): SaltedHashCommitment {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256').update(`${value}:${salt}`).digest('hex');
    return { hash, salt };
  }

  /**
   * Creates a blinded attribute with a random blinding factor.
   */
  public generateBlindedAttribute(value: unknown): BlindedAttribute {
    const blindingFactor = crypto.randomBytes(32).toString('hex');
    return { originalValue: value, blindingFactor };
  }

  /**
   * Applies a minimal disclosure policy to a given credential.
   * Redacts any fields in `credentialData` not specified in `allowedAttributes`.
   * Also enforces `attributeExpirations`.
   */
  public applyDisclosurePolicy(
    credential: VerifiableCredential,
    policy: MinimalDisclosurePolicy
  ): VerifiableCredential {
    const redactedData: Record<string, unknown> = {};

    const now = Date.now();
    for (const key of Object.keys(credential.credentialData)) {
      if (policy.allowedAttributes.includes(key)) {
        // Check attribute-level expiration
        const expiration = policy.attributeExpirations?.find(e => e.attributeName === key);
        if (expiration && now > expiration.expirationDate) {
          continue; // Attribute expired, omit it
        }

        // Apply blinding if required
        if (policy.requireBlindingFor?.includes(key)) {
          redactedData[key] = this.generateBlindedAttribute(credential.credentialData[key]);
        } else {
          redactedData[key] = credential.credentialData[key];
        }
      }
    }

    return {
      ...credential,
      credentialData: redactedData,
    };
  }
}
