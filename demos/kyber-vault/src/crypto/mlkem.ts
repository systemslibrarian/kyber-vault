// ML-KEM reference: NIST FIPS 203 (August 2024)
// https://csrc.nist.gov/pubs/fips/203/final

import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import type { KEM } from '@noble/post-quantum/utils.js';

export type MLKEMVariant = 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024';

export interface MLKEMKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  variant: MLKEMVariant;
}

export interface MLKEMEncapsResult {
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
}

export const ML_KEM_PARAMS = {
  'ml-kem-512': {
    publicKey: 800,
    privateKey: 1632,
    ciphertext: 768,
    sharedSecret: 32,
    securityCategory: 1,
  },
  'ml-kem-768': {
    publicKey: 1184,
    privateKey: 2400,
    ciphertext: 1088,
    sharedSecret: 32,
    securityCategory: 3,
  },
  'ml-kem-1024': {
    publicKey: 1568,
    privateKey: 3168,
    ciphertext: 1568,
    sharedSecret: 32,
    securityCategory: 5,
  },
} as const;

const VARIANT_IMPL: Record<MLKEMVariant, KEM> = {
  'ml-kem-512': ml_kem512,
  'ml-kem-768': ml_kem768,
  'ml-kem-1024': ml_kem1024,
};

function ensureLength(label: string, actual: number, expected: number): void {
  if (actual !== expected) {
    throw new Error(`${label} length mismatch: expected ${expected}, got ${actual}`);
  }
}

export async function generateKeyPair(variant: MLKEMVariant): Promise<MLKEMKeyPair> {
  const kem = VARIANT_IMPL[variant];
  const params = ML_KEM_PARAMS[variant];
  const pair = kem.keygen();
  ensureLength('public key', pair.publicKey.length, params.publicKey);
  ensureLength('private key', pair.secretKey.length, params.privateKey);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.secretKey,
    variant,
  };
}

export async function encapsulate(
  publicKey: Uint8Array,
  variant: MLKEMVariant,
): Promise<MLKEMEncapsResult> {
  const kem = VARIANT_IMPL[variant];
  const params = ML_KEM_PARAMS[variant];
  ensureLength('public key', publicKey.length, params.publicKey);
  const result = kem.encapsulate(publicKey);
  ensureLength('ciphertext', result.cipherText.length, params.ciphertext);
  ensureLength('shared secret', result.sharedSecret.length, params.sharedSecret);
  return {
    sharedSecret: result.sharedSecret,
    ciphertext: result.cipherText,
  };
}

export async function decapsulate(
  ciphertext: Uint8Array,
  privateKey: Uint8Array,
  variant: MLKEMVariant,
): Promise<Uint8Array> {
  const kem = VARIANT_IMPL[variant];
  const params = ML_KEM_PARAMS[variant];
  ensureLength('ciphertext', ciphertext.length, params.ciphertext);
  ensureLength('private key', privateKey.length, params.privateKey);
  const sharedSecret = kem.decapsulate(ciphertext, privateKey);
  ensureLength('shared secret', sharedSecret.length, params.sharedSecret);
  return sharedSecret;
}
