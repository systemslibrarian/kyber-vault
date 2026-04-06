import { describe, expect, it } from 'vitest';
import {
  type MLKEMVariant,
  ML_KEM_PARAMS,
  decapsulate,
  encapsulate,
  generateKeyPair,
} from '../crypto/mlkem';

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('ML-KEM wrappers', () => {
  it('all variants round-trip and shared secret is 32 bytes', async () => {
    for (const variant of VARIANTS) {
      const bob = await generateKeyPair(variant);
      const alice = await encapsulate(bob.publicKey, variant);
      const bobSecret = await decapsulate(alice.ciphertext, bob.privateKey, variant);

      expect(toHex(bobSecret)).toBe(toHex(alice.sharedSecret));
      expect(alice.sharedSecret.length).toBe(32);
      expect(bobSecret.length).toBe(32);
    }
  });

  it('wrong private key yields a different shared secret via implicit rejection', async () => {
    const variant: MLKEMVariant = 'ml-kem-768';
    const bob = await generateKeyPair(variant);
    const mallory = await generateKeyPair(variant);
    const alice = await encapsulate(bob.publicKey, variant);

    const bobSecret = await decapsulate(alice.ciphertext, bob.privateKey, variant);
    const mallorySecret = await decapsulate(alice.ciphertext, mallory.privateKey, variant);

    expect(toHex(bobSecret)).not.toBe(toHex(mallorySecret));
  });

  it('matches FIPS 203 parameter lengths for keys and ciphertext', async () => {
    for (const variant of VARIANTS) {
      const keyPair = await generateKeyPair(variant);
      const encapsResult = await encapsulate(keyPair.publicKey, variant);

      expect(keyPair.publicKey.length).toBe(ML_KEM_PARAMS[variant].publicKey);
      expect(keyPair.privateKey.length).toBe(ML_KEM_PARAMS[variant].privateKey);
      expect(encapsResult.ciphertext.length).toBe(ML_KEM_PARAMS[variant].ciphertext);
      expect(encapsResult.sharedSecret.length).toBe(ML_KEM_PARAMS[variant].sharedSecret);
    }
  });
});
