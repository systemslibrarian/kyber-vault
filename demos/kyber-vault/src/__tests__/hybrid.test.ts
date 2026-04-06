import { describe, expect, it } from 'vitest';
import { flipBase64Byte, hybridDecrypt, hybridEncrypt } from '../crypto/hybrid';
import { generateKeyPair, type MLKEMVariant } from '../crypto/mlkem';

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];

describe('Hybrid ML-KEM + AES-256-GCM flow', () => {
  it('round-trips encryption/decryption for all variants', async () => {
    for (const variant of VARIANTS) {
      const recipient = await generateKeyPair(variant);
      const message = `round-trip ${variant}`;
      const payload = await hybridEncrypt(message, recipient.publicKey, variant);
      const plaintext = await hybridDecrypt(payload, recipient.privateKey);
      expect(plaintext).toBe(message);
    }
  });

  it('tampered ML-KEM ciphertext causes explicit AES authentication failure', async () => {
    const recipient = await generateKeyPair('ml-kem-768');
    const payload = await hybridEncrypt('tamper test', recipient.publicKey, 'ml-kem-768');
    const tamperedPayload = {
      ...payload,
      mlkemCiphertext: flipBase64Byte(payload.mlkemCiphertext, 0),
    };

    await expect(hybridDecrypt(tamperedPayload, recipient.privateKey)).rejects.toThrow(
      'Authentication failed',
    );
  });
});
