import { describe, expect, it } from 'vitest';
import { Q, generateLWEInstance, verifyLWE } from '../crypto/lwe';

describe('LWE arithmetic engine', () => {
  it('verifyLWE(generateLWEInstance(4, 6)) returns true', () => {
    expect(verifyLWE(generateLWEInstance(4, 6))).toBe(true);
  });

  it('b is always in [0, Q)', () => {
    const instance = generateLWEInstance(4, 6);
    for (const value of instance.b) {
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(Q);
    }
  });

  it('CBD eta=2 samples stay small for s and e (|v| <= 3)', () => {
    const instance = generateLWEInstance(6, 4);
    for (const value of [...instance.s, ...instance.e]) {
      expect(Math.abs(value)).toBeLessThanOrEqual(3);
    }
  });
});
