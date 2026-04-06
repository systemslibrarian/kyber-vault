// ML-KEM reference: NIST FIPS 203 (August 2024)
// https://csrc.nist.gov/pubs/fips/203/final

export const Q = 3329;

export interface LWEInstance {
  A: number[][];
  s: number[];
  e: number[];
  b: number[];
  n: number;
  m: number;
}

function mod(value: number, q: number): number {
  return ((value % q) + q) % q;
}

function sampleUniformModQ(q: number): number {
  return Math.floor(Math.random() * q);
}

function sampleCBD(eta = 2): number {
  let heads = 0;
  let tails = 0;
  for (let i = 0; i < eta; i += 1) {
    heads += Math.random() < 0.5 ? 1 : 0;
    tails += Math.random() < 0.5 ? 1 : 0;
  }
  return heads - tails;
}

function dot(a: number[], b: number[], q: number): number {
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) {
    acc = mod(acc + a[i] * b[i], q);
  }
  return acc;
}

export function generateLWEInstance(n: number, m: number): LWEInstance {
  if (n <= 0 || m <= 0) {
    throw new Error('LWE dimensions n and m must be positive');
  }
  const A: number[][] = Array.from({ length: m }, () =>
    Array.from({ length: n }, () => sampleUniformModQ(Q)),
  );
  const s: number[] = Array.from({ length: n }, () => sampleCBD(2));
  const e: number[] = Array.from({ length: m }, () => sampleCBD(2));
  const b: number[] = Array.from({ length: m }, (_, i) => mod(dot(A[i], s, Q) + e[i], Q));

  return { A, s, e, b, n, m };
}

export function verifyLWE(instance: LWEInstance): boolean {
  const { A, s, e, b, m } = instance;
  for (let i = 0; i < m; i += 1) {
    const expected = mod(dot(A[i], s, Q) + e[i], Q);
    if (b[i] !== expected) {
      return false;
    }
  }
  return true;
}

function formatBigInt(value: bigint): string {
  const str = value.toString();
  return str.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function bruteForceSearchSpace(n: number): string {
  if (n <= 0) {
    throw new Error('n must be positive');
  }
  const space = BigInt(Q) ** BigInt(n);
  return `For n=${n} and q=${Q}, brute-force secret search is q^n = ${formatBigInt(space)} candidates.`;
}

export function generateIllustrativeLWEInstance(n: number, m: number, q: number): LWEInstance {
  const A: number[][] = Array.from({ length: m }, () =>
    Array.from({ length: n }, () => sampleUniformModQ(q)),
  );
  const s: number[] = Array.from({ length: n }, () => sampleCBD(2));
  const e: number[] = Array.from({ length: m }, () => sampleCBD(2));
  const b: number[] = Array.from({ length: m }, (_, i) => mod(dot(A[i], s, q) + e[i], q));

  return { A, s, e, b, n, m };
}

export function verifyLWEWithQ(instance: LWEInstance, q: number): boolean {
  for (let i = 0; i < instance.m; i += 1) {
    const expected = mod(dot(instance.A[i], instance.s, q) + instance.e[i], q);
    if (instance.b[i] !== expected) {
      return false;
    }
  }
  return true;
}
